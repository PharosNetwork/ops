// Package keystore implements the EIP-2335 BLS12-381 keystore format.
//
// EIP-2335 stores a secret (typically a 32-byte BLS12-381 private key)
// encrypted under a password-derived key. The on-disk form is a JSON
// document; see https://eips.ethereum.org/EIPS/eip-2335.
//
// The two most error-prone parts of the spec, pinned here so the
// implementation can be checked against them directly:
//
//   - AES cipher key   = decryption_key[0:16]   (first 16 bytes)
//   - checksum message = SHA256(decryption_key[16:32] || cipher_message)
//
// Do NOT swap those two slices — they use different halves of the DK.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// Keystore is the top-level EIP-2335 document (version 4).
type Keystore struct {
	Crypto      CryptoModule `json:"crypto"`
	Description string       `json:"description,omitempty"`
	Pubkey      string       `json:"pubkey,omitempty"`
	Path        string       `json:"path"`
	UUID        string       `json:"uuid"`
	Version     int          `json:"version"`
}

// CryptoModule holds the three EIP-2335 sub-modules.
type CryptoModule struct {
	KDF      Module `json:"kdf"`
	Checksum Module `json:"checksum"`
	Cipher   Module `json:"cipher"`
}

// Module is one of kdf/checksum/cipher. Params is kept as a raw map so
// unknown-but-valid params round-trip untouched, and so the JSON key order
// matches the spec examples when we control construction.
type Module struct {
	Function string                 `json:"function"`
	Params   map[string]interface{} `json:"params"`
	Message  string                 `json:"message"`
}

// KDF function names.
const (
	kdfScrypt = "scrypt"
	kdfPBKDF2 = "pbkdf2"
)

// Default scrypt parameters, matching the EIP-2335 scrypt test vector.
const (
	defaultScryptN     = 262144
	defaultScryptR     = 8
	defaultScryptP     = 1
	defaultScryptDKLen = 32
)

// normalizePassword applies the EIP-2335 password preprocessing:
// NFKD normalization, then strip C0 (0x00-0x1F), C1 (0x80-0x9F) and
// DEL (0x7F) control codes, then UTF-8 encode. Space (0x20) is kept.
func normalizePassword(password string) []byte {
	nfkd := norm.NFKD.String(password)
	out := make([]rune, 0, len(nfkd))
	for _, r := range nfkd {
		// Strip control codes per the spec. 0x20 (space) is explicitly kept.
		if (r >= 0x00 && r <= 0x1F) || (r >= 0x80 && r <= 0x9F) || r == 0x7F {
			continue
		}
		out = append(out, r)
	}
	return []byte(string(out))
}

// deriveKey runs the keystore's KDF over the preprocessed password and
// returns the 32-byte decryption key.
func deriveKey(kdf Module, password []byte) ([]byte, error) {
	saltHex, ok := kdf.Params["salt"].(string)
	if !ok {
		return nil, fmt.Errorf("kdf params missing string 'salt'")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("invalid kdf salt hex: %w", err)
	}
	dklen, err := paramInt(kdf.Params, "dklen")
	if err != nil {
		return nil, err
	}

	switch kdf.Function {
	case kdfScrypt:
		n, err := paramInt(kdf.Params, "n")
		if err != nil {
			return nil, err
		}
		r, err := paramInt(kdf.Params, "r")
		if err != nil {
			return nil, err
		}
		p, err := paramInt(kdf.Params, "p")
		if err != nil {
			return nil, err
		}
		return scrypt.Key(password, salt, n, r, p, dklen)
	case kdfPBKDF2:
		c, err := paramInt(kdf.Params, "c")
		if err != nil {
			return nil, err
		}
		prf, _ := kdf.Params["prf"].(string)
		if prf != "" && prf != "hmac-sha256" {
			return nil, fmt.Errorf("unsupported pbkdf2 prf: %q", prf)
		}
		return pbkdf2.Key(password, salt, c, dklen, sha256.New), nil
	default:
		return nil, fmt.Errorf("unsupported kdf function: %q", kdf.Function)
	}
}

// aesCTR runs AES-128-CTR over data with the given 16-byte key and iv.
// CTR is symmetric, so this both encrypts and decrypts.
func aesCTR(key16, iv, data []byte) ([]byte, error) {
	if len(key16) != 16 {
		return nil, fmt.Errorf("aes-128-ctr key must be 16 bytes, got %d", len(key16))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("aes iv must be %d bytes, got %d", aes.BlockSize, len(iv))
	}
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(out, data)
	return out, nil
}

// computeChecksum returns SHA256(dk[16:32] || cipherMessage).
func computeChecksum(dk, cipherMessage []byte) []byte {
	h := sha256.New()
	h.Write(dk[16:32])
	h.Write(cipherMessage)
	return h.Sum(nil)
}

// paramInt coerces a JSON-decoded numeric param to int. json.Unmarshal
// yields float64 for numbers; callers may also construct params with int.
func paramInt(params map[string]interface{}, key string) (int, error) {
	v, ok := params[key]
	if !ok {
		return 0, fmt.Errorf("kdf params missing %q", key)
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case int64:
		return int(n), nil
	default:
		return 0, fmt.Errorf("kdf param %q has unexpected type %T", key, v)
	}
}

// Marshal renders the keystore as indented JSON.
func (k *Keystore) Marshal() ([]byte, error) {
	return json.MarshalIndent(k, "", "  ")
}

// Parse decodes an EIP-2335 keystore JSON document.
func Parse(data []byte) (*Keystore, error) {
	var k Keystore
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("invalid keystore json: %w", err)
	}
	if k.Version != 4 {
		return nil, fmt.Errorf("unsupported keystore version: %d (want 4)", k.Version)
	}
	return &k, nil
}
