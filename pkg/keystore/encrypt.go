package keystore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/uuid"
)

// EncryptOptions controls keystore construction. All fields are optional;
// zero values trigger secure random generation. Deterministic values are
// injectable so tests can reproduce known EIP-2335 test vectors byte-for-byte.
type EncryptOptions struct {
	// KDF selects the key-derivation function: "scrypt" (default) or "pbkdf2".
	KDF string
	// Salt is the KDF salt. If nil, 32 random bytes are generated.
	Salt []byte
	// IV is the AES-128-CTR initialization vector. If nil, 16 random bytes.
	IV []byte
	// UUID overrides the generated RFC-4122 UUID. Empty => random v4.
	UUID string
	// Pubkey is the hex public key stored in the keystore (no 0x prefix).
	Pubkey string
	// Path is the ERC-2334 derivation path; "" if unknown.
	Path string
	// Description is an optional human-readable note.
	Description string
	// ScryptN/R/P override scrypt cost params (0 => defaults).
	ScryptN, ScryptR, ScryptP int
	// PBKDF2C overrides the pbkdf2 iteration count (0 => 262144).
	PBKDF2C int
}

// Encrypt builds an EIP-2335 keystore that seals `secret` under `password`.
// `secret` is the raw secret bytes (for BLS, the 32-byte private key scalar,
// WITHOUT any aldaba type tag).
func Encrypt(secret []byte, password string, opts EncryptOptions) (*Keystore, error) {
	kdfFn := opts.KDF
	if kdfFn == "" {
		kdfFn = kdfScrypt
	}

	salt := opts.Salt
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	iv := opts.IV
	if iv == nil {
		iv = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("failed to generate iv: %w", err)
		}
	}

	id := opts.UUID
	if id == "" {
		u, err := uuid.NewRandom()
		if err != nil {
			return nil, fmt.Errorf("failed to generate uuid: %w", err)
		}
		id = u.String()
	}

	// Build the KDF module.
	kdf, err := buildKDFModule(kdfFn, salt, opts)
	if err != nil {
		return nil, err
	}

	// Derive the 32-byte decryption key.
	pw := normalizePassword(password)
	dk, err := deriveKey(kdf, pw)
	if err != nil {
		return nil, fmt.Errorf("kdf failed: %w", err)
	}
	if len(dk) < 32 {
		return nil, fmt.Errorf("decryption key too short: %d bytes (need >= 32)", len(dk))
	}

	// Encrypt the secret with AES-128-CTR under DK[0:16].
	cipherMessage, err := aesCTR(dk[0:16], iv, secret)
	if err != nil {
		return nil, fmt.Errorf("aes encrypt failed: %w", err)
	}

	// Checksum = SHA256(DK[16:32] || cipherMessage).
	checksum := computeChecksum(dk, cipherMessage)

	ks := &Keystore{
		Crypto: CryptoModule{
			KDF: kdf,
			Checksum: Module{
				Function: "sha256",
				Params:   map[string]interface{}{},
				Message:  hex.EncodeToString(checksum),
			},
			Cipher: Module{
				Function: "aes-128-ctr",
				Params:   map[string]interface{}{"iv": hex.EncodeToString(iv)},
				Message:  hex.EncodeToString(cipherMessage),
			},
		},
		Description: opts.Description,
		Pubkey:      opts.Pubkey,
		Path:        opts.Path,
		UUID:        id,
		Version:     4,
	}
	return ks, nil
}

// buildKDFModule constructs the kdf Module with correct param ordering.
func buildKDFModule(fn string, salt []byte, opts EncryptOptions) (Module, error) {
	switch fn {
	case kdfScrypt:
		n, r, p := opts.ScryptN, opts.ScryptR, opts.ScryptP
		if n == 0 {
			n = defaultScryptN
		}
		if r == 0 {
			r = defaultScryptR
		}
		if p == 0 {
			p = defaultScryptP
		}
		return Module{
			Function: kdfScrypt,
			Params: map[string]interface{}{
				"dklen": defaultScryptDKLen,
				"n":     n,
				"p":     p,
				"r":     r,
				"salt":  hex.EncodeToString(salt),
			},
			Message: "",
		}, nil
	case kdfPBKDF2:
		c := opts.PBKDF2C
		if c == 0 {
			c = 262144
		}
		return Module{
			Function: kdfPBKDF2,
			Params: map[string]interface{}{
				"dklen": defaultScryptDKLen,
				"c":     c,
				"prf":   "hmac-sha256",
				"salt":  hex.EncodeToString(salt),
			},
			Message: "",
		}, nil
	default:
		return Module{}, fmt.Errorf("unsupported kdf function: %q", fn)
	}
}

// Decrypt recovers the secret sealed in the keystore under `password`.
// It verifies the checksum before returning; a wrong password or a corrupt
// keystore yields ErrInvalidPassword.
func Decrypt(k *Keystore, password string) ([]byte, error) {
	cipherMessage, err := hex.DecodeString(k.Crypto.Cipher.Message)
	if err != nil {
		return nil, fmt.Errorf("invalid cipher message hex: %w", err)
	}

	pw := normalizePassword(password)
	dk, err := deriveKey(k.Crypto.KDF, pw)
	if err != nil {
		return nil, fmt.Errorf("kdf failed: %w", err)
	}
	if len(dk) < 32 {
		return nil, fmt.Errorf("decryption key too short: %d bytes", len(dk))
	}

	// Verify checksum before attempting decryption.
	want := k.Crypto.Checksum.Message
	got := hex.EncodeToString(computeChecksum(dk, cipherMessage))
	if got != want {
		return nil, ErrInvalidPassword
	}

	if k.Crypto.Cipher.Function != "aes-128-ctr" {
		return nil, fmt.Errorf("unsupported cipher: %q", k.Crypto.Cipher.Function)
	}
	ivHex, _ := k.Crypto.Cipher.Params["iv"].(string)
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("invalid iv hex: %w", err)
	}

	secret, err := aesCTR(dk[0:16], iv, cipherMessage)
	if err != nil {
		return nil, fmt.Errorf("aes decrypt failed: %w", err)
	}
	return secret, nil
}

// ErrInvalidPassword is returned when the checksum does not match, which
// means either the password is wrong or the keystore is corrupt.
var ErrInvalidPassword = fmt.Errorf("invalid password or corrupt keystore (checksum mismatch)")
