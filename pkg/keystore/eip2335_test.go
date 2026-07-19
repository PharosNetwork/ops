package keystore

import (
	"encoding/hex"
	"testing"
)

// The canonical EIP-2335 scrypt test vector.
// Source: https://eips.ethereum.org/EIPS/eip-2335 (Test Vectors section).
//
// All three of {secret, password, salt, iv} are fixed by the spec, and the
// spec publishes the resulting checksum and cipher.message. If our Encrypt
// reproduces those two outputs byte-for-byte from the same inputs, the KDF /
// AES / checksum wiring is provably correct and interoperable with other
// EIP-2335 tooling.
const (
	tvSalt = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
	tvIV   = "264daa3f303d7259501c93d997d84fe6"

	tvScryptChecksum = "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
	tvScryptCipher   = "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"

	tvPubkey = "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
	tvUUID   = "1d85ae20-35c5-4611-98e8-aa14a633906f"
)

// tvPassword is the spec's test password "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑".
// We build it from the raw math-alphanumeric code points rather than hand
// transcribing escapes: 𝔱=U+1D531 ... (Mathematical Fraktur Small letters),
// followed by 🔑 U+1F511. NFKD folds the fraktur letters to ASCII
// "testpassword", giving the spec's UTF-8 encoding 7465737470617373776f7264f09f9491.
var tvPassword = "\U0001D531\U0001D522\U0001D530\U0001D531\U0001D52D\U0001D51E\U0001D530\U0001D530\U0001D534\U0001D52C\U0001D52F\U0001D521\U0001F511"

// tvSecretBytes is the exact 32-byte secret from the EIP-2335 test vector.
var tvSecretBytes = mustHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncryptScryptTestVector(t *testing.T) {
	// Guard: our test password must NFKD-fold to the spec's exact UTF-8 bytes.
	// Catches code-point transcription errors before the (misleading) checksum
	// mismatch would.
	const officialPwHex = "7465737470617373776f7264f09f9491"
	if got := hex.EncodeToString(normalizePassword(tvPassword)); got != officialPwHex {
		t.Fatalf("test password normalization wrong:\n got  %s\n want %s\n(fix the tvPassword code points)", got, officialPwHex)
	}

	salt, _ := hex.DecodeString(tvSalt)
	iv, _ := hex.DecodeString(tvIV)

	ks, err := Encrypt(tvSecretBytes, tvPassword, EncryptOptions{
		KDF:    "scrypt",
		Salt:   salt,
		IV:     iv,
		UUID:   tvUUID,
		Pubkey: tvPubkey,
		Path:   "m/12381/60/3141592653/589793238",
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if got := ks.Crypto.Cipher.Message; got != tvScryptCipher {
		t.Errorf("cipher.message mismatch:\n got  %s\n want %s", got, tvScryptCipher)
	}
	if got := ks.Crypto.Checksum.Message; got != tvScryptChecksum {
		t.Errorf("checksum.message mismatch:\n got  %s\n want %s", got, tvScryptChecksum)
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	// Encrypt with random salt/iv/uuid, then decrypt and compare.
	secret := mustHex("2e9c98a48e6d2e5c3e2f8c0d1a4b6f8e0a1c3d5f7b9d1e3c5a7f9b1d3e5c7a9f")
	pw := "correct horse battery staple"

	ks, err := Encrypt(secret, pw, EncryptOptions{KDF: "scrypt"})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := Decrypt(ks, pw)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(secret) {
		t.Errorf("round-trip secret mismatch:\n got  %x\n want %x", got, secret)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	secret := mustHex("2e9c98a48e6d2e5c3e2f8c0d1a4b6f8e0a1c3d5f7b9d1e3c5a7f9b1d3e5c7a9f")
	ks, err := Encrypt(secret, "right-password", EncryptOptions{KDF: "scrypt"})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := Decrypt(ks, "wrong-password"); err != ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestPBKDF2RoundTrip(t *testing.T) {
	secret := mustHex("2e9c98a48e6d2e5c3e2f8c0d1a4b6f8e0a1c3d5f7b9d1e3c5a7f9b1d3e5c7a9f")
	pw := "pbkdf2-password"
	ks, err := Encrypt(secret, pw, EncryptOptions{KDF: "pbkdf2"})
	if err != nil {
		t.Fatalf("Encrypt (pbkdf2) failed: %v", err)
	}
	got, err := Decrypt(ks, pw)
	if err != nil {
		t.Fatalf("Decrypt (pbkdf2) failed: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(secret) {
		t.Errorf("pbkdf2 round-trip mismatch")
	}
}
