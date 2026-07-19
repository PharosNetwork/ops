package bls

import (
	"encoding/hex"
	"testing"
)

// Real (privkey, pubkey) pair captured from a live mainnet node, with the
// aldaba type tags stripped:
//
//	stabilizing.key = 0x4002 + realPrivHex
//	stabilizing.pub = 0x4003 + realPubHex
//
// This is the ground-truth golden vector: DerivePublicKey(realPriv) must equal
// realPub byte-for-byte, proving scheme (min-pubkey-size / G1) and byte order
// (big-endian) are correct.
const (
	realPrivHex = "3f0e8d53a6ababb2e1e363a5c0fa5506303174893c298ff7b47b442661e5ff39"
	realPubHex  = "b7c1dd5e6ede474a508b7dac328b749826934bab9296491051316e5ee4e58a68b1a604ebae5a0942336f4752ba05b50a"
)

func TestDerivePublicKeyGolden(t *testing.T) {
	priv, _ := hex.DecodeString(realPrivHex)
	got, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("DerivePublicKey failed: %v", err)
	}
	if hex.EncodeToString(got) != realPubHex {
		t.Errorf("derived pubkey mismatch:\n got  %s\n want %s", hex.EncodeToString(got), realPubHex)
	}
	if len(got) != PublicKeySize {
		t.Errorf("pubkey length = %d, want %d", len(got), PublicKeySize)
	}
}

func TestVerifyKeyPair(t *testing.T) {
	priv, _ := hex.DecodeString(realPrivHex)
	pub, _ := hex.DecodeString(realPubHex)

	if err := VerifyKeyPair(priv, pub); err != nil {
		t.Errorf("VerifyKeyPair should succeed for matching pair: %v", err)
	}

	// Tamper the pubkey: must fail.
	badPub := make([]byte, len(pub))
	copy(badPub, pub)
	badPub[0] ^= 0xff
	if err := VerifyKeyPair(priv, badPub); err == nil {
		t.Error("VerifyKeyPair should fail for mismatched pair")
	}
}

func TestDerivePublicKeyBadLength(t *testing.T) {
	if _, err := DerivePublicKey([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for wrong-length private key")
	}
}

func TestStripTag(t *testing.T) {
	cases := map[string]string{
		"0x4002" + realPrivHex: realPrivHex, // priv with 0x + tag
		"4002" + realPrivHex:   realPrivHex, // priv with tag, no 0x
		"0x4003" + realPubHex:  realPubHex,  // pub with 0x + tag
		"0x" + realPrivHex:     realPrivHex, // 0x, no tag
		realPrivHex:            realPrivHex, // bare payload
	}
	for in, want := range cases {
		if got := StripTag(in); got != want {
			t.Errorf("StripTag(%.12s...) = %.12s..., want %.12s...", in, got, want)
		}
	}
}

func TestStripThenDerive(t *testing.T) {
	// Simulate reading a real stabilizing.key line and deriving the pubkey.
	keyLine := "0x4002" + realPrivHex
	priv, err := hex.DecodeString(StripTag(keyLine))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	// Compare against the tagged pub line.
	pubLine := "0x4003" + realPubHex
	if AddPubTag(hex.EncodeToString(got)) != pubLine {
		t.Errorf("round-trip pub mismatch: %s vs %s", AddPubTag(hex.EncodeToString(got)), pubLine)
	}
}
