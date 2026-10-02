// Package bls provides the minimal BLS12-381 operations ops needs for
// keystore migration: deriving a public key from a private key and
// verifying that a private key matches a known public key.
//
// Scheme: min-pubkey-size (pubkey in G1, 48-byte compressed; signatures in
// G2). This matches pharos/aldaba's on-disk stabilizing keys and Ethereum 2.0.
// Verified empirically: the 32-byte big-endian private key scalar, run through
// P1Affine.From().Compress(), reproduces the node's stabilizing.pub byte-for-byte.
package bls

import (
	"encoding/hex"
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// SecretKeySize is the byte length of a BLS12-381 private key scalar.
const SecretKeySize = 32

// PublicKeySize is the byte length of a compressed G1 public key.
const PublicKeySize = 48

// DerivePublicKey computes the 48-byte compressed G1 public key for the given
// 32-byte big-endian private key scalar (aldaba type tags must already be
// stripped). It returns an error if the scalar is not a valid field element.
func DerivePublicKey(privKey []byte) ([]byte, error) {
	if len(privKey) != SecretKeySize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", SecretKeySize, len(privKey))
	}
	sk := new(blst.SecretKey).FromBEndian(privKey)
	if sk == nil {
		return nil, fmt.Errorf("invalid BLS private key: scalar not in field")
	}
	pk := new(blst.P1Affine).From(sk)
	if pk == nil {
		return nil, fmt.Errorf("failed to derive public key from scalar")
	}
	return pk.Compress(), nil
}

// VerifyKeyPair checks that privKey derives to expectedPub. Both are raw bytes
// with aldaba tags stripped (privKey 32 bytes, expectedPub 48 bytes). Returns
// nil on match, a descriptive error otherwise.
func VerifyKeyPair(privKey, expectedPub []byte) error {
	derived, err := DerivePublicKey(privKey)
	if err != nil {
		return err
	}
	if len(expectedPub) != PublicKeySize {
		return fmt.Errorf("expected public key must be %d bytes, got %d", PublicKeySize, len(expectedPub))
	}
	if hex.EncodeToString(derived) != hex.EncodeToString(expectedPub) {
		return fmt.Errorf("key pair mismatch: derived pubkey %s does not match expected %s",
			hex.EncodeToString(derived), hex.EncodeToString(expectedPub))
	}
	return nil
}
