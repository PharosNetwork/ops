package genesis

import (
	"crypto/sha256"

	"github.com/ethereum/go-ethereum/crypto"
)

// keccak256 returns the Keccak-256 hash of concatenated inputs. Thin
// wrapper over go-ethereum's crypto.Keccak256 so the slot generators
// don't import that path directly.
func keccak256(parts ...[]byte) []byte {
	return crypto.Keccak256(parts...)
}

// sha256Sum returns the SHA-256 hash of b. Python: hashlib.sha256(b).digest().
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
