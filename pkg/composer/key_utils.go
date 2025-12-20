package composer

import (
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Key type constants matching Python aldaba.KeyType
const (
	KeyTypePrime256V1 = "prime256v1"
	KeyTypeRSA        = "rsa"
	KeyTypeSM2        = "sm2"
	KeyTypeBLS12381   = "bls12381"
)

// PubKeyPrefix constants matching Python documentation
const (
	PubKeyPrefixPrime256V1 = "1003" // P256v1 prefix
	PubKeyPrefixRSA        = "1023" // RSA prefix
	PubKeyPrefixBLS12381   = "4003" // BLS prefix
)

// GetPubkey reads domain public key from key_pub file or generates from private key
// Matches Python version Generator._get_pubkey logic (conf.py:144-173)
// Returns: (publicKeyHex string, publicKeyBytes []byte, error)
func GetPubkey(keyType string, keyPubPath string, keyPath string, noPrefix bool) (string, []byte, error) {
	// Try to read from key_pub file first
	if pubkeyBytes, err := os.ReadFile(keyPubPath); err == nil {
		pubkey := strings.TrimSpace(string(pubkeyBytes))
		if noPrefix && strings.HasPrefix(pubkey, "1003") {
			pubkey = pubkey[4:]
		}
		// Convert to bytes
		decoded, err := hex.DecodeString(pubkey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode public key hex: %w", err)
		}
		return pubkey, decoded, nil
	}

	// Fallback: generate from private key
	if noPrefix {
		return getPubkeyRaw(keyType, keyPath)
	}
	return getPubkey(keyType, keyPath)
}

// getPubkey generates public key from private key with prefix
// Matches Python version Generator._get_pubkey (conf.py:144-173)
func getPubkey(keyType string, keyPath string) (string, []byte, error) {
	if !exists(keyPath) {
		return "", nil, fmt.Errorf("private key file does not exist: %s", keyPath)
	}

	switch keyType {
	case KeyTypePrime256V1:
		// pubkey = '1003' + read_keyfile_to_hex('ec', prikey_path, key_passwd)
		pubkeyHex, err := readKeyFileToHex(keyType, keyPath)
		if err != nil {
			return "", nil, err
		}
		pubkey := PubKeyPrefixPrime256V1 + pubkeyHex
		pubkeyBytes, err := hex.DecodeString(pubkey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode public key: %w", err)
		}
		return pubkey, pubkeyBytes, nil

	case KeyTypeRSA:
		// pubkey = '1023' + read_keyfile_to_hex('rsa', prikey_path, key_passwd)
		pubkeyHex, err := readKeyFileToHex(keyType, keyPath)
		if err != nil {
			return "", nil, err
		}
		pubkey := PubKeyPrefixRSA + pubkeyHex
		pubkeyBytes, err := hex.DecodeString(pubkey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode public key: %w", err)
		}
		return pubkey, pubkeyBytes, nil

	case KeyTypeSM2:
		return "", nil, fmt.Errorf("SM2 key type is not supported")

	case KeyTypeBLS12381:
		return "", nil, fmt.Errorf("BLS12381 key type not implemented for pubkey generation")

	default:
		return "", nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// getPubkeyRaw generates public key from private key without prefix
// Matches Python version Generator._get_pubkey_raw (conf.py:175-199)
func getPubkeyRaw(keyType string, keyPath string) (string, []byte, error) {
	if !exists(keyPath) {
		return "", nil, fmt.Errorf("private key file does not exist: %s", keyPath)
	}

	switch keyType {
	case KeyTypePrime256V1:
		// pubkey = read_keyfile_to_hex('ec', prikey_path, key_passwd)
		pubkeyHex, err := readKeyFileToHex(keyType, keyPath)
		if err != nil {
			return "", nil, err
		}
		pubkeyBytes, err := hex.DecodeString(pubkeyHex)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode public key: %w", err)
		}
		return pubkeyHex, pubkeyBytes, nil

	case KeyTypeRSA:
		// pubkey = read_keyfile_to_hex('rsa', prikey_path, key_passwd)
		pubkeyHex, err := readKeyFileToHex(keyType, keyPath)
		if err != nil {
			return "", nil, err
		}
		pubkeyBytes, err := hex.DecodeString(pubkeyHex)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode public key: %w", err)
		}
		return pubkeyHex, pubkeyBytes, nil

	case KeyTypeSM2:
		return "", nil, fmt.Errorf("SM2 key type is not supported")

	case KeyTypeBLS12381:
		return "", nil, fmt.Errorf("BLS12381 key type not implemented for pubkey generation")

	default:
		return "", nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// readKeyFileToHex reads private key file and returns public key as hex string
// Matches Python version read_keyfile_to_hex function
// Currently supports: EC (prime256v1), RSA
func readKeyFileToHex(keyType string, keyPath string) (string, error) {
	// Read private key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}

	// Try to parse as PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		// Not a PEM file, might be raw hex or binary
		// For now, return error
		return "", fmt.Errorf("failed to decode PEM block from private key file")
	}

	switch keyType {
	case KeyTypePrime256V1:
		// Parse EC private key
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse EC private key: %w", err)
		}

		// Get public key from private key
		// The x509.ParseECPrivateKey already populates the PublicKey field
		publicKey := privateKey.PublicKey

		// Convert to uncompressed format (04 + X + Y)
		// P-256 curve uses 32 bytes for X and 32 bytes for Y
		pubkeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)

		// Return as hex string (without prefix)
		return hex.EncodeToString(pubkeyBytes), nil

	case KeyTypeRSA:
		// Parse PKCS1 or PKCS8 private key
		var privateKey interface{}
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return "", fmt.Errorf("failed to parse RSA private key: %w", err)
			}
		}

		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not an RSA private key")
		}
		_ = rsaKey
		// For RSA, we need to extract and encode the public key
		// This is more complex and depends on the specific format required
		return "", fmt.Errorf("RSA public key extraction not fully implemented")

	default:
		return "", fmt.Errorf("unsupported key type for readKeyFileToHex: %s", keyType)
	}
}

// exists checks if a file exists
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
