package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pharos-ops/pkg/utils"
)

// KeyGenerator handles key generation and extraction
type KeyGenerator struct {
	BuildRoot string
}

// NewKeyGenerator creates a new KeyGenerator
func NewKeyGenerator(buildRoot string) *KeyGenerator {
	return &KeyGenerator{BuildRoot: buildRoot}
}

// GetKeyFileName returns the key file name based on use_generated_keys setting
func GetKeyFileName(useGeneratedKeys bool) string {
	if useGeneratedKeys {
		return "generate"
	}
	return "new"
}

// GeneratePrivateKey generates a private key file using OpenSSL
// This matches Python's _generate_prikey function for prime256v1 and RSA
func (kg *KeyGenerator) GeneratePrivateKey(keyType, keyDir, keyFile, keyPasswd string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	prikeyPath := filepath.Join(keyDir, keyFile)
	pubkeyFile := strings.Replace(keyFile, ".key", ".pub", 1)
	popFile := strings.Replace(keyFile, ".key", ".pop", 1)

	// Check if key exists
	if _, err := os.Stat(prikeyPath); err == nil {
		utils.Debug("existed key: %s, override it with new key", prikeyPath)
	} else {
		utils.Info("generate new key %s", prikeyPath)
	}

	switch strings.ToLower(keyType) {
	case "prime256v1", "p256v1":
		// Generate EC key with prime256v1 curve
		// openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -outform pem -out {prikey_path} -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:{key_passwd}
		cmd := exec.Command("sh", "-c", fmt.Sprintf(
			"openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -outform pem -out %s -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:%s",
			prikeyPath, keyPasswd))
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to generate EC key: %v, output: %s", err, string(output))
		}

		// Extract public key
		pubkey, err := kg.GetPubkeyFromFile(keyType, prikeyPath, keyPasswd)
		if err != nil {
			return fmt.Errorf("failed to extract public key: %w", err)
		}

		// Write public key to file (with prefix)
		pubkeyHex := "1003" + hex.EncodeToString(pubkey)
		pubkeyPath := filepath.Join(keyDir, pubkeyFile)
		if err := os.WriteFile(pubkeyPath, []byte(pubkeyHex), 0644); err != nil {
			return fmt.Errorf("failed to write public key file: %w", err)
		}

		// Generate PoP using aldaba_cli
		if err := kg.generatePoP(keyDir, popFile, prikeyPath, keyPasswd); err != nil {
			utils.Warn("Failed to generate PoP: %v", err)
		}

	case "rsa", "rsa2048":
		// Generate RSA key
		cmd := exec.Command("sh", "-c", fmt.Sprintf(
			"openssl genrsa 2048 | openssl pkcs8 -topk8 -outform pem -out %s -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:%s",
			prikeyPath, keyPasswd))
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to generate RSA key: %v, output: %s", err, string(output))
		}

		// Extract public key
		pubkey, err := kg.GetPubkeyFromFile(keyType, prikeyPath, keyPasswd)
		if err != nil {
			return fmt.Errorf("failed to extract public key: %w", err)
		}

		// Write public key to file (with prefix)
		pubkeyHex := "1023" + hex.EncodeToString(pubkey)
		pubkeyPath := filepath.Join(keyDir, pubkeyFile)
		if err := os.WriteFile(pubkeyPath, []byte(pubkeyHex), 0644); err != nil {
			return fmt.Errorf("failed to write public key file: %w", err)
		}

	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}

	return nil
}

// generatePoP generates Proof of Possession using aldaba_cli
func (kg *KeyGenerator) generatePoP(keyDir, popFile, prikeyPath, keyPasswd string) error {
	aldabaCliPath := filepath.Join(kg.BuildRoot, "bin", ALDABA_CLI)
	evmonePath := filepath.Join(kg.BuildRoot, "bin", EVMONE_SO)

	// Check if aldaba_cli exists
	if _, err := os.Stat(aldabaCliPath); err != nil {
		return fmt.Errorf("aldaba_cli not found at %s", aldabaCliPath)
	}

	// Generate PoP
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"LD_PRELOAD=%s %s crypto -t gen-pop -f %s -p %s | tail -n 1",
		evmonePath, aldabaCliPath, prikeyPath, keyPasswd))
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate PoP: %v", err)
	}

	pop := strings.TrimSpace(strings.Split(string(output), " ")[0])
	popPath := filepath.Join(keyDir, popFile)
	if err := os.WriteFile(popPath, []byte(pop), 0644); err != nil {
		return fmt.Errorf("failed to write PoP file: %w", err)
	}

	return nil
}

// GenerateBLSKey generates a BLS12381 key
// This matches Python's implementation which uses aldaba_cli
func (kg *KeyGenerator) GenerateBLSKey(keyDir, keyFile string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create BLS key directory: %w", err)
	}

	aldabaCliPath := filepath.Join(kg.BuildRoot, "bin", ALDABA_CLI)
	evmonePath := filepath.Join(kg.BuildRoot, "bin", EVMONE_SO)

	pubkeyFile := strings.Replace(keyFile, ".key", ".pub", 1)
	popFile := strings.Replace(keyFile, ".key", ".pop", 1)

	// Check if aldaba_cli exists
	if _, err := os.Stat(aldabaCliPath); err != nil {
		utils.Warn("aldaba_cli not found at %s, creating placeholder BLS keys", aldabaCliPath)
		return kg.createPlaceholderBLSKeys(keyDir, keyFile, pubkeyFile)
	}

	// Generate BLS keys using aldaba_cli
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"LD_PRELOAD=%s %s crypto -t gen-key -a bls12381 | tail -n 2",
		evmonePath, aldabaCliPath))
	output, err := cmd.Output()
	if err != nil {
		utils.Warn("Failed to generate BLS keys using aldaba_cli: %v, creating placeholder keys", err)
		return kg.createPlaceholderBLSKeys(keyDir, keyFile, pubkeyFile)
	}

	// Parse output
	// Expected format:
	//   PRIVKEY:0x4002xxxxxxxx
	//   PUBKEY:0x4003xxxxxxxx
	outputStr := string(output)
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")

	var prikey, pubkey string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PRIVKEY:") {
			prikey = strings.TrimPrefix(line, "PRIVKEY:")
		} else if strings.HasPrefix(line, "PUBKEY:") {
			pubkey = strings.TrimPrefix(line, "PUBKEY:")
		}
	}

	if prikey == "" || pubkey == "" {
		utils.Warn("Failed to parse BLS keys from output, creating placeholder keys")
		return kg.createPlaceholderBLSKeys(keyDir, keyFile, pubkeyFile)
	}

	// Write keys to files
	prikeyPath := filepath.Join(keyDir, keyFile)
	pubkeyPath := filepath.Join(keyDir, pubkeyFile)

	if err := os.WriteFile(prikeyPath, []byte(prikey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS private key: %w", err)
	}
	if err := os.WriteFile(pubkeyPath, []byte(pubkey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS public key: %w", err)
	}

	// Generate BLS PoP
	cmd = exec.Command("sh", "-c", fmt.Sprintf(
		"LD_PRELOAD=%s %s crypto -t gen-pop --sk %s | tail -n 1",
		evmonePath, aldabaCliPath, prikey))
	popOutput, err := cmd.Output()
	if err != nil {
		utils.Warn("Failed to generate BLS PoP: %v", err)
	} else {
		pop := strings.TrimSpace(strings.Split(string(popOutput), " ")[0])
		popPath := filepath.Join(keyDir, popFile)
		if err := os.WriteFile(popPath, []byte(pop), 0644); err != nil {
			utils.Warn("Failed to write BLS PoP file: %v", err)
		}
	}

	return nil
}

// createPlaceholderBLSKeys creates placeholder BLS keys when aldaba_cli is not available
func (kg *KeyGenerator) createPlaceholderBLSKeys(keyDir, keyFile, pubkeyFile string) error {
	prikeyPath := filepath.Join(keyDir, keyFile)
	pubkeyPath := filepath.Join(keyDir, pubkeyFile)

	// Create placeholder BLS keys
	prikey := "4002" + strings.Repeat("00", 62)
	pubkey := "4003" + strings.Repeat("00", 62)

	if err := os.WriteFile(prikeyPath, []byte(prikey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS private key: %w", err)
	}
	if err := os.WriteFile(pubkeyPath, []byte(pubkey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS public key: %w", err)
	}

	utils.Warn("Created placeholder BLS keys. Replace them with proper keys for production use.")
	return nil
}

// GetPubkeyFromFile reads a private key file and extracts the raw public key bytes (without prefix)
func (kg *KeyGenerator) GetPubkeyFromFile(keyType, prikeyPath, keyPasswd string) ([]byte, error) {
	var cmd *exec.Cmd
	switch strings.ToLower(keyType) {
	case "prime256v1", "p256v1":
		cmd = exec.Command("openssl", "ec", "-in", prikeyPath, "-noout", "-text", "-passin", "pass:"+keyPasswd)
	case "rsa", "rsa2048":
		cmd = exec.Command("openssl", "rsa", "-in", prikeyPath, "-noout", "-text", "-passin", "pass:"+keyPasswd)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute openssl: %v, output: %s", err, string(output))
	}

	// Parse output to extract public key
	lines := strings.Split(string(output), "\n")

	// Filter lines that start with whitespace (contain hex data)
	var hexLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			hexLines = append(hexLines, line)
		}
	}

	if len(hexLines) < 4 {
		return nil, fmt.Errorf("invalid openssl output format")
	}

	// Skip first 3 lines (private key) and take the rest (public key)
	hexLines = hexLines[3:]

	// Remove all whitespace and colons
	hexStr := strings.Join(hexLines, "")
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, ":", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")

	// Decode hex string to bytes (raw public key without prefix)
	pubkeyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %v", err)
	}

	return pubkeyBytes, nil
}

// GetPubkeyWithPrefix reads a private key file and returns the public key with type prefix
func (kg *KeyGenerator) GetPubkeyWithPrefix(keyType, prikeyPath, keyPasswd string) (string, []byte, error) {
	pubkeyRaw, err := kg.GetPubkeyFromFile(keyType, prikeyPath, keyPasswd)
	if err != nil {
		return "", nil, err
	}

	var prefix string
	switch strings.ToLower(keyType) {
	case "prime256v1", "p256v1":
		prefix = "1003"
	case "rsa", "rsa2048":
		prefix = "1023"
	default:
		return "", nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	pubkeyHex := prefix + hex.EncodeToString(pubkeyRaw)
	pubkeyBytes, _ := hex.DecodeString(pubkeyHex)
	return pubkeyHex, pubkeyBytes, nil
}

// GenerateNodeID generates NODE_ID from domain public key
func (kg *KeyGenerator) GenerateNodeID(keyType, keyDir, keyFile, keyPasswd string, useGeneratedKeys bool) (string, error) {
	// Determine key file name
	keyFileName := GetKeyFileName(useGeneratedKeys)
	prikeyPath := filepath.Join(keyDir, keyFileName+".key")

	// If use_generated_keys is true, generate keys first
	if useGeneratedKeys {
		if err := kg.GeneratePrivateKey(keyType, keyDir, keyFileName+".key", keyPasswd); err != nil {
			utils.Warn("Failed to generate private key: %v", err)
		}

		// Also generate BLS key
		blsKeyDir := filepath.Join(filepath.Dir(filepath.Dir(keyDir)), "bls12381", filepath.Base(keyDir))
		if err := kg.GenerateBLSKey(blsKeyDir, keyFileName+".key"); err != nil {
			utils.Warn("Failed to generate BLS key: %v", err)
		}
	}

	// Get public key with prefix
	_, pubkeyBytes, err := kg.GetPubkeyWithPrefix(keyType, prikeyPath, keyPasswd)
	if err != nil {
		// Fallback to domain-based generation
		utils.Warn("Failed to read key file %s, using fallback NODE_ID: %v", prikeyPath, err)
		domainName := filepath.Base(keyDir)
		data := []byte(domainName + "-pharos-key")
		hash := sha256.Sum256(data)
		return fmt.Sprintf("%x", hash), nil
	}

	// Calculate SHA256 hash of the public key bytes
	hash := sha256.Sum256(pubkeyBytes)
	return fmt.Sprintf("%x", hash), nil
}

// ReadPubkeyFile reads a public key from file
func ReadPubkeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadPopFile reads a PoP from file
func ReadPopFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
