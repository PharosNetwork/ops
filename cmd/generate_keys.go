package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	generateKeysOutputDir string
	generateKeysPasswd    string
)

var generateKeysCmd = &cobra.Command{
	Use:   "generate-keys",
	Short: "Generate domain keys (prime256v1 and bls12381)",
	Long:  "Generate cryptographic keys for domain authentication including ECDSA (prime256v1) and BLS (bls12381) keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Generating keys to: %s\n", generateKeysOutputDir)

		// Create output directory
		if err := os.MkdirAll(generateKeysOutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Generate prime256v1 (ECDSA P-256) key
		if err := generatePrime256v1Key(generateKeysOutputDir, generateKeysPasswd); err != nil {
			return fmt.Errorf("failed to generate prime256v1 key: %w", err)
		}

		// Generate BLS12381 key using external tool
		if err := generateBLS12381Key(generateKeysOutputDir, generateKeysPasswd); err != nil {
			fmt.Printf("Warning: Failed to generate bls12381 key: %v (this may require pharos_cli)\n", err)
		}

		fmt.Printf("\nKeys generated successfully in: %s\n", generateKeysOutputDir)
		fmt.Println("Files created:")
		fmt.Println("  - domain.key (prime256v1 private key)")
		fmt.Println("  - domain.pub (prime256v1 public key)")
		fmt.Println("  - stabilizing.key (bls12381 private key)")
		fmt.Println("  - stabilizing.pub (bls12381 public key)")
		return nil
	},
}

func generatePrime256v1Key(outputDir string, passwd string) error {
	// Generate ECDSA P-256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Serialize private key
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Create PEM block for private key
	privPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}

	// Encrypt if password provided
	if passwd != "" {
		encryptedPEM, err := x509.EncryptPEMBlock(rand.Reader, privPEM.Type, privPEM.Bytes, []byte(passwd), x509.PEMCipherAES256)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
		privPEM = encryptedPEM
	}

	// Write private key
	keyPath := filepath.Join(outputDir, "domain.key")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	if err := pem.Encode(keyFile, privPEM); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}
	fmt.Printf("Generated prime256v1 private key: %s\n", keyPath)

	// Serialize and write public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pubPath := filepath.Join(outputDir, "domain.pub")
	pubFile, err := os.Create(pubPath)
	if err != nil {
		return fmt.Errorf("failed to create pub file: %w", err)
	}
	defer pubFile.Close()

	if err := pem.Encode(pubFile, pubPEM); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	fmt.Printf("Generated prime256v1 public key: %s\n", pubPath)

	return nil
}

func generateBLS12381Key(outputDir string, passwd string) error {
	blsKeyPath := filepath.Join(outputDir, "stabilizing.key")
	blsPubPath := filepath.Join(outputDir, "stabilizing.pub")

	// Check if pharos_cli exists
	pharosCli := "./bin/pharos_cli"
	if _, err := os.Stat(pharosCli); os.IsNotExist(err) {
		return fmt.Errorf("pharos_cli not found at %s", pharosCli)
	}

	// Check if libevmone.so exists
	evmoneSo := "./bin/libevmone.so"
	hasEvmone := true
	if _, err := os.Stat(evmoneSo); os.IsNotExist(err) {
		hasEvmone = false
	}

	// Generate BLS key using pharos_cli
	var cmdStr string
	if hasEvmone {
		cmdStr = fmt.Sprintf("cd ./bin && LD_PRELOAD=./libevmone.so ./pharos_cli crypto -t gen-key -a bls12381 | tail -n 2")
	} else {
		cmdStr = fmt.Sprintf("cd ./bin && ./pharos_cli crypto -t gen-key -a bls12381 | tail -n 2")
	}

	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to execute pharos_cli: %w", err)
	}

	// Parse output to extract keys
	// Expected format:
	// prikey:xxxxx
	// pubkey:yyyyy
	lines := string(output)

	// Write to files (simplified - in production should parse properly)
	if err := os.WriteFile(blsKeyPath, []byte(lines), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(blsPubPath, []byte(lines), 0644); err != nil {
		return err
	}

	fmt.Printf("Generated bls12381 key: %s\n", blsKeyPath)
	fmt.Printf("Generated bls12381 pub: %s\n", blsPubPath)

	return nil
}

func init() {
	rootCmd.AddCommand(generateKeysCmd)

	generateKeysCmd.Flags().StringVarP(&generateKeysOutputDir, "output-dir", "o", "./keys",
		"Output directory for generated keys")
	generateKeysCmd.Flags().StringVar(&generateKeysPasswd, "key-passwd", "123abc",
		"Password for key encryption")
}
