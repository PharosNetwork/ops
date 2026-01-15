package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	// Use openssl to generate prime256v1 key (same as Python version)
	keyPath := filepath.Join(outputDir, "domain.key")
	pubPath := filepath.Join(outputDir, "domain.pub")

	// Generate encrypted private key using openssl
	// openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -outform pem -out domain.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:123abc
	cmdStr := fmt.Sprintf("openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -outform pem -out %s -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:%s", keyPath, passwd)
	cmd := exec.Command("bash", "-c", cmdStr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate prime256v1 key: %w", err)
	}
	fmt.Printf("Generated prime256v1 private key: %s\n", keyPath)

	// Extract public key in hex format (without 0x prefix)
	// openssl ec -in domain.key -passin pass:123abc -pubout -outform DER | tail -c 65 | xxd -p -c 65
	extractPubCmd := fmt.Sprintf("openssl ec -in %s -passin pass:%s -pubout -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 65 | tr -d '\\n'", keyPath, passwd)
	pubCmd := exec.Command("bash", "-c", extractPubCmd)
	pubOutput, err := pubCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to extract public key: %w", err)
	}

	// Add prefix "1003" to public key
	pubKeyHex := "1003" + string(pubOutput)

	if err := os.WriteFile(pubPath, []byte(pubKeyHex), 0644); err != nil {
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
		cmdStr = "cd ./bin && LD_PRELOAD=./libevmone.so ./pharos_cli crypto -t gen-key -a bls12381 | tail -n 2"
	} else {
		cmdStr = "cd ./bin && ./pharos_cli crypto -t gen-key -a bls12381 | tail -n 2"
	}

	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute pharos_cli: %w, output: %s", err, string(output))
	}

	// Debug: print raw output
	fmt.Printf("DEBUG: pharos_cli output:\n%s\n", string(output))

	// Parse output to extract keys
	// Expected format:
	// prikey:0x400238d28e50623cba45dfd569ac65d51905b2f6ffbe791ac086df191922ffcb588b
	// pubkey:0x400389d3bfe4256ace7d4db0d1a9ca5add712553490fc8298a3cd2c43e1b0004f21598df06655cdc514e73f21b01d9c23b82
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	var prikey, pubkey string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "prikey:") {
			prikey = strings.TrimSpace(strings.TrimPrefix(line, "prikey:"))
		} else if strings.HasPrefix(line, "pubkey:") {
			pubkey = strings.TrimSpace(strings.TrimPrefix(line, "pubkey:"))
		}
	}

	fmt.Printf("DEBUG: parsed prikey: %s\n", prikey)
	fmt.Printf("DEBUG: parsed pubkey: %s\n", pubkey)

	if prikey == "" || pubkey == "" {
		return fmt.Errorf("failed to parse BLS keys from pharos_cli output: prikey=%q, pubkey=%q", prikey, pubkey)
	}

	// Write keys to files
	if err := os.WriteFile(blsKeyPath, []byte(prikey), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(blsPubPath, []byte(pubkey), 0644); err != nil {
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
