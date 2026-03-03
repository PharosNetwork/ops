package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	getNodeIDKeysDir string
	getNodeIDFormat  string
)

var getNodeIDCmd = &cobra.Command{
	Use:   "get-nodeid",
	Short: "Get the Node ID (Pool ID) from domain public key",
	Long:  "Calculate and display the Node ID / Pool ID by hashing the domain public key (sha256)",
	RunE: func(cmd *cobra.Command, args []string) error {
		pubKeyPath := filepath.Join(getNodeIDKeysDir, "domain.pub")

		// Read domain.pub file
		pubKeyData, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read domain.pub from %s: %w", pubKeyPath, err)
		}

		pubKeyHex := strings.TrimSpace(string(pubKeyData))

		// Remove prefix if present
		// Possible prefixes: "1003", "0x1003"
		rawPubKey := pubKeyHex
		if strings.HasPrefix(rawPubKey, "0x1003") {
			rawPubKey = rawPubKey[6:] // Remove "0x1003"
		} else if strings.HasPrefix(rawPubKey, "1003") {
			rawPubKey = rawPubKey[4:] // Remove "1003"
		} else if strings.HasPrefix(rawPubKey, "0x") {
			rawPubKey = rawPubKey[2:] // Remove "0x"
		}

		// Decode hex to bytes
		pubKeyBytes, err := hex.DecodeString(rawPubKey)
		if err != nil {
			return fmt.Errorf("failed to decode public key hex: %w", err)
		}

		// Calculate SHA256 hash
		hash := sha256.Sum256(pubKeyBytes)
		nodeID := hex.EncodeToString(hash[:])

		// Format output based on --format flag
		switch getNodeIDFormat {
		case "0x", "hex-prefixed":
			fmt.Printf("Node ID: 0x%s\n", nodeID)
		case "hex", "":
			fmt.Printf("Node ID: %s\n", nodeID)
		default:
			return fmt.Errorf("invalid format: %s (valid options: hex, 0x)", getNodeIDFormat)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(getNodeIDCmd)

	getNodeIDCmd.Flags().StringVarP(&getNodeIDKeysDir, "keys-dir", "k", "./keys",
		"Directory containing the domain.pub file")
	getNodeIDCmd.Flags().StringVar(&getNodeIDFormat, "format", "hex",
		"Output format: 'hex' (default, no prefix) or '0x' (with 0x prefix)")
}
