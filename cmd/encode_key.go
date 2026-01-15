package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	encodeKeyToPharosConf string
	encodeKeyType         string
)

// encodeKeyCmd encodes a key file to base64 and outputs it
var encodeKeyCmd = &cobra.Command{
	Use:   "encode-key <key_path>",
	Short: "Encode key file to base64",
	Long:  "Read a key file and output its contents as base64 encoded string",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		keyPath := args[0]

		fmt.Printf("key path: %s\n", keyPath)

		// Read key file
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}

		// Encode to base64
		encoded := base64.StdEncoding.EncodeToString(keyData)

		// Output the encoded key
		fmt.Println(encoded)

		return nil
	},
}

// encodeKeyToConfCmd encodes a key file and writes it to pharos.conf
var encodeKeyToConfCmd = &cobra.Command{
	Use:   "encode-key-to-conf <key_path>",
	Short: "Encode key file to base64 and write to pharos.conf",
	Long:  "Read a key file, encode it as base64, and update the pharos.conf file with the encoded key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		keyPath := args[0]

		fmt.Printf("Encoding %s key from: %s\n", encodeKeyType, keyPath)
		fmt.Printf("Writing to: %s\n", encodeKeyToPharosConf)

		// Read key file
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}

		// Encode to base64
		encoded := base64.StdEncoding.EncodeToString(keyData)

		// Read pharos.conf
		confData, err := os.ReadFile(encodeKeyToPharosConf)
		if err != nil {
			return fmt.Errorf("failed to read pharos conf: %w", err)
		}

		var pharosConf map[string]interface{}
		if err := json.Unmarshal(confData, &pharosConf); err != nil {
			return fmt.Errorf("failed to parse pharos conf: %w", err)
		}

		// Navigate to the correct location and update the key
		// Format: {"aldaba": {"secret_config": {"domain_key": "", "stabilizing_key": ""}}}
		aldaba, ok := pharosConf["aldaba"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("aldaba not found in pharos.conf")
		}

		// Get or create secret_config
		var secretConfig map[string]interface{}
		if sc, ok := aldaba["secret_config"].(map[string]interface{}); ok {
			secretConfig = sc
		} else {
			secretConfig = make(map[string]interface{})
			aldaba["secret_config"] = secretConfig
		}

		// Update the appropriate key based on key type
		switch encodeKeyType {
		case "domain":
			secretConfig["domain_key"] = encoded
			fmt.Println("Updated domain_key in pharos.conf")
		case "stabilizing":
			secretConfig["stabilizing_key"] = encoded
			fmt.Println("Updated stabilizing_key in pharos.conf")
		default:
			return fmt.Errorf("unknown key type: %s (must be 'domain' or 'stabilizing')", encodeKeyType)
		}

		// Write back to pharos.conf
		updatedData, err := json.MarshalIndent(pharosConf, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		if err := os.WriteFile(encodeKeyToPharosConf, updatedData, 0644); err != nil {
			return fmt.Errorf("failed to write pharos conf: %w", err)
		}

		fmt.Printf("Successfully wrote %s key to %s\n", encodeKeyType, encodeKeyToPharosConf)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(encodeKeyCmd)
	rootCmd.AddCommand(encodeKeyToConfCmd)

	encodeKeyToConfCmd.Flags().StringVar(&encodeKeyToPharosConf, "pharos-conf", "./conf/pharos.conf",
		"Path to pharos.conf file")
	encodeKeyToConfCmd.Flags().StringVar(&encodeKeyType, "key-type", "",
		"Type of key: domain or stabilizing")
	encodeKeyToConfCmd.MarkFlagRequired("key-type")
}
