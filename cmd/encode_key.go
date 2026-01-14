package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"pharos-ops/pkg/utils"

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

		utils.Info("key path: %s", keyPath)

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

		utils.Info("Encoding %s key from: %s", encodeKeyType, keyPath)
		utils.Info("Writing to: %s", encodeKeyToPharosConf)

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
		// Format: {"aldaba": {"startup_config": {"init_config": {...}}}}
		aldaba, ok := pharosConf["aldaba"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("aldaba not found in pharos.conf")
		}

		startupConfig, ok := aldaba["startup_config"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("startup_config not found in aldaba")
		}

		initConfig, ok := startupConfig["init_config"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("init_config not found in startup_config")
		}

		// Update the appropriate key based on key type
		switch encodeKeyType {
		case "domain":
			// Update domain key
			if secret, ok := initConfig["secret"].(map[string]interface{}); ok {
				if domain, ok := secret["domain"].(map[string]interface{}); ok {
					domain["key"] = encoded
					utils.Info("Updated domain key in pharos.conf")
				} else {
					// Create domain section
					secret["domain"] = map[string]interface{}{"key": encoded}
					utils.Info("Created domain key in pharos.conf")
				}
			} else {
				// Create secret.domain section
				initConfig["secret"] = map[string]interface{}{
					"domain": map[string]interface{}{"key": encoded},
				}
				utils.Info("Created secret.domain.key in pharos.conf")
			}
		case "stabilizing":
			// Update stabilizing key
			if secret, ok := initConfig["secret"].(map[string]interface{}); ok {
				if stabilizing, ok := secret["stabilizing"].(map[string]interface{}); ok {
					stabilizing["key"] = encoded
					utils.Info("Updated stabilizing key in pharos.conf")
				} else {
					// Create stabilizing section
					secret["stabilizing"] = map[string]interface{}{"key": encoded}
					utils.Info("Created stabilizing key in pharos.conf")
				}
			} else {
				// Create secret.stabilizing section
				initConfig["secret"] = map[string]interface{}{
					"stabilizing": map[string]interface{}{"key": encoded},
				}
				utils.Info("Created secret.stabilizing.key in pharos.conf")
			}
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

		utils.Info("Successfully wrote %s key to %s", encodeKeyType, encodeKeyToPharosConf)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(encodeKeyCmd)
	rootCmd.AddCommand(encodeKeyToConfCmd)

	encodeKeyToConfCmd.Flags().StringVar(&encodeKeyToPharosConf, "pharos-conf", "../conf/pharos.conf",
		"Path to pharos.conf file")
	encodeKeyToConfCmd.Flags().StringVar(&encodeKeyType, "key-type", "",
		"Type of key: domain or stabilizing")
	encodeKeyToConfCmd.MarkFlagRequired("key-type")
}
