package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var setIPCmd = &cobra.Command{
	Use:   "set-ip [ip] [deploy_file]",
	Short: "Set public IP in deploy configuration",
	Long:  "Update the public IP address in deploy configuration file",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]
		deployFile := "deploy.light.json"
		if len(args) > 1 {
			deployFile = args[1]
		}

		// Validate IP address
		if ip == "127.0.0.1" {
			return fmt.Errorf("please set a valid public IP address")
		}

		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}

		utils.Info("Setting public IP to %s in %s", ip, deployFile)

		// Read deploy file
		data, err := os.ReadFile(deployFile)
		if err != nil {
			return fmt.Errorf("failed to read deploy file: %w", err)
		}

		var deploy map[string]interface{}
		if err := json.Unmarshal(data, &deploy); err != nil {
			return fmt.Errorf("failed to parse deploy file: %w", err)
		}

		// Update IP addresses
		if domains, ok := deploy["domains"].(map[string]interface{}); ok {
			for domainName, domainData := range domains {
				if domain, ok := domainData.(map[string]interface{}); ok {
					if cluster, ok := domain["cluster"].([]interface{}); ok {
						for _, nodeData := range cluster {
							if node, ok := nodeData.(map[string]interface{}); ok {
								node["host"] = ip
								node["ip"] = ip
								utils.Info("Updated %s node IP to %s", domainName, ip)
							}
						}
					}
				}
			}
		}

		// Write back to file
		updatedData, err := json.MarshalIndent(deploy, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		if err := os.WriteFile(deployFile, updatedData, 0644); err != nil {
			return fmt.Errorf("failed to write deploy file: %w", err)
		}

		utils.Info("Successfully set public IP to %s", ip)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(setIPCmd)
}