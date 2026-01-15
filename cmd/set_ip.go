package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
)

var setIPCmd = &cobra.Command{
	Use:   "set-ip <ip_address>",
	Short: "Set public IP address in pharos.conf",
	Long:  "Update the host_ip field in pharos.conf with the specified public IP address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]
		pharosConfFile := "./conf/pharos.conf"

		// Validate IP address
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}

		if ip == "127.0.0.1" {
			return fmt.Errorf("please set a public IP address, not 127.0.0.1")
		}

		// Read pharos.conf
		confData, err := os.ReadFile(pharosConfFile)
		if err != nil {
			return fmt.Errorf("failed to read pharos.conf: %w", err)
		}

		var pharosConf map[string]interface{}
		if err := json.Unmarshal(confData, &pharosConf); err != nil {
			return fmt.Errorf("failed to parse pharos.conf: %w", err)
		}

		// Navigate to aldaba.startup_config.init_config.host_ip
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

		// Update host_ip
		oldIP := ""
		if hostIP, ok := initConfig["host_ip"].(string); ok {
			oldIP = hostIP
		}

		initConfig["host_ip"] = ip

		// Write back to pharos.conf
		updatedData, err := json.MarshalIndent(pharosConf, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		if err := os.WriteFile(pharosConfFile, updatedData, 0644); err != nil {
			return fmt.Errorf("failed to write pharos.conf: %w", err)
		}

		if oldIP != "" {
			fmt.Printf("Updated host_ip: %s -> %s\n", oldIP, ip)
		} else {
			fmt.Printf("Set host_ip to: %s\n", ip)
		}
		fmt.Printf("Successfully updated %s\n", pharosConfFile)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(setIPCmd)
}
