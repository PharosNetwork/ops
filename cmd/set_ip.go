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
	Use:   "set-ip [ip] [pharos_conf_file]",
	Short: "Set public IP in pharos configuration",
	Long:  "Update the public IP address in pharos.conf file (aldaba.startup_config.init_config.host_ip)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]
		pharosConfFile := "../conf/pharos.conf"
		if len(args) > 1 {
			pharosConfFile = args[1]
		}

		// Validate IP address
		if ip == "127.0.0.1" {
			return fmt.Errorf("please set a valid public IP address")
		}

		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address: %s", ip)
		}

		// Read pharos.conf file
		data, err := os.ReadFile(pharosConfFile)
		if err != nil {
			return fmt.Errorf("failed to read pharos conf file: %w", err)
		}

		var pharosConf map[string]interface{}
		if err := json.Unmarshal(data, &pharosConf); err != nil {
			return fmt.Errorf("failed to parse pharos conf file: %w", err)
		}

		// Update IP in pharos.conf based on new format
		// Format: {"aldaba": {"startup_config": {"init_config": {"host_ip": "127.0.0.1", ...}}}}
		aldaba, ok := pharosConf["aldaba"].(map[string]interface{})
		if !ok {
			utils.Warn("aldaba.startup_config not found in pharos.conf")
			return fmt.Errorf("aldaba not found in pharos.conf")
		}

		startupConfig, ok := aldaba["startup_config"].(map[string]interface{})
		if !ok {
			utils.Warn("init_config not found in startup_config")
			return fmt.Errorf("startup_config not found in aldaba")
		}

		initConfig, ok := startupConfig["init_config"].(map[string]interface{})
		if !ok {
			utils.Warn("init_config not found in startup_config")
			return fmt.Errorf("init_config not found in startup_config")
		}

		// Update host_ip
		if oldIP, exists := initConfig["host_ip"]; exists {
			initConfig["host_ip"] = ip
			utils.Info("Updated host_ip: %v -> %s", oldIP, ip)
		} else {
			utils.Warn("host_ip not found in init_config")
			initConfig["host_ip"] = ip
			utils.Info("Added host_ip: %s", ip)
		}

		// Write back to pharos.conf
		updatedData, err := json.MarshalIndent(pharosConf, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal updated config: %w", err)
		}

		if err := os.WriteFile(pharosConfFile, updatedData, 0644); err != nil {
			return fmt.Errorf("failed to write pharos conf file: %w", err)
		}

		utils.Info("Set public ip to %s in %s", ip, pharosConfFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(setIPCmd)
}