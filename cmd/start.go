package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var (
	startConfigPath string
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start pharos services",
	Long:  "Start pharos_light service in daemon mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Starting services")

		// Check if pharos.conf exists
		if _, err := os.Stat(startConfigPath); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", startConfigPath)
		}

		// Check if pharos_light binary exists
		pharosLight := "./bin/pharos_light"
		if _, err := os.Stat(pharosLight); os.IsNotExist(err) {
			return fmt.Errorf("pharos_light binary not found: %s", pharosLight)
		}

		// Check if libevmone.so exists
		evmoneSo := "./bin/libevmone.so"
		hasEvmone := true
		if _, err := os.Stat(evmoneSo); os.IsNotExist(err) {
			hasEvmone = false
		}

		// Get password and set environment variable
		password, err := GetPassword()
		if err != nil {
			fmt.Printf("Warning: %v\n", err)
			fmt.Println("Starting without password. Set password with: ./ops set-password <password>")
		} else {
			fmt.Println("Using saved password")
		}

		// Build command
		var cmdStr string
		if hasEvmone {
			cmdStr = fmt.Sprintf("cd ./bin && LD_PRELOAD=./libevmone.so ./pharos_light -c %s -d", startConfigPath)
		} else {
			cmdStr = fmt.Sprintf("cd ./bin && ./pharos_light -c %s -d", startConfigPath)
		}

		fmt.Printf("Starting pharos_light: %s\n", cmdStr)

		execCmd := exec.Command("bash", "-c", cmdStr)
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		// Set password environment variable if available
		if password != "" {
			execCmd.Env = append(os.Environ(), fmt.Sprintf("CONSENSUS_KEY_PWD=%s", password))
		}

		if err := execCmd.Start(); err != nil {
			return fmt.Errorf("failed to start services: %w", err)
		}

		fmt.Println("Services started successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	startCmd.Flags().StringVar(&startConfigPath, "config", "./conf/pharos.conf", "Path to pharos.conf file")
}
