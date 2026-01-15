package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start pharos services",
	Long:  "Start pharos_light service in daemon mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Starting services")

		// Check if pharos.conf exists
		pharosConfFile := "./conf/pharos.conf"
		if _, err := os.Stat(pharosConfFile); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", pharosConfFile)
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

		// Build command
		var cmdStr string
		if hasEvmone {
			cmdStr = "cd ./bin && LD_PRELOAD=./libevmone.so ./pharos_light -c ../conf/pharos.conf -d"
		} else {
			cmdStr = "cd ./bin && ./pharos_light -c ../conf/pharos.conf -d"
		}

		fmt.Printf("Starting pharos_light: %s\n", cmdStr)

		execCmd := exec.Command("bash", "-c", cmdStr)
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		if err := execCmd.Start(); err != nil {
			return fmt.Errorf("failed to start services: %w", err)
		}

		fmt.Println("Services started successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
