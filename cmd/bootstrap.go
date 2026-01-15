package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Bootstrap pharos domain",
	Long:  "Generate genesis state and initialize pharos domain. Old data and logs will be cleaned up.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Starting bootstrap")

		// Check if genesis.conf exists
		genesisFile := "./genesis.conf"
		if _, err := os.Stat(genesisFile); os.IsNotExist(err) {
			return fmt.Errorf("genesis file not found: %s", genesisFile)
		}

		// Check if pharos.conf exists
		pharosConfFile := "./conf/pharos.conf"
		if _, err := os.Stat(pharosConfFile); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", pharosConfFile)
		}

		// Check if pharos_cli binary exists
		pharosCli := "./bin/pharos_cli"
		if _, err := os.Stat(pharosCli); os.IsNotExist(err) {
			return fmt.Errorf("pharos_cli binary not found: %s", pharosCli)
		}

		// Check if libevmone.so exists
		evmoneSo := "./bin/libevmone.so"
		hasEvmone := true
		if _, err := os.Stat(evmoneSo); os.IsNotExist(err) {
			hasEvmone = false
		}

		// Run bootstrap genesis command
		// pharos_cli genesis -g ./genesis.conf -c ./conf/pharos.conf
		var cmdStr string
		if hasEvmone {
			cmdStr = fmt.Sprintf("cd ./bin && LD_PRELOAD=./libevmone.so ./pharos_cli genesis -g ../genesis.conf -c ../conf/pharos.conf")
		} else {
			cmdStr = fmt.Sprintf("cd ./bin && ./pharos_cli genesis -g ../genesis.conf -c ../conf/pharos.conf")
		}

		fmt.Printf("Running: %s\n", cmdStr)

		execCmd := exec.Command("bash", "-c", cmdStr)
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		if err := execCmd.Run(); err != nil {
			return fmt.Errorf("bootstrap failed: %w", err)
		}

		fmt.Println("Bootstrap completed successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)
}
