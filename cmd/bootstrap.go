package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	bootstrapConfigPath string
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Bootstrap pharos domain",
	Long:  "Generate genesis state and initialize pharos domain. Old data and logs will be cleaned up.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Starting bootstrap")

		// Convert config path to absolute path (used as both config and storage)
		absConfigPath, err := filepath.Abs(bootstrapConfigPath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for config: %w", err)
		}

		// Check if genesis.conf exists
		genesisFile := "./genesis.conf"
		if _, err := os.Stat(genesisFile); os.IsNotExist(err) {
			return fmt.Errorf("genesis file not found: %s", genesisFile)
		}

		// Get absolute path for genesis.conf
		absGenesisPath, err := filepath.Abs(genesisFile)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for genesis: %w", err)
		}

		// Check if pharos.conf exists
		if _, err := os.Stat(bootstrapConfigPath); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", bootstrapConfigPath)
		}

		// Check if pharos_cli binary exists
		pharosCli := "./bin/pharos_cli"
		if _, err := os.Stat(pharosCli); os.IsNotExist(err) {
			return fmt.Errorf("pharos_cli binary not found: %s", pharosCli)
		}

		// Get password and set environment variable
		password, err := GetPassword()
		if err != nil {
			fmt.Printf("Warning: %v\n", err)
			fmt.Println("Bootstrapping without password. Set password with: ./ops set-password <password>")
		} else {
			fmt.Println("Using saved password")
		}

		// Run bootstrap genesis command
		// pharos_cli genesis -c <config_path> -g <genesis_path>
		// libevmone is linked into the binaries since v0.14.2, so no LD_PRELOAD.
		cmdStr := fmt.Sprintf("cd ./bin && ./pharos_cli genesis -c %s -g %s", absConfigPath, absGenesisPath)

		fmt.Printf("Running: %s\n", cmdStr)

		execCmd := exec.Command("bash", "-c", cmdStr)
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		// Set password environment variables if available
		if password != "" {
			execCmd.Env = append(os.Environ(),
				fmt.Sprintf("CONSENSUS_KEY_PWD=%s", password),
				fmt.Sprintf("PORTAL_SSL_PWD=%s", password),
			)
		}

		if err := execCmd.Run(); err != nil {
			return fmt.Errorf("bootstrap failed: %w", err)
		}

		fmt.Println("Bootstrap completed successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)

	bootstrapCmd.Flags().StringVar(&bootstrapConfigPath, "config", "./conf/pharos.conf", "Path to pharos.conf file")
}
