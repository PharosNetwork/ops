package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pharos-ops",
	Short: "Pharos operations tool",
	Long:  "A simplified operations tool for Pharos blockchain deployment and management",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Global flags can be added here if needed
}
