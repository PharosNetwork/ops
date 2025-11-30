package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	debug   bool
	verbose bool
	rootCmd = &cobra.Command{
		Use:   "pharos-ops",
		Short: "Pharos blockchain operations tool",
		Long:  "A comprehensive tool for managing Pharos blockchain networks",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				fmt.Println("Debug mode is on")
			}
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug mode")
}