package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version number, build time, and git commit of pharos-ops`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Pharos Ops Version:     %s\n", GetVersionInfo().Version)
		fmt.Printf("Build Time:             %s\n", GetVersionInfo().BuildTime)
		fmt.Printf("Git Commit:             %s\n", GetVersionInfo().GitCommit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}