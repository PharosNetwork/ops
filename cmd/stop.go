package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop <domain.json>",
	Short: "Stop pharos node",
	Long:  "Stop pharos node from domain configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainFile := args[0]
		utils.Info("Stopping node: %s", domainFile)
		
		c, err := composer.New(domainFile)
		if err != nil {
			return fmt.Errorf("failed to load domain file: %w", err)
		}
		
		return c.Stop("")
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}