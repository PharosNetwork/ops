package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status <domain.json>",
	Short: "Check status of pharos node",
	Long:  "Check the running status of pharos node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainFile := args[0]
		utils.Info("Checking status for node: %s", domainFile)
		
		c, err := composer.New(domainFile)
		if err != nil {
			return fmt.Errorf("failed to load domain file: %w", err)
		}
		
		return c.Status("")
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}