package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart <domain.json>",
	Short: "Restart pharos node",
	Long:  "Stop and start pharos node from domain configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainFile := args[0]
		utils.Info("Restarting node: %s", domainFile)
		
		c, err := composer.New(domainFile)
		if err != nil {
			return fmt.Errorf("failed to load domain file: %w", err)
		}
		
		// Stop first
		if err := c.Stop(""); err != nil {
			utils.Error("Failed to stop node: %v", err)
		}
		
		// Then start
		return c.Start("", "")
	},
}

func init() {
	rootCmd.AddCommand(restartCmd)
}