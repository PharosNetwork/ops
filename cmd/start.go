package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start <domain.json>",
	Short: "Start pharos node",
	Long:  "Start pharos node from domain configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domainFile := args[0]
		utils.Info("Starting node: %s", domainFile)
		
		c, err := composer.New(domainFile)
		if err != nil {
			return fmt.Errorf("failed to load domain file: %w", err)
		}
		
		return c.Start("")
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}