package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start [domain_files...]",
	Short: "Start pharos light nodes",
	Long:  "Start pharos light node domains",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, domainFile := range args {
			utils.Info("Starting light node: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			if err := c.Start(""); err != nil {
				utils.Error("Failed to start light node: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}