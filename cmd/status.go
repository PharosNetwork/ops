package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status [domain_files...]",
	Short: "Check status of pharos light nodes",
	Long:  "Check the running status of pharos light node domains",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, domainFile := range args {
			utils.Info("Checking status for light node: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			if err := c.Status(""); err != nil {
				utils.Error("Failed to check status: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}