package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop [domain_files...]",
	Short: "Stop pharos light nodes",
	Long:  "Stop pharos light node domains",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, domainFile := range args {
			utils.Info("Stopping light node: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			if err := c.Stop(""); err != nil {
				utils.Error("Failed to stop light node: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}