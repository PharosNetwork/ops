package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart [domain_files...]",
	Short: "Restart pharos light nodes",
	Long:  "Stop and start pharos light node domains",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, domainFile := range args {
			utils.Info("Restarting light node: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			// Stop first
			if err := c.Stop(""); err != nil {
				utils.Error("Failed to stop light node: %v", err)
				continue
			}
			
			// Then start
			if err := c.Start(""); err != nil {
				utils.Error("Failed to start light node: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	rootCmd.AddCommand(restartCmd)
}