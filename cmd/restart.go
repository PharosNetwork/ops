package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart [domain_files...]",
	Short: "Restart pharos domains",
	Long:  "Stop and start pharos domain services",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		service, _ := cmd.Flags().GetString("service")
		
		for _, domainFile := range args {
			utils.Info("Restarting domain: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			// Stop first
			if err := c.Stop(service); err != nil {
				utils.Error("Failed to stop domain: %v", err)
				continue
			}
			
			// Then start
			if err := c.Start(service); err != nil {
				utils.Error("Failed to start domain: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	restartCmd.Flags().StringP("service", "s", "", "Specific service to restart")
	rootCmd.AddCommand(restartCmd)
}