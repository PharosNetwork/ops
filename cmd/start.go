package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start [domain_files...]",
	Short: "Start pharos domains",
	Long:  "Start pharos domain services",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		service, _ := cmd.Flags().GetString("service")
		
		for _, domainFile := range args {
			utils.Info("Starting domain: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			if err := c.Start(service); err != nil {
				utils.Error("Failed to start domain: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	startCmd.Flags().StringP("service", "s", "", "Specific service to start")
	rootCmd.AddCommand(startCmd)
}