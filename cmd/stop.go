package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop [domain_files...]",
	Short: "Stop pharos domains",
	Long:  "Stop pharos domain services",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		service, _ := cmd.Flags().GetString("service")
		
		for _, domainFile := range args {
			utils.Info("Stopping domain: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			if err := c.Stop(service); err != nil {
				utils.Error("Failed to stop domain: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	stopCmd.Flags().StringP("service", "s", "", "Specific service to stop")
	rootCmd.AddCommand(stopCmd)
}