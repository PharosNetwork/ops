package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean [domain_files...]",
	Short: "Clean pharos domains",
	Long:  "Clean pharos domain data and logs",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		service, _ := cmd.Flags().GetString("service")
		all, _ := cmd.Flags().GetBool("all")
		
		for _, domainFile := range args {
			utils.Info("Cleaning domain: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			if err := c.Clean(service, all); err != nil {
				utils.Error("Failed to clean domain: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	cleanCmd.Flags().StringP("service", "s", "", "Specific service to clean")
	cleanCmd.Flags().Bool("all", false, "Clean all data including configuration")
	rootCmd.AddCommand(cleanCmd)
}