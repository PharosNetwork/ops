package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap [domain_files...]",
	Short: "Bootstrap pharos domains",
	Long:  "Generate genesis state and initialize pharos domains. Old data and logs will be cleaned up.",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, domainFile := range args {
			utils.Info("Bootstrapping domain: %s", domainFile)
			
			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}
			
			if err := c.Bootstrap(); err != nil {
				utils.Error("Failed to bootstrap domain: %v", err)
				continue
			}
		}
		
		return nil
	},
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)
}