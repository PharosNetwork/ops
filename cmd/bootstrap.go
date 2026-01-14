package cmd

import (
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap [domain_files...]",
	Short: "Bootstrap pharos domains",
	Long:  "Generate genesis state and initialize pharos domains. Old data and logs will be cleaned up.\nIf no domain files are provided, runs in simplified mode without domain.json.",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			// Old way: with domain.json files
			utils.Warn("Using domain.json is deprecated. Bootstrap will work without it in the future.")
			
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
		} else {
			// New way: without domain.json
			if err := BootstrapSimple(); err != nil {
				return err
			}
		}
		
		return nil
	},
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)
}