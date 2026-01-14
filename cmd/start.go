package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	startService           string
	extraMygridServiceArgs string
)

var startCmd = &cobra.Command{
	Use:   "start [domain_files...]",
	Short: "Start pharos node",
	Long:  "Start pharos node from domain configuration.\nIf no domain files are provided, runs in simplified mode without domain.json.",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			// Old way: with domain.json files
			utils.Warn("Using domain.json is deprecated. Start will work without it in the future.")
			
			for _, domainFile := range args {
				fmt.Printf("%s\n", domainFile)

				c, err := composer.New(domainFile)
				if err != nil {
					utils.Error("Failed to load domain file %s: %v", domainFile, err)
					continue
				}

				if err := c.Start(startService, extraMygridServiceArgs); err != nil {
					utils.Error("Failed to start domain %s: %v", domainFile, err)
					continue
				}
			}
		} else {
			// New way: without domain.json
			if err := StartSimple(startService, extraMygridServiceArgs); err != nil {
				return err
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Add flags matching Python version
	startCmd.Flags().StringVarP(&startService, "service", "s", "",
		"service [etcd|mygrid_service|portal|dog|txpool|controller|compute]]")
	startCmd.Flags().StringVarP(&extraMygridServiceArgs, "extra-mygrid_service-args", "a", "",
		"extra storage args for storage start command")
}