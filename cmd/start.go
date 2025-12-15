package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	startService         string
	extraMygridServiceArgs string
)

var startCmd = &cobra.Command{
	Use:   "start [domain_files...]",
	Short: "Start pharos node",
	Long:  "Start pharos node from domain configuration",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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