package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	startService       string
	extraStorageArgs   string
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

			if err := c.Start(startService, extraStorageArgs); err != nil {
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
		"service to start [etcd|storage|portal|dog|txpool|controller|compute]")
	startCmd.Flags().StringVarP(&extraStorageArgs, "extra-storage-args", "a", "",
		"extra storage args for storage start command")
}