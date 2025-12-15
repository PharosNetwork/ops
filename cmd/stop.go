package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	stopService string
)

var stopCmd = &cobra.Command{
	Use:   "stop [domain_files...]",
	Short: "Stop pharos node",
	Long:  "Stop pharos node from domain configuration",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, domainFile := range args {
			fmt.Printf("%s\n", domainFile)

			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}

			if err := c.Stop(stopService); err != nil {
				utils.Error("Failed to stop domain %s: %v", domainFile, err)
				continue
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)

	// Add flags matching Python version
	stopCmd.Flags().StringVarP(&stopService, "service", "s", "",
		"service [etcd|mygrid_service|portal|dog|txpool|controller|compute]]")
}