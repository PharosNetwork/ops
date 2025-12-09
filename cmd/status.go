package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	statusService string
)

var statusCmd = &cobra.Command{
	Use:   "status [domain_files...]",
	Short: "Check status of pharos node",
	Long:  "Check the running status of pharos node",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, domainFile := range args {
			fmt.Printf("%s\n", domainFile)

			c, err := composer.New(domainFile)
			if err != nil {
				utils.Error("Failed to load domain file %s: %v", domainFile, err)
				continue
			}

			if err := c.Status(statusService); err != nil {
				utils.Error("Failed to check status for %s: %v", domainFile, err)
				continue
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)

	// Add flags matching Python version
	statusCmd.Flags().StringVarP(&statusService, "service", "s", "",
		"service to check status [etcd|storage|portal|dog|txpool|controller|compute]")
}