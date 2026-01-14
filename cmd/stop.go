package cmd

import (
	"fmt"
	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	stopService string
	stopForce   bool
)

var stopCmd = &cobra.Command{
	Use:   "stop [domain_files...]",
	Short: "Stop pharos node",
	Long:  "Stop pharos node from domain configuration.\nIf no domain files are provided, runs in simplified mode without domain.json.",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			// Old way: with domain.json files
			utils.Warn("Using domain.json is deprecated. Stop will work without it in the future.")
			
			for _, domainFile := range args {
				fmt.Printf("%s\n", domainFile)

				c, err := composer.New(domainFile)
				if err != nil {
					utils.Error("Failed to load domain file %s: %v", domainFile, err)
					continue
				}

				if err := c.Stop(stopService, stopForce); err != nil {
					utils.Error("Failed to stop domain %s: %v", domainFile, err)
					continue
				}
			}
		} else {
			// New way: without domain.json
			if err := StopSimple(stopService, stopForce); err != nil {
				return err
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
	stopCmd.Flags().BoolVarP(&stopForce, "force", "f", false,
		"Force stop")
}