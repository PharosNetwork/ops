package cmd

import (
	"fmt"

	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var deployCmd = &cobra.Command{
	Use:   "deploy <domain.json> [domain.json...]",
	Short: "Deploy pharos node(s)",
	Long: `Deploy pharos node(s) from domain configuration file(s).
Multiple domain files can be specified for multi-domain deployment.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		service, _ := cmd.Flags().GetString("service")

		utils.Info("Deploying with service: %s", service)

		if len(args) == 1 {
			// Single domain deployment
			domainFile := args[0]
			utils.Info("Deploying single domain: %s", domainFile)

			c, err := composer.New(domainFile)
			if err != nil {
				return fmt.Errorf("failed to load domain file: %w", err)
			}

			return c.Deploy(service)
		} else {
			// Multi-domain deployment
			utils.Info("Deploying %d domains", len(args))

			// TODO: Implement concurrent deployment like Python version
			// For now, deploy sequentially
			for _, domainFile := range args {
				utils.Info("Deploying domain: %s", domainFile)

				c, err := composer.New(domainFile)
				if err != nil {
					utils.Error("Failed to load domain file %s: %v", domainFile, err)
					continue
				}

				if err := c.Deploy(service); err != nil {
					utils.Error("Failed to deploy domain %s: %v", domainFile, err)
					continue
				}
			}
		}

		return nil
	},
}

func init() {
	deployCmd.Flags().StringP("service", "s", "", "Service to deploy [etcd|mygrid_service|portal|dog|txpool|controller|compute]")
	rootCmd.AddCommand(deployCmd)
}