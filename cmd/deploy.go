package cmd

import (
	"fmt"

	"pharos-ops/pkg/composer"
	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	service string
	all     bool
)

var deployCmd = &cobra.Command{
	Use:   "deploy [domain_file]",
	Short: "Deploy Pharos blockchain nodes",
	Long: `Deploy Pharos blockchain nodes to remote hosts.
This will clean existing data, deploy binaries and configurations.

Examples:
  pharos-ops deploy domain.json           # Deploy all services
  pharos-ops deploy -s light domain.json  # Deploy specific service
  pharos-ops deploy -s all domain.json     # Deploy all services explicitly`,
	RunE: runDeploy,
}

func init() {
	deployCmd.Flags().StringVarP(&service, "service", "s", "", "Service to deploy (light, all, svc)")
	deployCmd.Flags().BoolVar(&all, "all", false, "Deploy all services including client tools")
	deployCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose output")
	rootCmd.AddCommand(deployCmd)
}

func runDeploy(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("domain file is required")
	}

	domainFile := args[0]

	// Validate service parameter
	if service != "" && service != "light" && service != "all" && service != "svc" {
		return fmt.Errorf("invalid service: %s (must be light, all, or svc)", service)
	}

	// Create composer
	c, err := composer.New(domainFile)
	if err != nil {
		return fmt.Errorf("failed to create composer: %w", err)
	}

	// Execute deployment
	utils.Info("Starting deployment for domain: %s", c.Domain().DomainLabel)

	if err := c.Deploy(service, all); err != nil {
		return fmt.Errorf("deployment failed: %w", err)
	}

	utils.Info("Deployment completed successfully")
	return nil
}