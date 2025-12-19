package cmd

import (
	"fmt"
	"sync"

	"pharos-ops/pkg/composer"

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

		// Print domain files like Python version
		for _, domainFile := range args {
			fmt.Printf("%s\n", domainFile)
		}

		if len(args) == 1 {
			// Single domain deployment
			domainFile := args[0]

			c, err := composer.New(domainFile)
			if err != nil {
				return fmt.Errorf("failed to load domain file: %w", err)
			}

			return c.Deploy(service)
		} else {
			// Multi-domain deployment - concurrent like Python version
			var wg sync.WaitGroup
			errChan := make(chan error, len(args))

			for _, domainFile := range args {
				wg.Add(1)
				go func(df string) {
					defer wg.Done()

					c, err := composer.New(df)
					if err != nil {
						errChan <- fmt.Errorf("failed to load domain file %s: %w", df, err)
						return
					}

					if err := c.Deploy(service); err != nil {
						errChan <- fmt.Errorf("failed to deploy domain %s: %w", df, err)
						return
					}
				}(domainFile)
			}

			wg.Wait()
			close(errChan)

			// Return first error if any
			for err := range errChan {
				if err != nil {
					return err
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