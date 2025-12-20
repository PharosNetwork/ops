package cmd

import (
	"fmt"
	"sync"

	"pharos-ops/pkg/composer"

	"github.com/spf13/cobra"
)

// Default private key from Python version
const defaultPrivateKey = "fcfc69bd0056a2592e1f46cfba8264d8918fe98ecf5a2ef43aaa4ed1463725e1"

var addValidatorCmd = &cobra.Command{
	Use:   "add-validator <domain.json> [domain.json...]",
	Short: "Change a non validator domain to validator domain",
	Long: `Register a new validator on the blockchain by calling the staking contract's
registerValidator function with a stake deposit.

This command requires:
  - endpoint: JSON-RPC URL of the blockchain node
  - key: private key for signing transactions (default provided)
  - domains: one or more domain configuration files`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		endpoint, _ := cmd.Flags().GetString("endpoint")
		key, _ := cmd.Flags().GetString("key")
		noPrefix, _ := cmd.Flags().GetBool("no-prefix")

		// Print domain files like Python version (click.format_filename)
		for _, domainFile := range args {
			fmt.Printf("%s\n", domainFile)
		}

		if len(args) == 1 {
			// Single domain
			domainFile := args[0]

			c, err := composer.New(domainFile)
			if err != nil {
				return fmt.Errorf("failed to load domain file: %w", err)
			}

			return c.AddValidator(endpoint, key, noPrefix)
		} else {
			// Multiple domains - process like Python version (sequentially)
			for _, domainFile := range args {
				c, err := composer.New(domainFile)
				if err != nil {
					return fmt.Errorf("failed to load domain file %s: %w", domainFile, err)
				}

				if err := c.AddValidator(endpoint, key, noPrefix); err != nil {
					return fmt.Errorf("failed to add validator for domain %s: %w", domainFile, err)
				}
			}
		}

		return nil
	},
}

func init() {
	addValidatorCmd.Flags().StringP("endpoint", "e", "", "JSON-RPC endpoint URL (required)")
	addValidatorCmd.Flags().String("key", defaultPrivateKey, "Private key for signing transactions")
	addValidatorCmd.Flags().Bool("no-prefix", false, "Remove prefix from keys (1003 for domain pubkey, 4003 for BLS pubkey)")

	// Mark endpoint as required
	addValidatorCmd.MarkFlagRequired("endpoint")

	rootCmd.AddCommand(addValidatorCmd)
}

// addValidatorWG is a helper for concurrent processing (matching Python's potential concurrency)
// Currently Python processes sequentially, but this is prepared for future optimization
func addValidatorWG(endpoint, key string, noPrefix bool, domainFiles []string) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(domainFiles))

	for _, domainFile := range domainFiles {
		wg.Add(1)
		go func(df string) {
			defer wg.Done()

			c, err := composer.New(df)
			if err != nil {
				errChan <- fmt.Errorf("failed to load domain file %s: %w", df, err)
				return
			}

			if err := c.AddValidator(endpoint, key, noPrefix); err != nil {
				errChan <- fmt.Errorf("failed to add validator for domain %s: %w", df, err)
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

	return nil
}
