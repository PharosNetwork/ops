package cmd

import (
	"fmt"

	"pharos-ops/pkg/composer"

	"github.com/spf13/cobra"
)

var exitValidatorCmd = &cobra.Command{
	Use:   "exit-validator <domain.json> [domain.json...]",
	Short: "Change a validator domain to non validator domain",
	Long: `Request a validator to exit from the blockchain by calling the staking contract's
exitValidator function. The validator must wait for a withdrawal period (4 epochs by default)
before their stake can be fully withdrawn.

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

		// Process each domain file sequentially (matching Python behavior)
		for _, domainFile := range args {
			c, err := composer.New(domainFile)
			if err != nil {
				return fmt.Errorf("failed to load domain file %s: %w", domainFile, err)
			}

			if err := c.ExitValidator(endpoint, key, noPrefix); err != nil {
				return fmt.Errorf("failed to exit validator for domain %s: %w", domainFile, err)
			}
		}

		return nil
	},
}

func init() {
	exitValidatorCmd.Flags().StringP("endpoint", "e", "", "JSON-RPC endpoint URL (required)")
	exitValidatorCmd.Flags().String("key", defaultPrivateKey, "Private key for signing transactions")
	exitValidatorCmd.Flags().Bool("no-prefix", false, "Remove prefix from keys (1003 for domain pubkey)")

	// Mark endpoint as required
	exitValidatorCmd.MarkFlagRequired("endpoint")

	rootCmd.AddCommand(exitValidatorCmd)
}
