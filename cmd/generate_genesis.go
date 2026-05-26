package cmd

import (
	"fmt"
	"time"

	"pharos-ops/pkg/genesis"

	"github.com/spf13/cobra"
)

var (
	ggDeployPath string
	ggKeysDir    string
	ggOutput     string
	ggTimestamp  int64
	ggKeyPasswd  string
)

var generateGenesisCmd = &cobra.Command{
	Use:   "generate-genesis",
	Short: "Generate genesis.conf from deploy.json + pre-generated keys",
	Long: `Produces a genesis.conf equivalent to aldaba-ops generate, suitable for ` +
		`feeding to './ops bootstrap'. Ports the EVM storage-slot logic from ` +
		`aldaba_ops/toolkit/conf.py.

The --keys-dir is expected to contain a pre-generated key tree:
  <keys-dir>/prime256v1/<domain_label>/{domain.key, domain.pub, domain.pop}
  <keys-dir>/bls12381/<domain_label>/{stabilizing.key, stabilizing.pub, stabilizing.pop}
.pop files are produced by 'pharos_cli crypto -t gen-pop' upstream.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		passwd := ggKeyPasswd
		if passwd == "" {
			if saved, err := GetPassword(); err == nil {
				passwd = saved
			} else {
				passwd = "123abc"
				fmt.Println("Warning: no password set, falling back to default '123abc' for key reads")
			}
		}

		timestampMs := ggTimestamp
		if timestampMs == 0 {
			timestampMs = time.Now().UnixMilli()
		}

		g, err := genesis.New(genesis.Options{
			DeployPath:  ggDeployPath,
			KeysDir:     ggKeysDir,
			KeyPasswd:   passwd,
			TimestampMs: timestampMs,
		})
		if err != nil {
			return fmt.Errorf("init generator: %w", err)
		}

		if err := g.Run(ggOutput); err != nil {
			return fmt.Errorf("generate genesis: %w", err)
		}

		fmt.Printf("Generated %s\n", ggOutput)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateGenesisCmd)

	generateGenesisCmd.Flags().StringVar(&ggDeployPath, "deploy", "./deploy.json",
		"Path to deploy.json")
	generateGenesisCmd.Flags().StringVar(&ggKeysDir, "keys-dir", "./scripts/resources/domain_keys",
		"Root of pre-generated key tree")
	generateGenesisCmd.Flags().StringVar(&ggOutput, "output", "./genesis.conf",
		"Output genesis.conf path")
	generateGenesisCmd.Flags().Int64Var(&ggTimestamp, "timestamp", 0,
		"Genesis timestamp in milliseconds (0 = time.Now())")
	generateGenesisCmd.Flags().StringVar(&ggKeyPasswd, "key-passwd", "",
		"Password for encrypted key files (falls back to saved password, then '123abc')")
}
