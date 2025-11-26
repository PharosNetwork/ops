package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

// Deploy 等结构体已在 light.go 中定义

var generateCmd = &cobra.Command{
	Use:   "generate [deploy_file]",
	Short: "Generate domain files from deploy configuration",
	Long:  "Generate individual domain configuration files from a deploy.json file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		deployFile := "deploy.light.json"
		if len(args) > 0 {
			deployFile = args[0]
		}

		genesis, _ := cmd.Flags().GetBool("genesis")

		utils.Info("Generating domain files from: %s", deployFile)

		// 使用 light.go 中的 GenerateDomain 函数
		domain, err := GenerateDomain(deployFile)
		if err != nil {
			return fmt.Errorf("failed to generate domain: %w", err)
		}

		// 生成 domain.json 文件
		domainFile := "domain.json"
		utils.Info("Generating domain file: %s", domainFile)

		if err := writeDomainFile(domainFile, domain); err != nil {
			return fmt.Errorf("failed to write domain file: %w", err)
		}

		// 如果启用了 genesis 选项
		if genesis {
			utils.Info("Generating genesis configuration...")
			if err := generateGenesisConfig(domain); err != nil {
				return fmt.Errorf("failed to generate genesis: %w", err)
			}
		}

		utils.Info("Generation completed successfully")
		return nil
	},
}

// writeDomainFile 将 Domain 结构写入 JSON 文件
func writeDomainFile(filename string, domain *Domain) error {
	// 转换为 map[string]interface{} 以便更好地控制 JSON 输出
	domainMap := domainToMap(domain)

	data, err := json.MarshalIndent(domainMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain config: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

// domainToMap 将 Domain 结构转换为 map，保持字段顺序和格式
func domainToMap(domain *Domain) map[string]interface{} {
	result := map[string]interface{}{
		"build_root":        domain.BuildRoot,
		"chain_id":          domain.ChainID,
		"chain_protocol":    domain.ChainProtocol,
		"domain_label":      domain.DomainLabel,
		"version":           domain.Version,
		"run_user":          domain.RunUser,
		"deploy_dir":        domain.DeployDir,
		"genesis_conf":      domain.GenesisConf,
		"mygrid": map[string]interface{}{
			"conf": map[string]interface{}{
				"enable_adaptive": domain.Mygrid.Conf.EnableAdaptive,
				"filepath":        domain.Mygrid.Conf.FilePath,
			},
			"env": map[string]interface{}{
				"enable_adaptive": domain.Mygrid.Env.EnableAdaptive,
				"filepath":        domain.Mygrid.Env.FilePath,
			},
		},
		"secret": map[string]interface{}{
			"domain": map[string]interface{}{
				"key_type": domain.Secret.Domain.KeyType,
				"files":    domain.Secret.Domain.Files,
			},
			"client": map[string]interface{}{
				"key_type": domain.Secret.Client.KeyType,
				"files":    domain.Secret.Client.Files,
			},
		},
		"use_generated_keys":    domain.UseGeneratedKeys,
		"key_passwd":           domain.KeyPasswd,
		"portal_ssl_pass":      domain.PortalSslPass,
		"enable_setkey_env":    domain.EnableSetkeyEnv,
		"docker": map[string]interface{}{
			"enable":   domain.Docker.Enable,
			"registry": domain.Docker.Registry,
		},
		"common": map[string]interface{}{
			"env":    domain.Common.Env,
			"log":    domain.Common.Log,
			"config": domain.Common.Config,
			"gflags": domain.Common.Gflags,
			"metrics": map[string]interface{}{
				"enable":        domain.Common.Metrics.Enable,
				"push_address":  domain.Common.Metrics.PushAddress,
				"job_name":      domain.Common.Metrics.JobName,
				"push_interval": domain.Common.Metrics.PushInterval,
				"push_port":     domain.Common.Metrics.PushPort,
			},
		},
		"cluster":               clusterToMap(domain.Cluster),
		"initial_stake_in_gwei": domain.InitialStakeInGwei,
	}

	return result
}

// clusterToMap 将 cluster map 转换为合适的格式
func clusterToMap(cluster map[string]Instance) map[string]interface{} {
	result := make(map[string]interface{})
	for name, instance := range cluster {
		result[name] = map[string]interface{}{
			"service": instance.Service,
			"name":    instance.Name,
			"ip":      instance.IP,
			"dir":     instance.Dir,
			"args":    instance.Args,
			"env":     instance.Env,
			"log":     instance.Log,
			"config":  instance.Config,
			"gflags":  instance.Gflags,
		}
	}
	return result
}

// generateGenesisConfig 生成创世配置
func generateGenesisConfig(domain *Domain) error {
	// 读取公钥
	pubkeyContent, err := os.ReadFile(domain.Secret.Domain.Files["key_pub"])
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	blsPubkeyContent, err := os.ReadFile(domain.Secret.Domain.Files["stabilizing_pk"])
	if err != nil {
		return fmt.Errorf("failed to read BLS public key: %w", err)
	}

	pubkey := string(pubkeyContent)
	blsPubkey := string(blsPubkeyContent)

	// 获取第一个 light 实例的配置
	lightInst, exists := domain.Cluster["light"]
	if !exists {
		return fmt.Errorf("light instance not found in cluster")
	}

	endpoint := lightInst.Env["CLIENT_ADVERTISE_URLS"]

	// 生成验证者存储槽
	domainSlots := GenerateDomainSlots(
		1, // totalDomains
		0, // domainIndex
		pubkey,
		blsPubkey,
		endpoint,
		int(domain.InitialStakeInGwei),
		"2cc298bdee7cfeac9b49f9659e2f3d637e149696", // 默认 admin address
	)

	// 生成链配置存储槽
	configSlots := GenerateChaincfgSlots(
		map[string]string{
			"epoch_blocks":          "64",
			"block_period":          "3",
			"max_validators":        "100",
			"unbond_period":         "4032",
			"withdraw_period":       "4032",
			"min_stake":             "1000000000000000000", // 1 ETH in wei
			"max_stake":             "1000000000000000000000", // 1000 ETH in wei
			"commission_rate":       "1000", // 10%
			"validator_join_rate":   "10",
			"min_balance":           "100000000000000000", // 0.1 ETH in wei
		},
		"2cc298bdee7cfeac9b49f9659e2f3d637e149696", // 默认 admin address
	)

	// 生成规则管理器存储槽
	ruleSlots := GenerateRuleMngSlots(configSlots, "2cc298bdee7cfeac9b49f9659e2f3d637e149696")

	// 生成创世配置文件
	genesisFile := fmt.Sprintf("genesis%s.conf", domain.ChainID)
	if err := writeGenesisConf(genesisFile, domainSlots, ruleSlots); err != nil {
		return fmt.Errorf("failed to write genesis config: %w", err)
	}

	utils.Info("Genesis configuration written to: %s", genesisFile)
	return nil
}

// writeGenesisConf 写入创世配置文件
func writeGenesisConf(filename string, domainSlots, ruleSlots map[string]string) error {
	// 简化的创世配置格式
	genesis := map[string]interface{}{
		"genesis": map[string]interface{}{
			"chain_id": 1000,
			"gas_limit": 30000000,
			"timestamp": 1737937200,
			"alloc": map[string]interface{}{
				"0000000000000000000000000000000000001000": map[string]interface{}{
					"balance": "1000000000000000000000000", // 1M ETH for faucet
				},
				"0000000000000000000000000000000000001001": map[string]interface{}{
					"balance": "1000000000000000000000000", // 1M ETH for test
				},
				"2cc298bdee7cfeac9b49f9659e2f3d637e149696": map[string]interface{}{
					"balance": "1000000000000000000000000", // 1M ETH for admin
				},
			},
			"validators": map[string]interface{}{
				"contract": "0x0000000000000000000000000000000000001000",
				"storage":   domainSlots,
			},
			"chain_cfg": map[string]interface{}{
				"contract": "0x0000000000000000000000000000000000001001",
				"storage":   ruleSlots,
			},
			"rule_manager": map[string]interface{}{
				"contract": "0x0000000000000000000000000000000000001002",
				"storage":   ruleSlots,
			},
		},
	}

	data, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal genesis config: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func init() {
	generateCmd.Flags().BoolP("genesis", "g", false, "Generate genesis files")
	rootCmd.AddCommand(generateCmd)
}