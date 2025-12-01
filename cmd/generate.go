package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

type DeployConfig struct {
	BuildRoot   string                 `json:"build_root"`
	ChainID     string                 `json:"chain_id"`
	Version     string                 `json:"version"`
	RunUser     string                 `json:"run_user"`
	DeployRoot  string                 `json:"deploy_root"`
	Domains     map[string]DomainConfig `json:"domains"`
}

type DomainConfig struct {
	DeployDir    string        `json:"deploy_dir"`
	Cluster      []ClusterNode `json:"cluster"`
}

type ClusterNode struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

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
		
		// Read deploy file
		data, err := os.ReadFile(deployFile)
		if err != nil {
			return fmt.Errorf("failed to read deploy file: %w", err)
		}

		var deploy DeployConfig
		if err := json.Unmarshal(data, &deploy); err != nil {
			return fmt.Errorf("failed to parse deploy file: %w", err)
		}

		// Generate domain files
		for domainName, domainConfig := range deploy.Domains {
			domainFile := fmt.Sprintf("%s.json", domainName)
			utils.Info("Generating domain file: %s", domainFile)

			if err := generateDomainFile(domainFile, domainName, domainConfig, deploy); err != nil {
				utils.Error("Failed to generate %s: %v", domainFile, err)
				continue
			}
		}

		if genesis {
			utils.Info("Genesis flag enabled - would generate genesis files")
		}

		return nil
	},
}

func generateDomainFile(filename, domainName string, config DomainConfig, deploy DeployConfig) error {
	// Generate NODE_ID using SHA256 hash (matching Python logic)
	nodeID := generateNodeID()

	// Use deploy_dir from config, or fall back to deploy_root/domainName
	deployDir := config.DeployDir
	if deployDir == "" && deploy.DeployRoot != "" {
		deployDir = filepath.Join(deploy.DeployRoot, domainName)
	}
	if deployDir == "" {
		deployDir = "/tmp/pharos/" + domainName
	}

	// Create basic domain structure matching Python output
	domain := map[string]interface{}{
		"build_root":     deploy.BuildRoot,
		"chain_id":       deploy.ChainID,
		"chain_protocol": "evm",
		"domain_label":   domainName,
		"deploy_dir":     deployDir,
		"version":        deploy.Version,
		"run_user":       deploy.RunUser,
		"genesis_conf":   "../genesis.conf",
		"mygrid": map[string]interface{}{
			"conf": map[string]interface{}{
				"enable_adaptive": true,
				"filepath":        "../conf/mygrid.conf.json",
			},
			"env": map[string]interface{}{
				"enable_adaptive": true,
				"filepath":        "../conf/mygrid.light.env.json",
			},
		},
		"secret": map[string]interface{}{
			"domain": map[string]interface{}{
				"key_type": "prime256v1",
				"files": map[string]string{
					"key":             fmt.Sprintf("../scripts/resources/domain_keys/prime256v1/%s/new.key", domainName),
					"key_pub":         fmt.Sprintf("../scripts/resources/domain_keys/prime256v1/%s/new.pub", domainName),
					"stabilizing_key": fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/new.key", domainName),
					"stabilizing_pk":  fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/new.pub", domainName),
				},
			},
			"client": map[string]interface{}{
				"key_type": "prime256v1",
				"files": map[string]string{
					"ca_cert": "../conf/resources/portal/prime256v1/client/ca.crt",
					"cert":    "../conf/resources/portal/prime256v1/client/client.crt",
					"key":     "../conf/resources/portal/prime256v1/client/client.key",
				},
			},
		},
		"use_generated_keys": true,
		"key_passwd":         "123abc",
		"docker": map[string]interface{}{
			"enable":   false,
			"registry": "registry-vpc.cn-shanghai.aliyuncs.com/pharos",
		},
		"common": createCommonConfig(),
		"cluster": createClusterConfig(domainName, config, nodeID),
		"initial_stake_in_gwei": 1000000000,
	}

	// Write domain file
	data, err := json.MarshalIndent(domain, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain config: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func generateNodeID() string {
	// Generate a random 32-byte key and hash it with SHA256 (matching Python logic)
	// In production, this would read from actual key files
	randomBytes := make([]byte, 32)
	for i := range randomBytes {
		randomBytes[i] = byte(i) // Simple deterministic pattern for demo
	}
	
	hash := sha256.Sum256(randomBytes)
	return fmt.Sprintf("%x", hash)
}

func createCommonConfig() map[string]interface{} {
	return map[string]interface{}{
		"env": map[string]string{},
		"log": map[string]interface{}{
			"storage_write": map[string]interface{}{
				"filename":      "../log/storage_write.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"pharos": map[string]interface{}{
				"filename":      "../log/pharos.log",
				"max_file_size": 209715200,
				"max_files":     200,
				"level":         "info",
				"flush":         false,
			},
		},
		"config": map[string]interface{}{
			"metrics": map[string]interface{}{
				"enable_pamir_cetina":                false,
				"pamir_cetina_push_address":          "metrics.prometheus-prometheus-pushgateway.prometheus-agent-namespace.svc.cluster.local",
				"pamir_cetina_job_name":              "pharos_evm_16c",
			},
		},
		"gflags": map[string]string{
			"enable_eip155":           "true",
			"max_pending_txs_depth":   "64",
			"enable_perf":             "false",
			"enable_rpc_rate_limit":   "false",
		},
		"metrics": map[string]interface{}{
			"push_address":  "",
			"push_interval": "",
			"enable":        false,
			"push_port":     "",
			"job_name":      "",
		},
	}
}

func createClusterConfig(domainName string, config DomainConfig, nodeID string) map[string]interface{} {
	if len(config.Cluster) == 0 {
		return map[string]interface{}{}
	}
	
	node := config.Cluster[0]
	return map[string]interface{}{
		"light": map[string]interface{}{
			"service": "light",
			"ip":      "127.0.0.1",
			"host":    node.Host,
			"args":    []string{"-d"},
			"env": map[string]string{
				"LIGHT_RPC_LISTEN_URL":     "0.0.0.0:20000",
				"LIGHT_RPC_ADVERTISE_URL":  fmt.Sprintf("%s:20000", node.Host),
				"CLIENT_ADVERTISE_URLS":    fmt.Sprintf("tls://%s:18000,http://%s:18100,ws://%s:18200,wss://%s:18300", node.Host, node.Host, node.Host, node.Host),
				"CLIENT_LISTEN_URLS":       "tls://0.0.0.0:18000,http://0.0.0.0:18100,ws://0.0.0.0:18200,wss://0.0.0.0:18300",
				"PORTAL_UUID":              "100",
				"DOMAIN_LISTEN_URLS0":      "tcp://0.0.0.0:19000",
				"DOMAIN_LISTEN_URLS1":      "tcp://0.0.0.0:19001",
				"DOMAIN_LISTEN_URLS2":      "tcp://0.0.0.0:19002",
				"STORAGE_RPC_ADVERTISE_URL": fmt.Sprintf("%s:20000", node.Host),
				"STORAGE_ID":               "0",
				"STORAGE_MSU":              "0-255",
				"TXPOOL_PARTITION_LIST":    "0-255",
				"NODE_ID":                  nodeID,
			},
			"log":    map[string]interface{}{},
			"config": map[string]interface{}{},
			"gflags": map[string]interface{}{},
		},
	}
}

func init() {
	generateCmd.Flags().BoolP("genesis", "g", false, "Generate genesis files")
	rootCmd.AddCommand(generateCmd)
}