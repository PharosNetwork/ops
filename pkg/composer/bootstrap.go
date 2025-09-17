package composer

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/utils"
)

func (c *Composer) Bootstrap() error {
	utils.Info("Bootstrapping domain: %s", c.domain.DomainLabel)

	// Clean all data first (removed clean functionality)

	return c.bootstrapLight()
}

func (c *Composer) bootstrapLight() error {
	utils.Info("Bootstrapping light mode domain")

	lightInst, exists := c.domain.Cluster[domain.ServiceLight]
	if !exists {
		return fmt.Errorf("light instance not found")
	}

	// Create necessary directories
	dirs := []string{"bin", "conf", "log", "data"}
	for _, dir := range dirs {
		dirPath := filepath.Join(lightInst.Dir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
		}
	}

	// Initialize configuration
	if err := c.initializeConf(lightInst); err != nil {
		return fmt.Errorf("failed to initialize configuration: %w", err)
	}

	// Generate genesis state
	if err := c.generateGenesis(lightInst); err != nil {
		return fmt.Errorf("failed to generate genesis: %w", err)
	}

	utils.Info("Light mode bootstrap completed")
	return nil
}

func (c *Composer) bootstrapUltra() error {
	utils.Info("Bootstrapping ultra mode domain")
	return fmt.Errorf("ultra mode not supported")
}

func (c *Composer) initializeConf(inst domain.Instance) error {
	utils.Info("Initializing configuration for instance: %s", inst.Name)

	// Create client directory structure
	clientDir := filepath.Join(".", "client")
	binDir := filepath.Join(clientDir, "bin")
	confDir := filepath.Join(clientDir, "conf")

	for _, dir := range []string{binDir, confDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Copy genesis configuration
	genesisSource := c.domain.GenesisConf
	if !filepath.IsAbs(genesisSource) {
		genesisSource = filepath.Join(c.domainPath, genesisSource)
	}

	genesisTarget := filepath.Join(confDir, "genesis.conf")
	if err := copyFile(genesisSource, genesisTarget); err != nil {
		utils.Warn("Failed to copy genesis config: %v", err)
	}

	utils.Info("Configuration initialized")
	return nil
}

func (c *Composer) generateGenesis(inst domain.Instance) error {
	utils.Info("Generating genesis state for instance: %s", inst.Name)

	clientBinDir := filepath.Join(".", "client", "bin")
	genesisConf := filepath.Join(".", "client", "conf", "genesis.conf")

	// Check if pharos_cli exists
	pharosCli := filepath.Join(clientBinDir, "pharos_cli")
	if _, err := os.Stat(pharosCli); os.IsNotExist(err) {
		utils.Warn("pharos_cli not found at %s, skipping genesis generation", pharosCli)
		return nil
	}

	// Generate genesis command
	cmd := exec.Command(pharosCli, "genesis", "-g", genesisConf, "--spec", "0")
	cmd.Dir = clientBinDir

	// Set environment variables
	cmd.Env = os.Environ()
	if c.domain.ChainProtocol == "evm" || c.domain.ChainProtocol == "all" {
		cmd.Env = append(cmd.Env, "LD_PRELOAD=./libevmone.so")
	}

	utils.Info("Running genesis command: %s", cmd.String())
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		utils.Error("Genesis generation failed: %v", err)
		utils.Error("Output: %s", string(output))
		return fmt.Errorf("genesis generation failed: %w", err)
	}

	utils.Info("Genesis generation completed")
	utils.Debug("Genesis output: %s", string(output))
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
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
			"storage_read": map[string]interface{}{
				"filename":      "../log/storage_read.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"pamir": map[string]interface{}{
				"filename":      "../log/pamir.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"vm": map[string]interface{}{
				"filename":      "../log/vm.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"consensus": map[string]interface{}{
				"filename":      "../log/consensus.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         true,
			},
			"pharos": map[string]interface{}{
				"filename":      "../log/pharos.log",
				"max_file_size": 209715200,
				"max_files":     200,
				"level":         "info",
				"flush":         false,
			},
			"tracing": map[string]interface{}{
				"filename":      "../log/tracing.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "error",
				"flush":         false,
			},
			"audit": map[string]interface{}{
				"filename":      "../log/audit.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "error",
				"flush":         false,
			},
			"profile": map[string]interface{}{
				"filename":      "../log/profile.log",
				"max_file_size": 209715200,
				"max_files":     200,
				"level":         "info",
				"flush":         false,
			},
			"alert": map[string]interface{}{
				"filename":      "../log/alert.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"cubenet": map[string]interface{}{
				"filename":      "../log/cubenet.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"traffic_in": map[string]interface{}{
				"filename":      "../log/traffic_in.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"traffic_out": map[string]interface{}{
				"filename":      "../log/traffic_out.log",
				"max_file_size": 209715200,
				"max_files":     100,
				"level":         "info",
				"flush":         false,
			},
			"access": map[string]interface{}{
				"filename":      "../log/access.log",
				"max_file_size": 209715200,
				"max_files":     100,
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

func createClusterConfig(domainName string, nodeID string) map[string]interface{} {
	// Use default host for demo
	host := "127.0.0.1"
	return map[string]interface{}{
		"light": map[string]interface{}{
			"service": "light",
			"ip":      "127.0.0.1",
			"host":    host,
			"args":    []string{"-d"},
			"env": map[string]string{
				"LIGHT_RPC_LISTEN_URL":     "0.0.0.0:20000",
				"LIGHT_RPC_ADVERTISE_URL":  fmt.Sprintf("%s:20000", host),
				"CLIENT_ADVERTISE_URLS":    fmt.Sprintf("tls://%s:18000,http://%s:18100,ws://%s:18200,wss://%s:18300", host, host, host, host),
				"CLIENT_LISTEN_URLS":       "tls://0.0.0.0:18000,http://0.0.0.0:18100,ws://0.0.0.0:18200,wss://0.0.0.0:18300",
				"PORTAL_UUID":              "100",
				"DOMAIN_LISTEN_URLS0":      "tcp://0.0.0.0:19000",
				"DOMAIN_LISTEN_URLS1":      "tcp://0.0.0.0:19001",
				"DOMAIN_LISTEN_URLS2":      "tcp://0.0.0.0:19002",
				"STORAGE_RPC_ADVERTISE_URL": fmt.Sprintf("%s:20000", host),
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