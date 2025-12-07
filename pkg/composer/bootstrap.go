package composer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/utils"
)

const (
	META_SERVICE_CONFIG_FILENAME = "meta_service.conf"
	MYGRID_GENESIS_CONFIG_FILENAME = "mygrid_genesis.conf"
	EVMONE_SO = "libevmone.so"
)

func (c *Composer) Bootstrap() error {
	utils.Info("Bootstrapping domain: %s", c.domain.DomainLabel)

	if c.isLight {
		return c.bootstrapLight()
	}

	return c.bootstrapUltra()
}

func (c *Composer) bootstrapLight() error {
	utils.Info("Bootstrapping light mode domain")

	// 1. Clean all logs and data except metasvc_db (matching Python logic)
	if err := c.clean(domain.ServiceLight, false); err != nil {
		return fmt.Errorf("failed to clean light instance: %w", err)
	}

	utils.Info("Starting generate genesis state")

	lightInst, exists := c.domain.Cluster[domain.ServiceLight]
	if !exists {
		return fmt.Errorf("light instance not found")
	}

	// Connect to the light instance host
	user := c.domain.RunUser
	if lightInst.IP == "127.0.0.1" || lightInst.IP == "localhost" {
		user = "" // Let SSH use current user
	}

	sshClient, err := ssh.NewClient(lightInst.IP, user)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer sshClient.Close()

	if err := sshClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to %s: %w", lightInst.IP, err)
	}

	// Initialize configuration
	if err := c.initializeConf(sshClient); err != nil {
		return fmt.Errorf("failed to initialize configuration: %w", err)
	}

	// Generate genesis state
	if err := c.generateGenesis(sshClient); err != nil {
		return fmt.Errorf("failed to generate genesis: %w", err)
	}

	utils.Info("Bootstrap completed successfully")
	return nil
}

func (c *Composer) bootstrapUltra() error {
	utils.Info("Bootstrapping ultra mode domain")

	// 1. Clean all data
	if err := c.clean("", true); err != nil {
		return fmt.Errorf("failed to clean all data: %w", err)
	}

	// 2. Start etcd service
	if err := c.startService(domain.ServiceETCD); err != nil {
		return fmt.Errorf("failed to start etcd: %w", err)
	}

	// 3. Start storage service
	if err := c.startService(domain.ServiceStorage); err != nil {
		return fmt.Errorf("failed to start storage: %w", err)
	}

	utils.Info("Starting generate genesis state")

	// 4. Ensure services are stopped in finally block
	defer func() {
		utils.Info("Stopping services...")
		if err := c.stopService(domain.ServiceStorage); err != nil {
			utils.Error("Failed to stop storage service: %v", err)
		}
		if err := c.stopService(domain.ServiceETCD); err != nil {
			utils.Error("Failed to stop etcd service: %v", err)
		}
	}()

	// 5. Connect to controller instance
	controllerInst, exists := c.domain.Cluster[domain.ServiceController]
	if !exists {
		return fmt.Errorf("controller instance not found")
	}

	user := c.domain.RunUser
	if controllerInst.IP == "127.0.0.1" || controllerInst.IP == "localhost" {
		user = "" // Let SSH use current user
	}

	sshClient, err := ssh.NewClient(controllerInst.IP, user)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer sshClient.Close()

	if err := sshClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to %s: %w", controllerInst.IP, err)
	}

	// 6. Initialize configuration
	if err := c.initializeConf(sshClient); err != nil {
		return fmt.Errorf("failed to initialize configuration: %w", err)
	}

	// 7. Generate genesis state
	if err := c.generateGenesis(sshClient); err != nil {
		return fmt.Errorf("failed to generate genesis: %w", err)
	}

	utils.Info("Bootstrap completed successfully")
	return nil
}

// initializeConf sets up configuration in etcd using meta_tool
// This matches Python's initialize_conf method exactly
func (c *Composer) initializeConf(sshClient *ssh.Client) error {
	utils.Info("Setting pharos configuration in etcd")

	// Remote client bin directory
	cliBinDir := filepath.Join(c.getRemoteClientDir(), "bin")

	// Set global and service configurations
	jsonFiles := map[string]string{
		fmt.Sprintf("/%s/global/config", c.domain.ChainID):           c.getBuildConf("global.conf"),
		fmt.Sprintf("/%s/services/portal/config", c.domain.ChainID):  c.getBuildConf("portal.conf"),
		fmt.Sprintf("/%s/services/dog/config", c.domain.ChainID):     c.getBuildConf("dog.conf"),
		fmt.Sprintf("/%s/services/txpool/config", c.domain.ChainID):  c.getBuildConf("txpool.conf"),
		fmt.Sprintf("/%s/services/controller/config", c.domain.ChainID): c.getBuildConf("controller.conf"),
		fmt.Sprintf("/%s/services/compute/config", c.domain.ChainID): c.getBuildConf("compute.conf"),
	}

	for key, filepath := range jsonFiles {
		utils.Info("Setting %s", key)
		content, err := os.ReadFile(filepath)
		if err != nil {
			utils.Warn("Failed to read config file %s: %v", filepath, err)
			continue
		}

		// Escape single quotes in the content for shell command
		contentStr := strings.ReplaceAll(string(content), "'", "'\"'\"'")
		cmd := fmt.Sprintf("cd %s; ./meta_tool -conf %s -set -key=%s -value='%s'",
			cliBinDir, META_SERVICE_CONFIG_FILENAME, key, contentStr)

		if _, err := sshClient.RunCommand(cmd); err != nil {
			utils.Error("Failed to set config %s: %v", key, err)
			return fmt.Errorf("failed to set config %s: %w", key, err)
		}
	}

	// Set certificates and secrets
	confs := map[string]interface{}{
		fmt.Sprintf("/%s/portal/certs", c.domain.ChainID): map[string]string{
			"ca.crt":   toBase64(c.domain.Secret.Client.Files["ca_cert"]),
			"server.crt": toBase64(c.domain.Secret.Client.Files["cert"]),
			"server.key": toBase64(c.domain.Secret.Client.Files["key"]),
		},
		fmt.Sprintf("/%s/secrets/domain.key", c.domain.ChainID): map[string]string{
			"domain_key":      toBase64(c.domain.Secret.Domain.Files["key"]),
			"stabilizing_key": toBase64(c.domain.Secret.Domain.Files["stabilizing_key"]),
		},
	}

	// Add instance-specific configurations
	for name, inst := range c.domain.Cluster {
		if inst.Log != nil || inst.Config != nil {
			// Convert gflags to parameters
			parameters := make(map[string]string)
			for k, v := range inst.GFlags {
				parameters[fmt.Sprintf("/GlobalFlag/%s", k)] = v
			}

			confs[fmt.Sprintf("/%s/services/%s/instance_config/%s", c.domain.ChainID, inst.Service, name)] = map[string]interface{}{
				"log":        inst.Log,
				"parameters": parameters,
				"config":     inst.Config,
			}
		}
	}

	for key, value := range confs {
		utils.Info("Setting %s", key)
		jsonValue, err := json.Marshal(value)
		if err != nil {
			utils.Error("Failed to marshal config for %s: %v", key, err)
			continue
		}

		// Escape single quotes in the JSON for shell command
		jsonStr := strings.ReplaceAll(string(jsonValue), "'", "'\"'\"'")
		cmd := fmt.Sprintf("cd %s; ./meta_tool -conf %s -set -key=%s -value='%s'",
			cliBinDir, META_SERVICE_CONFIG_FILENAME, key, jsonStr)

		if _, err := sshClient.RunCommand(cmd); err != nil {
			utils.Error("Failed to set config %s: %v", key, err)
			return fmt.Errorf("failed to set config %s: %w", key, err)
		}
	}

	utils.Info("Configuration initialized successfully")
	return nil
}

// generateGenesis runs the pharos_cli genesis command
// This matches Python's genesis generation exactly
func (c *Composer) generateGenesis(sshClient *ssh.Client) error {
	utils.Info("Starting generate genesis state")

	cliBinDir := filepath.Join(c.getRemoteClientDir(), "bin")

	// Build the command matching Python exactly
	// Python: cd {cli_bin_dir}; LD_PRELOAD=./{EVMONE_SO} ./pharos_cli genesis -g ../conf/genesis.conf -s {MYGRID_GENESIS_CONFIG_FILENAME}
	cmd := fmt.Sprintf("cd %s; LD_PRELOAD=./%s ./pharos_cli genesis -g ../conf/genesis.conf -s %s",
		cliBinDir, EVMONE_SO, MYGRID_GENESIS_CONFIG_FILENAME)

	utils.Info("Running genesis command: %s", cmd)

	output, err := sshClient.RunCommand(cmd)
	if err != nil {
		utils.Error("Failed to init genesis tool")
		utils.Error("Exit code: %v", err)
		utils.Error("Output: %s", output)
		return fmt.Errorf("failed to init genesis tool: %w", err)
	}

	utils.Info("Genesis generation completed")
	if len(output) > 0 {
		utils.Debug("Genesis output: %s", output)
	}

	return nil
}

// Helper functions

// toBase64 encodes a file to base64 string
func toBase64(filepath string) string {
	if filepath == "" {
		return ""
	}

	data, err := os.ReadFile(filepath)
	if err != nil {
		utils.Warn("Failed to read file %s: %v", filepath, err)
		return ""
	}

	return base64.StdEncoding.EncodeToString(data)
}

// getBuildConf returns the path to a config file in the build directory
func (c *Composer) getBuildConf(filename string) string {
	return filepath.Join(c.domain.BuildRoot, "conf", filename)
}

// getRemoteClientDir returns the remote client directory path
// Python: return join(self.deploy_dir, 'client')
func (c *Composer) getRemoteClientDir() string {
	// client is deployed to temporary directory and then to remote
	// Python uses: /tmp/{chain_id}/{domain_label}/client
	return fmt.Sprintf("/tmp/%s/%s/client", c.domain.ChainID, c.domain.DomainLabel)
}

func copyFile(src, dst string) error {
	// Read source file
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Get source file permissions
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Write file with source permissions
	return os.WriteFile(dst, data, srcInfo.Mode())
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

// clean cleans data and logs for services
// Matches Python's clean method exactly
func (c *Composer) clean(service string, cleanMeta bool) error {
	utils.Info("Cleaning %s, service: %s, cleanMeta: %v", c.domain.DomainLabel, service, cleanMeta)

	if c.isLight {
		// Light mode: clean only light instance
		lightInst, exists := c.domain.Cluster[domain.ServiceLight]
		if !exists {
			return fmt.Errorf("light instance not found")
		}

		user := c.domain.RunUser
		if lightInst.IP == "127.0.0.1" || lightInst.IP == "localhost" {
			user = ""
		}

		sshClient, err := ssh.NewClient(lightInst.IP, user)
		if err != nil {
			return fmt.Errorf("failed to create SSH client: %w", err)
		}
		defer sshClient.Close()

		if err := sshClient.Connect(); err != nil {
			return fmt.Errorf("failed to connect to %s: %w", lightInst.IP, err)
		}

		return c.cleanInstance(domain.ServiceLight, sshClient, cleanMeta)
	}

	// Ultra mode
	if service == "" {
		// Clean all services
		services := []string{
			domain.ServiceStorage,
			domain.ServiceTxPool,
			domain.ServiceCompute,
			domain.ServiceController,
			domain.ServiceDog,
			domain.ServicePortal,
		}

		// Add etcd first if cleanMeta is true
		if cleanMeta {
			services = append([]string{domain.ServiceETCD}, services...)
		}

		for _, svc := range services {
			if err := c.cleanService(svc); err != nil {
				utils.Error("Failed to clean service %s: %v", svc, err)
				return err
			}
		}
	} else {
		// Clean specific service
		return c.cleanService(service)
	}

	return nil
}

// cleanInstance cleans a specific instance
// Matches Python's clean_instance method
func (c *Composer) cleanInstance(instanceName string, sshClient *ssh.Client, cleanMeta bool) error {
	utils.Info("Cleaning %s, cleanMeta: %v", instanceName, cleanMeta)

	_, exists := c.domain.Cluster[instanceName]
	if !exists {
		return fmt.Errorf("instance %s not found", instanceName)
	}

	// Get mygrid placements from mygrid_env.json
	// For now, use default placement path matching Python logic
	deployDir := c.domain.DeployDir
	if deployDir == "" {
		deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
	}

	// Clean placement directories
	placements := []string{
		fmt.Sprintf("%s/%s", deployDir, instanceName),
	}

	if instanceName == domain.ServiceLight && !cleanMeta {
		// Light mode with cleanMeta=false: preserve metasvc_db
		for _, placement := range placements {
			if err := c.cleanFolder(sshClient, placement, "metasvc_db"); err != nil {
				utils.Warn("Failed to clean placement %s: %v", placement, err)
			}
		}
	} else {
		// Clean all placement directories
		for _, placement := range placements {
			if err := c.cleanFolder(sshClient, placement, ""); err != nil {
				utils.Warn("Failed to clean placement %s: %v", placement, err)
			}
		}
	}

	// Clean data directory if cleanMeta is true
	if cleanMeta {
		dataDir := fmt.Sprintf("%s/%s/data", deployDir, instanceName)
		if err := c.cleanFolder(sshClient, dataDir, ""); err != nil {
			utils.Warn("Failed to clean data directory %s: %v", dataDir, err)
		}
	}

	// Always clean log directory
	logDir := fmt.Sprintf("%s/%s/log", deployDir, instanceName)
	if err := c.cleanFolder(sshClient, logDir, ""); err != nil {
		utils.Warn("Failed to clean log directory %s: %v", logDir, err)
	}

	// Clean specific files
	binDir := fmt.Sprintf("%s/%s/bin", deployDir, instanceName)
	files := []string{
		fmt.Sprintf("%s/epoch.conf", binDir),
		fmt.Sprintf("%s/*.log", binDir),
		fmt.Sprintf("%s/*.stdout", binDir),
	}

	for _, file := range files {
		cmd := fmt.Sprintf("rm -f %s", file)
		if _, err := sshClient.RunCommand(cmd); err != nil {
			utils.Warn("Failed to remove file %s: %v", file, err)
		}
	}

	return nil
}

// cleanService cleans all instances of a service
func (c *Composer) cleanService(serviceType string) error {
	utils.Info("Cleaning service %s", serviceType)

	// Group instances by host
	hosts := make(map[string][]*domain.Instance)
	for _, inst := range c.domain.Cluster {
		if inst.Service == serviceType {
			hosts[inst.IP] = append(hosts[inst.IP], inst)
		}
	}

	// Clean each host
	for host, instances := range hosts {
		user := c.domain.RunUser
		if host == "127.0.0.1" || host == "localhost" {
			user = ""
		}

		sshClient, err := ssh.NewClient(host, user)
		if err != nil {
			return fmt.Errorf("failed to create SSH client for %s: %w", host, err)
		}
		defer sshClient.Close()

		if err := sshClient.Connect(); err != nil {
			return fmt.Errorf("failed to connect to %s: %w", host, err)
		}

		for _, inst := range instances {
			if err := c.cleanInstance(inst.Name, sshClient, true); err != nil {
				return fmt.Errorf("failed to clean instance %s: %w", inst.Name, err)
			}
		}
	}

	return nil
}

// cleanFolder removes contents of a folder, optionally excluding one item
// Matches Python's clean_folder method
func (c *Composer) cleanFolder(sshClient *ssh.Client, folder, except string) error {
	if folder == "/" {
		return fmt.Errorf("attempted to clean root directory")
	}

	// Check if folder exists
	cmd := fmt.Sprintf("test -d %s", folder)
	if _, err := sshClient.RunCommand(cmd); err != nil {
		// Folder doesn't exist, nothing to clean
		return nil
	}

	utils.Info("Cleaning folder: %s", folder)

	var cleanCmd string
	if except != "" {
		// Clean all except the specified item
		cleanCmd = fmt.Sprintf("cd %s && find . -maxdepth 1 ! -path . ! -name %s -print0 | xargs -0 -I {} rm -rf {}",
			folder, except)
	} else {
		// Clean everything
		cleanCmd = fmt.Sprintf("cd %s && find . -maxdepth 1 ! -path . -print0 | xargs -0 -I {} rm -rf {}",
			folder)
	}

	_, err := sshClient.RunCommand(cleanCmd)
	return err
}

// startService starts a service
// Matches Python's start_service method
func (c *Composer) startService(serviceType string) error {
	utils.Info("Starting service %s", serviceType)

	// Group instances by host
	hosts := make(map[string][]*domain.Instance)
	for _, inst := range c.domain.Cluster {
		if inst.Service == serviceType {
			hosts[inst.IP] = append(hosts[inst.IP], inst)
		}
	}

	for host, instances := range hosts {
		user := c.domain.RunUser
		if host == "127.0.0.1" || host == "localhost" {
			user = ""
		}

		sshClient, err := ssh.NewClient(host, user)
		if err != nil {
			return fmt.Errorf("failed to create SSH client for %s: %w", host, err)
		}
		defer sshClient.Close()

		if err := sshClient.Connect(); err != nil {
			return fmt.Errorf("failed to connect to %s: %w", host, err)
		}

		for _, inst := range instances {
			if err := c.startInstance(inst, sshClient); err != nil {
				return fmt.Errorf("failed to start instance %s: %w", inst.Name, err)
			}
		}
	}

	// Give services time to start
	time.Sleep(2 * time.Second)

	return nil
}

// startInstance starts a specific instance
func (c *Composer) startInstance(inst *domain.Instance, sshClient *ssh.Client) error {
	deployDir := c.domain.DeployDir
	if deployDir == "" {
		deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
	}

	binDir := fmt.Sprintf("%s/%s/bin", deployDir, inst.Service)

	var cmd string
	switch inst.Service {
	case domain.ServiceETCD:
		// Start etcd with environment variables
		cmd = fmt.Sprintf("cd %s && nohup ./etcd --data-dir ../data/etcd > /dev/null 2>&1 &", binDir)
	case domain.ServiceStorage:
		// Start mygrid service (master or server)
		role := "server"
		if strings.Contains(strings.ToLower(inst.Name), "master") {
			role = "master"
		}
		cmd = fmt.Sprintf("cd %s && nohup ./mygrid_service %s > /dev/null 2>&1 &", binDir, role)
	default:
		// Start other services using launch.sh
		cmd = fmt.Sprintf("cd %s && nohup ./launch.sh > /dev/null 2>&1 &", binDir)
	}

	utils.Info("Starting %s: %s", inst.Name, cmd)

	_, err := sshClient.RunCommand(cmd)
	return err
}

// stopService stops a service
// Matches Python's stop_service method
func (c *Composer) stopService(serviceType string) error {
	utils.Info("Stopping service %s", serviceType)

	// Group instances by host
	hosts := make(map[string][]*domain.Instance)
	for _, inst := range c.domain.Cluster {
		if inst.Service == serviceType {
			hosts[inst.IP] = append(hosts[inst.IP], inst)
		}
	}

	for host := range hosts {
		user := c.domain.RunUser
		if host == "127.0.0.1" || host == "localhost" {
			user = ""
		}

		sshClient, err := ssh.NewClient(host, user)
		if err != nil {
			return fmt.Errorf("failed to create SSH client for %s: %w", host, err)
		}
		defer sshClient.Close()

		if err := sshClient.Connect(); err != nil {
			return fmt.Errorf("failed to connect to %s: %w", host, err)
		}

		deployDir := c.domain.DeployDir
		if deployDir == "" {
			deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
		}

		binDir := fmt.Sprintf("%s/%s/bin", deployDir, serviceType)

		// Find and kill processes
		cmd := fmt.Sprintf("pgrep -f \"%s\"", binDir)
		output, err := sshClient.RunCommand(cmd)
		if err == nil && output != "" {
			// Kill processes gracefully
			pids := strings.Split(strings.TrimSpace(output), "\n")
			for _, pid := range pids {
				killCmd := fmt.Sprintf("kill %s", strings.TrimSpace(pid))
				sshClient.RunCommand(killCmd)
			}

			// Wait a bit
			time.Sleep(1 * time.Second)

			// Force kill any remaining processes
			forceKillCmd := fmt.Sprintf("pkill -9 -f \"%s\"", binDir)
			sshClient.RunCommand(forceKillCmd)
		}
	}

	return nil
}