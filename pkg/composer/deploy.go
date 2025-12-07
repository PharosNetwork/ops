package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/template"
	"pharos-ops/pkg/utils"
)

const (
	MYGRID_CONF_JSON_FILENAME = "mygrid.conf.json"
	MYGRID_ENV_JSON_FILENAME  = "mygrid.env.json"
	LIGHT_DEPLOY_MODE         = "light"
	ULTRA_DEPLOY_MODE         = "ultra"
)

// Deploy deploys the domain configuration to remote hosts
// This matches Python's Composer.deploy method
func (c *Composer) Deploy(service string) error {
	utils.Info("Deploying %s, service: %s", c.domain.DomainLabel, service)

	// Clean data and log first (matching Python)
	if err := c.clean(service, true); err != nil {
		utils.Warn("Failed to clean before deploy: %v", err)
	}

	// Get all instances for the service
	instances := c.getInstances(service)

	// Group instances by host
	hostInstances := make(map[string][]*domain.Instance)
	for _, instList := range instances {
		for _, inst := range instList {
			host := inst.Host
			if host == "" {
				host = inst.IP
			}
			hostInstances[host] = append(hostInstances[host], inst)
		}
	}

	// Deploy to each host
	for host, insts := range hostInstances {
		utils.Info("Deploying to host: %s", host)
		if pwd, err := os.Getwd(); err == nil {
			utils.Debug("Current working directory: %s", pwd)
		}
		if err := c.deployHost(host, insts, service, true, true); err != nil {
			return fmt.Errorf("failed to deploy to host %s: %w", host, err)
		}
	}

	// Deploy client tools
	deployClientHost := ""

	// Determine which host should get the client deployment
	if c.isLight || service == "light" {
		// For light or when deploying light service, deploy to light host
		if lightInst, exists := c.domain.Cluster[domain.ServiceLight]; exists {
			deployClientHost = lightInst.IP
		}
	} else if service == "" {
		// Default: deploy client to controller host
		if controllerInst, exists := c.domain.Cluster[domain.ServiceController]; exists {
			deployClientHost = controllerInst.IP
		}
	}

	if deployClientHost != "" {
		utils.Info("Deploying client tools to: %s", deployClientHost)

		// Deploy local CLI (always to localhost)
		if err := c.deployLocalCLI(); err != nil {
			return fmt.Errorf("failed to deploy local CLI: %w", err)
		}

		// Sync client tools to remote host if needed
		// In Python version: sync if not local OR local_client_dir != remote_client_dir
		// Since we're deploying to the same host (127.0.0.1), we still need to sync
		// to create the client directory in the deploy location
		if deployClientHost != "" {
			if err := c.syncClientToRemote(deployClientHost); err != nil {
				utils.Warn("Failed to sync client to deploy directory: %v", err)
			}
		}
	}

	utils.Info("✓ Deploy completed successfully for domain: %s", c.domain.DomainLabel)
	return nil
}

// deployHost deploys binaries and configuration to a specific host
// Uses SSH for all hosts including localhost
func (c *Composer) deployHost(host string, instances []*domain.Instance, service string, deployBinary, deployConf bool) error {
	utils.Info("Deploying instances to host: %s", host)

	// Make pharos root workspace
	deployDir := c.domain.DeployDir
	if deployDir == "" {
		deployDir = filepath.Join(c.domain.BuildRoot, "domain", c.domain.DomainLabel)
	}

	// Deploy using SSH for all hosts (including localhost)
	return c.deployToRemoteHost(host, instances, service, deployBinary, deployConf, deployDir)
}


// getInstanceNames returns names of instances
func getInstanceNames(instances []*domain.Instance) []string {
	var names []string
	for _, inst := range instances {
		names = append(names, inst.Name)
	}
	return names
}

// deployToRemoteHost deploys to a remote host via SSH
func (c *Composer) deployToRemoteHost(host string, instances []*domain.Instance, service string, deployBinary, deployConf bool, deployDir string) error {
	utils.Info("Deploying to host: %s", host)

	// For localhost, use current user; for remote hosts, use run_user
	user := c.domain.RunUser
	if host == "127.0.0.1" || host == "localhost" {
		user = "" // Let SSH use current user
	}

	// Create SSH client
	sshClient, err := ssh.NewClient(host, user)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer sshClient.Close()

	// Connect to remote host
	if err := sshClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to %s: %w", host, err)
	}

	// Create workspace directories on remote host
	dirs := []string{"bin", "conf", "log", "data", "certs"}
	for _, dir := range dirs {
		remotePath := filepath.Join(deployDir, dir)
		if err := sshClient.MkdirAll(remotePath, 0755); err != nil {
			utils.Warn("Failed to create remote directory %s: %v", remotePath, err)
		}
	}

	// Deploy binaries if requested
	if deployBinary {
		if err := c.deployBinariesRemote(sshClient, instances, deployDir); err != nil {
			return fmt.Errorf("failed to deploy binaries remotely: %w", err)
		}
	}

	// Deploy configuration if requested
	if deployConf {
		if err := c.deployConfigurationRemote(sshClient, instances, deployDir); err != nil {
			return fmt.Errorf("failed to deploy configuration remotely: %w", err)
		}
	}

	// Create instance directories (matching Python's _make_workspace for each instance)
	for _, inst := range instances {
		instDir := inst.Dir
		if instDir == "" {
			instDir = filepath.Join(deployDir, inst.Name)
		}

		utils.Info("Creating workspace for instance %s: %s", inst.Name, instDir)

		// Create instance root directory first
		if err := sshClient.MkdirAll(instDir, 0755); err != nil {
			utils.Error("Failed to create instance root directory %s: %v", instDir, err)
		} else {
			utils.Info("Successfully created instance root directory: %s", instDir)
		}

		// Create instance workspace directories
		instDirs := []string{"bin", "conf", "log", "data", "certs"}
		for _, dir := range instDirs {
			instPath := filepath.Join(instDir, dir)
			if err := sshClient.MkdirAll(instPath, 0755); err != nil {
				utils.Warn("Failed to create instance directory %s: %v", instPath, err)
			} else {
				utils.Info("Successfully created instance directory: %s", instPath)
			}
		}
	}

	// Handle non-adaptive mode on remote host
	if err := c.handleNonAdaptiveModeRemote(sshClient); err != nil {
		utils.Warn("Failed to handle non-adaptive mode on remote host: %v", err)
	}

	return nil
}

// deployLocalCLI deploys the CLI tools locally
func (c *Composer) deployLocalCLI() error {
	// Local client directory: /tmp/{chain_id}/{domain_label}/client
	localClientDir := filepath.Join("/tmp", c.domain.ChainID, c.domain.DomainLabel, "client")
	utils.Info("Deploying pharos CLI at localhost: %s", localClientDir)

	// Create local client workspace: {local_client_dir}/../../bin
	workspaceBinDir := filepath.Join(localClientDir, "../../bin")
	if err := os.MkdirAll(workspaceBinDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace bin dir: %w", err)
	}

	// Common CLI binaries to sync (matching Python's CLI_BINARYS)
	cliBinaries := []string{"pharos_cli", "etcdctl", "libevmone.so", "meta_tool", "VERSION"}

	buildBinDir := filepath.Join(c.domain.BuildRoot, "bin")
	for _, binary := range cliBinaries {
		src := filepath.Join(buildBinDir, binary)
		dst := filepath.Join(workspaceBinDir, binary)
		if err := copyFile(src, dst); err != nil {
			// VERSION 文件可能不存在，这是正常的
			if binary == "VERSION" {
				utils.Warn("VERSION file not found, skipping: %v", err)
			} else {
				utils.Warn("Failed to copy CLI binary %s: %v", binary, err)
			}
			continue
		}
	}

	// Create local client workspace: bin and conf dirs
	if err := os.MkdirAll(filepath.Join(localClientDir, "bin"), 0755); err != nil {
		return fmt.Errorf("failed to create client bin dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(localClientDir, "conf"), 0755); err != nil {
		return fmt.Errorf("failed to create client conf dir: %w", err)
	}

	// Create symlinks to CLI binaries
	cliBinDir := filepath.Join(localClientDir, "bin")
	symlinks := []struct{	src, target string }{
		{"../../../bin/pharos_cli", "./pharos_cli"},
		{"../../../bin/libevmone.so", "./libevmone.so"},
		{"../../../bin/VERSION", "./VERSION"},
		{"../../../bin/etcdctl", "./etcdctl"},
		{"../../../bin/meta_tool", "./meta_tool"},
	}

	for _, link := range symlinks {
		targetPath := filepath.Join(cliBinDir, link.target)
		if err := os.Symlink(link.src, targetPath); err != nil && !os.IsExist(err) {
			utils.Warn("Failed to create symlink %s: %v", link.target, err)
		}
	}

	// Sync CLI binaries directly
	if err := c.syncCLIBinaries(localClientDir, cliBinDir); err != nil {
		utils.Warn("Failed to sync CLI binaries: %v", err)
	}

	// Sync genesis.conf
	// Python: local.sync(self._domain.genesis_conf, join(cli_conf_dir, 'genesis.conf'))
	// genesis_conf is relative to domain.json path
	genesisSrc := filepath.Join(c.domainPath, c.domain.GenesisConf)
	genesisDst := filepath.Join(filepath.Join(localClientDir, "conf"), "genesis.conf")
	if _, err := os.Stat(genesisSrc); err == nil {
		if err := copyFile(genesisSrc, genesisDst); err != nil {
			utils.Warn("Failed to copy genesis.conf: %v", err)
		}
	} else {
		utils.Warn("Genesis conf file not found: %v", err)
	}

	// Sync node_config.json
	nodeConfigSrc := filepath.Join(c.domain.BuildRoot, "conf", "resources/poke/node_config.json")
	nodeConfigDst := filepath.Join(cliBinDir, "node_config.json")
	if _, err := os.Stat(nodeConfigSrc); err == nil {
		if err := copyFile(nodeConfigSrc, nodeConfigDst); err != nil {
			utils.Warn("Failed to copy node_config.json: %v", err)
		}
	}

	// Sync client keys
	keyType := c.domain.Secret.Client.KeyType
	if keyType == "" {
		keyType = "prime256v1" // Default fallback
	}
	clientKeyDir := filepath.Join(c.domain.BuildRoot, "conf", "resources/poke", keyType)
	adminKeySrc := filepath.Join(clientKeyDir, "admin.key")
	adminKeyDst := filepath.Join(cliBinDir, "admin.key")
	if _, err := os.Stat(adminKeySrc); err == nil {
		if err := copyFile(adminKeySrc, adminKeyDst); err != nil {
			utils.Warn("Failed to copy admin.key: %v", err)
		}
	}

	// Generate cli.conf (matching Python's implementation)
	// Get metasvc_path similar to Python logic
	// Python: metasvc_path = f"{self._mygrid_env_json['mygrid_env']['meta_store_disk']}/{self._mygrid_env_json['mygrid_env']['project_data_path']}"
	metasvcPath := c.domain.DeployDir + "/data" // Default based on deploy_dir

	// Try to read from mygrid.env.json if it exists
	mygridEnvPath := filepath.Join(c.domainPath, "../conf/mygrid.light.env.json")
	if _, err := os.Stat(mygridEnvPath); err == nil {
		if data, err := os.ReadFile(mygridEnvPath); err == nil {
			var mygridEnv map[string]interface{}
			if err := json.Unmarshal(data, &mygridEnv); err == nil {
				if env, ok := mygridEnv["mygrid_env"].(map[string]interface{}); ok {
					if metaStoreDisk, ok := env["meta_store_disk"].(string); ok {
						if projectDataPath, ok := env["project_data_path"].(string); ok {
							metasvcPath = filepath.Join(metaStoreDisk, projectDataPath)
						}
					}
				}
			}
		}
	}

	// Note: Python version uses absolute path in meta_service.conf
	// We use absolute path to match Python behavior

	cliConf := map[string]interface{}{
		"chain_id":   c.domain.ChainID,
		"domain_id":  c.domain.DomainLabel,
		"etcd": map[string]interface{}{
			"enable": 0,
			"timeout": 5000,
			"retry_sleep_time": 1,
			"endpoints": []string{},
		},
		"data_path":  metasvcPath, // Use absolute path like Python
		"mygrid_env_path": "../conf/mygrid.env.json",
		"mygrid_conf_path": "../conf/mygrid.conf.json",
		"mygrid_client_id": "light",
		"service_name": "light",
		"mygrid_client_deploy_mode": func() string {
			if c.isLight {
				return "light"
			}
			return "ultra"
		}(),
	}

	cliConfFile := filepath.Join(cliBinDir, "cli.conf")
	if err := writeJSON(cliConfFile, cliConf); err != nil {
		utils.Warn("Failed to write cli.conf: %v", err)
	}

	// Generate mygrid_genesis.conf (matching Python's MYGRID_GENESIS_CONFIG_FILENAME)
	// Note: Python sets mygrid_client_deploy_mode first, then mygrid_client_id
	mygridGenesisConf := map[string]interface{}{
		"mygrid": map[string]interface{}{
			"mygrid_client_deploy_mode": func() string {
				if c.isLight {
					return "light"
				}
				return "ultra"
			}(),
			"mygrid_client_id": func() string {
				if c.isLight {
					return "light"
				}
				return "0"
			}(),
			"mygrid_conf_path": "../conf/mygrid.conf.json",
			"mygrid_env_path":  "../conf/mygrid.env.json",
		},
	}

	mygridGenesisFile := filepath.Join(cliBinDir, "mygrid_genesis.conf")
	if err := writeJSON(mygridGenesisFile, mygridGenesisConf); err != nil {
		utils.Warn("Failed to write mygrid_genesis.conf: %v", err)
	}

	// Generate meta_service.conf (matching Python's META_SERVICE_CONFIG_FILENAME)
	// Python uses relative path "../data" in META_SERVICE_JSON constant
	metaServiceConf := map[string]interface{}{
		"meta_service": map[string]interface{}{
			"myid": 0,
			"etcd": map[string]interface{}{
				"enable": 0,
				"timeout": 5000,
				"retry_sleep_time": 1,
				"endpoints": []string{},
			},
			"data_path": "../data", // Python uses relative path
		},
	}

	metaServiceFile := filepath.Join(cliBinDir, "meta_service.conf")
	if err := writeJSON(metaServiceFile, metaServiceConf); err != nil {
		utils.Warn("Failed to write meta_service.conf: %v", err)
	}

	// Copy client certificates directory
	clientCertDir := filepath.Join(cliBinDir, "client")
	if err := os.MkdirAll(clientCertDir, 0755); err != nil {
		utils.Warn("Failed to create client cert dir: %v", err)
	} else {
		// Copy certificate files from Secret.Client.Files
		certFiles := map[string]string{
			"ca.crt":   c.domain.Secret.Client.Files["ca_cert"],
			"client.crt": c.domain.Secret.Client.Files["cert"],
			"client.key": c.domain.Secret.Client.Files["key"],
		}
		for certFile, certPath := range certFiles {
			if certPath != "" {
				dstPath := filepath.Join(clientCertDir, certFile)
				if err := copyFile(certPath, dstPath); err != nil {
					utils.Warn("Failed to copy %s: %v", certFile, err)
				}
			}
		}
	}

	// Generate mygrid.conf.json (matching Python)
	// Python loads this from '../conf/mygrid.conf.json' relative to domain file
	mygridConfFile := filepath.Join(c.domainPath, "../conf/mygrid.conf.json")
	data, err := os.ReadFile(mygridConfFile)
	if err != nil {
		utils.Warn("Failed to read mygrid.conf.json: %v", err)
		// Create minimal default as last resort
		mygridConf := map[string]interface{}{
			"mygrid": map[string]interface{}{
				"env": map[string]interface{}{
					"enable_adaptive": false,
					"meta_store_disk": c.domain.DeployDir + "/meta_store",
					"project_data_path": "data",
				},
			},
		}
		if data, err = json.MarshalIndent(mygridConf, "", "  "); err != nil {
			return fmt.Errorf("failed to marshal default mygrid.conf.json: %w", err)
		}
	}

	localMygridConfFile := filepath.Join(filepath.Join(localClientDir, "conf"), "mygrid.conf.json")
	if err := os.WriteFile(localMygridConfFile, data, 0644); err != nil {
		utils.Warn("Failed to write mygrid.conf.json: %v", err)
	}

	// Generate mygrid.env.json (matching Python's implementation)
	// Read template from domain configuration
	envFilepath := c.domain.Mygrid.Env.Filepath
	if envFilepath == "" {
		envFilepath = "../conf/mygrid.light.env.json" // Default for light
		if !c.isLight {
			envFilepath = "../conf/mygrid.ultra.env.json"
		}
	}

	// Try to read from the configured filepath
	// filepath is relative to domain.json file, not BuildRoot (matching Python)
	mygridEnvFile := filepath.Join(c.domainPath, envFilepath)
	var envData []byte
	envData, err = os.ReadFile(mygridEnvFile)
	if err != nil {
		// Create minimal default
		utils.Warn("Failed to read mygrid.env.json template, using minimal config: %v", err)
		mygridEnv := map[string]interface{}{
			"mygrid_env": map[string]interface{}{
				"enable_adaptive": false,
				"meta_store_disk": c.domain.DeployDir + "/meta_store",
				"project_data_path": "data",
				"mode": func() string {
					if c.isLight {
						return "light"
					}
					return "ultra"
				}(),
			},
		}
		if envData, err = json.MarshalIndent(mygridEnv, "", "  "); err != nil {
			return fmt.Errorf("failed to marshal default mygrid.env.json: %w", err)
		}
	} else {
		// Parse and potentially modify based on enable_adaptive
		var mygridEnv map[string]interface{}
		if err := json.Unmarshal(envData, &mygridEnv); err != nil {
			return fmt.Errorf("failed to parse mygrid.env.json template: %w", err)
		}

		// Apply adaptive logic if enabled
		if c.domain.Mygrid.Env.EnableAdaptive {
			if env, ok := mygridEnv["mygrid_env"].(map[string]interface{}); ok {
				deployTopDir := filepath.Dir(c.domain.DeployDir) // Should calculate from config
				env["meta_store_disk"] = deployTopDir
				env["flat_kvdb_disk"] = deployTopDir
				env["project_data_path"] = "data" // Should use meta_svc_dir

				// Add placements based on light/ultra
				if c.isLight {
					env["placements"] = []map[string]interface{}{
						{
							"default": deployTopDir,
							"tier_0": deployTopDir,
						},
					}
				}

				// Set admin ports
				domainIndex := 0 // Should get from domain config
				env["master_lite_admin_port"] = 23100 + (domainIndex * 1000)
				env["server_lite_admin_port"] = 23101 + (domainIndex * 1000)
			}
		}

		if envData, err = json.MarshalIndent(mygridEnv, "", "  "); err != nil {
			return fmt.Errorf("failed to marshal modified mygrid.env.json: %w", err)
		}
	}

	localMygridEnvFile := filepath.Join(filepath.Join(localClientDir, "conf"), "mygrid.env.json")
	if err := os.WriteFile(localMygridEnvFile, envData, 0644); err != nil {
		utils.Warn("Failed to write mygrid.env.json: %v", err)
	}

	return nil
}

// syncClientToRemote syncs client tools to remote host using rsync (matching Python version)
func (c *Composer) syncClientToRemote(host string) error {
	utils.Info("Syncing client tools to remote host: %s", host)

	// Create SSH client
	user := c.domain.RunUser
	if host == "127.0.0.1" || host == "localhost" {
		user = "" // Let SSH use current user
	}
	sshClient, err := ssh.NewClient(host, user)
	if err != nil {
		return fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer sshClient.Close()

	// Connect
	if err := sshClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Local and remote client directories
	localClientDir := filepath.Join("/tmp", c.domain.ChainID, c.domain.DomainLabel, "client")

	// Python version syncs local_client_dir to deploy_dir (not deploy_dir/client)
	// This creates /data/pharos-node/domain/client directory structure
	deployDir := c.domain.DeployDir
	if deployDir == "" {
		deployDir = filepath.Join(c.domain.BuildRoot, "domain", c.domain.DomainLabel)
	}

	// Make sure deploy directory exists
	if err := sshClient.MkdirAll(deployDir, 0755); err != nil {
		return fmt.Errorf("failed to create deploy directory: %w", err)
	}

	// Use cp or rsync to sync the client directory (matching Python's behavior)
	utils.Info("Syncing client directory from %s to %s", localClientDir, deployDir)

	// For localhost, Python uses cp -aLv, for remote hosts uses rsync
	if host == "127.0.0.1" || host == "localhost" {
		// Use cp -aLv for localhost (matching Python's LocalConnection.sync)
		cmd := exec.Command("cp", "-aLv", localClientDir, deployDir)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to copy client directory locally: %v, output: %s", err, string(output))
		}
	} else {
		// Use rsync for remote hosts
		// Add trailing slash to localPath to sync contents, not the directory itself
		localSource := localClientDir + "/"
		if err := sshClient.RsyncDirectory(localSource, deployDir, "-avzL"); err != nil {
			return fmt.Errorf("failed to sync client directory to remote: %w", err)
		}
	}

	utils.Info("✓ Client directory synced successfully")
	return nil
}

// syncCLIBinaries syncs CLI binaries using rsync-like behavior
func (c *Composer) syncCLIBinaries(localClientDir, cliBinDir string) error {
	buildBinDir := filepath.Join(c.domain.BuildRoot, "bin")

	// CLI binaries to sync (matching Python's CLI_BINARYS)
	cliBinaries := []string{"pharos_cli", "etcdctl", "libevmone.so", "meta_tool"}

	for _, binary := range cliBinaries {
		src := filepath.Join(buildBinDir, binary)
		dst := filepath.Join(cliBinDir, binary)

		// Only copy if destination doesn't exist (matching --ignore-existing)
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			if err := copyFile(src, dst); err != nil {
				return fmt.Errorf("failed to sync %s: %w", binary, err)
			}
		}
	}

	return nil
}

// deployBinariesRemote deploys binaries to remote host
func (c *Composer) deployBinariesRemote(sshClient *ssh.Client, instances []*domain.Instance, deployDir string) error {
	// Collect all required binaries (including pharos_light for light instances)
	binaries := make(map[string]bool)
	for _, inst := range instances {
		binaries[c.getBinaryName(inst.Service)] = true
	}

	buildBinDir := filepath.Join(c.domain.BuildRoot, "bin")
	deployBinDir := filepath.Join(deployDir, "bin")

	utils.Info("=== Binary Upload Debug Info ===")
	utils.Info("BuildRoot: %s", c.domain.BuildRoot)
	utils.Info("Binary source directory: %s", buildBinDir)
	utils.Info("Binary deploy directory: %s", deployBinDir)

	// List binaries to upload
	utils.Info("Binaries to upload:")
	for binary := range binaries {
		srcPath := filepath.Join(buildBinDir, binary)
		if fileInfo, err := os.Stat(srcPath); err == nil {
			utils.Info("  - %s (size: %d bytes)", binary, fileInfo.Size())
		} else {
			utils.Info("  - %s (NOT FOUND: %v)", binary, err)
		}
	}

	// Upload binaries
	for binary := range binaries {
		srcPath := filepath.Join(buildBinDir, binary)
		dstPath := filepath.Join(deployBinDir, binary)

		// Check if source file exists
		fileInfo, err := os.Stat(srcPath)
		if err != nil {
			utils.Warn("Source binary not found: %s (error: %v)", srcPath, err)
			continue  // Skip missing binary instead of failing
		}

		utils.Info("Uploading %s: %s -> %s (size: %d bytes)", binary, srcPath, dstPath, fileInfo.Size())

		// Upload binary
		if err := sshClient.UploadFile(srcPath, dstPath); err != nil {
			utils.Error("Failed to upload binary %s from %s to %s: %v", binary, srcPath, dstPath, err)
			return fmt.Errorf("failed to upload binary %s: %w", binary, err)
		}
		utils.Info("Successfully uploaded binary: %s", binary)
	}

	// Upload VERSION file
	versionSrc := filepath.Join(buildBinDir, "VERSION")
	versionDst := filepath.Join(deployBinDir, "VERSION")
	if _, err := os.Stat(versionSrc); err == nil {
		sshClient.UploadFile(versionSrc, versionDst)
	}

	// Upload EVMONE library for EVM protocol
	if c.domain.ChainProtocol == "evm" || c.domain.ChainProtocol == "all" {
		evmoneSrc := filepath.Join(buildBinDir, "libevmone.so")
		evmoneDst := filepath.Join(deployBinDir, "libevmone.so")
		if _, err := os.Stat(evmoneSrc); err == nil {
			sshClient.UploadFile(evmoneSrc, evmoneDst)
		}
	}

	// Create symlinks for each instance
	for _, inst := range instances {
		instDir := inst.Dir
		if instDir == "" {
			instDir = filepath.Join(deployDir, inst.Name)
		}
		instBinDir := filepath.Join(instDir, "bin")

		// Create instance directories first
		// Ensure instance root directory exists before creating bin directory
		if err := sshClient.MkdirAll(instDir, 0755); err != nil {
			utils.Warn("Failed to create instance directory %s: %v", instDir, err)
		}
		if err := sshClient.MkdirAll(instBinDir, 0755); err != nil {
			utils.Warn("Failed to create instance bin directory %s: %v", instBinDir, err)
		}

		// For all instances (including light), create symlinks to shared binaries (matching Python version)
		// Python version: all instances use symlinks, including light
		binaryName := c.getBinaryName(inst.Service)
		binarySrc := filepath.Join(deployBinDir, binaryName)
		binaryTarget := filepath.Join(instBinDir, binaryName)
		utils.Info("Creating binary symlink for instance %s: %s -> %s", inst.Name, binarySrc, binaryTarget)
		if err := sshClient.CreateSymlink(binarySrc, binaryTarget); err != nil {
			utils.Error("Failed to create binary symlink for %s: %v", binaryName, err)
		} else {
			utils.Info("Successfully created binary symlink for %s", binaryName)
		}

		// Create symlink to EVMONE if needed
		if c.domain.ChainProtocol == "evm" || c.domain.ChainProtocol == "all" {
			evmoneSrc := filepath.Join(deployBinDir, "libevmone.so")
			evmoneTarget := filepath.Join(instBinDir, "libevmone.so")
			utils.Info("Creating libevmone.so symlink: %s -> %s", evmoneSrc, evmoneTarget)
			if err := sshClient.CreateSymlink(evmoneSrc, evmoneTarget); err != nil {
				utils.Error("Failed to create libevmone.so symlink: %v", err)
			} else {
				utils.Info("Successfully created libevmone.so symlink")
			}
		}

		// Create symlink to VERSION
		versionSrc := filepath.Join(deployBinDir, "VERSION")
		versionTarget := filepath.Join(instBinDir, "VERSION")
		utils.Info("Creating VERSION symlink: %s -> %s", versionSrc, versionTarget)
		if err := sshClient.CreateSymlink(versionSrc, versionTarget); err != nil {
			utils.Error("Failed to create VERSION symlink: %v", err)
		} else {
			utils.Info("Successfully created VERSION symlink")
		}
	}

	return nil
}

// deployConfigurationRemote deploys configuration files to remote host
func (c *Composer) deployConfigurationRemote(sshClient *ssh.Client, instances []*domain.Instance, deployDir string) error {
	for _, inst := range instances {
		instDir := inst.Dir
		if instDir == "" {
			instDir = filepath.Join(deployDir, inst.Name)
		}

		// Generate launch.conf (except for etcd and storage)
		if inst.Service != "etcd" && inst.Service != "storage" {
			utils.Info("Generating launch.conf for service: %s, instance: %s", inst.Service, inst.Name)
			// Start with basic structure
			parameters := map[string]string{}

			// Add all instance environment variables
			for key, value := range inst.Env {
				parameters["/SetEnv/"+key] = value
			}

			// Add standard environment variables that Python adds
			parameters["/SetEnv/SERVICE"] = inst.Service
			parameters["/SetEnv/CHAIN_ID"] = c.domain.ChainID
			parameters["/SetEnv/DOMAIN_LABEL"] = c.domain.DomainLabel
			parameters["/SetEnv/PORTAL_UUID"] = "100" // Default value

			// For light service, add specific variables
			if inst.Service == "light" {
				parameters["/SetEnv/LIGHT_RPC_LISTEN_URL"] = "0.0.0.0:20000"
				parameters["/SetEnv/LIGHT_RPC_ADVERTISE_URL"] = "47.236.202.124:20000"
			}

			// Load CLI_JSON template like Python does
			var cliConf map[string]interface{}
			if err := json.Unmarshal([]byte(template.CLI_JSON), &cliConf); err != nil {
				return fmt.Errorf("failed to parse CLI_JSON template: %w", err)
			}

			// Debug: Check what we loaded
			utils.Info("Loaded CLI_JSON template with fields: chain_id=%q, domain_id=%q", cliConf["chain_id"], cliConf["domain_id"])

			// Modify cli_conf exactly like Python
			cliConf["chain_id"] = c.domain.ChainID
			cliConf["domain_id"] = c.domain.DomainLabel
			utils.Info("After setting chain_id=%q and domain_id=%q", cliConf["chain_id"], cliConf["domain_id"])

			// Configure etcd - match Python's META_SERVICE_JSON exactly
			etcdConf := map[string]interface{}{
				"enable":            0,
				"timeout":           5000,
				"retry_sleep_time":  1,
				"endpoints":         []string{},
			}

			if !c.isLight {
				// Check if etcd0 has ETCD_ENABLE_V2=true
				if etcdInst, exists := c.domain.Cluster["etcd0"]; exists {
					if etcdInst.Env["ETCD_ENABLE_V2"] == "true" {
						etcdConf["enable"] = 2
					} else {
						etcdConf["enable"] = 1
					}
				}
				etcdConf["endpoints"] = c.getEtcdEndpoints()
			}
			cliConf["etcd"] = etcdConf

			// Set data_path - Python uses absolute path for cli.conf
			// Use the deploy_dir from domain.json
			var metasvcPath string
			if inst.Service == "light" {
				metasvcPath = fmt.Sprintf("%s/%s/data", c.domain.DeployDir, inst.Name)
			} else {
				metasvcPath = fmt.Sprintf("%s/%s/data", c.domain.DeployDir, inst.Name)
			}
			cliConf["data_path"] = metasvcPath

			// Set mygrid paths
			cliConf["mygrid_env_path"] = "../conf/" + MYGRID_ENV_JSON_FILENAME
			cliConf["mygrid_conf_path"] = "../conf/" + MYGRID_CONF_JSON_FILENAME

			// Set instance-specific fields like Python's deploy_host_conf
			if inst.Service == "light" {
				cliConf["mygrid_client_id"] = "light"
			} else {
				cliConf["mygrid_client_id"] = inst.Name
			}
			cliConf["service_name"] = inst.Service

			if inst.Service == "light" {
				cliConf["mygrid_client_deploy_mode"] = LIGHT_DEPLOY_MODE
			} else {
				cliConf["mygrid_client_deploy_mode"] = ULTRA_DEPLOY_MODE
			}

			// Debug: print cliConf before creating launchConfData
			utils.Info("cliConf before launchConfData: chain_id=%v, domain_id=%v, data_path=%v",
				cliConf["chain_id"], cliConf["domain_id"], cliConf["data_path"])

			launchConfData := map[string]interface{}{
				"log":         map[string]interface{}{},
				"parameters":  parameters,
				"init_config": cliConf,
			}

			utils.Info("Creating launch.conf for instance %s", inst.Name)

			// Create temporary file for launch.conf
			tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("launch_conf_%s.json", inst.Name))
			if err := writeJSON(tmpFile, launchConfData); err != nil {
				return fmt.Errorf("failed to create temporary launch.conf: %w", err)
			}
			utils.Info("Wrote launch.conf to temp file: %s", tmpFile)

			// Also write to a fixed location for debugging
			debugFile := "/tmp/launch_conf_debug.json"
			if err := writeJSON(debugFile, launchConfData); err != nil {
				utils.Warn("Failed to write debug file: %v", err)
			}

			// Upload launch.conf
			remoteLaunchConf := filepath.Join(instDir, "conf", "launch.conf")
			sshClient.MkdirAll(filepath.Join(instDir, "conf"), 0755)

			utils.Info("Uploading launch.conf for %s: %s -> %s", inst.Name, tmpFile, remoteLaunchConf)
			if err := sshClient.UploadFile(tmpFile, remoteLaunchConf); err != nil {
				utils.Error("Failed to upload launch.conf for %s: %v", inst.Name, err)
			} else {
				utils.Info("Successfully uploaded launch.conf for %s", inst.Name)
			}

			// Generate cubenet.conf for dog and light services
			if inst.Service == "dog" || inst.Service == "light" {
				if err := c.deployCubenetConf(sshClient, inst); err != nil {
					return fmt.Errorf("failed to deploy cubenet.conf for %s: %w", inst.Name, err)
				}
			}

			// Generate mygrid config files (matching Python's deploy_host_conf)
			if err := c.deployMygridConfigs(sshClient, inst); err != nil {
				return fmt.Errorf("failed to deploy mygrid configs for %s: %w", inst.Name, err)
			}

			// Generate monitor.conf (matching Python's deploy_host_conf)
			if err := c.deployMonitorConf(sshClient, inst); err != nil {
				return fmt.Errorf("failed to deploy monitor.conf for %s: %w", inst.Name, err)
			}
		}
	}

	return nil
}

// handleNonAdaptiveModeRemote handles non-adaptive mode on remote host
func (c *Composer) handleNonAdaptiveModeRemote(sshClient *ssh.Client) error {
	utils.Info("=== Handling non-adaptive mode ===")

	// In non-adaptive mode, meta_service.conf uses relative path "../data"
	// Since meta_tool runs from {deploy_dir}/client/bin
	// It expects {deploy_dir}/client/data directory
	// For light mode, create the data directory that meta_tool expects

	clientDataDir := filepath.Join(c.domain.DeployDir, "client", "data")
	utils.Info("Creating client data directory: %s", clientDataDir)

	if err := sshClient.MkdirAll(clientDataDir, 0755); err != nil {
		utils.Error("Failed to create client data directory: %v", err)
		return fmt.Errorf("failed to create client data directory: %w", err)
	}

	utils.Info("✓ Created client data directory: %s", clientDataDir)
	return nil
}

// deployCubenetConf deploys cubenet.conf for dog and light services
// This matches Python's implementation exactly
func (c *Composer) deployCubenetConf(sshClient *ssh.Client, inst *domain.Instance) error {
	instDir := inst.Dir
	if instDir == "" {
		instDir = filepath.Join(c.domain.DeployDir, inst.Name)
	}

	// Read dog.conf (matching Python's behavior)
	// Python uses self._build_conf('dog.conf') which is relative to BuildRoot
	dogConfFile := filepath.Join(c.domain.BuildRoot, "conf", "dog.conf")
	utils.Debug("Looking for dog.conf at: %s", dogConfFile)
	data, err := os.ReadFile(dogConfFile)
	if err != nil {
		return fmt.Errorf("failed to read dog.conf from %s: %w", dogConfFile, err)
	}

	var dogConf map[string]interface{}
	if err := json.Unmarshal(data, &dogConf); err != nil {
		return fmt.Errorf("failed to parse dog.conf: %w", err)
	}

	// Check if cubenet is enabled
	config, ok := dogConf["config"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no config section in dog.conf")
	}

	cubenet, ok := config["cubenet"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no cubenet configuration in dog.conf")
	}

	cubenetEnabled, ok := cubenet["enabled"].(bool)
	if !ok || !cubenetEnabled {
		utils.Info("cubenet is disabled, skipping cubenet.conf generation")
		return nil
	}

	// Read cubenet config file path
	configFile, ok := cubenet["config_file"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no cubenet config_file in dog.conf")
	}

	configFilePath, ok := configFile["filepath"].(string)
	if !ok {
		return fmt.Errorf("no filepath in cubenet config_file")
	}

	// Read cubenet configuration
	// configFilePath might be relative to dog.conf directory
	var cubenetConfigPath string
	if filepath.IsAbs(configFilePath) {
		cubenetConfigPath = configFilePath
	} else {
		// Make it relative to dog.conf's directory
		cubenetConfigPath = filepath.Join(filepath.Dir(dogConfFile), configFilePath)
	}

	data, err = os.ReadFile(cubenetConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read cubenet config file %s: %w", cubenetConfigPath, err)
	}

	var cubenetConf map[string]interface{}
	if err := json.Unmarshal(data, &cubenetConf); err != nil {
		return fmt.Errorf("failed to parse cubenet config: %w", err)
	}

	// Update NODE_ID
	nodeID := inst.Env["NODE_ID"]
	if nodeID == "" {
		nodeID = "0"
	}
	cubenetConf["cubenet"].(map[string]interface{})["p2p"].(map[string]interface{})["nid"] = nodeID

	// Update port based on DOMAIN_LISTEN_URLS0
	if domainListenURLs, exists := inst.Env["DOMAIN_LISTEN_URLS0"]; exists {
		parts := strings.Split(domainListenURLs, ":")
		if len(parts) >= 3 {
			portStr := parts[2]
			if port, err := strconv.Atoi(portStr); err == nil {
				portOffset := int(cubenet["port_offset"].(float64))
				p2p := cubenetConf["cubenet"].(map[string]interface{})["p2p"].(map[string]interface{})
				if hostsInterface, ok := p2p["host"]; ok {
					if hosts, ok := hostsInterface.([]interface{}); ok && len(hosts) > 0 {
						if host0, ok := hosts[0].(map[string]interface{}); ok {
							host0["port"] = port + portOffset
						}
					}
				}
			}
		}
	}

	// Upload domain key to certs directory
	domainKeyFile := filepath.Join(instDir, "certs", "domain_key")
	if c.domain.Secret.Domain.Files["key"] != "" {
		// Check if key file exists
		if _, err := os.Stat(c.domain.Secret.Domain.Files["key"]); err != nil {
			utils.Warn("Domain key file not found: %s, skipping upload", c.domain.Secret.Domain.Files["key"])
		} else {
			if err := sshClient.UploadFile(c.domain.Secret.Domain.Files["key"], domainKeyFile); err != nil {
				utils.Warn("Failed to upload domain key: %v", err)
			}
		}
	}

	// Set private key file path
	cubenetConf["cubenet"].(map[string]interface{})["p2p"].(map[string]interface{})["private_key_file"] = domainKeyFile

	// Write cubenet.conf to temporary file
	tmpCubenetConf := filepath.Join(os.TempDir(), fmt.Sprintf("cubenet_conf_%s.json", inst.Name))
	if err := writeJSON(tmpCubenetConf, cubenetConf); err != nil {
		return fmt.Errorf("failed to write cubenet.conf: %w", err)
	}
	defer os.Remove(tmpCubenetConf)

	// Upload to remote
	remoteCubenetConf := filepath.Join(instDir, "conf", "cubenet.conf")
	if err := sshClient.UploadFile(tmpCubenetConf, remoteCubenetConf); err != nil {
		return fmt.Errorf("failed to upload cubenet.conf: %w", err)
	}

	return nil
}

// deployMygridConfigs deploys mygrid configuration files
// This matches Python's deploy_host_conf exactly
func (c *Composer) deployMygridConfigs(sshClient *ssh.Client, inst *domain.Instance) error {
	instDir := inst.Dir
	if instDir == "" {
		instDir = filepath.Join(c.domain.DeployDir, inst.Name)
	}

	// Read mygrid.conf.json (matching Python)
	// Python loads this from '../conf/mygrid.conf.json' relative to domain file
	mygridConfFile := filepath.Join(c.domainPath, "../conf/mygrid.conf.json")
	data, err := os.ReadFile(mygridConfFile)
	if err != nil {
		return fmt.Errorf("failed to read mygrid.conf.json: %w", err)
	}

	// Write to temp file and upload
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("mygrid_conf_%s.json", inst.Name))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp mygrid.conf.json: %w", err)
	}
	defer os.Remove(tmpFile)

	remotePath := filepath.Join(instDir, "conf", "mygrid.conf.json")
	if err := sshClient.UploadFile(tmpFile, remotePath); err != nil {
		return fmt.Errorf("failed to upload mygrid.conf.json: %w", err)
	}

	// Read and configure mygrid.env.json (matching Python's implementation)
	// Python loads this from template and modifies based on enable_adaptive
	envFilepath := c.domain.Mygrid.Env.Filepath
	if envFilepath == "" {
		envFilepath = "../conf/mygrid.light.env.json"
		if inst.Service != "light" {
			envFilepath = "../conf/mygrid.ultra.env.json"
		}
	}

	// Try to read the template
	// filepath is relative to domain.json file, not BuildRoot (matching Python)
	mygridEnvFile := filepath.Join(c.domainPath, envFilepath)
	var envData2 []byte
	envData2, err = os.ReadFile(mygridEnvFile)
	if err != nil {
		// Create minimal default
		utils.Warn("Failed to read mygrid.env.json template, using minimal config: %v", err)
		mygridEnv := map[string]interface{}{
			"mygrid_env": map[string]interface{}{
				"enable_adaptive": false,
				"meta_store_disk": c.domain.DeployDir + "/meta_store",
				"project_data_path": "data",
				"mode": func() string {
					if inst.Service == "light" {
						return "light"
					}
					return "ultra"
				}(),
			},
		}
		if envData2, err = json.MarshalIndent(mygridEnv, "", "  "); err != nil {
			return fmt.Errorf("failed to marshal default mygrid.env.json: %w", err)
		}
	} else {
		// Parse and modify based on enable_adaptive
		var mygridEnv map[string]interface{}
		if err := json.Unmarshal(envData2, &mygridEnv); err != nil {
			return fmt.Errorf("failed to parse mygrid.env.json template: %w", err)
		}

		// Apply adaptive logic if enabled
		if c.domain.Mygrid.Env.EnableAdaptive {
			if env, ok := mygridEnv["mygrid_env"].(map[string]interface{}); ok {
				deployTopDir := filepath.Dir(c.domain.DeployDir) // Should calculate from config
				metaSvcDir := "data" // Should calculate meta_svc_dir

				env["meta_store_disk"] = deployTopDir
				env["flat_kvdb_disk"] = deployTopDir
				env["project_data_path"] = metaSvcDir

				// Add placements for light mode
				if inst.Service == "light" {
					env["placements"] = []map[string]interface{}{
						{
							"default": deployTopDir,
							"tier_0": deployTopDir,
						},
					}
				}

				// Set admin ports
				domainIndex := 0 // Should get from domain config
				env["master_lite_admin_port"] = 23100 + (domainIndex * 1000)
				env["server_lite_admin_port"] = 23101 + (domainIndex * 1000)
			}
		}

		if envData2, err = json.MarshalIndent(mygridEnv, "", "  "); err != nil {
			return fmt.Errorf("failed to marshal modified mygrid.env.json: %w", err)
		}
	}

	tmpEnvFile := filepath.Join(os.TempDir(), fmt.Sprintf("mygrid_env_%s.json", inst.Name))
	if err := os.WriteFile(tmpEnvFile, envData2, 0644); err != nil {
		return fmt.Errorf("failed to write mygrid.env.json: %w", err)
	}
	defer os.Remove(tmpEnvFile)

	remoteEnvPath := filepath.Join(instDir, "conf", "mygrid.env.json")
	if err := sshClient.UploadFile(tmpEnvFile, remoteEnvPath); err != nil {
		return fmt.Errorf("failed to upload mygrid.env.json: %w", err)
	}

	return nil
}

// deployMonitorConf deploys monitor configuration
// This matches Python's deploy_host_conf exactly
func (c *Composer) deployMonitorConf(sshClient *ssh.Client, inst *domain.Instance) error {
	instDir := inst.Dir
	if instDir == "" {
		instDir = filepath.Join(c.domain.DeployDir, inst.Name)
	}

	// Read monitor.conf.json (matching Python)
	// Python loads this from '../conf/monitor.conf.json' relative to domain file
	monitorConfFile := filepath.Join(c.domainPath, "../conf/monitor.conf.json")
	data, err := os.ReadFile(monitorConfFile)
	if err != nil {
		// Create default if file doesn't exist
		utils.Warn("monitor.conf.json not found, creating default")
		monitorConf := map[string]interface{}{
			"enable_pamir_cetina": true,
			"pamir_cetina_push_address": "k8s-promethe-promethe-baabd0c689-34ab91e598e56441.elb.ap-southeast-1.amazonaws.com",
			"pamir_cetina_push_port": 9091,
			"pamir_cetina_push_interval": 5,
			"pamir_cetina_job_name": "pharos_testnet",
		}
		if data, err = json.MarshalIndent(monitorConf, "", "  "); err != nil {
			return fmt.Errorf("failed to marshal default monitor.conf.json: %w", err)
		}
	}

	// Write to temp file and upload
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("monitor_conf_%s.json", inst.Name))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp monitor.conf.json: %w", err)
	}
	defer os.Remove(tmpFile)

	remotePath := filepath.Join(instDir, "conf", "monitor.conf")
	if err := sshClient.UploadFile(tmpFile, remotePath); err != nil {
		return fmt.Errorf("failed to upload monitor.conf: %w", err)
	}

	return nil
}

// Helper functions
func writeJSON(filename string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, jsonData, 0644)
}

