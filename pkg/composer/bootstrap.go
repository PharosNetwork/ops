package composer

import (
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

	// Match Python exactly: clean all logs and data
	// Python: self.clean(const.SERVICE_LIGHT)  # clean_meta defaults to True
	if err := c.clean(domain.ServiceLight, true); err != nil {
		return fmt.Errorf("failed to clean light instance: %w", err)
	}

	utils.Info("Starting generate genesis state")

	// Connect to light instance
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

	// 6. Initialize configuration (commented out to match Python - Python doesn't use initialize_conf)
	// if err := c.initializeConf(sshClient); err != nil {
	// 	return fmt.Errorf("failed to initialize configuration: %w", err)
	// }

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
	// Python: cd {cli_bin_dir}; LD_PRELOAD=./{EVMONE_SO} ./aldaba_cli genesis -g ../conf/genesis.conf -s {MYGRID_GENESIS_CONFIG_FILENAME}
	cmd := fmt.Sprintf("cd %s; LD_PRELOAD=./%s ./aldaba_cli genesis -g ../conf/genesis.conf -s %s",
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
	// Match Python exactly: client dir at remote is under deploy_dir
	return c.remoteClientDir
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

// copyDir copies a directory and all its contents recursively
func copyDir(src, dst string) error {
	// Get source directory info
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Create destination directory
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	// Read directory contents
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	// Copy each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectory
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy file
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
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

// extractMygridPlacements extracts placement paths from mygrid_env configuration
// Matches Python's extract_mygrid_placements function exactly
func (c *Composer) extractMygridPlacements() []string {
	placementPaths := make(map[string]bool)

	// Access storage.mygrid_env.mygrid_env from aldabaConf
	storage, ok := c.aldabaConf["storage"].(map[string]interface{})
	if !ok {
		utils.Debug("No storage config found in aldabaConf")
		return nil
	}

	mygridEnvOuter, ok := storage["mygrid_env"].(map[string]interface{})
	if !ok {
		utils.Debug("No mygrid_env config found in storage")
		return nil
	}

	mygridEnv, ok := mygridEnvOuter["mygrid_env"].(map[string]interface{})
	if !ok {
		utils.Debug("No inner mygrid_env config found")
		return nil
	}

	// Get project_data_path
	projectDataPath, _ := mygridEnv["project_data_path"].(string)
	if projectDataPath == "" {
		projectDataPath = "data"
	}

	// Get placements array
	placements, ok := mygridEnv["placements"].([]interface{})
	if !ok {
		utils.Debug("No placements found in mygrid_env")
		return nil
	}

	// Extract placement paths
	// Python: for placement in placements:
	//            for key, value in placement.items():
	//                if isinstance(value, list):
	//                    for item in value:
	//                        placement_paths.add(f"{item}/{project_data_path}")
	//                else:
	//                    placement_paths.add(f"{value}/{project_data_path}")
	for _, placement := range placements {
		placementMap, ok := placement.(map[string]interface{})
		if !ok {
			continue
		}

		for _, value := range placementMap {
			switch v := value.(type) {
			case []interface{}:
				for _, item := range v {
					if itemStr, ok := item.(string); ok {
						path := filepath.Join(itemStr, projectDataPath)
						placementPaths[path] = true
					}
				}
			case string:
				path := filepath.Join(v, projectDataPath)
				placementPaths[path] = true
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(placementPaths))
	for path := range placementPaths {
		result = append(result, path)
	}

	return result
}

// getMetasvcPath returns the metasvc_db path from mygrid_env configuration
func (c *Composer) getMetasvcPath() string {
	storage, ok := c.aldabaConf["storage"].(map[string]interface{})
	if !ok {
		return ""
	}

	mygridEnvOuter, ok := storage["mygrid_env"].(map[string]interface{})
	if !ok {
		return ""
	}

	mygridEnv, ok := mygridEnvOuter["mygrid_env"].(map[string]interface{})
	if !ok {
		return ""
	}

	metaStoreDisk, _ := mygridEnv["meta_store_disk"].(string)
	projectDataPath, _ := mygridEnv["project_data_path"].(string)

	if metaStoreDisk == "" || projectDataPath == "" {
		return ""
	}

	return filepath.Join(metaStoreDisk, projectDataPath)
}

// cleanInstance cleans a specific instance
// Matches Python's clean_instance method exactly
func (c *Composer) cleanInstance(instanceName string, sshClient *ssh.Client, cleanMeta bool) error {
	utils.Info("Cleaning %s, cleanMeta: %v", instanceName, cleanMeta)

	inst, exists := c.domain.Cluster[instanceName]
	if !exists {
		return fmt.Errorf("instance %s not found", instanceName)
	}

	deployDir := c.domain.DeployDir
	if deployDir == "" {
		deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
	}

	instDir := filepath.Join(deployDir, instanceName)

	// Extract mygrid placements from config
	// Python: mygrid_placements = extract_mygrid_placements(self._aldaba_conf.storage.mygrid_env)
	mygridPlacements := c.extractMygridPlacements()
	metasvcPath := c.getMetasvcPath()

	utils.Info("Clean placements: %v, metasvc_path: %s on host", mygridPlacements, metasvcPath)

	// Clean placements
	// Python: for placement in mygrid_placements:
	//            if clean_meta:
	//                clean_folder(conn, placement)
	//            else:
	//                clean_folder(conn, placement, 'metasvc_db')
	for _, placement := range mygridPlacements {
		if cleanMeta {
			if err := c.cleanFolder(sshClient, placement, ""); err != nil {
				utils.Warn("Failed to clean placement %s: %v", placement, err)
			}
		} else {
			if err := c.cleanFolder(sshClient, placement, "metasvc_db"); err != nil {
				utils.Warn("Failed to clean placement %s: %v", placement, err)
			}
		}
	}

	// Clean data directory if cleanMeta is true
	// Python: if clean_meta:
	//            clean_folder(conn, join(instance.dir, 'data'))
	if cleanMeta {
		dataDir := filepath.Join(instDir, "data")
		if err := c.cleanFolder(sshClient, dataDir, ""); err != nil {
			utils.Warn("Failed to clean data directory %s: %v", dataDir, err)
		}
	}

	// Always clean log directory
	// Python: clean_folder(conn, join(instance.dir, 'log'))
	logDir := filepath.Join(instDir, "log")
	if err := c.cleanFolder(sshClient, logDir, ""); err != nil {
		utils.Warn("Failed to clean log directory %s: %v", logDir, err)
	}

	// Clean specific files in bin directory
	// Python: clean_files = [
	//            join(instance.dir, 'bin/epoch.conf'),
	//            join(instance.dir, 'bin/*.log'),
	//            join(instance.dir, 'bin/*.stdout')
	//         ]
	binDir := filepath.Join(instDir, "bin")
	cleanFiles := []string{
		filepath.Join(binDir, "epoch.conf"),
		filepath.Join(binDir, "*.log"),
		filepath.Join(binDir, "*.stdout"),
	}

	for _, file := range cleanFiles {
		cmd := fmt.Sprintf("rm -f %s", file)
		if _, err := sshClient.RunCommand(cmd); err != nil {
			utils.Warn("Failed to remove file %s: %v", file, err)
		}
	}

	// NOTE: Python version does NOT delete conf/ directory - this preserves launch.conf etc.
	// This is critical for the deploy -> bootstrap -> start workflow
	_ = inst // Suppress unused warning

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

// cleanFolderMultiple removes contents of a folder, excluding multiple items
// Extension of clean_folder to handle multiple exceptions
func (c *Composer) cleanFolderMultiple(sshClient *ssh.Client, folder string, excepts ...string) error {
	if folder == "/" {
		return fmt.Errorf("attempted to clean root directory")
	}

	// Check if folder exists
	cmd := fmt.Sprintf("test -d %s", folder)
	if _, err := sshClient.RunCommand(cmd); err != nil {
		// Folder doesn't exist, nothing to clean
		return nil
	}

	utils.Info("Cleaning folder: %s (preserving: %v)", folder, excepts)

	var cleanCmd string
	if len(excepts) > 0 {
		// Build exclude patterns for find command
		var excludePatterns []string
		for _, except := range excepts {
			excludePatterns = append(excludePatterns, fmt.Sprintf("! -name %s", except))
		}
		cleanCmd = fmt.Sprintf("cd %s && find . -maxdepth 1 ! -path . %s -print0 | xargs -0 -I {} rm -rf {}",
			folder, strings.Join(excludePatterns, " "))
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

// getInstanceDir returns the instance directory path
func (c *Composer) getInstanceDir(inst *domain.Instance) string {
	deployDir := c.domain.DeployDir
	if deployDir == "" {
		deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
	}
	return fmt.Sprintf("%s/%s", deployDir, inst.Name)
}

// startInstance starts a specific instance
// Matches Python's start_instance method exactly
func (c *Composer) startInstance(inst *domain.Instance, sshClient *ssh.Client) error {
	utils.Info("Starting %s", inst.Name)

	// Check if launch.conf exists
	launchConfPath := c.getInstanceDir(inst) + "/conf/launch.conf"
	checkCmd := fmt.Sprintf("test -f %s", launchConfPath)
	if _, err := sshClient.RunCommand(checkCmd); err == nil {
		// Use launch.conf to start
		return c.startInstanceWithLaunchConf(inst, sshClient)
	}

	// Special handling for specific services
	switch inst.Service {
	case domain.ServiceETCD:
		return c.startEtcdInstance(inst, sshClient)
	case domain.ServiceStorage:
		return c.startStorageInstance(inst, sshClient)
	default:
		// For other services without launch.conf, error
		return fmt.Errorf("no launch.conf found for instance %s", inst.Name)
	}
}

// startInstanceWithLaunchConf starts an instance using launch.conf
// Matches Python's launch.conf startup logic
func (c *Composer) startInstanceWithLaunchConf(inst *domain.Instance, sshClient *ssh.Client) error {
	instDir := c.getInstanceDir(inst)
	workDir := fmt.Sprintf("%s/bin", instDir)
	binary := c.getBinaryName(inst.Service)

	// Build command matching Python exactly
	var cmdBuilder strings.Builder

	// Change to work directory and execute command
	if c.isEVMProtocol() {
		cmdBuilder.WriteString(fmt.Sprintf("cd %s; LD_PRELOAD=./%s ./%s", workDir, "libevmone.so", binary))
	} else {
		cmdBuilder.WriteString(fmt.Sprintf("cd %s; ./%s", workDir, binary))
	}

	// Add config file parameter
	cmdBuilder.WriteString(" -c ../conf/launch.conf")

	// Add service parameter for Ultra mode
	if !c.isLight {
		cmdBuilder.WriteString(fmt.Sprintf(" -s %s", inst.Service))
	}

	// Add daemon flag
	cmdBuilder.WriteString(" -d")

	cmd := cmdBuilder.String()
	utils.Info("Starting %s: %s", inst.Name, cmd)

	_, err := sshClient.RunCommand(cmd)
	return err
}

// startEtcdInstance starts an etcd instance
// Matches Python's etcd startup logic
func (c *Composer) startEtcdInstance(inst *domain.Instance, sshClient *ssh.Client) error {
	instDir := c.getInstanceDir(inst)
	workDir := fmt.Sprintf("%s/bin", instDir)
	binary := "etcd"

	var cmds []string

	// Set environment variables from instance config
	for k, v := range inst.Env {
		cmds = append(cmds, fmt.Sprintf("export %s='%s'", k, v))
	}

	// Set STORAGE_ETCD environment variable
	etcdConfig := c.buildEtcdConfig()
	etcdConfigJSON, _ := json.Marshal(etcdConfig)
	cmds = append(cmds, fmt.Sprintf("export STORAGE_ETCD='%s'", string(etcdConfigJSON)))

	// Build start command
	startCmd := fmt.Sprintf("cd %s; ./%s %s", workDir, binary, strings.Join(inst.Args, " "))
	cmds = append(cmds, startCmd)

	utils.Info("Starting etcd %s: %s", inst.Name, startCmd)

	// Wait 3 seconds after starting etcd
	cmds = append(cmds, "sleep 3")

	fullCmd := strings.Join(cmds, "; ")
	_, err := sshClient.RunCommand(fullCmd)
	return err
}

// startStorageInstance starts a storage (mygrid) instance
// Matches Python's storage startup logic
func (c *Composer) startStorageInstance(inst *domain.Instance, sshClient *ssh.Client) error {
	instDir := c.getInstanceDir(inst)
	workDir := fmt.Sprintf("%s/bin", instDir)
	binary := "mygrid_service"

	var cmds []string

	// Start master node
	masterCmd := fmt.Sprintf(
		"cd %s && ./%s --role=master --conf=../conf/%s --env=../conf/%s > master.log 2>&1 &",
		workDir, binary, "mygrid.conf.json", "mygrid.env.json",
	)
	cmds = append(cmds, masterCmd)

	// Wait 3 seconds
	cmds = append(cmds, "sleep 3")

	// Start server node
	serverID := "0"
	if c.extraStorageArgs != "" {
		// Parse server ID from extra args
		if parsed := c.parseServerID(c.extraStorageArgs); parsed != "" {
			serverID = parsed
		}
	}

	serverCmd := fmt.Sprintf(
		"cd %s && ./%s --role=server --server_id=%s --conf=../conf/%s --env=../conf/%s > server.log 2>&1 &",
		workDir, binary, serverID, "mygrid.conf.json", "mygrid.env.json",
	)
	cmds = append(cmds, serverCmd)

	// Wait 3 seconds
	cmds = append(cmds, "sleep 3")

	utils.Info("Starting storage %s", inst.Name)

	fullCmd := strings.Join(cmds, "; ")
	_, err := sshClient.RunCommand(fullCmd)
	return err
}

// isEVMProtocol checks if chain protocol is EVM or ALL
func (c *Composer) isEVMProtocol() bool {
	if c.chainProtocol == "" {
		// Default to check domain configuration
		// Note: domain.json uses lowercase "evm"
		return c.domain.ChainProtocol == "evm" || c.domain.ChainProtocol == "EVM" ||
			c.domain.ChainProtocol == "ALL" || c.domain.ChainProtocol == "all"
	}
	return c.chainProtocol == "evm" || c.chainProtocol == "EVM" ||
		c.chainProtocol == "ALL" || c.chainProtocol == "all"
}

// buildEtcdConfig builds etcd configuration
func (c *Composer) buildEtcdConfig() map[string]interface{} {
	endpoints := []string{}
	for _, inst := range c.domain.Cluster {
		if inst.Service == domain.ServiceETCD {
			endpoint := fmt.Sprintf("%s:2379", inst.IP)
			endpoints = append(endpoints, endpoint)
		}
	}

	return map[string]interface{}{
		"endpoints": endpoints,
	}
}

// parseServerID extracts server_id from extra arguments
func (c *Composer) parseServerID(extraArgs string) string {
	// Simple parsing for --server_id=X format
	parts := strings.Split(extraArgs, " ")
	for _, part := range parts {
		if strings.HasPrefix(part, "--server_id=") {
			return strings.TrimPrefix(part, "--server_id=")
		}
	}
	return ""
}

// getBinaryName returns the binary name for a service
func (c *Composer) getBinaryName(service string) string {
	binaryMap := map[string]string{
		domain.ServiceETCD:       "etcd",
		domain.ServiceStorage:    "mygrid_service",
		domain.ServicePortal:     "aldaba",
		domain.ServiceDog:        "aldaba",
		domain.ServiceTxPool:     "aldaba",
		domain.ServiceController: "aldaba",
		domain.ServiceCompute:    "aldaba",
		domain.ServiceLight:      "aldaba_light",
	}

	if binary, exists := binaryMap[service]; exists {
		return binary
	}
	return service
}

// stopServiceDocker stops all services via Docker Compose
func (c *Composer) stopServiceDocker() error {
	// Group instances by host (use all instances)
	hosts := make(map[string][]*domain.Instance)
	for _, inst := range c.domain.Cluster {
		host := inst.Host
		if host == "" {
			host = inst.IP
		}
		hosts[host] = append(hosts[host], inst)
	}

	// Sequential stop, not parallel
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

		// Stop all services on this host via Docker
		if err := c.stopHost(sshClient, "", instances); err != nil {
			return fmt.Errorf("failed to stop service on %s: %w", host, err)
		}
	}

	return nil
}

// stopService stops a service
// Matches Python's stop_service method
func (c *Composer) stopService(serviceType string) error {
	utils.Info("Stopping service %s", serviceType)

	// Group instances by host
	hosts := c.getInstances(serviceType)

	// Sequential stop, not parallel
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

		// Stop service on this host
		if err := c.stopHost(sshClient, serviceType, instances); err != nil {
			return fmt.Errorf("failed to stop service on %s: %w", host, err)
		}
	}

	return nil
}

// stopHost stops service on a specific host
// Matches Python's stop_host method exactly
func (c *Composer) stopHost(sshClient *ssh.Client, service string, instances []*domain.Instance) error {
	// Get host from the first instance
	var host string
	if len(instances) > 0 {
		host = instances[0].IP
		if host == "" {
			host = instances[0].Host
		}
	}

	// Docker mode handling
	if c.enableDocker && service == "" {
		// Stop all services via docker compose
		deployDir := c.domain.DeployDir
		if deployDir == "" {
			deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
		}
		cmd := fmt.Sprintf("cd %s; docker compose stop", deployDir)
		_, err := sshClient.RunCommand(cmd)
		return err // Don't mask errors in Docker mode
	}

	// Get host for logging (if not in Docker mode)
	if host == "" {
		host = "unknown"
	}

	utils.Info("Stopping service %s on %s", service, host)

	// Graceful stop all instances
	for _, inst := range instances {
		if err := c.gracefulStopInstance(inst, sshClient); err != nil {
			utils.Error("Failed to gracefully stop instance %s: %v", inst.Name, err)
		}
	}

	// Wait for processes to end, max 5 seconds
	timeout := 5
	for timeout > 0 {
		// Check if there are still running processes
		hasProcess, err := c.hasRunningProcess(sshClient, service, instances)
		if err != nil {
			return err
		}

		if !hasProcess {
			break // No processes, exit
		}

		timeout--
		utils.Debug("Waiting for service %s to stop on %s, %d seconds left", service, host, timeout)
		time.Sleep(1 * time.Second)
	}

	// If there are still processes, force stop
	hasProcess, err := c.hasRunningProcess(sshClient, service, instances)
	if err != nil {
		return err
	}

	if hasProcess {
		utils.Info("Force stopping service %s on %s", service, host)
		for _, inst := range instances {
			if err := c.forceStopInstance(inst, sshClient); err != nil {
				utils.Error("Failed to force stop instance %s: %v", inst.Name, err)
			}
		}
	} else {
		utils.Info("Service %s on %s stopped gracefully", service, host)
	}

	return nil
}

// gracefulStopInstance gracefully stops an instance
// Matches Python's graceful_stop_instance method exactly
func (c *Composer) gracefulStopInstance(inst *domain.Instance, sshClient *ssh.Client) error {
	if c.enableDocker {
		// Docker mode: use docker compose stop
		deployDir := c.domain.DeployDir
		if deployDir == "" {
			deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
		}
		cmd := fmt.Sprintf("cd %s; docker compose stop %s", deployDir, inst.Name)
		_, err := sshClient.RunCommand(cmd)
		return err
	}

	// Process mode: use complex pipeline like Python
	binary := c.getBinaryName(inst.Service)
	workDir := c.getInstanceDir(inst) + "/bin"

	// Build command matching Python's complex pipeline
	// Python: ps -eo pid,cmd | grep 'binary' | awk '{system("pwdx "$1" 2>&1")}' | grep -v MATCH_MATCH | sed "s#work_dir#MATCH_MATCH#g" | grep MATCH_MATCH | awk -F: '{system("kill -15 "$1" 2>&1")}'
	cmd := fmt.Sprintf(`ps -eo pid,cmd | grep '%s' | grep -v grep | awk '{system("pwdx "$1" 2>&1")}' | grep -v MATCH_MATCH | sed "s#%s#MATCH_MATCH#g" | grep MATCH_MATCH | awk -F: '{system("kill -15 "$1" 2>&1")}'`,
		binary, workDir)

	_, err := sshClient.RunCommand(cmd)
	return err
}

// forceStopInstance forcefully stops an instance
// Matches Python's stop_instance method exactly
func (c *Composer) forceStopInstance(inst *domain.Instance, sshClient *ssh.Client) error {
	// Process mode only (Docker mode doesn't need force stop)
	binary := c.getBinaryName(inst.Service)
	workDir := c.getInstanceDir(inst) + "/bin"

	// Build command matching Python's complex pipeline
	// Python: ps -eo pid,cmd | grep 'binary' | awk '{system("pwdx "$1" 2>&1")}' | grep -v MATCH_MATCH | sed "s#work_dir#MATCH_MATCH#g" | grep MATCH_MATCH | awk -F: '{system("kill -9 "$1" 2>&1")}'
	cmd := fmt.Sprintf(`ps -eo pid,cmd | grep '%s' | grep -v grep | awk '{system("pwdx "$1" 2>&1")}' | grep -v MATCH_MATCH | sed "s#%s#MATCH_MATCH#g" | grep MATCH_MATCH | awk -F: '{system("kill -9 "$1" 2>&1")}'`,
		binary, workDir)

	_, err := sshClient.RunCommand(cmd)
	return err
}

// hasRunningProcess checks if there are still running processes
func (c *Composer) hasRunningProcess(sshClient *ssh.Client, service string, instances []*domain.Instance) (bool, error) {
	// Collect all binary names
	binaries := make(map[string]bool)
	workDirs := make(map[string]string)

	for _, inst := range instances {
		binary := c.getBinaryName(inst.Service)
		binaries[binary] = true
		workDirs[binary] = c.getInstanceDir(inst) + "/bin"
	}

	// Build check command
	var grepPatterns []string
	for binary := range binaries {
		grepPatterns = append(grepPatterns, binary)
	}

	if len(grepPatterns) == 0 {
		return false, nil
	}

	cmd := fmt.Sprintf("ps -eo pid,cmd | grep -E '%s' | grep -v grep",
		strings.Join(grepPatterns, "|"))

	output, err := sshClient.RunCommand(cmd)
	if err != nil {
		return false, nil // Command failed means no processes
	}

	// Check each process's working directory
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pid := fields[0]
		cmdStr := strings.Join(fields[1:], " ")

		// Check if it's our binary
		for binary := range binaries {
			if strings.Contains(cmdStr, binary) {
				// Get working directory
				pwdCmd := fmt.Sprintf("pwdx %s 2>/dev/null", pid)
				pwdOutput, err := sshClient.RunCommand(pwdCmd)
				if err != nil {
					continue
				}

				parts := strings.Split(strings.TrimSpace(pwdOutput), ":")
				if len(parts) == 2 {
					workDir := parts[1]
					// Check if deploy_dir is contained in the working directory (substring match like Python)
					deployDir := c.domain.DeployDir
					if deployDir == "" {
						deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
					}
					if strings.Contains(workDir, deployDir) {
						return true, nil // Found matching process
					}
				}
			}
		}
	}

	return false, nil
}