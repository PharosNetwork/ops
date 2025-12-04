package composer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/utils"
)

// Deploy handles the deployment of services
func (c *Composer) Deploy(service string, deployAll bool) error {
	utils.Info("Starting deployment for domain: %s", c.domain.DomainLabel)

	// Parse service parameter
	services := c.parseService(service)

	// Clean existing data and logs first
	utils.Info("Cleaning existing data and logs...")
	for _, svc := range services {
		if err := c.clean(svc, true); err != nil {
			return fmt.Errorf("failed to clean service %s: %w", svc, err)
		}
	}

	// Group instances by host
	instancesByHost := c.getInstancesByHost(services)

	// Deploy to each host
	for host, instances := range instancesByHost {
		utils.Info("Deploying to host: %s", host)

		if host == "127.0.0.1" || host == "localhost" {
			// Local deployment
			if err := c.deployLocal(instances); err != nil {
				return fmt.Errorf("failed to deploy locally: %w", err)
			}
		} else {
			// Remote deployment
			if err := c.deployRemote(host, instances); err != nil {
				return fmt.Errorf("failed to deploy to %s: %w", host, err)
			}
		}
	}

	// Deploy local CLI tools if needed
	if deployAll || len(services) == 0 {
		if err := c.deployLocalCLI(); err != nil {
			return fmt.Errorf("failed to deploy local CLI: %w", err)
		}
	}

	utils.Info("Deployment completed successfully")
	return nil
}

// parseService determines which services to deploy based on the service parameter
func (c *Composer) parseService(service string) []string {
	if service == "all" || service == "svc" {
		// Return all services
		var services []string
		for name := range c.domain.Cluster {
			services = append(services, name)
		}
		return services
	}

	if service != "" {
		return []string{service}
	}

	// Default: deploy all configured services
	var services []string
	for name := range c.domain.Cluster {
		services = append(services, name)
	}
	return services
}

// getInstancesByHost groups instances by host for the given services
func (c *Composer) getInstancesByHost(services []string) map[string][]domain.Instance {
	instancesByHost := make(map[string][]domain.Instance)

	for name, inst := range c.domain.Cluster {
		// Check if this instance's service is in our target services
		for _, svc := range services {
			if inst.Service == svc {
				// Set the name if it's empty (Python version doesn't include name in the struct)
				if inst.Name == "" {
					inst.Name = name
				}

				// Set default dir if empty
				if inst.Dir == "" && c.domain.DeployDir != "" {
					inst.Dir = filepath.Join(c.domain.DeployDir, inst.Name)
				}

				host := inst.Host
				if host == "" {
					host = inst.IP
				}
				if host == "" {
					host = "127.0.0.1"
				}
				instancesByHost[host] = append(instancesByHost[host], inst)
				break
			}
		}
	}

	return instancesByHost
}

// deployLocal handles local deployment
func (c *Composer) deployLocal(instances []domain.Instance) error {
	for _, inst := range instances {
		if err := c.deployInstanceLocal(inst); err != nil {
			return fmt.Errorf("failed to deploy instance %s locally: %w", inst.Name, err)
		}
	}
	return nil
}

// deployRemote handles remote deployment via SSH
func (c *Composer) deployRemote(host string, instances []domain.Instance) error {
	// Create SSH command wrapper with timeout
	sshCmd := func(command string) error {
		utils.Debug("Executing SSH command: %s", command)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "ssh",
			"-o", "ConnectTimeout=10",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", c.domain.RunUser, host), command)

		output, err := cmd.CombinedOutput()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("SSH command timed out after 30 seconds")
			}
			if len(output) > 0 {
				return fmt.Errorf("SSH command failed: %v, output: %s", err, string(output))
			}
			return fmt.Errorf("SSH command failed: %w", err)
		}
		return nil
	}

	// Test SSH connection first
	if err := sshCmd("echo 'Connection test'"); err != nil {
		utils.Error("Cannot connect to %s via SSH: %v", host, err)
		utils.Error("Please ensure:")
		utils.Error("1. SSH service is running on the remote host")
		utils.Error("2. You can SSH manually using: ssh %s@%s", c.domain.RunUser, host)
		utils.Error("3. SSH key authentication is properly configured")
		return fmt.Errorf("SSH connection to %s failed: %w", host, err)
	}

	// Create workspace directory
	workspace := c.domain.DeployDir
	if err := sshCmd(fmt.Sprintf("mkdir -p %s", workspace)); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	// Deploy binaries
	if err := c.deployBinariesRemote(host, instances); err != nil {
		return fmt.Errorf("failed to deploy binaries: %w", err)
	}

	// Deploy configurations
	if err := c.deployConfigsRemote(host, instances); err != nil {
		return fmt.Errorf("failed to deploy configs: %w", err)
	}

	return nil
}

// deployInstanceLocal deploys a single instance locally
func (c *Composer) deployInstanceLocal(inst domain.Instance) error {
	utils.Info("Deploying instance locally: %s", inst.Name)

	// Validate instance directory
	if inst.Dir == "" {
		return fmt.Errorf("instance directory is empty for %s", inst.Name)
	}

	// Create directories
	dirs := []string{
		inst.Dir,
		filepath.Join(inst.Dir, "bin"),
		filepath.Join(inst.Dir, "conf"),
		filepath.Join(inst.Dir, "data"),
		filepath.Join(inst.Dir, "logs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Deploy binary - check multiple possible locations
	binaryName := c.getBinaryName(inst.Service)
	var binaryPath string
	var searchPaths []string

	// Build list of search paths
	if c.domain.BuildRoot != "" {
		searchPaths = append(searchPaths, filepath.Join(c.domain.BuildRoot, "bin", binaryName))
	}

	// Common relative paths
	searchPaths = append(searchPaths,
		filepath.Join("bin", binaryName),
		filepath.Join("..", "bin", binaryName),
		filepath.Join("../bin", binaryName),
		filepath.Join("../../bin", binaryName),
	)

	// Try all paths
	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			binaryPath = path
			utils.Debug("Found binary at: %s", binaryPath)
			break
		}
	}

	// If still not found, try alternative binary names
	if binaryPath == "" && binaryName == "pharos" {
		alternativeNames := []string{"aldaba", "pharos_node", "pharos-service"}
		for _, altName := range alternativeNames {
			for _, path := range searchPaths {
				testPath := filepath.Join(filepath.Dir(path), altName)
				if _, err := os.Stat(testPath); err == nil {
					binaryPath = testPath
					utils.Debug("Found alternative binary at: %s", binaryPath)
					break
				}
			}
			if binaryPath != "" {
				break
			}
		}
	}

	if binaryPath != "" {
		destPath := filepath.Join(inst.Dir, "bin", binaryName)
		if err := copyFile(binaryPath, destPath); err != nil {
			utils.Warn("Failed to copy binary %s: %v", binaryName, err)
		} else {
			// Make binary executable
			if err := os.Chmod(destPath, 0755); err != nil {
				utils.Warn("Failed to make binary executable: %v", err)
			} else {
				utils.Info("Deployed binary: %s -> %s", binaryPath, destPath)
			}
		}
	} else {
		utils.Warn("Binary %s not found, skipping binary deployment", binaryName)
	}

	// Deploy configuration files
	if err := c.deployConfigLocal(inst); err != nil {
		utils.Warn("Failed to deploy config: %v", err)
	}

	// Deploy libraries (EVM support)
	if c.domain.ChainProtocol == "evm" || c.domain.ChainProtocol == "all" {
		if err := c.deployLibrariesLocal(inst); err != nil {
			utils.Warn("Failed to deploy libraries: %v", err)
		}
	}

	// Deploy client tools and CLI binaries
	if err := c.deployClientToolsLocal(inst); err != nil {
		utils.Warn("Failed to deploy client tools: %v", err)
	}

	return nil
}

// deployBinariesRemote deploys binaries to remote host
func (c *Composer) deployBinariesRemote(host string, instances []domain.Instance) error {
	// Group binaries by type to avoid duplicate transfers
	binaries := make(map[string]bool)
	for _, inst := range instances {
		binaries[c.getBinaryName(inst.Service)] = true
	}

	// Copy each binary
	for binary := range binaries {
		srcPath := filepath.Join(c.domain.BuildRoot, "bin", binary)
		destDir := filepath.Join(c.domain.DeployDir, "bin")

		// Use scp to copy binary
		cmd := exec.Command("scp", srcPath, fmt.Sprintf("%s@%s:%s", c.domain.RunUser, host, destDir))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to copy binary %s: %w", binary, err)
		}

		// Make binary executable on remote host
		sshCmd := exec.Command("ssh", fmt.Sprintf("%s@%s", c.domain.RunUser, host),
			fmt.Sprintf("chmod +x %s/%s", destDir, binary))
		if err := sshCmd.Run(); err != nil {
			return fmt.Errorf("failed to make binary executable: %w", err)
		}
	}

	// Create symlinks for each instance
	for _, inst := range instances {
		binaryPath := filepath.Join(c.domain.DeployDir, "bin", c.getBinaryName(inst.Service))
		targetPath := filepath.Join(inst.Dir, "bin")

		sshCmd := exec.Command("ssh", fmt.Sprintf("%s@%s", c.domain.RunUser, host),
			fmt.Sprintf("ln -sf %s %s", binaryPath, targetPath))
		if err := sshCmd.Run(); err != nil {
			utils.Warn("Failed to create symlink for %s: %v", inst.Name, err)
		}
	}

	return nil
}

// deployConfigsRemote deploys configuration files to remote host
func (c *Composer) deployConfigsRemote(host string, instances []domain.Instance) error {
	for _, inst := range instances {
		// Create instance directories
		dirs := []string{
			inst.Dir,
			filepath.Join(inst.Dir, "conf"),
			filepath.Join(inst.Dir, "data"),
			filepath.Join(inst.Dir, "logs"),
		}

		for _, dir := range dirs {
			cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", c.domain.RunUser, host),
				fmt.Sprintf("mkdir -p %s", dir))
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}

		// Deploy launch configuration
		if err := c.deployLaunchConfigRemote(host, inst); err != nil {
			return fmt.Errorf("failed to deploy launch config: %w", err)
		}
	}

	return nil
}

// deployConfigLocal deploys configuration for a local instance
func (c *Composer) deployConfigLocal(inst domain.Instance) error {
	// Generate launch configuration
	launchConfig := c.generateLaunchConfig(inst)
	configPath := filepath.Join(inst.Dir, "conf", "launch.conf")

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(launchConfig); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// deployLaunchConfigRemote deploys launch configuration to remote host
func (c *Composer) deployLaunchConfigRemote(host string, inst domain.Instance) error {
	launchConfig := c.generateLaunchConfig(inst)

	// Create temporary file locally
	tmpFile, err := os.CreateTemp("", "launch-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(launchConfig); err != nil {
		return fmt.Errorf("failed to write config to temp file: %w", err)
	}
	tmpFile.Close()

	// Copy to remote host
	remotePath := filepath.Join(inst.Dir, "conf", "launch.conf")
	cmd := exec.Command("scp", tmpFile.Name(), fmt.Sprintf("%s@%s:%s", c.domain.RunUser, host, remotePath))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy config to remote: %w", err)
	}

	return nil
}

// deployLibrariesLocal deploys required libraries locally
func (c *Composer) deployLibrariesLocal(inst domain.Instance) error {
	// Deploy EVM library if needed
	if c.domain.ChainProtocol == "evm" || c.domain.ChainProtocol == "all" {
		evmLib := filepath.Join(c.domain.BuildRoot, "bin", "libevmone.so")
		if _, err := os.Stat(evmLib); err == nil {
			destPath := filepath.Join(inst.Dir, "bin", "libevmone.so")
			if err := copyFile(evmLib, destPath); err != nil {
				return fmt.Errorf("failed to copy EVM library: %w", err)
			}
		}
	}

	// Deploy client tools
	clientTools := []string{"pharos_cli"}
	for _, tool := range clientTools {
		srcPath := filepath.Join(c.domain.BuildRoot, "bin", tool)
		if _, err := os.Stat(srcPath); err == nil {
			destPath := filepath.Join(inst.Dir, "bin", tool)
			if err := copyFile(srcPath, destPath); err != nil {
				return fmt.Errorf("failed to copy %s: %w", tool, err)
			}
			if err := os.Chmod(destPath, 0755); err != nil {
				return fmt.Errorf("failed to make %s executable: %w", tool, err)
			}
		}
	}

	return nil
}

// deployLocalCLI deploys CLI tools locally
func (c *Composer) deployLocalCLI() error {
	utils.Info("Deploying pharos client at localhost")

	// Create local client directory structure
	localClientDir := filepath.Join(c.domainPath, "bin")
	clientBinDir := filepath.Join(localClientDir, "bin")
	clientConfDir := filepath.Join(localClientDir, "conf")

	// Create directories
	for _, dir := range []string{localClientDir, clientBinDir, clientConfDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// List of CLI binaries to deploy (matching Python version)
	cliBinaries := []string{
		"pharos_cli",
		"etcdctl",
		"meta_tool",
	}

	// Deploy CLI binaries
	for _, binary := range cliBinaries {
		var srcPath string

		// Search for binary
		searchPaths := []string{
			filepath.Join(c.domain.BuildRoot, "bin", binary),
			filepath.Join("bin", binary),
			filepath.Join("../bin", binary),
			filepath.Join("../../bin", binary),
		}

		for _, path := range searchPaths {
			if _, err := os.Stat(path); err == nil {
				srcPath = path
				break
			}
		}

		if srcPath != "" {
			// Copy to both local bin and client bin
			destPaths := []string{
				filepath.Join(localClientDir, binary),
				filepath.Join(clientBinDir, binary),
			}

			for _, dest := range destPaths {
				if err := copyFile(srcPath, dest); err != nil {
					utils.Warn("Failed to copy %s to %s: %v", binary, dest, err)
				} else {
					if err := os.Chmod(dest, 0755); err == nil {
						utils.Info("Deployed %s -> %s", binary, dest)
					}
				}
			}
		} else {
			utils.Warn("CLI binary %s not found", binary)
		}
	}

	// Deploy libraries
	libraries := []string{"libevmone.so", "VERSION"}
	for _, lib := range libraries {
		var srcPath string

		searchPaths := []string{
			filepath.Join(c.domain.BuildRoot, "bin", lib),
			filepath.Join("bin", lib),
			filepath.Join("../bin", lib),
			filepath.Join("../../bin", lib),
		}

		for _, path := range searchPaths {
			if _, err := os.Stat(path); err == nil {
				srcPath = path
				break
			}
		}

		if srcPath != "" {
			dest := filepath.Join(clientBinDir, lib)
			if err := copyFile(srcPath, dest); err != nil {
				utils.Warn("Failed to copy library %s: %v", lib, err)
			}
		}
	}

	// Copy genesis configuration if exists
	if c.domain.GenesisConf != "" {
		if _, err := os.Stat(c.domain.GenesisConf); err == nil {
			dest := filepath.Join(clientConfDir, "genesis.conf")
			if err := copyFile(c.domain.GenesisConf, dest); err != nil {
				utils.Warn("Failed to copy genesis.conf: %v", err)
			}
		}
	}

	utils.Info("CLI tools deployed to %s", localClientDir)
	return nil
}

// deployClientToolsLocal deploys client tools to instance directory
func (c *Composer) deployClientToolsLocal(inst domain.Instance) error {
	// List of CLI tools that need to be deployed (matching Python version)
	cliTools := []string{
		"pharos_cli",    // PHAROS_CLI
		"etcdctl",       // ETCD_CTL_BIN
		"meta_tool",     // SVC_META_TOOL
	}

	// List of libraries
	libraries := []string{
		"libevmone.so",  // EVMONE_SO
		"VERSION",       // PHAROS_VERSION
	}

	// Deploy CLI tools
	for _, tool := range cliTools {
		if err := c.deployBinaryToLocal(inst, tool); err != nil {
			utils.Warn("Failed to deploy CLI tool %s: %v", tool, err)
		}
	}

	// Deploy libraries
	for _, lib := range libraries {
		if err := c.deployBinaryToLocal(inst, lib); err != nil {
			utils.Warn("Failed to deploy library %s: %v", lib, err)
		}
	}

	return nil
}

// deployBinaryToLocal deploys a binary or library to local instance
func (c *Composer) deployBinaryToLocal(inst domain.Instance, binaryName string) error {
	var srcPath string

	// Try multiple locations to find the binary
	searchPaths := []string{}

	if c.domain.BuildRoot != "" {
		searchPaths = append(searchPaths, filepath.Join(c.domain.BuildRoot, "bin", binaryName))
	}

	searchPaths = append(searchPaths,
		filepath.Join("bin", binaryName),
		filepath.Join("../bin", binaryName),
		filepath.Join("../../bin", binaryName),
	)

	// Try all paths
	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			srcPath = path
			break
		}
	}

	if srcPath == "" {
		return fmt.Errorf("binary %s not found in search paths", binaryName)
	}

	destPath := filepath.Join(inst.Dir, "bin", binaryName)

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Copy file
	if err := copyFile(srcPath, destPath); err != nil {
		return fmt.Errorf("failed to copy %s: %w", binaryName, err)
	}

	// Make executable if it's a binary (not a library or version file)
	if !strings.Contains(binaryName, ".so") && binaryName != "VERSION" {
		if err := os.Chmod(destPath, 0755); err != nil {
			return fmt.Errorf("failed to make %s executable: %w", binaryName, err)
		}
	}

	utils.Info("Deployed %s: %s -> %s", binaryName, srcPath, destPath)
	return nil
}

// generateLaunchConfig generates the launch configuration for an instance
func (c *Composer) generateLaunchConfig(inst domain.Instance) string {
	var config strings.Builder

	// Basic configuration
	config.WriteString(fmt.Sprintf("# Pharos Launch Configuration for %s\n", inst.Name))
	config.WriteString(fmt.Sprintf("service = %q\n", inst.Service))
	config.WriteString(fmt.Sprintf("chain_id = %q\n", c.domain.ChainID))
	config.WriteString(fmt.Sprintf("domain_label = %q\n", c.domain.DomainLabel))
	config.WriteString(fmt.Sprintf("deploy_dir = %q\n", c.domain.DeployDir))
	config.WriteString("\n")

	// Network configuration
	if inst.Config != nil {
		if endpoint, ok := inst.Config["endpoint"].(string); ok && endpoint != "" {
			config.WriteString(fmt.Sprintf("endpoint = %q\n", endpoint))
		}
	}

	if p2pConfig, ok := inst.Config["p2p"].(map[string]interface{}); ok {
		if host, ok := p2pConfig["host"].(string); ok && host != "" {
			config.WriteString(fmt.Sprintf("p2p_host = %q\n", host))
		}
		if port, ok := p2pConfig["port"].(float64); ok {
			config.WriteString(fmt.Sprintf("p2p_port = %d\n", int(port)))
		}
	}

	// Add gflags
	if inst.GFlags != nil {
		config.WriteString("\n[gflags]\n")
		for key, value := range inst.GFlags {
			config.WriteString(fmt.Sprintf("%s = %q\n", key, value))
		}
	}

	// Add logging configuration
	if inst.Log != nil {
		config.WriteString("\n[log]\n")
		if level, ok := inst.Log["level"].(string); ok {
			config.WriteString(fmt.Sprintf("level = %q\n", level))
		}
		if dir, ok := inst.Log["dir"].(string); ok {
			config.WriteString(fmt.Sprintf("dir = %q\n", dir))
		}
	}

	return config.String()
}

// clean removes data, logs, and metadata for services
func (c *Composer) clean(service string, cleanMeta bool) error {
	instances := c.getInstances(service)

	for host, insts := range instances {
		if host == "127.0.0.1" || host == "localhost" {
			// Local clean
			for _, inst := range insts {
				if err := c.cleanLocal(inst, cleanMeta); err != nil {
					return fmt.Errorf("failed to clean %s locally: %w", inst.Name, err)
				}
			}
		} else {
			// Remote clean
			if err := c.cleanRemote(host, insts, cleanMeta); err != nil {
				return fmt.Errorf("failed to clean on %s: %w", host, err)
			}
		}
	}

	return nil
}

// cleanLocal cleans up local instance data
func (c *Composer) cleanLocal(inst domain.Instance, cleanMeta bool) error {
	utils.Info("Cleaning instance: %s", inst.Name)

	// Clean data directory
	dataDir := filepath.Join(inst.Dir, "data")
	if _, err := os.Stat(dataDir); err == nil {
		if err := os.RemoveAll(dataDir); err != nil {
			return fmt.Errorf("failed to remove data directory: %w", err)
		}
	}

	// Clean log directory
	logDir := filepath.Join(inst.Dir, "logs")
	if _, err := os.Stat(logDir); err == nil {
		if err := os.RemoveAll(logDir); err != nil {
			return fmt.Errorf("failed to remove log directory: %w", err)
		}
	}

	// Clean metadata if requested
	if cleanMeta {
		metaDir := filepath.Join(inst.Dir, "meta")
		if _, err := os.Stat(metaDir); err == nil {
			if err := os.RemoveAll(metaDir); err != nil {
				return fmt.Errorf("failed to remove meta directory: %w", err)
			}
		}
	}

	return nil
}

// cleanRemote cleans up remote instance data
func (c *Composer) cleanRemote(host string, instances []domain.Instance, cleanMeta bool) error {
	for _, inst := range instances {
		// Create a context with timeout for SSH commands
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Remove data directory
		cmd := exec.CommandContext(ctx, "ssh",
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", c.domain.RunUser, host),
			fmt.Sprintf("rm -rf %s/data", inst.Dir))

		if err := cmd.Run(); err != nil {
			utils.Warn("Failed to remove remote data directory: %v", err)
		}

		// Remove log directory
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		cmd = exec.CommandContext(ctx, "ssh",
			"-o", "ConnectTimeout=5",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("%s@%s", c.domain.RunUser, host),
			fmt.Sprintf("rm -rf %s/logs", inst.Dir))
		cancel()

		if err := cmd.Run(); err != nil {
			utils.Warn("Failed to remove remote log directory: %v", err)
		}

		// Remove metadata if requested
		if cleanMeta {
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			cmd = exec.CommandContext(ctx, "ssh",
				"-o", "ConnectTimeout=5",
				"-o", "BatchMode=yes",
				"-o", "StrictHostKeyChecking=no",
				fmt.Sprintf("%s@%s", c.domain.RunUser, host),
				fmt.Sprintf("rm -rf %s/meta", inst.Dir))
			cancel()

			if err := cmd.Run(); err != nil {
				utils.Warn("Failed to remove remote meta directory: %v", err)
			}
		}
	}

	return nil
}


