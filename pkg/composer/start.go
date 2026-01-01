package composer

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/utils"
)


// Service constants
const (
	ServiceETCD       = "etcd"
	ServiceStorage    = "mygrid"
	ServiceTxPool     = "txpool"
	ServiceCompute    = "compute"
	ServiceController = "controller"
	ServiceDog        = "dog"
	ServicePortal     = "portal"
	ServiceLight      = "light"
)

// SERVICES defines the startup order - etcd must be first
var SERVICES = []string{
	ServiceETCD,
	ServiceStorage,
	ServiceTxPool,
	ServiceCompute,
	ServiceController,
	ServiceDog,
	ServicePortal,
}

// ASAN options for debugging
var TPL_ASAN_OPS = map[string]string{
	"detect_leaks":       "false",
	"leak_check_at_exit": "false",
	"disable_coredump":   "0",
	"unmap_shadow_on_exit": "1",
	"abort_on_error":     "1",
}

// File name constants
const (
	MygridConfJsonFilename    = "mygrid.conf.json"
	MygridEnvJsonFilename     = "mygrid.env.json"
	EVMOneSO                  = "libevmone.so"
)

// Start starts the services based on the Python implementation
func (c *ComposerRefactor) Start(service string, extraArgs string) error {
	utils.Info("Starting %s, service: %s", c.domain.DomainLabel, service)

	// Save extra storage args
	c.extraStorageArgs = extraArgs

	// Check if Docker mode is enabled
	if c.domain.Docker.Enable && service == "" {
		if err := c.startServiceForStart(""); err != nil {
			return err
		}
		return c.Status("")
	}

	// Light mode handling
	if c.isLight {
		if service != "" && service != ServiceLight {
			utils.Error("Light mode only has light instance")
			return fmt.Errorf("light mode only supports light service")
		}
		if err := c.startServiceForStart(ServiceLight); err != nil {
			return err
		}
	} else if service == "" {
		// Ultra mode - start all services in order
		for _, s := range SERVICES {
			if err := c.startServiceForStart(s); err != nil {
				return err
			}
		}
	} else {
		// Start specific service
		if err := c.startServiceForStart(service); err != nil {
			return err
		}
	}

	// Show status after starting (matching Python behavior)
	return c.Status(service)
}

// startService starts all instances of a specific service
func (c *ComposerRefactor) startServiceForStart(service string) error {
	utils.Info("Starting service: %s", service)

	// Get instances for this service
	instances := c.getInstances(service)

	// Start sequentially (not parallel), following Python behavior
	for host, hostInstances := range instances {
		user := c.domain.RunUser
		if c.isLocal(host) {
			user = ""
		}

		sshClient, err := ssh.NewClient(host, user)
		if err != nil {
			return fmt.Errorf("failed to clientect to host %s: %w", host, err)
		}
		defer sshClient.Close()

		if err := c.startHostForStart(sshClient, service, hostInstances); err != nil {
			return err
		}
	}

	return nil
}

// startHost starts service instances on a specific host
func (c *ComposerRefactor) startHostForStart(client *ssh.Client, service string, instances []*domain.Instance) error {
	utils.Info("Starting service %s on host %s", service, client.GetHost())

	// Docker mode handling
	if c.domain.Docker.Enable && service == "" {
		cmd := fmt.Sprintf("cd %s; docker compose start", c.domain.DeployDir)
		_, err := client.RunCommand(cmd)
		return err
	}

	// Start each instance
	for _, instance := range instances {
		if err := c.startInstanceForStart(instance, client); err != nil {
			return fmt.Errorf("failed to start instance %s: %w", instance.Name, err)
		}
	}

	return nil
}

// startInstance starts a single service instance
func (c *ComposerRefactor) startInstanceForStart(instance *domain.Instance, client *ssh.Client) error {
	utils.Info("Starting %s on %s", instance.Name, client.GetHost())

	// Prepare environment variables
	envPrefix, err := c.prepareEnvironmentVariables(instance, client)
	if err != nil {
		return fmt.Errorf("failed to prepare environment variables: %w", err)
	}

	// Docker mode
	if c.domain.Docker.Enable {
		cmd := fmt.Sprintf("cd %s; docker compose start %s", c.domain.DeployDir, instance.Name)
		_, err := client.RunCommand(cmd)
		return err
	}

	// Native mode
	workDir := filepath.Join(instance.Dir, "bin")
	binary := c.getInstanceBinary(instance)

	// Check if aldaba.conf exists
	aldabaConfPath := filepath.Join(instance.Dir, "conf", "aldaba.conf")
	exists, err := client.FileExists(aldabaConfPath)
	if err != nil {
		return fmt.Errorf("failed to check aldaba.conf: %w", err)
	}

	if exists {
		// Start with aldaba.conf
		return c.startWithConfig(instance, client, envPrefix, workDir, binary)
	}

	// Service-specific startup
	switch instance.Service {
	case ServiceETCD:
		return c.startETCD(instance, client, envPrefix, workDir, binary)
	case ServiceStorage:
		return c.startStorage(instance, client, envPrefix, workDir, binary)
	default:
		return fmt.Errorf("unknown service type: %s", instance.Service)
	}
}

// prepareEnvironmentVariables prepares environment variables based on enable_setkey_env setting
func (c *ComposerRefactor) prepareEnvironmentVariables(instance *domain.Instance, client *ssh.Client) (string, error) {
	// Prepare ASAN options
	asanOptions := make(map[string]string)
	for k, v := range TPL_ASAN_OPS {
		asanOptions[k] = v
	}
	asanOptions["log_path"] = filepath.Join(instance.Dir, "bin", "asanerr.log")

	asanOptionsStr := ""
	for k, v := range asanOptions {
		if asanOptionsStr != "" {
			asanOptionsStr += ":"
		}
		asanOptionsStr += fmt.Sprintf("%s=%s", k, v)
	}

	// Check if enable_setkey_env is enabled
	// Python: if self._domain.enable_setkey_env:
	if c.domain.EnableSetkeyEnv {
		// Auto-set environment variables
		envPrefix := fmt.Sprintf(
			"export CONSENSUS_KEY_PWD='%s'; export PORTAL_SSL_PWD='%s'; export ASAN_OPTIONS='%s';",
			c.domain.KeyPasswd,
			c.domain.PortalSslPass,
			asanOptionsStr,
		)
		utils.Info("Setting environment variables at %s", client.GetHost())
		utils.Info("Setting environment asan option0 %s", asanOptionsStr)
		return envPrefix, nil
	}

	// Manual environment variable verification
	// Python: env_vars_to_check = ['CONSENSUS_KEY_PWD', 'PORTAL_SSL_PWD']
	envVarsToCheck := []string{"CONSENSUS_KEY_PWD", "PORTAL_SSL_PWD"}

	for _, envVar := range envVarsToCheck {
		cmd := fmt.Sprintf("[ -n \"${%s}\" ]", envVar)
		_, err := client.RunCommand(cmd)
		if err != nil {
			return "", fmt.Errorf("%s environment variable not set at %s. Please set it manually", envVar, client.GetHost())
		}
		utils.Info("Environment variable %s verified at %s", envVar, client.GetHost())
	}

	envPrefix := fmt.Sprintf("export ASAN_OPTIONS='%s';", asanOptionsStr)
	utils.Info("Setting environment variables at %s", client.GetHost())
	utils.Info("Setting environment asan option1 %s", asanOptionsStr)

	return envPrefix, nil
}

// startWithConfig starts a service using aldaba.conf
func (c *ComposerRefactor) startWithConfig(instance *domain.Instance, client *ssh.Client, envPrefix, workDir, binary string) error {
	var cmd string

	if c.isLight {
		// Light mode
		if c.needsEVM() {
			cmd = fmt.Sprintf("cd %s; LD_PRELOAD=./%s ./%s -d", workDir, EVMOneSO, binary)
		} else {
			cmd = fmt.Sprintf("cd %s; ./%s -d", workDir, binary)
		}
	} else {
		// Ultra mode
		if c.needsEVM() {
			cmd = fmt.Sprintf("cd %s; LD_PRELOAD=./%s ./%s -s %s -d", workDir, EVMOneSO, binary, instance.Service)
		} else {
			cmd = fmt.Sprintf("cd %s; ./%s -s %s -d", workDir, binary, instance.Service)
		}
	}

	fullCmd := fmt.Sprintf("%s%s", envPrefix, cmd)
	_, err := client.RunCommand(fullCmd)
	return err
}

// startETCD starts an ETCD service instance
func (c *ComposerRefactor) startETCD(instance *domain.Instance, client *ssh.Client, envPrefix, workDir, binary string) error {
	var cmds []string

	// Set instance environment variables
	for k, v := range instance.Env {
		cmds = append(cmds, fmt.Sprintf("export %s='%s'", k, v))
	}

	// Add ETCD cluster information
	etcdConfig := c.cliConf["etcd"]
	etcdJSON, err := json.Marshal(etcdConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal etcd config: %w", err)
	}
	cmds = append(cmds, fmt.Sprintf("export STORAGE_ETCD='%s'", string(etcdJSON)))

	// Build startup command
	cmd := fmt.Sprintf("cd %s; ./%s %s", workDir, binary, strings.Join(instance.Args, " "))

	// Wait before starting
	time.Sleep(3 * time.Second)

	utils.Info("%s: %s", client.GetHost(), cmd)
	cmds = append(cmds, cmd)

	fullCmd := fmt.Sprintf("%s%s", envPrefix, strings.Join(cmds, ";"))
	_, err = client.RunCommand(fullCmd)
	return err
}

// startStorage starts a storage (mygrid) service instance
func (c *ComposerRefactor) startStorage(instance *domain.Instance, client *ssh.Client, envPrefix, workDir, binary string) error {
	var cmds []string

	// Master command
	masterCmd := fmt.Sprintf(
		"cd %s; ./%s --role=master --conf=../conf/%s --env=../conf/%s %s > master.log 2>&1 &",
		workDir,
		binary,
		MygridConfJsonFilename,
		MygridEnvJsonFilename,
		c.extraStorageArgs,
	)

	// Server command
	serverCmd := fmt.Sprintf(
		"cd %s; ./%s --role=server --server_id=0 --conf=../conf/%s --env=../conf/%s %s > server.log 2>&1 &",
		workDir,
		binary,
		MygridConfJsonFilename,
		MygridEnvJsonFilename,
		c.extraStorageArgs,
	)

	// Combine commands with sleep
	cmd := fmt.Sprintf("%s; sleep 3; %s", masterCmd, serverCmd)

	utils.Info("%s: %s", client.GetHost(), cmd)
	cmds = append(cmds, cmd)

	fullCmd := fmt.Sprintf("%s%s", envPrefix, strings.Join(cmds, ";"))
	_, err := client.RunCommand(fullCmd)
	if err != nil {
		return err
	}

	// Wait for service to start
	time.Sleep(3 * time.Second)
	return nil
}

