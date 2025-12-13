package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/utils"
)

type Composer struct {
	domain           *domain.Domain
	domainPath       string
	isLight          bool
	extraStorageArgs string
	enableDocker     bool
	chainProtocol    string
}

func New(domainFile string) (*Composer, error) {
	absPath, err := filepath.Abs(domainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read domain file: %w", err)
	}

	var d domain.Domain
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("failed to parse domain file: %w", err)
	}

	// Convert build_root to absolute path if relative
	if d.BuildRoot != "" && !filepath.IsAbs(d.BuildRoot) {
		// build_root is relative to the domain file's directory
		d.BuildRoot = filepath.Join(filepath.Dir(absPath), d.BuildRoot)
	}

	// Debug output
	utils.Debug("Domain file: %s", absPath)
	utils.Debug("Domain directory: %s", filepath.Dir(absPath))
	utils.Debug("BuildRoot: %s", d.BuildRoot)

	c := &Composer{
		domain:     &d,
		domainPath: filepath.Dir(absPath),
		isLight:    false,
	}

	// Set instance names (matching Python: instance.name = name)
	for name, inst := range d.Cluster {
		inst.Name = name
	}

	// Check if light mode
	if _, exists := d.Cluster[domain.ServiceLight]; exists {
		c.isLight = true
	}

	return c, nil
}

func (c *Composer) IsLight() bool {
	return c.isLight
}

func (c *Composer) Domain() *domain.Domain {
	return c.domain
}

func (c *Composer) Status(service string) error {
	// Print header matching Python version
	if service != "" {
		utils.Info("=========== %s %s==========", c.domain.DomainLabel, service)
	} else {
		utils.Info("=========== %s===========", c.domain.DomainLabel)
	}

	// Group instances by host
	hosts := c.getInstances(service)

	// Check each host
	for host, instances := range hosts {
		user := c.domain.RunUser
		if host == "127.0.0.1" || host == "localhost" {
			user = ""
		}

		sshClient, err := ssh.NewClient(host, user)
		if err != nil {
			utils.Error("Failed to create SSH client for %s: %v", host, err)
			continue
		}

		if err := sshClient.Connect(); err != nil {
			utils.Error("Failed to connect to %s: %v", host, err)
			sshClient.Close()
			continue
		}

		// Check status on this host
		if err := c.statusHost(sshClient, service, instances); err != nil {
			utils.Error("Failed to check status on %s: %v", host, err)
		}

		sshClient.Close()
	}

	return nil
}

func (c *Composer) Start(service string, extraMygridServiceArgs string) error {
	utils.Info("Starting %s, service: %s", c.domain.DomainLabel, service)

	// Save extra storage args for performance testing scenarios
	c.extraStorageArgs = extraMygridServiceArgs

	// Check Docker mode (if implemented)
	if c.enableDocker && service == "" {
		// TODO: Implement Docker mode
		// c.startService("")
		// c.status("")
		return fmt.Errorf("docker mode not yet implemented")
	}

	if c.isLight {
		// Light mode: only support light service
		if service != "" && service != domain.ServiceLight {
			utils.Error("light mode only has light instance")
			return nil
		}
		if err := c.startService(domain.ServiceLight); err != nil {
			return err
		}
	} else if service == "" {
		// Ultra mode: start all services in order
		services := []string{
			domain.ServiceETCD,
			domain.ServiceStorage,
			domain.ServiceTxPool,
			domain.ServiceCompute,
			domain.ServiceController,
			domain.ServiceDog,
			domain.ServicePortal,
		}
		for _, svc := range services {
			if err := c.startService(svc); err != nil {
				return err
			}
		}
	} else {
		// Start specified service
		if err := c.startService(service); err != nil {
			return err
		}
	}

	// Show status after starting
	return c.Status(service)
}

func (c *Composer) Stop(service string) error {
	utils.Info("Stopping %s, service: %s", c.domain.DomainLabel, service)

	// Docker mode handling
	if c.enableDocker && service == "" {
		// TODO: Implement Docker mode
		return fmt.Errorf("docker mode not yet implemented")
	}

	// Light mode handling
	if c.isLight {
		if service != "" && service != domain.ServiceLight {
			utils.Error("light mode only has light instance")
			return nil
		}
		if err := c.stopService(domain.ServiceLight); err != nil {
			return err
		}
	} else if service == "" {
		// Ultra mode: stop services in reverse order
		services := []string{
			domain.ServicePortal,
			domain.ServiceDog,
			domain.ServiceController,
			domain.ServiceCompute,
			domain.ServiceTxPool,
			domain.ServiceStorage,
			domain.ServiceETCD,
		}
		for _, svc := range services {
			if err := c.stopService(svc); err != nil {
				return err
			}
		}
	} else {
		// Stop specific service
		if err := c.stopService(service); err != nil {
			return err
		}
	}

	// Check status after stopping
	return c.Status(service)
}



func (c *Composer) getInstances(service string) map[string][]*domain.Instance {
	instances := make(map[string][]*domain.Instance)
	
	for _, inst := range c.domain.Cluster {
		if service == "" || inst.Service == service {
			host := inst.Host
			if host == "" {
				host = inst.IP
			}
			instances[host] = append(instances[host], inst)
		}
	}
	
	return instances
}

// getEtcdEndpoints returns etcd endpoints in the format expected by CLI_JSON
func (c *Composer) getEtcdEndpoints() []string {
	var endpoints []string
	for _, inst := range c.domain.Cluster {
		if inst.Service == "etcd" {
			endpoint := fmt.Sprintf("%s:2379", inst.IP)
			endpoints = append(endpoints, endpoint)
		}
	}
	return endpoints
}

// statusHost checks status of all instances on a specific host
// Matches Python's status_host method exactly
func (c *Composer) statusHost(sshClient *ssh.Client, service string, instances []*domain.Instance) error {
	// Get host from the first instance
	var host string
	if len(instances) > 0 {
		host = instances[0].IP
		if host == "" {
			host = instances[0].Host
		}
	}

	// Collect service names
	services := make(map[string]bool)
	for _, inst := range instances {
		services[inst.Service] = true
	}

	// Build grep pattern
	var serviceNames []string
	for svc := range services {
		serviceNames = append(serviceNames, svc)
	}
	pattern := strings.Join(serviceNames, "|")

	// Execute ps command
	cmd := fmt.Sprintf("ps -eo pid,user,cmd | grep -E '%s' | grep -v grep | grep -v watchdog", pattern)
	output, err := sshClient.RunCommand(cmd)
	if err != nil {
		return nil // No processes found is not an error
	}

	// Parse output
	lines := strings.Split(output, "\n")
	var results []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse: pid user cmd
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pid := fields[0]
		user := fields[1]
		cmdStr := strings.Join(fields[2:], " ")

		// Get working directory
		pwdCmd := fmt.Sprintf("pwdx %s", pid)
		pwdOutput, err := sshClient.RunCommand(pwdCmd)
		if err != nil {
			continue
		}

		// Parse working directory: pid: work_dir
		parts := strings.Split(strings.TrimSpace(pwdOutput), ":")
		if len(parts) != 2 {
			continue
		}
		workDir := parts[1]

		// Validate working directory
		deployDir := c.domain.DeployDir
		if deployDir == "" {
			deployDir = fmt.Sprintf("/data/pharos-node/%s", c.domain.DomainLabel)
		}

		if !strings.Contains(workDir, deployDir) {
			continue
		}

		// Format output: host<15 pid<8 user<12 workDir<48 cmd
		lineStr := fmt.Sprintf("%-15s %-8s %-12s %-48s %s",
			host, pid, user, workDir, cmdStr)
		results = append(results, lineStr)
	}

	// Output results
	for _, result := range results {
		fmt.Println(result)
	}

	return nil
}