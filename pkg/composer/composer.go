package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/utils"
)

type Composer struct {
	domain     *domain.Domain
	domainPath string
	isLight    bool
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
	utils.Info("Checking status for domain: %s", c.domain.DomainLabel)
	
	instances := c.getInstances(service)
	for host, insts := range instances {
		utils.Info("Host: %s", host)
		for _, inst := range insts {
			if err := c.statusInstance(inst); err != nil {
				utils.Error("Failed to check status for %s: %v", inst.Name, err)
			}
		}
	}
	return nil
}

func (c *Composer) Start(service string) error {
	utils.Info("Starting light node: %s", c.domain.DomainLabel)
	
	if service != "" && service != domain.ServiceLight {
		return fmt.Errorf("only light service is supported")
	}
	
	return c.startService(domain.ServiceLight)
}

func (c *Composer) Stop(service string) error {
	utils.Info("Stopping light node: %s", c.domain.DomainLabel)
	
	if service != "" && service != domain.ServiceLight {
		return fmt.Errorf("only light service is supported")
	}
	
	return c.stopService(domain.ServiceLight)
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

func (c *Composer) statusInstance(inst *domain.Instance) error {
	// Check if process is running
	cmd := exec.Command("pgrep", "-f", inst.Service)
	output, err := cmd.Output()
	if err != nil {
		utils.Info("  %s: STOPPED", inst.Name)
		return nil
	}
	
	if len(strings.TrimSpace(string(output))) > 0 {
		utils.Info("  %s: RUNNING", inst.Name)
	} else {
		utils.Info("  %s: STOPPED", inst.Name)
	}
	
	return nil
}

func (c *Composer) startService(service string) error {
	utils.Info("Starting service: %s", service)
	
	instances := c.getInstances(service)
	for host, insts := range instances {
		for _, inst := range insts {
			if err := c.startInstance(inst); err != nil {
				return fmt.Errorf("failed to start instance %s on %s: %w", inst.Name, host, err)
			}
		}
	}
	
	return nil
}

func (c *Composer) stopService(service string) error {
	utils.Info("Stopping service: %s", service)
	
	instances := c.getInstances(service)
	for host, insts := range instances {
		for _, inst := range insts {
			if err := c.stopInstance(inst); err != nil {
				utils.Error("Failed to stop instance %s on %s: %v", inst.Name, host, err)
			}
		}
	}
	
	return nil
}



func (c *Composer) startInstance(inst *domain.Instance) error {
	utils.Info("Starting instance: %s", inst.Name)
	
	workDir := filepath.Join(inst.Dir, "bin")
	binary := c.getBinaryName(inst.Service)
	
	// Create start command
	cmd := exec.Command(binary, "-s", inst.Service, "-d")
	
	cmd.Dir = workDir
	
	// Set environment variables
	cmd.Env = os.Environ()
	for k, v := range inst.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	
	return cmd.Start()
}

func (c *Composer) stopInstance(inst *domain.Instance) error {
	utils.Info("Stopping instance: %s", inst.Name)
	
	// Find and kill process
	cmd := exec.Command("pkill", "-f", inst.Service)
	return cmd.Run()
}



func (c *Composer) getBinaryName(service string) string {
	// Binary name mapping matching Python's BINARY_MAP
	binaryMap := map[string]string{
		"etcd":       "etcd",           // SERVICE_ETCD -> ETCD_BIN
		"storage":    "mygrid_service", // SERVICE_STORAGE -> STORAGE_BIN
		"portal":     "pharos",         // SERVICE_PORTAL -> PHAROS_BIN
		"dog":        "pharos",         // SERVICE_DOG -> PHAROS_BIN
		"txpool":     "pharos",         // SERVICE_TXPOOL -> PHAROS_BIN
		"controller": "pharos",         // SERVICE_CONTROLLER -> PHAROS_BIN
		"compute":    "pharos",         // SERVICE_COMPUTE -> PHAROS_BIN
		"light":      "pharos_light",   // SERVICE_LIGHT -> PHAROS_BIN_LIGHT
	}

	if binary, exists := binaryMap[service]; exists {
		return binary
	}

	// Fallback to service name
	return service
}