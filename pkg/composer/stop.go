package composer

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/utils"
)

// Stop stops services based on the Python implementation
func (c *ComposerRefactor) Stop(service string, force bool) error {
	utils.Info("stop %s, service: %s, force: %t", c.domain.DomainLabel, service, force)

	// Docker mode handling
	if c.domain.Docker.Enable && service == "" {
		if err := c.stopServiceInStop("", force); err != nil {
			return err
		}
		return c.Status("")
	}

	// Light mode handling
	if c.isLight {
		if service != "" && service != ServiceLight {
			utils.Error("light mode only has light instance")
			return fmt.Errorf("light mode only supports light service")
		}
		if err := c.stopServiceInStop(ServiceLight, force); err != nil {
			return err
		}
	} else {
		// Ultra mode
		if service == "" {
			// Stop all services in reverse order
			for i := len(SERVICES) - 1; i >= 0; i-- {
				if err := c.stopServiceInStop(SERVICES[i], force); err != nil {
					return err
				}
			}
		} else {
			// Stop specific service
			if err := c.stopServiceInStop(service, force); err != nil {
				return err
			}
		}
	}

	// Show status after stopping
	return c.Status(service)
}

// stopServiceForStop stops all instances of a specific service
func (c *ComposerRefactor) stopServiceInStop(service string, force bool) error {
	utils.Info("stop service %s force %t", service, force)

	// Get instances for this service
	instances := c.getInstances(service)

	// Stop sequentially (not parallel), following Python behavior
	for host, hostInstances := range instances {
		user := c.domain.RunUser
		if c.isLocal(host) {
			user = ""
		}

		sshClient, err := ssh.NewClient(host, user)
		if err != nil {
			utils.Error("Failed to connect to host %s: %v", host, err)
			continue
		}
		defer sshClient.Close()

		if err := c.stopHostInStop(sshClient, service, hostInstances, force); err != nil {
			utils.Error("Failed to stop service on host %s: %v", host, err)
		}
	}

	return nil
}

// stopHostForStop stops service instances on a specific host
func (c *ComposerRefactor) stopHostInStop(client *ssh.Client, service string, instances []*domain.Instance, force bool) error {
	// Docker mode handling
	if c.domain.Docker.Enable && service == "" {
		var cmd string
		if force {
			cmd = fmt.Sprintf("cd %s; docker compose down -f", c.domain.DeployDir)
		} else {
			cmd = fmt.Sprintf("cd %s; docker compose stop", c.domain.DeployDir)
		}
		_, err := client.RunCommand(cmd)
		return err
	}

	// Stop each instance
	for _, instance := range instances {
		if force {
			if err := c.stopInstanceForStop(instance, client); err != nil {
				utils.Debug("Failed to force stop instance %s: %v", instance.Name, err)
			}
		} else {
			if err := c.gracefulStopInstanceForStop(instance, client); err != nil {
				utils.Debug("Failed to gracefully stop instance %s: %v", instance.Name, err)
				// Try force stop if graceful fails
				if err := c.stopInstanceForStop(instance, client); err != nil {
					utils.Error("Failed to force stop instance %s after graceful failure: %v", instance.Name, err)
				}
			}
		}
	}

	return nil
}

// gracefulStopInstance gracefully stops a service instance (SIGTERM)
func (c *ComposerRefactor) gracefulStopInstanceForStop(instance *domain.Instance, client *ssh.Client) error {
	utils.Info("stop %s on %s", instance.Name, client.GetHost())

	// Docker mode
	if c.domain.Docker.Enable {
		cmd := fmt.Sprintf("cd %s; docker compose stop %s", c.domain.DeployDir, instance.Name)
		_, err := client.RunCommand(cmd)
		return err
	}

	// Native mode - send SIGTERM
	if err := c.sendSignalToInstance(instance, client, 15); err != nil {
		return err
	}

	// Wait for graceful shutdown
	return c.waitForGracefulShutdown(instance, client)
}

// stopInstance forcefully stops a service instance (SIGKILL)
func (c *ComposerRefactor) stopInstanceForStop(instance *domain.Instance, client *ssh.Client) error {
	utils.Info("stop %s on %s", instance.Name, client.GetHost())

	// Docker mode
	if c.domain.Docker.Enable {
		cmd := fmt.Sprintf("cd %s; docker compose kill %s", c.domain.DeployDir, instance.Name)
		_, err := client.RunCommand(cmd)
		return err
	}

	// Native mode - send SIGKILL
	return c.sendSignalToInstance(instance, client, 9)
}

// sendSignalToInstance sends a signal to processes matching the instance
func (c *ComposerRefactor) sendSignalToInstance(instance *domain.Instance, client *ssh.Client, signal int) error {
	// Get binary name
	binary := c.getInstanceBinary(instance)
	if binary == "" {
		return fmt.Errorf("unknown binary for service %s", instance.Service)
	}

	// Get working directory
	workDir := filepath.Join(instance.Dir, "bin")

	// Build process finding and signal sending command
	// This mirrors the Python implementation using pspid_greps
	cmd := fmt.Sprintf(
		"ps -eo pid,cmd | "+
			"grep '%s' | "+
			"grep -v grep | "+
			"awk '{system(\"pwdx \"$1\" 2>&1\")}' | "+
			"grep -v MATCH_MATCH | "+
			"sed 's#%s#MATCH_MATCH#g' | "+
			"grep MATCH_MATCH | "+
			"awk -F: '{system(\"kill -%d \"$1\" 2>&1\")}'",
		binary, workDir, signal,
	)

	_, err := client.RunCommand(cmd)
	return err
}

// waitForGracefulShutdown waits for processes to exit after SIGTERM
func (c *ComposerRefactor) waitForGracefulShutdown(instance *domain.Instance, client *ssh.Client) error {
	// Wait up to 5 seconds (matching Python implementation)
	timeout := 5 * time.Second
	interval := 1 * time.Second

	start := time.Now()
	for time.Since(start) < timeout {
		// Check if processes are still running
		running, err := c.isInstanceRunning(instance, client)
		if err != nil {
			utils.Debug("Failed to check instance status: %v", err)
			continue
		}

		if !running {
			utils.Info("%s stopped gracefully", instance.Name)
			return nil
		}

		time.Sleep(interval)
	}

	// Timeout reached
	utils.Warn("%s did not stop gracefully within %v, forcing...", instance.Name, timeout)
	return c.stopInstanceForStop(instance, client)
}

// isInstanceRunning checks if an instance has running processes
func (c *ComposerRefactor) isInstanceRunning(instance *domain.Instance, client *ssh.Client) (bool, error) {
	// Get binary name
	binary := c.getInstanceBinary(instance)
	if binary == "" {
		return false, fmt.Errorf("unknown binary for service %s", instance.Service)
	}

	// Get working directory
	workDir := filepath.Join(instance.Dir, "bin")

	// Build command to count matching processes
	cmd := fmt.Sprintf(
		"ps -eo pid,cmd | "+
			"grep '%s' | "+
			"grep -v grep | "+
			"awk '{system(\"pwdx \"$1\" 2>&1\")}' | "+
			"grep -v MATCH_MATCH | "+
			"sed 's#%s#MATCH_MATCH#g' | "+
			"grep MATCH_MATCH | "+
			"wc -l",
		binary, workDir,
	)

	result, err := client.RunCommand(cmd)
	if err != nil {
		return false, err
	}

	// Parse count
	count := strings.TrimSpace(result)
	if count == "0" {
		return false, nil
	}

	return true, nil
}