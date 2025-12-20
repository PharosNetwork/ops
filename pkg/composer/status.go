package composer

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"pharos-ops/pkg/domain"
	"pharos-ops/pkg/ssh"
	"pharos-ops/pkg/utils"
)

// Status displays the status of services based on the Python implementation
func (c *ComposerRefactor) Status(service string) error {
	// Print domain header
	if service != "" {
		utils.Info("===========%s %s==========", c.domain.DomainLabel, service)
	} else {
		utils.Info("===========%s===========", c.domain.DomainLabel)
	}

	// Get instances grouped by host
	instances := c.getInstances(service)

	// Query each host's status
	for host := range instances {
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

		if err := c.statusHost(sshClient, service, instances[host]); err != nil {
			utils.Error("Failed to get status from host %s: %v", host, err)
		}
	}

	return nil
}

// statusHost queries service status on a specific host
func (c *ComposerRefactor) statusHost(client *ssh.Client, service string, instances []*domain.Instance) error {
	// Docker mode handling
	if c.domain.Docker.Enable {
		return c.showDockerStatus(client, service, instances)
	}

	// Native mode: query process status
	return c.showProcessStatus(client, service, instances)
}

// showDockerStatus displays Docker container status
func (c *ComposerRefactor) showDockerStatus(client *ssh.Client, service string, instances []*domain.Instance) error {
	utils.Info("%s", client.GetHost())

	if service != "" && len(instances) > 0 {
		// Show specific service containers
		for _, instance := range instances {
			cmd := fmt.Sprintf("cd %s; docker compose ps -a | grep %s", c.domain.DeployDir, instance.Name)
			result, err := client.RunCommand(cmd)
			if err != nil {
				utils.Debug("Failed to query container %s: %v", instance.Name, err)
				continue
			}
			if result != "" {
				utils.Info("%s", result)
			}
		}
	} else {
		// Show all containers
		cmd := fmt.Sprintf("cd %s; docker compose ps -a", c.domain.DeployDir)
		result, err := client.RunCommand(cmd)
		if err != nil {
			utils.Debug("Failed to query containers: %v", err)
			return nil
		}
		if result != "" {
			utils.Info("%s", result)
		}
	}

	return nil
}

// showProcessStatus displays native process status
func (c *ComposerRefactor) showProcessStatus(client *ssh.Client, service string, instances []*domain.Instance) error {
	// Collect service types for this host
	services := make(map[string]bool)
	for _, instance := range instances {
		services[instance.Service] = true
	}

	if len(services) == 0 {
		utils.Info("%s", client.GetHost())
		utils.Info("No services configured on %s", client.GetHost())
		return nil
	}

	// Build grep pattern from service names
	var servicePatterns []string
	for svc := range services {
		servicePatterns = append(servicePatterns, svc)
	}
	pattern := strings.Join(servicePatterns, "|")

	// Build and execute ps command
	cmd := fmt.Sprintf(
		"ps -eo pid,user,cmd | grep -E '%s' | grep -v grep | grep -v watchdog",
		pattern,
	)

	result, err := client.RunCommand(cmd)
	if err != nil {
		utils.Debug("Failed to query processes on %s: %v", client.GetHost(), err)
		return nil
	}

	// Parse and format output
	var processes []ProcessInfo
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		processInfo := c.parseProcessLine(line, client)
		if processInfo != nil && processInfo.isValid(c.domain.DeployDir) {
			processes = append(processes, *processInfo)
		}
	}

	// Display results
	if len(processes) > 0 {
		c.printStatusHeader(client.GetHost())
		for _, proc := range processes {
			c.printStatusLine(proc)
		}
	} else {
		utils.Info("No running services found on %s", client.GetHost())
	}

	return nil
}

// ProcessInfo holds parsed process information
type ProcessInfo struct {
	PID     string
	User    string
	Cmd     string
	WorkDir string
	Host    string
}

// parseProcessLine parses a single line of ps output
func (c *ComposerRefactor) parseProcessLine(line string, client *ssh.Client) *ProcessInfo {
	// Split into max 3 parts: PID, user, and command
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return nil
	}

	// Clean up parts
	pid := strings.TrimSpace(parts[0])
	user := strings.TrimSpace(parts[1])
	cmd := strings.TrimSpace(parts[2])

	// Get process working directory
	workDir := c.getProcessWorkDir(client, pid)
	if workDir == "" {
		return nil
	}

	return &ProcessInfo{
		PID:     pid,
		User:    user,
		Cmd:     cmd,
		WorkDir: workDir,
		Host:    client.GetHost(),
	}
}

// getProcessWorkDir gets the working directory of a process using pwdx
func (c *ComposerRefactor) getProcessWorkDir(client *ssh.Client, pid string) string {
	cmd := fmt.Sprintf("pwdx %s", pid)
	result, err := client.RunCommand(cmd)
	if err != nil {
		utils.Debug("Failed to get workdir for pid %s: %v", pid, err)
		return ""
	}

	// Parse output: "pid: /path/to/workdir"
	parts := strings.Split(result, ":")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}

	return ""
}

// isValid checks if the process belongs to the deployment directory
func (p *ProcessInfo) isValid(deployDir string) bool {
	return strings.Contains(p.WorkDir, deployDir)
}

// printStatusHeader prints the status table header
func (c *ComposerRefactor) printStatusHeader(host string) {
	utils.Info("%s", host)

	// Using tabwriter for alignment
	writer := new(strings.Builder)
	w := tabwriter.NewWriter(writer, 0, 0, 1, ' ', 0)

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s",
		"HOST", "PID", "USER", "DIR", "CMD")
	w.Flush()

	header := writer.String()
	utils.Info("%s", header)
	utils.Info("%s", strings.Repeat("-", len(header)))
}

// printStatusLine prints a formatted status line
func (c *ComposerRefactor) printStatusLine(proc ProcessInfo) {
	// Truncate long fields
	maxCmdLen := 100
	if len(proc.Cmd) > maxCmdLen {
		proc.Cmd = proc.Cmd[:maxCmdLen] + "..."
	}

	// Format with fixed widths (matching Python output)
	writer := new(strings.Builder)
	w := tabwriter.NewWriter(writer, 0, 0, 1, ' ', 0)

	fmt.Fprintf(w, "%-15s\t%-8s\t%-12s\t%-48s\t%s",
		proc.Host,
		proc.PID,
		proc.User,
		proc.WorkDir,
		proc.Cmd,
	)
	w.Flush()

	utils.Info("%s", writer.String())
}

// getStatusForPort checks if a specific port is being listened on
func (c *ComposerRefactor) getStatusForPort(client *ssh.Client, port int) (bool, error) {
	cmd := fmt.Sprintf("netstat -tlnp 2>/dev/null | grep ':%d '", port)
	result, err := client.RunCommand(cmd)
	if err != nil {
		return false, err
	}
	return strings.Contains(result, "LISTEN"), nil
}