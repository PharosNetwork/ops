package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pharos-ops/pkg/utils"
)

// BootstrapSimple executes bootstrap without domain.json file
// Simplified bootstrap for new deployment flow
func BootstrapSimple() error {
	utils.Info("Starting bootstrap (simplified mode)")

	// Get paths relative to management directory (scripts/)
	binDir, err := filepath.Abs("../bin")
	if err != nil {
		return fmt.Errorf("failed to get bin directory: %w", err)
	}

	pharosConfFile, err := filepath.Abs("../conf/pharos.conf")
	if err != nil {
		return fmt.Errorf("failed to get pharos.conf path: %w", err)
	}

	// Check if pharos.conf exists
	if _, err := os.Stat(pharosConfFile); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", pharosConfFile)
	}

	// Get genesis.conf path
	genesisFile, err := filepath.Abs("../genesis.conf")
	if err != nil {
		return fmt.Errorf("failed to get genesis.conf path: %w", err)
	}

	// Check if genesis.conf exists
	if _, err := os.Stat(genesisFile); os.IsNotExist(err) {
		return fmt.Errorf("genesis file not found: %s", genesisFile)
	}

	// Check if pharos_cli binary exists
	pharosCli := filepath.Join(binDir, "pharos_cli")
	if _, err := os.Stat(pharosCli); os.IsNotExist(err) {
		return fmt.Errorf("pharos_cli binary not found: %s", pharosCli)
	}

	// Check if libevmone.so exists
	evmoneSo := filepath.Join(binDir, "libevmone.so")
	hasEvmone := true
	if _, err := os.Stat(evmoneSo); os.IsNotExist(err) {
		hasEvmone = false
	}

	// Run bootstrap genesis command
	// pharos_cli genesis -g ../genesis.conf -c ../conf/pharos.conf
	var cmd *exec.Cmd
	if hasEvmone {
		cmdStr := fmt.Sprintf("cd %s && LD_PRELOAD=./libevmone.so ./pharos_cli genesis -g %s -c %s", binDir, genesisFile, pharosConfFile)
		cmd = exec.Command("bash", "-c", cmdStr)
		utils.Info("Running: %s", cmdStr)
	} else {
		cmd = exec.Command(pharosCli, "genesis", "-g", genesisFile, "-c", pharosConfFile)
		cmd.Dir = binDir
		utils.Info("Running: %s genesis -g %s -c %s", pharosCli, genesisFile, pharosConfFile)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	utils.Info("Bootstrap completed successfully")
	return nil
}

// StartSimple starts services without domain.json file
// Simplified start for new deployment flow
func StartSimple(service string, extraArgs string) error {
	utils.Info("Starting services (simplified mode)")

	// Get paths relative to management directory (scripts/)
	binDir, err := filepath.Abs("../bin")
	if err != nil {
		return fmt.Errorf("failed to get bin directory: %w", err)
	}

	pharosConfFile, err := filepath.Abs("../conf/pharos.conf")
	if err != nil {
		return fmt.Errorf("failed to get pharos.conf path: %w", err)
	}

	// Check if pharos.conf exists
	if _, err := os.Stat(pharosConfFile); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", pharosConfFile)
	}

	// Check if pharos_light binary exists
	pharosLight := filepath.Join(binDir, "pharos_light")
	if _, err := os.Stat(pharosLight); os.IsNotExist(err) {
		return fmt.Errorf("pharos_light binary not found: %s", pharosLight)
	}

	// Check if libevmone.so exists
	evmoneSo := filepath.Join(binDir, "libevmone.so")
	hasEvmone := true
	if _, err := os.Stat(evmoneSo); os.IsNotExist(err) {
		hasEvmone = false
	}

	// Build command
	var cmdStr string
	if hasEvmone {
		cmdStr = fmt.Sprintf("cd %s && LD_PRELOAD=./libevmone.so ./pharos_light -c %s -d", binDir, pharosConfFile)
	} else {
		cmdStr = fmt.Sprintf("cd %s && ./pharos_light -c %s -d", binDir, pharosConfFile)
	}

	utils.Info("Starting pharos_light: %s", cmdStr)

	cmd := exec.Command("bash", "-c", cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}

	utils.Info("Services started successfully")
	return nil
}

// StopSimple stops services without domain.json file
// Simplified stop for new deployment flow
func StopSimple(service string, force bool) error {
	utils.Info("Stopping services (simplified mode), service: %s, force: %v", service, force)

	// Find pharos_light process
	cmd := exec.Command("bash", "-c", "ps -eo pid,cmd | grep pharos_light | grep -v grep | awk '{print $1}'")
	output, err := cmd.Output()
	if err != nil {
		utils.Info("No pharos_light process found")
		return nil
	}

	pids := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(pids) == 0 || (len(pids) == 1 && pids[0] == "") {
		utils.Info("No pharos_light process found")
		return nil
	}

	for _, pid := range pids {
		pid = strings.TrimSpace(pid)
		if pid == "" {
			continue
		}

		var signal string
		if force {
			signal = "-9"
			utils.Info("Force stopping pharos_light (PID: %s)", pid)
		} else {
			signal = "-15"
			utils.Info("Gracefully stopping pharos_light (PID: %s)", pid)
		}

		killCmd := exec.Command("kill", signal, pid)
		if err := killCmd.Run(); err != nil {
			utils.Error("Failed to stop process %s: %v", pid, err)
		} else {
			utils.Info("Successfully stopped process %s", pid)
		}
	}

	utils.Info("Services stopped successfully")
	return nil
}
