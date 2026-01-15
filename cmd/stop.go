package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var (
	stopForce bool
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop pharos services",
	Long:  "Stop running pharos_light processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Stopping services (force: %v)\n", stopForce)

		// Find pharos_light process
		findCmd := exec.Command("bash", "-c", "ps -eo pid,cmd | grep pharos_light | grep -v grep | awk '{print $1}'")
		output, err := findCmd.Output()
		if err != nil {
			fmt.Println("No pharos_light process found")
			return nil
		}

		pids := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(pids) == 0 || (len(pids) == 1 && pids[0] == "") {
			fmt.Println("No pharos_light process found")
			return nil
		}

		for _, pid := range pids {
			pid = strings.TrimSpace(pid)
			if pid == "" {
				continue
			}

			var signal string
			if stopForce {
				signal = "-9"
				fmt.Printf("Force stopping pharos_light (PID: %s)\n", pid)
			} else {
				signal = "-15"
				fmt.Printf("Gracefully stopping pharos_light (PID: %s)\n", pid)
			}

			killCmd := exec.Command("kill", signal, pid)
			if err := killCmd.Run(); err != nil {
				fmt.Printf("Failed to stop process %s: %v\n", pid, err)
			} else {
				fmt.Printf("Successfully stopped process %s\n", pid)
			}
		}

		fmt.Println("Services stopped successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)

	stopCmd.Flags().BoolVarP(&stopForce, "force", "f", false, "Force stop with SIGKILL")
}
