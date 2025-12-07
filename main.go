package main

import (
	"fmt"
	"os"

	"pharos-ops/cmd"
)

const logo = `
  ____  _   _    _    ____   ___  ____
 |  _ \| | | |  / \  |  _ \ / _ \/ ___|
 | |_) | |_| | / _ \ | |_) | | | \___ \
 |  __/|  _  |/ ___ \|  _ <| |_| |___) |
 |_|   |_| |_/_/   \_\_| \_\\___/|____/

`

var (
	version   = "dev"     // Set by build.sh
	buildTime = "unknown" // Set by build.sh
	gitCommit = "unknown" // Set by build.sh
)

func main() {
	// Set version info for cmd package
	cmd.SetVersionInfo(version, buildTime, gitCommit)

	fmt.Print(logo)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}