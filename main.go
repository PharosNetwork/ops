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

func main() {
	fmt.Print(logo)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}