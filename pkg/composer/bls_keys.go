package composer

import (
	"fmt"
	"os"
	"path/filepath"

	"pharos-ops/pkg/utils"
)

// copyGenesisConf copies genesis configuration files
func (c *Composer) copyGenesisConf(localClientDir string) error {
	cliConfDir := filepath.Join(localClientDir, "conf")

	// Copy genesis.conf as genesis.aldaba-ng.conf (matching Python)
	genesisSrc := filepath.Join(c.domainPath, c.domain.GenesisConf)
	genesisDst := filepath.Join(cliConfDir, "genesis.aldaba-ng.conf")

	if _, err := os.Stat(genesisSrc); err == nil {
		if err := copyFile(genesisSrc, genesisDst); err != nil {
			return fmt.Errorf("failed to copy genesis.aldaba-ng.conf: %w", err)
		}
	} else {
		utils.Warn("Genesis conf file not found: %v", err)
	}

	return nil
}