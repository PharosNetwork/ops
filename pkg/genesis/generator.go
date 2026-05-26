// Package genesis ports the EVM storage-slot logic from
// aldaba_ops/toolkit/conf.py into Go, so PharosNetwork can produce a
// genesis.conf with a known admin account from a deploy.json + a
// pre-generated key tree, without depending on the Python aldaba-ops
// toolchain.
//
// Source of truth for the port:
//
//	AntChainOpenLabs/AntChainAldabaNG  scripts/aldaba-ops/aldaba_ops/toolkit/conf.py
//
// All slot generation MUST be byte-identical with the Python output —
// genesis is a state-root input, any drift breaks chain bring-up.
package genesis

import "fmt"

// Options configures a Generator.
type Options struct {
	// DeployPath is the path to deploy.json.
	DeployPath string

	// KeysDir is the root of the pre-generated key tree. Expected layout:
	//   <KeysDir>/prime256v1/<domain_label>/{domain.key, domain.pub, domain.pop}
	//   <KeysDir>/bls12381/<domain_label>/{stabilizing.key, stabilizing.pub, stabilizing.pop}
	KeysDir string

	// KeyPasswd unlocks the encrypted prime256v1 private keys when we
	// need to extract a pubkey (only used if domain.pub is missing).
	KeyPasswd string

	// TimestampMs is the genesis chain epoch start, in milliseconds since
	// epoch. Pin this for reproducible builds (used as
	// chain.epoch_start_timestamp).
	TimestampMs int64
}

// Generator produces a genesis.conf from a deploy.json + key tree.
type Generator struct {
	opts Options
}

// New returns a Generator with the provided options. It does not touch
// the filesystem yet — call Run() to actually produce the genesis.
func New(opts Options) (*Generator, error) {
	if opts.DeployPath == "" {
		return nil, fmt.Errorf("DeployPath is required")
	}
	if opts.KeysDir == "" {
		return nil, fmt.Errorf("KeysDir is required")
	}
	if opts.TimestampMs == 0 {
		return nil, fmt.Errorf("TimestampMs is required (use time.Now().UnixMilli() for current)")
	}
	return &Generator{opts: opts}, nil
}

// Run produces genesis.conf at outputPath.
//
// TODO: implement. See plan at /Users/Zhuanz1/.claude/plans/luminous-growing-frost.md.
func (g *Generator) Run(outputPath string) error {
	return fmt.Errorf("not implemented yet")
}
