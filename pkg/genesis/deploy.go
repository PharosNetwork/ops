package genesis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DeployConfig holds the subset of deploy.json that Run() actually
// reads. Mirrors aldaba_ops/toolkit/schemas/deploy.py + domain.py, but
// only with fields the genesis generator needs — multi-node deployment
// concerns are out of scope.
type DeployConfig struct {
	// BuildRoot is the build directory referenced by other paths
	// (relative to deploy.json's dir).
	BuildRoot string `json:"build_root"`

	// ChainID is the chain identifier (e.g. "aldaba-ng"). Output goes
	// into genesis.{ChainID}.conf upstream, but we write to a flag-
	// driven path so it's informational only here.
	ChainID string `json:"chain_id"`

	// AdminAddr is the system admin (used in all four contracts'
	// AccessControl + TransactionDeny owner). Must be a 0x-prefixed
	// 20-byte hex address.
	AdminAddr string `json:"admin_addr"`

	// GenesisTpl is the path to genesis.tpl.conf, resolved relative to
	// deploy.json's directory.
	GenesisTpl string `json:"genesis_tpl"`

	// DomainKeyType is the key type for validator keys. Currently
	// only "prime256v1" is supported by the Go port; the Python source
	// also has rsa/sm2 branches but they're unused in light deployments.
	DomainKeyType string `json:"domain_key_type"`

	// Domains in deploy.json order. We use OrderedDomains rather than a
	// plain map so the loop in Run() matches Python's iteration order.
	Domains *OrderedDomains `json:"domains"`

	// DeployFileDir is the absolute path to the directory containing
	// deploy.json. Populated by LoadDeployConfig; used to resolve
	// relative paths (like GenesisTpl).
	DeployFileDir string `json:"-"`
}

// DomainConfig is the subset of each entry in deploy.json's domains map
// that genesis generation reads.
type DomainConfig struct {
	DomainPort         int            `json:"domain_port"`
	Cluster            []ClusterEntry `json:"cluster"`
	InitialStakeInGwei uint64         `json:"initial_stake_in_gwei"`
}

// ClusterEntry describes one node within a domain. We only use Host
// (advertise host) for endpoint construction.
type ClusterEntry struct {
	Host      string `json:"host"`
	DeployIP  string `json:"deploy_ip"`
	StartPort int    `json:"start_port"`
	Instances string `json:"instances"`
}

// OrderedDomains is an order-preserving map of domain_label →
// DomainConfig. Mirrors OrderedStringMap but for richer values.
type OrderedDomains struct {
	keys   []string
	values map[string]*DomainConfig
}

// Labels returns the domain labels in deploy.json order.
func (od *OrderedDomains) Labels() []string {
	out := make([]string, len(od.keys))
	copy(out, od.keys)
	return out
}

// Get returns the DomainConfig for label.
func (od *OrderedDomains) Get(label string) (*DomainConfig, bool) {
	d, ok := od.values[label]
	return d, ok
}

// Len returns the number of domains.
func (od *OrderedDomains) Len() int {
	return len(od.keys)
}

// UnmarshalJSON streams the JSON object to preserve insertion order.
func (od *OrderedDomains) UnmarshalJSON(data []byte) error {
	od.keys = od.keys[:0]
	od.values = make(map[string]*DomainConfig)

	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("domains: expected object, got %v", tok)
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		label, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("domains: non-string key %v", keyTok)
		}
		var dc DomainConfig
		if err := dec.Decode(&dc); err != nil {
			return fmt.Errorf("domains[%s]: %w", label, err)
		}
		od.keys = append(od.keys, label)
		od.values[label] = &dc
	}
	// closing brace
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// LoadDeployConfig reads deploy.json from path and returns a populated
// DeployConfig.
func LoadDeployConfig(path string) (*DeployConfig, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve deploy path: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read deploy.json: %w", err)
	}

	var cfg DeployConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse deploy.json: %w", err)
	}
	cfg.DeployFileDir = filepath.Dir(abs)

	if cfg.AdminAddr == "" {
		return nil, fmt.Errorf("deploy.json: admin_addr is required")
	}
	if cfg.GenesisTpl == "" {
		return nil, fmt.Errorf("deploy.json: genesis_tpl is required")
	}
	if cfg.Domains == nil || cfg.Domains.Len() == 0 {
		return nil, fmt.Errorf("deploy.json: at least one domain required")
	}
	if cfg.DomainKeyType == "" {
		cfg.DomainKeyType = "prime256v1"
	}
	if cfg.DomainKeyType != "prime256v1" {
		return nil, fmt.Errorf("deploy.json: unsupported domain_key_type %q (only prime256v1)",
			cfg.DomainKeyType)
	}
	return &cfg, nil
}

// ResolveGenesisTpl returns the absolute path of the genesis template.
// Relative paths are resolved against the deploy file's directory.
func (c *DeployConfig) ResolveGenesisTpl() string {
	if filepath.IsAbs(c.GenesisTpl) {
		return c.GenesisTpl
	}
	return filepath.Join(c.DeployFileDir, c.GenesisTpl)
}

// Endpoint returns the TCP endpoint string baked into the validator
// storage slot for a given domain. Matches conf.py:1007 — uses the
// first cluster entry's host with the domain's domain_port.
//
// Light-mode deployments only have one cluster entry; multi-cluster
// topologies are not supported.
func (c *DeployConfig) Endpoint(label string) (string, error) {
	dc, ok := c.Domains.Get(label)
	if !ok {
		return "", fmt.Errorf("domain %q not found in deploy.json", label)
	}
	if len(dc.Cluster) == 0 {
		return "", fmt.Errorf("domain %q has no cluster entries", label)
	}
	return fmt.Sprintf("tcp://%s:%d", dc.Cluster[0].Host, dc.DomainPort), nil
}
