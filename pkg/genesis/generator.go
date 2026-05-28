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

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

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

	// KeyStem is the basename of key files. Python writes "generate" when
	// use_generated_keys=true and "new"/"domain" otherwise. Default
	// "domain" matches cmd/generate_keys.go output.
	KeyStem string

	// StabilizingStem is the basename of BLS stabilizing key files
	// (typically same as KeyStem). Default "stabilizing".
	StabilizingStem string
}

// Generator produces a genesis.conf from a deploy.json + key tree.
type Generator struct {
	opts   Options
	deploy *DeployConfig
	tpl    *GenesisTemplate
}

// New returns a Generator, loading deploy.json and the genesis
// template up front. It does not yet read any key files — call Run()
// for that.
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
	if opts.KeyStem == "" {
		opts.KeyStem = "domain"
	}
	if opts.StabilizingStem == "" {
		opts.StabilizingStem = "stabilizing"
	}

	deploy, err := LoadDeployConfig(opts.DeployPath)
	if err != nil {
		return nil, fmt.Errorf("load deploy.json: %w", err)
	}

	tpl, err := LoadGenesisTemplate(deploy.ResolveGenesisTpl())
	if err != nil {
		return nil, fmt.Errorf("load genesis template: %w", err)
	}

	return &Generator{opts: opts, deploy: deploy, tpl: tpl}, nil
}

// Run executes the full Python orchestration order (conf.py:1013-1175)
// and writes the resulting genesis JSON to outputPath.
//
// Step-by-step the order matters: storage_slot_kvs is built per
// contract and `.update()`-merged into the template account's storage,
// matching Python's dict-merge semantics.
func (g *Generator) Run(outputPath string) error {
	// -----------------------------------------------------------------
	// 1. Per-domain accumulation into staking storage.
	// -----------------------------------------------------------------
	totalDomains := g.deploy.Domains.Len()

	stakingStorage := NewOrderedStringMap()
	totalStakeWei := new(big.Int)
	domainsOut := g.tpl.Domains() // RawDomainMap

	for domainIndex, label := range g.deploy.Domains.Labels() {
		dc, _ := g.deploy.Domains.Get(label)

		// 1.1 read key material for this domain.
		keyDir := filepath.Join(g.opts.KeysDir, g.deploy.DomainKeyType, label)
		stabilDir := filepath.Join(g.opts.KeysDir, "bls12381", label)

		pubkey, err := ReadDomainPubkey(keyDir, g.opts.KeyStem, g.opts.KeyPasswd)
		if err != nil {
			return fmt.Errorf("domain %s: %w", label, err)
		}
		pubkeyPop, err := ReadPop(filepath.Join(keyDir, g.opts.KeyStem+".pop"))
		if err != nil {
			return fmt.Errorf("domain %s: %w", label, err)
		}
		blsPubkey, err := ReadStabilizingPubkey(stabilDir, g.opts.StabilizingStem)
		if err != nil {
			return fmt.Errorf("domain %s: %w", label, err)
		}
		blsPubkeyPop, err := ReadPop(filepath.Join(stabilDir, g.opts.StabilizingStem+".pop"))
		if err != nil {
			return fmt.Errorf("domain %s: %w", label, err)
		}

		// 1.2 endpoint.
		endpoint, err := g.deploy.Endpoint(label)
		if err != nil {
			return fmt.Errorf("domain %s: %w", label, err)
		}

		// 1.3 node_id = sha256(pubkey_bytes).
		pubkeyBytes, err := hex.DecodeString(pubkey)
		if err != nil {
			return fmt.Errorf("domain %s: bad pubkey hex: %w", label, err)
		}
		nodeID := hex.EncodeToString(sha256Sum(pubkeyBytes))

		// 1.4 stake in wei (used both in the domains[] entry and in
		// per-validator slot generation below).
		domainStakeWei := new(big.Int).Mul(
			new(big.Int).SetUint64(dc.InitialStakeInGwei),
			big.NewInt(1_000_000_000),
		)

		// 1.5 build the genesis.domains[label] entry. Field shapes and
		// order mirror what `mirror/release/v0.13.1` (and Atlantic prod)
		// emit — pharos_cli's genesis parser is strict:
		//   - stabilizing_pubkey carries the "0x" prefix
		//   - owner is the chain admin address, not the string "root"
		//   - staking is the wei stake as a JSON number, not a string
		//   - commission_rate sits BEFORE staking in the object
		domainEntry := map[string]interface{}{
			"pubkey":             "0x" + pubkey,
			"stabilizing_pubkey": "0x" + stripHex0x(blsPubkey),
			"owner":              g.deploy.AdminAddr,
			"endpoints":          []string{endpoint},
			"commission_rate":    "10",
			"staking":            domainStakeWei,
			"node_id":            nodeID,
		}
		// Preserve emission order via a manual marshal — Go's
		// encoding/json maps alphabetize, which would differ from the
		// Atlantic/v0.13.1 output.
		entryJSON, err := marshalDomainEntry(domainEntry)
		if err != nil {
			return fmt.Errorf("domain %s entry marshal: %w", label, err)
		}
		domainsOut.Set(label, entryJSON)

		// 1.6 accumulate per-domain storage slots.
		domainSlots := GenerateDomainSlots(totalDomains, domainIndex,
			pubkey, blsPubkey, endpoint, domainStakeWei, pubkeyPop, blsPubkeyPop)

		// Apply the admin-owned slots (Validator.owner + v2 delegation).
		applyOwnerSlot(domainSlots, totalDomains, domainIndex,
			pubkey, g.deploy.AdminAddr, domainStakeWei)

		totalStakeWei.Add(totalStakeWei, domainStakeWei)
		stakingStorage.Update(domainSlots)
	}

	// -----------------------------------------------------------------
	// 2. Override 5 staking contract slots (epoch num, total stake,
	//    cfg addr, lastInflationAdjustmentTime, lastEpochStartTime).
	// -----------------------------------------------------------------
	stakingStorage.Set(hex0x(uint64Slot(5)), hex0x(uint64Slot(0)))
	stakingStorage.Set(hex0x(uint64Slot(6)), hex0x(bigIntSlot(totalStakeWei)))

	cfgAddrBytes, _ := hex.DecodeString(chainCfgImplAddr) // 3100...0000
	stakingStorage.Set(hex0x(uint64Slot(7)), hex0x(leftPad32(cfgAddrBytes)))

	timestampS := g.opts.TimestampMs / 1000
	stakingStorage.Set(hex0x(uint64Slot(11)),
		hex0x(leftPad32(big.NewInt(timestampS).Bytes())))
	stakingStorage.Set(hex0x(uint64Slot(30)),
		hex0x(leftPad32(big.NewInt(timestampS).Bytes())))

	// -----------------------------------------------------------------
	// 3. Access control + initializers for staking.
	// -----------------------------------------------------------------
	GenerateAccessControlAdmin(stakingStorage, g.deploy.AdminAddr, "") // chain admin
	GenerateAccessControlAdmin(stakingStorage, g.deploy.AdminAddr, intrinsicTxSender)
	GenerateDisableInitializers(stakingStorage)

	// -----------------------------------------------------------------
	// 4. Merge into template.alloc[staking].storage; set balance.
	// -----------------------------------------------------------------
	stakingAcct := g.tpl.Alloc().MustGet(sysStakingAddr)
	mergeStorage(stakingAcct, stakingStorage)
	stakingAcct.SetBalance(fmt.Sprintf("0x%x", totalStakeWei))

	// -----------------------------------------------------------------
	// 5. chain.epoch_start_timestamp = TimestampMs.
	// -----------------------------------------------------------------
	g.tpl.Configs().Set("chain.epoch_start_timestamp",
		fmt.Sprintf("%d", g.opts.TimestampMs))

	// -----------------------------------------------------------------
	// 6. ChainConfig storage slots (depends on configs map ordering).
	// -----------------------------------------------------------------
	chainCfgStorage := GenerateChainCfgSlots(g.tpl.Configs())
	GenerateAccessControlAdmin(chainCfgStorage, g.deploy.AdminAddr, "")
	GenerateAccessControlAdmin(chainCfgStorage, g.deploy.AdminAddr, intrinsicTxSender)
	GenerateDisableInitializers(chainCfgStorage)
	chainCfgAcct := g.tpl.Alloc().MustGet(sysChainCfgAddr)
	mergeStorage(chainCfgAcct, chainCfgStorage)

	// -----------------------------------------------------------------
	// 7. RuleManager storage slots.
	// -----------------------------------------------------------------
	ruleMngStorage := GenerateRuleMngSlots()
	GenerateAccessControlAdmin(ruleMngStorage, g.deploy.AdminAddr, "")
	GenerateAccessControlAdmin(ruleMngStorage, g.deploy.AdminAddr, intrinsicTxSender)
	GenerateDisableInitializers(ruleMngStorage)
	ruleMngAcct := g.tpl.Alloc().MustGet(sysRuleMngAddr)
	mergeStorage(ruleMngAcct, ruleMngStorage)

	// -----------------------------------------------------------------
	// 8. TransactionDeny — mutate existing storage in place.
	// -----------------------------------------------------------------
	txDenyAcct := g.tpl.Alloc().MustGet(sysTxDenyAddr)
	GenerateDisableInitializers(txDenyAcct.Storage())
	GenerateTransactionDenySlots(txDenyAcct.Storage(), g.deploy.AdminAddr)

	// -----------------------------------------------------------------
	// 9. Marshal + write.
	// -----------------------------------------------------------------
	out, err := g.tpl.Marshal()
	if err != nil {
		return fmt.Errorf("marshal genesis: %w", err)
	}

	abs, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}
	if err := os.WriteFile(abs, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", abs, err)
	}
	return nil
}

// System contract addresses referenced in Run() — duplicated here from
// contract_slots.go so the orchestration is readable on its own.
const (
	sysChainCfgAddr = "3100000000000000000000000000000000000000"
	sysRuleMngAddr  = "2100000000000000000000000000000000000000"
	sysTxDenyAddr   = "82fef98b55a32226dd600d5c3298cbb9b94b5a35"

	// Intrinsic transaction sender (per Aldaba protocol). conf.py:1107.
	intrinsicTxSender = "1111111111111111111111111111111111111111"
)

// mergeStorage applies all entries from src to acct.Storage(), creating
// the storage map if the account didn't have one. Python:
//
//	if 'storage' not in genesis_data['alloc'][addr]:
//	    genesis_data['alloc'][addr]['storage'] = storage_slot_kvs
//	else:
//	    genesis_data['alloc'][addr]['storage'].update(storage_slot_kvs)
func mergeStorage(acct *Account, src *OrderedStringMap) {
	dest := acct.Storage()
	dest.Update(src)
}

// marshalDomainEntry emits a JSON object for one genesis.domains entry,
// preserving the field order that pharos_cli (v0.13.1 / Atlantic) emits:
//
//	pubkey, stabilizing_pubkey, owner, endpoints, commission_rate, staking, node_id.
//
// Note `commission_rate` comes BEFORE `staking` — diverges from the
// older Python aldaba-ops layout.
func marshalDomainEntry(d map[string]interface{}) (json.RawMessage, error) {
	order := []string{
		"pubkey", "stabilizing_pubkey", "owner", "endpoints",
		"commission_rate", "staking", "node_id",
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range order {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, "%q:", k)
		b, err := json.Marshal(d[k])
		if err != nil {
			return nil, fmt.Errorf("marshal field %s: %w", k, err)
		}
		buf.Write(b)
	}
	buf.WriteByte('}')
	return json.RawMessage(buf.Bytes()), nil
}
