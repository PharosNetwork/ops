package genesis

import (
	"encoding/json"
	"math/big"
	"os"
	"sort"
	"testing"
)

// TestGenerateDomainSlotsGolden compares Go's per-validator slot output
// against a Python-produced reference. Inputs are read from
// testdata/keys/ to keep the fixture under version control.
//
// The reference was produced by running aldaba_ops.toolkit.conf.Generator
// ._generate_domain_slots on the same inputs (with admin_addr=
// 0x2cc298bdee7cfeac9b49f9659e2f3d637e149696, totalDomains=1, idx=0).
func TestGenerateDomainSlotsGolden(t *testing.T) {
	keysRoot := "./testdata/keys"

	pubkey, err := ReadDomainPubkey(
		keysRoot+"/prime256v1/domain0", "domain", "123abc")
	if err != nil {
		t.Fatalf("ReadDomainPubkey: %v", err)
	}
	pubkeyPop, err := ReadPop(keysRoot + "/prime256v1/domain0/domain.pop")
	if err != nil {
		t.Fatalf("ReadPop pk: %v", err)
	}
	blsPubkey, err := ReadStabilizingPubkey(keysRoot+"/bls12381/domain0", "stabilizing")
	if err != nil {
		t.Fatalf("ReadStabilizingPubkey: %v", err)
	}
	blsPubkeyPop, err := ReadPop(keysRoot + "/bls12381/domain0/stabilizing.pop")
	if err != nil {
		t.Fatalf("ReadPop bls: %v", err)
	}

	// Match Python invocation in golden_setup.sh.
	stakeWei := new(big.Int).Mul(
		big.NewInt(1_000_000_000_000_000), // 1e15 gwei
		big.NewInt(1_000_000_000),         // gwei → wei
	)

	slots := GenerateDomainSlots(1, 0,
		pubkey, blsPubkey, "tcp://127.0.0.1:19000",
		stakeWei, pubkeyPop, blsPubkeyPop)
	applyOwnerSlot(slots, 1, 0,
		pubkey, "0x2cc298bdee7cfeac9b49f9659e2f3d637e149696", stakeWei)

	// Convert Go's OrderedStringMap → unordered map[string]string for
	// comparison (Python iteration order is preserved internally but
	// the golden file is sorted for predictability).
	gotMap := make(map[string]string)
	for _, k := range slots.Keys() {
		v, _ := slots.Get(k)
		gotMap[k] = v
	}

	// Load the golden file (sorted JSON object).
	want, err := os.ReadFile("./testdata/golden/domain_slots_domain0.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var wantMap map[string]string
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	// Compare both ways.
	missing := []string{}
	wrong := []string{}
	for k, v := range wantMap {
		got, ok := gotMap[k]
		if !ok {
			missing = append(missing, k)
			continue
		}
		if got != v {
			wrong = append(wrong, k)
		}
	}
	extra := []string{}
	for k := range gotMap {
		if _, ok := wantMap[k]; !ok {
			extra = append(extra, k)
		}
	}

	sort.Strings(missing)
	sort.Strings(wrong)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("missing %d slots in Go output:\n%s",
			len(missing), formatList(missing, wantMap, gotMap))
	}
	if len(extra) > 0 {
		t.Errorf("extra %d slots in Go output (not in golden):\n%s",
			len(extra), formatList(extra, wantMap, gotMap))
	}
	if len(wrong) > 0 {
		max := 5
		if len(wrong) < max {
			max = len(wrong)
		}
		for _, k := range wrong[:max] {
			t.Errorf("slot %s:\n  Go    = %s\n  Py    = %s",
				k, gotMap[k], wantMap[k])
		}
		if len(wrong) > max {
			t.Errorf("(+%d more diffs)", len(wrong)-max)
		}
	}
	if len(missing) == 0 && len(extra) == 0 && len(wrong) == 0 {
		t.Logf("✅ all %d slots match Python output", len(wantMap))
	}
}

func formatList(keys []string, want, got map[string]string) string {
	var b []byte
	for _, k := range keys {
		b = append(b, "  "...)
		b = append(b, k...)
		b = append(b, '\n')
		b = append(b, "    want: "...)
		b = append(b, want[k]...)
		b = append(b, '\n')
		b = append(b, "    got:  "...)
		b = append(b, got[k]...)
		b = append(b, '\n')
	}
	return string(b)
}

// compareToGolden loads the named golden JSON and asserts gotMap is
// byte-identical to it. Common code for the contract-slot subtests.
func compareToGolden(t *testing.T, goldenName string, got *OrderedStringMap) {
	t.Helper()

	want, err := os.ReadFile("./testdata/golden/" + goldenName)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenName, err)
	}
	var wantMap map[string]string
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatalf("parse golden %s: %v", goldenName, err)
	}

	gotMap := make(map[string]string)
	for _, k := range got.Keys() {
		v, _ := got.Get(k)
		gotMap[k] = v
	}

	missing := []string{}
	wrong := []string{}
	extra := []string{}
	for k, v := range wantMap {
		g, ok := gotMap[k]
		if !ok {
			missing = append(missing, k)
		} else if g != v {
			wrong = append(wrong, k)
		}
	}
	for k := range gotMap {
		if _, ok := wantMap[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(wrong)

	if len(missing) > 0 {
		t.Errorf("[%s] missing %d slots:\n%s",
			goldenName, len(missing), formatList(missing, wantMap, gotMap))
	}
	if len(extra) > 0 {
		t.Errorf("[%s] extra %d slots:\n%s",
			goldenName, len(extra), formatList(extra, wantMap, gotMap))
	}
	if len(wrong) > 0 {
		max := 5
		if len(wrong) < max {
			max = len(wrong)
		}
		for _, k := range wrong[:max] {
			t.Errorf("[%s] slot %s:\n  Go    = %s\n  Py    = %s",
				goldenName, k, gotMap[k], wantMap[k])
		}
		if len(wrong) > max {
			t.Errorf("[%s] (+%d more diffs)", goldenName, len(wrong)-max)
		}
	}
	if len(missing) == 0 && len(extra) == 0 && len(wrong) == 0 {
		t.Logf("✅ [%s] all %d slots match Python", goldenName, len(wantMap))
	}
}

func TestGenerateChainCfgSlotsGolden(t *testing.T) {
	// Same configs map order as the Python script.
	configs := NewOrderedStringMap()
	configs.Set("chainId", "35039958")
	configs.Set("chain.epoch_duration", "1800000")
	configs.Set("chain.gas_price", "1000000000")
	configs.Set("consensus.algorithm", "mytumbler")
	configs.Set("staking.min_delegator_stake", "1000000000000000000")

	got := GenerateChainCfgSlots(configs)
	compareToGolden(t, "chaincfg_slots.json", got)
}

func TestGenerateRuleMngSlotsGolden(t *testing.T) {
	got := GenerateRuleMngSlots()
	compareToGolden(t, "rulemng_slots.json", got)
}

func TestGenerateAccessControlAdminGolden(t *testing.T) {
	got := NewOrderedStringMap()
	GenerateAccessControlAdmin(got, "0x2cc298bdee7cfeac9b49f9659e2f3d637e149696", "")
	compareToGolden(t, "accesscontrol_admin.json", got)
}

func TestGenerateAccessControlIntrinsicGolden(t *testing.T) {
	got := NewOrderedStringMap()
	GenerateAccessControlAdmin(got,
		"0x2cc298bdee7cfeac9b49f9659e2f3d637e149696",
		"1111111111111111111111111111111111111111")
	compareToGolden(t, "accesscontrol_intrinsic.json", got)
}

func TestGenerateDisableInitializersGolden(t *testing.T) {
	got := NewOrderedStringMap()
	GenerateDisableInitializers(got)
	compareToGolden(t, "disable_initializers.json", got)
}

func TestGenerateTransactionDenySlotsGolden(t *testing.T) {
	got := NewOrderedStringMap()
	GenerateTransactionDenySlots(got, "0x2cc298bdee7cfeac9b49f9659e2f3d637e149696")
	compareToGolden(t, "transaction_deny.json", got)
}
