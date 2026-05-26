package genesis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestLoadGenesisTemplate confirms we can load conf/genesis.tpl.conf
// and pull out the typed views.
func TestLoadGenesisTemplate(t *testing.T) {
	tpl, err := LoadGenesisTemplate(
		"/Users/Zhuanz1/pharos/git/AntChainAldabaNG/conf/genesis.tpl.conf")
	if err != nil {
		t.Fatalf("LoadGenesisTemplate: %v", err)
	}

	if tpl.Configs() == nil {
		t.Fatal("Configs() is nil")
	}
	if tpl.Configs().Len() != 27 {
		t.Errorf("Configs.Len = %d, want 27", tpl.Configs().Len())
	}
	if cid, _ := tpl.Configs().Get("chainId"); cid != "35039958" {
		t.Errorf("chainId = %q, want 35039958", cid)
	}

	if tpl.Alloc() == nil {
		t.Fatal("Alloc() is nil")
	}
	if len(tpl.Alloc().keys) != 41 {
		t.Errorf("alloc len = %d, want 41", len(tpl.Alloc().keys))
	}

	// Staking contract must exist and have storage (the template has 1 slot).
	staking, ok := tpl.Alloc().Get("4100000000000000000000000000000000000000")
	if !ok {
		t.Fatal("alloc missing staking contract 0x4100…")
	}
	if staking.storage == nil {
		t.Fatal("staking storage is nil — template should have at least 1 slot")
	}

	// Domains is empty in the template.
	if tpl.Domains() == nil {
		t.Fatal("Domains() is nil")
	}
	if len(tpl.Domains().keys) != 0 {
		t.Errorf("domains keys at load = %v, want empty", tpl.Domains().keys)
	}
}

// TestTemplateRoundTrip is the critical correctness check: load the
// template and re-marshal it. The output must be JSON-equivalent to the
// input (parse trees match). We don't insist on byte-identical output
// because gofmt-style indentation can differ from Python's json.dump on
// edge cases like trailing whitespace; what matters is that NO field
// content has drifted.
func TestTemplateRoundTrip(t *testing.T) {
	path := "/Users/Zhuanz1/pharos/git/AntChainAldabaNG/conf/genesis.tpl.conf"
	originalBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	tpl, err := LoadGenesisTemplate(path)
	if err != nil {
		t.Fatalf("LoadGenesisTemplate: %v", err)
	}

	regen, err := tpl.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Compare parse trees.
	var origTree, regenTree interface{}
	if err := json.Unmarshal(originalBytes, &origTree); err != nil {
		t.Fatalf("unmarshal original: %v", err)
	}
	if err := json.Unmarshal(regen, &regenTree); err != nil {
		t.Fatalf("unmarshal regen: %v", err)
	}

	origCanon, err := json.Marshal(origTree)
	if err != nil {
		t.Fatalf("canonicalize orig: %v", err)
	}
	regenCanon, err := json.Marshal(regenTree)
	if err != nil {
		t.Fatalf("canonicalize regen: %v", err)
	}

	if !bytes.Equal(origCanon, regenCanon) {
		// Surface a small location hint.
		var diffAt int
		minLen := len(origCanon)
		if len(regenCanon) < minLen {
			minLen = len(regenCanon)
		}
		for diffAt = 0; diffAt < minLen; diffAt++ {
			if origCanon[diffAt] != regenCanon[diffAt] {
				break
			}
		}
		start := diffAt - 40
		if start < 0 {
			start = 0
		}
		t.Fatalf("round-trip diff at byte %d (len orig=%d regen=%d)\norig: ...%s...\nregen: ...%s...",
			diffAt, len(origCanon), len(regenCanon),
			string(origCanon[start:min(diffAt+40, len(origCanon))]),
			string(regenCanon[start:min(diffAt+40, len(regenCanon))]))
	}
}

func TestTemplateKeyOrderPreserved(t *testing.T) {
	tpl, err := LoadGenesisTemplate(
		"/Users/Zhuanz1/pharos/git/AntChainAldabaNG/conf/genesis.tpl.conf")
	if err != nil {
		t.Fatalf("LoadGenesisTemplate: %v", err)
	}

	// Top-level Python order:
	wantTop := []string{"domains", "configs", "nonce", "timestamp", "extraData",
		"gasLimit", "difficulty", "mixHash", "coinbase", "alloc", "number",
		"gasUsed", "parentHash", "baseFeePerGas", "excessBlobGas", "blobGasUsed"}
	if len(tpl.topOrder) != len(wantTop) {
		t.Fatalf("topOrder len = %d, want %d", len(tpl.topOrder), len(wantTop))
	}
	for i, w := range wantTop {
		if tpl.topOrder[i] != w {
			t.Errorf("topOrder[%d] = %q, want %q", i, tpl.topOrder[i], w)
		}
	}

	// configs first key should be chainId (per the template).
	if k := tpl.Configs().Keys()[0]; k != "chainId" {
		t.Errorf("configs first key = %q, want chainId", k)
	}
}

func TestAccountSetBalance(t *testing.T) {
	raw := []byte(`{"code":"0xdeadbeef","storage":{"0x01":"0x02"}}`)
	var a Account
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	a.SetBalance("0x1234")

	out, err := a.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// After mutation: original code field + new balance + storage last.
	want := `{"code":"0xdeadbeef","balance":"0x1234","storage":{"0x01":"0x02"}}`
	if string(out) != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
}

func TestAccountStorageAddedWhenAbsent(t *testing.T) {
	// Template account with only "code"; generator wants to add storage.
	raw := []byte(`{"code":"0xab"}`)
	var a Account
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	s := a.Storage()
	s.Set("0x05", "0x42")

	out, err := a.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"code":"0xab","storage":{"0x05":"0x42"}}`
	if string(out) != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
}

// helper that returns minimum of two ints — Go has min built-in in
// 1.21+, this is a guard against older toolchains.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = fmt.Sprintf // keep fmt import alive if I drop debug prints later
