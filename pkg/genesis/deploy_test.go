package genesis

import (
	"testing"
)

func TestLoadDeployConfig(t *testing.T) {
	cfg, err := LoadDeployConfig(
		"/Users/Zhuanz1/pharos/git/AntChainAldabaNG/scripts/deploy.chain.light.json")
	if err != nil {
		t.Fatalf("LoadDeployConfig: %v", err)
	}

	if cfg.ChainID != "aldaba-ng" {
		t.Errorf("ChainID = %q, want aldaba-ng", cfg.ChainID)
	}
	if cfg.AdminAddr != "0x2cc298bdee7cfeac9b49f9659e2f3d637e149696" {
		t.Errorf("AdminAddr = %q", cfg.AdminAddr)
	}
	if cfg.DomainKeyType != "prime256v1" {
		t.Errorf("DomainKeyType = %q, want prime256v1", cfg.DomainKeyType)
	}
	if cfg.Domains.Len() != 4 {
		t.Errorf("Domains.Len = %d, want 4", cfg.Domains.Len())
	}

	wantLabels := []string{"domain0", "domain1", "domain2", "domain3"}
	gotLabels := cfg.Domains.Labels()
	if len(gotLabels) != len(wantLabels) {
		t.Fatalf("labels len = %d, want %d", len(gotLabels), len(wantLabels))
	}
	for i, w := range wantLabels {
		if gotLabels[i] != w {
			t.Errorf("labels[%d] = %q, want %q", i, gotLabels[i], w)
		}
	}

	d0, _ := cfg.Domains.Get("domain0")
	if d0.DomainPort != 19000 {
		t.Errorf("domain0.DomainPort = %d, want 19000", d0.DomainPort)
	}
	if d0.InitialStakeInGwei != 1_000_000_000_000_000 {
		t.Errorf("domain0.InitialStakeInGwei = %d", d0.InitialStakeInGwei)
	}
	if len(d0.Cluster) != 1 {
		t.Errorf("domain0.Cluster len = %d, want 1", len(d0.Cluster))
	}
	if d0.Cluster[0].Host != "127.0.0.1" {
		t.Errorf("domain0.Cluster[0].Host = %q, want 127.0.0.1", d0.Cluster[0].Host)
	}

	endpoint, err := cfg.Endpoint("domain0")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if endpoint != "tcp://127.0.0.1:19000" {
		t.Errorf("Endpoint(domain0) = %q, want tcp://127.0.0.1:19000", endpoint)
	}

	resolved := cfg.ResolveGenesisTpl()
	want := "/Users/Zhuanz1/pharos/git/AntChainAldabaNG/conf/genesis.tpl.conf"
	if resolved != want {
		t.Errorf("ResolveGenesisTpl = %q\nwant                 %q", resolved, want)
	}
}
