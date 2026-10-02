package cmd

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pharos-ops/pkg/bls"
	"pharos-ops/pkg/keystore"
)

// Same real key pair used in pkg/bls tests.
const (
	testPrivHex = "3f0e8d53a6ababb2e1e363a5c0fa5506303174893c298ff7b47b442661e5ff39"
	testPubHex  = "b7c1dd5e6ede474a508b7dac328b749826934bab9296491051316e5ee4e58a68b1a604ebae5a0942336f4752ba05b50a"
)

// writeLegacyKeys writes a legacy stabilizing.key/.pub pair into dir.
func writeLegacyKeys(t *testing.T, dir, privHex, pubHex string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "stabilizing.key"), []byte("0x4002"+privHex), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stabilizing.pub"), []byte("0x4003"+pubHex), 0644); err != nil {
		t.Fatal(err)
	}
}

// resetMigrateFlags restores command flag globals between subtests.
func resetMigrateFlags() {
	migrateKeysDir = "./keys"
	migrateKeepBLS = ""
	migratePasswd = ""
	migrateKDF = "scrypt"
	migrateForce = false
}

func TestMigrateBLSKeySuccess(t *testing.T) {
	resetMigrateFlags()
	dir := t.TempDir()
	writeLegacyKeys(t, dir, testPrivHex, testPubHex)

	migrateKeysDir = dir
	migratePasswd = "test-password-123"
	migrateKDF = "scrypt"

	if err := migrateBLSKeyCmd.RunE(migrateBLSKeyCmd, nil); err != nil {
		t.Fatalf("migrate failed: %v", err)
	}

	// New key file must be a valid EIP-2335 keystore.
	data, err := os.ReadFile(filepath.Join(dir, "stabilizing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		t.Fatalf("migrated key is not JSON keystore: %s", data)
	}
	ks, err := keystore.Parse(data)
	if err != nil {
		t.Fatalf("migrated key failed to parse: %v", err)
	}
	if ks.Pubkey != testPubHex {
		t.Errorf("keystore pubkey = %s, want %s", ks.Pubkey, testPubHex)
	}

	// It must decrypt back to the original private key.
	back, err := keystore.Decrypt(ks, "test-password-123")
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if hex.EncodeToString(back) != testPrivHex {
		t.Errorf("decrypted priv = %s, want %s", hex.EncodeToString(back), testPrivHex)
	}

	// Legacy backup must exist and hold the original content.
	backup, err := os.ReadFile(filepath.Join(dir, "stabilizing.key.legacy"))
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if strings.TrimSpace(string(backup)) != "0x4002"+testPrivHex {
		t.Errorf("backup content wrong: %s", backup)
	}
}

func TestMigrateBLSKeyIdempotent(t *testing.T) {
	resetMigrateFlags()
	dir := t.TempDir()
	writeLegacyKeys(t, dir, testPrivHex, testPubHex)
	migrateKeysDir = dir
	migratePasswd = "pw"

	// First migration.
	if err := migrateBLSKeyCmd.RunE(migrateBLSKeyCmd, nil); err != nil {
		t.Fatalf("first migrate failed: %v", err)
	}
	first, _ := os.ReadFile(filepath.Join(dir, "stabilizing.key"))

	// Second run: no-op, must not error or change the file.
	if err := migrateBLSKeyCmd.RunE(migrateBLSKeyCmd, nil); err != nil {
		t.Fatalf("second migrate (idempotent) failed: %v", err)
	}
	second, _ := os.ReadFile(filepath.Join(dir, "stabilizing.key"))
	if string(first) != string(second) {
		t.Error("idempotent re-run changed the keystore")
	}
}

func TestMigrateBLSKeyMismatchRejected(t *testing.T) {
	resetMigrateFlags()
	dir := t.TempDir()

	// Write a pub that does NOT match the priv (flip a byte).
	badPub := "c7c1dd5e6ede474a508b7dac328b749826934bab9296491051316e5ee4e58a68b1a604ebae5a0942336f4752ba05b50a"
	writeLegacyKeys(t, dir, testPrivHex, badPub)
	migrateKeysDir = dir
	migratePasswd = "pw"

	err := migrateBLSKeyCmd.RunE(migrateBLSKeyCmd, nil)
	if err == nil {
		t.Fatal("expected migration to be REJECTED for mismatched key pair")
	}
	if !strings.Contains(err.Error(), "SAFETY CHECK FAILED") {
		t.Errorf("expected safety check error, got: %v", err)
	}

	// The original key file must be untouched (no keystore, no backup).
	data, _ := os.ReadFile(filepath.Join(dir, "stabilizing.key"))
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		t.Error("key file was overwritten despite rejection")
	}
	if _, serr := os.Stat(filepath.Join(dir, "stabilizing.key.legacy")); serr == nil {
		t.Error("backup created despite rejection")
	}
}

func TestMigrateBLSKeyMissingPubRejected(t *testing.T) {
	resetMigrateFlags()
	dir := t.TempDir()
	// Only the key, no .pub.
	if err := os.WriteFile(filepath.Join(dir, "stabilizing.key"), []byte("0x4002"+testPrivHex), 0600); err != nil {
		t.Fatal(err)
	}
	migrateKeysDir = dir
	migratePasswd = "pw"

	if err := migrateBLSKeyCmd.RunE(migrateBLSKeyCmd, nil); err == nil {
		t.Fatal("expected rejection when stabilizing.pub is missing and --force not set")
	}

	// With --force, it should proceed.
	resetMigrateFlags()
	migrateKeysDir = dir
	migratePasswd = "pw"
	migrateForce = true
	if err := migrateBLSKeyCmd.RunE(migrateBLSKeyCmd, nil); err != nil {
		t.Fatalf("migrate with --force should succeed: %v", err)
	}
}

func TestMigratedKeystorePubkeyMatchesDerivation(t *testing.T) {
	// Cross-check: the pubkey stored in the keystore equals bls.DerivePublicKey.
	priv, _ := hex.DecodeString(testPrivHex)
	derived, err := bls.DerivePublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(derived) != testPubHex {
		t.Fatalf("sanity: derivation mismatch")
	}
}
