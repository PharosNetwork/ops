package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pharos-ops/pkg/bls"
	"pharos-ops/pkg/keystore"

	"github.com/spf13/cobra"
)

var (
	migrateKeysDir string
	migratePasswd  string
	migrateKDF     string
	migrateForce   bool
	migrateKeepBLS string // path override for stabilizing.key
)

var migrateBLSKeyCmd = &cobra.Command{
	Use:   "migrate-bls-key",
	Short: "Migrate a legacy plaintext BLS key to EIP-2335 keystore format",
	Long: `Convert a legacy stabilizing.key (0x4002 + plaintext hex) into an
encrypted EIP-2335 keystore, in place.

Safety: before writing anything, the private key's public key is re-derived
and checked against stabilizing.pub. If they don't match, migration aborts
and no files are touched. The original key is backed up to
stabilizing.key.legacy. Re-running on an already-migrated key is a no-op.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		keyPath := migrateKeepBLS
		if keyPath == "" {
			keyPath = filepath.Join(migrateKeysDir, "stabilizing.key")
		}
		pubPath := filepath.Join(filepath.Dir(keyPath), "stabilizing.pub")

		// Resolve password (flag > saved).
		passwd, err := resolvePassword(migratePasswd)
		if err != nil {
			return err
		}

		// Read the existing key file.
		raw, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", keyPath, err)
		}
		content := strings.TrimSpace(string(raw))

		// Idempotency: already an EIP-2335 keystore?
		if looksLikeKeystore(content) {
			if migrateForce {
				fmt.Printf("%s is already EIP-2335 format; --force given but nothing to re-migrate (skipping)\n", keyPath)
			} else {
				fmt.Printf("%s is already in EIP-2335 format; nothing to do.\n", keyPath)
			}
			return nil
		}

		// Parse legacy plaintext key: strip 0x4002 tag, decode 32 bytes.
		privHex := bls.StripTag(content)
		privKey, err := hex.DecodeString(privHex)
		if err != nil {
			return fmt.Errorf("failed to decode legacy private key hex: %w", err)
		}
		if len(privKey) != bls.SecretKeySize {
			return fmt.Errorf("legacy private key is %d bytes after stripping tag, expected %d", len(privKey), bls.SecretKeySize)
		}

		// Derive the public key from the private key.
		derivedPub, err := bls.DerivePublicKey(privKey)
		if err != nil {
			return fmt.Errorf("failed to derive public key: %w", err)
		}
		derivedPubHex := hex.EncodeToString(derivedPub)

		// Verify against stabilizing.pub if present (the safety check).
		if pubRaw, perr := os.ReadFile(pubPath); perr == nil {
			expectedPubHex := bls.StripTag(strings.TrimSpace(string(pubRaw)))
			expectedPub, derr := hex.DecodeString(expectedPubHex)
			if derr != nil {
				return fmt.Errorf("failed to decode %s: %w", pubPath, derr)
			}
			if verr := bls.VerifyKeyPair(privKey, expectedPub); verr != nil {
				return fmt.Errorf("SAFETY CHECK FAILED — refusing to migrate: %w\n"+
					"  key file: %s\n  pub file: %s\n"+
					"The private key does not correspond to stabilizing.pub. "+
					"Migrating would produce a keystore for the wrong node.", verr, keyPath, pubPath)
			}
			fmt.Printf("✓ Verified: derived public key matches %s\n", pubPath)
		} else {
			// No .pub to check against. Warn but proceed only with --force.
			if !migrateForce {
				return fmt.Errorf("stabilizing.pub not found at %s — cannot verify the key pair. "+
					"Re-run with --force to migrate without verification (not recommended).", pubPath)
			}
			fmt.Printf("⚠  %s not found; skipping key-pair verification (--force)\n", pubPath)
		}

		// Build the EIP-2335 keystore. Store the 48-byte pubkey (no tag) so
		// standard tooling can read it.
		ks, err := keystore.Encrypt(privKey, passwd, keystore.EncryptOptions{
			KDF:         migrateKDF,
			Pubkey:      derivedPubHex,
			Path:        "",
			Description: "aldaba stabilizing (BLS12-381) key",
		})
		if err != nil {
			return fmt.Errorf("failed to build keystore: %w", err)
		}
		ksJSON, err := ks.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal keystore: %w", err)
		}

		// Sanity: the keystore must decrypt back to the same private key
		// before we overwrite anything.
		if back, derr := keystore.Decrypt(ks, passwd); derr != nil {
			return fmt.Errorf("post-encryption self-check failed to decrypt: %w", derr)
		} else if hex.EncodeToString(back) != privHex {
			return fmt.Errorf("post-encryption self-check mismatch: decrypted key differs from source")
		}

		// Back up the legacy key, then atomically replace it.
		backupPath := keyPath + ".legacy"
		if _, serr := os.Stat(backupPath); serr == nil && !migrateForce {
			return fmt.Errorf("backup %s already exists; refusing to overwrite (use --force)", backupPath)
		}
		if werr := os.WriteFile(backupPath, raw, 0600); werr != nil {
			return fmt.Errorf("failed to write backup %s: %w", backupPath, werr)
		}

		tmpPath := keyPath + ".tmp"
		if werr := os.WriteFile(tmpPath, ksJSON, 0600); werr != nil {
			return fmt.Errorf("failed to write temp keystore: %w", werr)
		}
		if rerr := os.Rename(tmpPath, keyPath); rerr != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to replace key file: %w", rerr)
		}

		fmt.Printf("✅ Migrated %s to EIP-2335 (%s KDF)\n", keyPath, ks.Crypto.KDF.Function)
		fmt.Printf("   Legacy key backed up to %s\n", backupPath)
		fmt.Printf("   Public key: %s\n", derivedPubHex)
		return nil
	},
}

// looksLikeKeystore reports whether content is already a JSON keystore.
func looksLikeKeystore(content string) bool {
	trimmed := strings.TrimSpace(content)
	return strings.HasPrefix(trimmed, "{")
}

// resolvePassword returns the flag password if set, else the saved password.
func resolvePassword(flagPasswd string) (string, error) {
	if flagPasswd != "" {
		return flagPasswd, nil
	}
	saved, err := GetPassword()
	if err != nil {
		return "", fmt.Errorf("password not found. Run: ./ops set-password <password> or use --key-passwd")
	}
	fmt.Println("Using saved password")
	return saved, nil
}

func init() {
	rootCmd.AddCommand(migrateBLSKeyCmd)

	migrateBLSKeyCmd.Flags().StringVarP(&migrateKeysDir, "keys-dir", "k", "./keys",
		"Directory containing stabilizing.key and stabilizing.pub")
	migrateBLSKeyCmd.Flags().StringVar(&migrateKeepBLS, "key-file", "",
		"Explicit path to stabilizing.key (overrides --keys-dir)")
	migrateBLSKeyCmd.Flags().StringVar(&migratePasswd, "key-passwd", "",
		"Password for keystore encryption (uses saved password if omitted)")
	migrateBLSKeyCmd.Flags().StringVar(&migrateKDF, "kdf", "scrypt",
		"Key derivation function: scrypt or pbkdf2")
	migrateBLSKeyCmd.Flags().BoolVar(&migrateForce, "force", false,
		"Proceed past non-fatal guards (missing .pub, existing backup)")
}
