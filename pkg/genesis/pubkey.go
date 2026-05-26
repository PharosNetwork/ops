package genesis

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ReadDomainPubkey returns the prime256v1 pubkey for a domain as a hex
// string WITHOUT a "0x" prefix.
//
// Lookup order matches Python conf.py:1047-1053:
//  1. If <domain.pub> exists, read it verbatim (already includes the
//     "1003" prefix and is the canonical form Python writes).
//  2. Otherwise extract the uncompressed SEC1 point from the encrypted
//     PKCS8 PEM <domain.key> via openssl and prepend the "1003"
//     prime256v1 type prefix.
//
// keyDir is the directory holding {domain.key, domain.pub, domain.pop}
// for the requested domain. keyStem is typically "domain" (matches
// `cmd/generate_keys.go`) but Python uses "generate" when
// use_generated_keys=true — we let the caller pass it.
func ReadDomainPubkey(keyDir, keyStem, keyPasswd string) (string, error) {
	pubPath := filepath.Join(keyDir, keyStem+".pub")
	if data, err := os.ReadFile(pubPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	keyPath := filepath.Join(keyDir, keyStem+".key")
	if _, err := os.Stat(keyPath); err != nil {
		return "", fmt.Errorf("neither %s.pub nor %s.key found in %s",
			keyStem, keyStem, keyDir)
	}
	rawHex, err := extractP256PubkeyHex(keyPath, keyPasswd)
	if err != nil {
		return "", err
	}
	// Prefix "1003" is the Aldaba pubkey-type tag for prime256v1.
	return "1003" + rawHex, nil
}

// extractP256PubkeyHex returns the lowercase hex encoding of the
// uncompressed SEC1 point (65 bytes, starting with 0x04) extracted
// from the prime256v1 private key at keyPath.
//
// Mirrors Python's chained `openssl ec | tail -c 65 | xxd -p -c 65`.
// We do the byte trimming in Go so we don't depend on xxd/tail being
// present (the runner image has them, but keeping it explicit is
// cheaper than auditing the image).
func extractP256PubkeyHex(keyPath, keyPasswd string) (string, error) {
	cmd := exec.Command("openssl", "ec",
		"-in", keyPath,
		"-passin", "pass:"+keyPasswd,
		"-pubout",
		"-outform", "DER",
	)
	// stderr says "read EC key" etc. on success; suppress it.
	cmd.Stderr = nil
	der, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("openssl ec %s: %w", keyPath, err)
	}
	if len(der) < 65 {
		return "", fmt.Errorf("openssl produced %d bytes, expected at least 65 (SEC1 uncompressed point)", len(der))
	}
	point := der[len(der)-65:]
	if point[0] != 0x04 {
		return "", fmt.Errorf("last 65 bytes do not start with 0x04 (got 0x%02x); not an uncompressed SEC1 point", point[0])
	}
	return hexLower(point), nil
}

// ReadStabilizingPubkey returns the BLS12-381 pubkey for a domain as a
// hex string WITHOUT a "0x" prefix. Reads <stabilizing.pub> verbatim.
func ReadStabilizingPubkey(stabilizingDir, keyStem string) (string, error) {
	pubPath := filepath.Join(stabilizingDir, keyStem+".pub")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("read stabilizing pubkey %s: %w", pubPath, err)
	}
	s := strings.TrimSpace(string(data))
	return strings.TrimPrefix(s, "0x"), nil
}

// ReadPop returns the PoP file content (with any "0x" prefix stripped).
// Mirrors Python's `pop_file.read().strip()` followed by hex handling.
func ReadPop(popPath string) (string, error) {
	data, err := os.ReadFile(popPath)
	if err != nil {
		return "", fmt.Errorf("read PoP %s: %w", popPath, err)
	}
	s := strings.TrimSpace(string(data))
	return strings.TrimPrefix(s, "0x"), nil
}

// hexLower returns lowercase hex without a 0x prefix.
func hexLower(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}
