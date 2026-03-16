package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/cobra"
)

var (
	hcKeysDir     string
	hcBinDir      string
	hcRPCEndpoint string
)

const (
	atlanticVersionURL = "https://raw.githubusercontent.com/PharosNetwork/resources/main/atlantic.version"
	mainnetVersionURL  = "https://raw.githubusercontent.com/PharosNetwork/resources/main/mainnet.version"
)

type infoItem struct {
	Item  string
	Value string
}

type checkItem struct {
	Item   string
	Status string // ✅ or ❌
	Detail string
}

var healthCheckCmd = &cobra.Command{
	Use:   "health-check",
	Short: "Run node health checks",
	Long:  "Perform a series of self-checks on the node: system info, ulimit, spec version, binary version, node ID, validator status",
	RunE: func(cmd *cobra.Command, args []string) error {
		var infos []infoItem
		var checks []checkItem

		// === INFO section ===
		// Network (detect from VERSION file)
		network := detectNetwork(hcBinDir)
		infos = append(infos, infoItem{"Network", network})

		// CPU
		infos = append(infos, infoItem{"CPU Cores", fmt.Sprintf("%d", runtime.NumCPU())})

		// Memory
		infos = append(infos, infoItem{"Memory", getMemoryInfo()})

		// Node ID
		nodeID, nodeIDErr := getNodeIDFromKeys(hcKeysDir)
		if nodeIDErr != nil {
			infos = append(infos, infoItem{"Node ID", fmt.Sprintf("error: %v", nodeIDErr)})
		} else {
			infos = append(infos, infoItem{"Node ID", nodeID})
		}

		// Validator status
		rpcEndpoint := hcRPCEndpoint
		if rpcEndpoint == "" {
			if strings.Contains(strings.ToLower(network), "atlantic") {
				rpcEndpoint = "https://atlantic.dplabs-internal.com"
			} else {
				rpcEndpoint = "https://rpc.pharos.xyz"
			}
		}
		validatorStr := getValidatorStatus(cmd, hcKeysDir, rpcEndpoint)
		infos = append(infos, infoItem{"Validator", validatorStr})

		// === CHECK section ===
		// Ulimit
		checks = append(checks, checkUlimit()...)

		// Spec Version
		checks = append(checks, checkSpecVersion(hcBinDir)...)

		// Binary Version
		checks = append(checks, checkBinaryVersion(hcBinDir))

		// Print INFO table
		fmt.Println()
		fmt.Println("📋 NODE INFO")
		fmt.Println(strings.Repeat("─", 60))
		wi := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		for _, info := range infos {
			fmt.Fprintf(wi, "  %s\t%s\n", info.Item, info.Value)
		}
		wi.Flush()

		// Print CHECK table
		fmt.Println()
		fmt.Println("🔍 HEALTH CHECK")
		fmt.Println(strings.Repeat("─", 60))
		wc := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		for _, c := range checks {
			fmt.Fprintf(wc, "  %s %s\t%s\n", c.Status, c.Item, c.Detail)
		}
		wc.Flush()
		fmt.Println()

		// Summary
		failCount := 0
		for _, c := range checks {
			if c.Status == "❌" {
				failCount++
			}
		}
		if failCount > 0 {
			fmt.Printf("⚠️  %d check(s) failed. Please fix the issues above.\n\n", failCount)
		} else {
			fmt.Println("✅ All checks passed.")
		}

		return nil
	},
}

// ==================== INFO helpers ====================

func detectNetwork(binDir string) string {
	versionPath := filepath.Join(binDir, "VERSION")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return "unknown"
	}
	content := strings.ToLower(string(data))
	if strings.Contains(content, "atlantic") {
		return "Atlantic"
	}
	if strings.Contains(content, "mainnet") {
		return "Mainnet"
	}
	return "unknown"
}

func getMemoryInfo() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kbVal, _ := strconv.ParseUint(fields[1], 10, 64)
					return fmt.Sprintf("%.1f GB", float64(kbVal)/1024/1024)
				}
			}
		}
	}
	// macOS fallback
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		bytesVal, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
		return fmt.Sprintf("%.1f GB", float64(bytesVal)/1024/1024/1024)
	}
	return "unknown"
}

func getNodeIDFromKeys(keysDir string) (string, error) {
	pubKeyPath := filepath.Join(keysDir, "domain.pub")
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read domain.pub: %v", err)
	}

	rawPubKey := strings.TrimSpace(string(pubKeyData))
	if strings.HasPrefix(rawPubKey, "0x1003") {
		rawPubKey = rawPubKey[6:]
	} else if strings.HasPrefix(rawPubKey, "0x4003") {
		rawPubKey = rawPubKey[6:]
	} else if strings.HasPrefix(rawPubKey, "0x4002") {
		rawPubKey = rawPubKey[6:]
	} else if strings.HasPrefix(rawPubKey, "1003") {
		rawPubKey = rawPubKey[4:]
	} else if strings.HasPrefix(rawPubKey, "0x") {
		rawPubKey = rawPubKey[2:]
	}

	pubKeyBytes, err := hex.DecodeString(rawPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %v", err)
	}

	hash := sha256.Sum256(pubKeyBytes)
	return fmt.Sprintf("0x%s", hex.EncodeToString(hash[:])), nil
}

func getValidatorStatus(cmd *cobra.Command, keysDir string, rpcEndpoint string) string {
	pubKeyPath := filepath.Join(keysDir, "domain.pub")

	poolIDHex, err := computePoolID(pubKeyPath)
	if err != nil {
		return fmt.Sprintf("❌ (error: %v)", err)
	}

	poolIDHex = strings.TrimPrefix(poolIDHex, "0x")
	poolIDBytes, err := hex.DecodeString(poolIDHex)
	if err != nil {
		return fmt.Sprintf("❌ (invalid pool ID: %v)", err)
	}

	var poolIDBytes32 [32]byte
	copy(poolIDBytes32[:], poolIDBytes)

	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		return fmt.Sprintf("❌ (RPC error: %v)", err)
	}
	defer client.Close()

	parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
	if err != nil {
		return fmt.Sprintf("❌ (ABI error: %v)", err)
	}

	contractAddr := common.HexToAddress(stakingAddress)
	data, err := parsedABI.Pack("getValidator", poolIDBytes32)
	if err != nil {
		return fmt.Sprintf("❌ (pack error: %v)", err)
	}

	result, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return fmt.Sprintf("❌ (call error: %v)", err)
	}

	results, err := parsedABI.Unpack("getValidator", result)
	if err != nil {
		return fmt.Sprintf("❌ (unpack error: %v)", err)
	}

	if len(results) == 0 {
		return "❌ (no result)"
	}

	v := reflect.ValueOf(results[0])
	if v.Kind() != reflect.Struct {
		return "❌ (unexpected type)"
	}

	statusField := v.FieldByName("Status")
	if !statusField.IsValid() {
		return "❌ (status field not found)"
	}

	status := uint8(statusField.Uint())
	if status > 0 {
		return fmt.Sprintf("✅ (status=%d)", status)
	}
	return "❌ (not registered)"
}

// ==================== CHECK: ulimit ====================

func checkUlimit() []checkItem {
	out, err := exec.Command("bash", "-c", "ulimit -n").Output()
	if err != nil {
		return []checkItem{{"Ulimit (open files)", "❌", fmt.Sprintf("failed to get: %v", err)}}
	}
	ulimitStr := strings.TrimSpace(string(out))
	ulimitVal, _ := strconv.ParseUint(ulimitStr, 10, 64)

	if ulimitVal >= 655350 {
		return []checkItem{{"Ulimit (open files)", "✅", ulimitStr}}
	}
	return []checkItem{{"Ulimit (open files)", "❌", fmt.Sprintf("%s (required >= 655350)", ulimitStr)}}
}

// ==================== CHECK: Spec Version ====================

func checkSpecVersion(binDir string) []checkItem {
	versionPath := filepath.Join(binDir, "VERSION")
	localData, err := os.ReadFile(versionPath)
	if err != nil {
		return []checkItem{{"Spec Version", "❌", fmt.Sprintf("failed to read %s: %v", versionPath, err)}}
	}

	localContent := strings.TrimSpace(string(localData))

	var localVersions map[string]json.RawMessage
	if err := json.Unmarshal([]byte(localContent), &localVersions); err != nil {
		return []checkItem{{"Spec Version", "❌", fmt.Sprintf("failed to parse local VERSION: %v", err)}}
	}

	// Detect network
	isAtlantic := false
	for key := range localVersions {
		if strings.Contains(strings.ToLower(key), "atlantic") {
			isAtlantic = true
			break
		}
	}

	var remoteURL string
	if isAtlantic {
		remoteURL = atlanticVersionURL
	} else {
		remoteURL = mainnetVersionURL
	}

	resp, err := http.Get(remoteURL)
	if err != nil {
		return []checkItem{{"Spec Version", "❌", fmt.Sprintf("failed to fetch remote: %v", err)}}
	}
	defer resp.Body.Close()

	remoteData, err := io.ReadAll(resp.Body)
	if err != nil {
		return []checkItem{{"Spec Version", "❌", fmt.Sprintf("failed to read remote: %v", err)}}
	}

	remoteContent := strings.TrimSpace(string(remoteData))

	var localMap, remoteMap map[string]map[string]interface{}
	if err := json.Unmarshal([]byte(localContent), &localMap); err != nil {
		return []checkItem{{"Spec Version", "❌", fmt.Sprintf("parse error: %v", err)}}
	}
	if err := json.Unmarshal([]byte(remoteContent), &remoteMap); err != nil {
		return []checkItem{{"Spec Version", "❌", fmt.Sprintf("remote parse error: %v", err)}}
	}

	matched := true
	var diffs []string

	for key, remoteVal := range remoteMap {
		localVal, exists := localMap[key]
		if !exists {
			matched = false
			diffs = append(diffs, fmt.Sprintf("missing: %s", key))
			continue
		}
		remoteJSON, _ := json.Marshal(remoteVal)
		localJSON, _ := json.Marshal(localVal)
		if string(remoteJSON) != string(localJSON) {
			matched = false
			diffs = append(diffs, fmt.Sprintf("%s mismatch", key))
		}
	}

	for key := range localMap {
		if _, exists := remoteMap[key]; !exists {
			matched = false
			diffs = append(diffs, fmt.Sprintf("extra: %s", key))
		}
	}

	if matched {
		return []checkItem{{"Spec Version", "✅", "matches remote"}}
	}
	return []checkItem{{"Spec Version", "❌", strings.Join(diffs, "; ")}}
}

// ==================== CHECK: Binary Version ====================

func checkBinaryVersion(binDir string) checkItem {
	binaryPath := filepath.Join(binDir, "pharos_light")
	libPath := filepath.Join(binDir, "libevmone.so")
	cmdExec := exec.Command(binaryPath, "--version")
	cmdExec.Env = append(os.Environ(), fmt.Sprintf("LD_PRELOAD=%s", libPath))

	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return checkItem{"Binary Version", "❌", fmt.Sprintf("failed: %v (%s)", err, strings.TrimSpace(string(out)))}
	}

	versionStr := strings.TrimSpace(string(out))
	commitID := versionStr
	if idx := strings.Index(versionStr, "-"); idx > 0 {
		commitID = versionStr[:idx]
	}

	return checkItem{"Binary Version", "✅", fmt.Sprintf("%s (commit: %s)", versionStr, commitID)}
}

func init() {
	rootCmd.AddCommand(healthCheckCmd)

	healthCheckCmd.Flags().StringVarP(&hcKeysDir, "keys-dir", "k", "./keys", "Directory containing domain.pub")
	healthCheckCmd.Flags().StringVar(&hcBinDir, "bin-dir", "./bin", "Directory containing pharos_light and VERSION")
	healthCheckCmd.Flags().StringVar(&hcRPCEndpoint, "rpc-endpoint", "", "RPC endpoint URL (auto-detect if empty)")
}
