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

type checkResult struct {
	Item   string
	Status string // ✅ or ❌
	Detail string
}

var healthCheckCmd = &cobra.Command{
	Use:   "health-check",
	Short: "Run node health checks",
	Long:  "Perform a series of self-checks on the node: ulimit, CPU/memory, spec version, binary version, node ID, validator status",
	RunE: func(cmd *cobra.Command, args []string) error {
		var results []checkResult

		// 1. System resources: ulimit, CPU, memory
		results = append(results, checkUlimit()...)
		results = append(results, checkSystemResources()...)

		// 2. Spec version check
		results = append(results, checkSpecVersion(hcBinDir)...)

		// 3. Binary version (pharos_light)
		results = append(results, checkBinaryVersion(hcBinDir))

		// 4. Node ID
		results = append(results, checkNodeID(hcKeysDir))

		// 5. Validator status
		// Determine RPC endpoint: if user didn't specify, pick based on network
		rpcEndpoint := hcRPCEndpoint
		if rpcEndpoint == "" {
			// Detect network from spec version results
			isAtlantic := false
			for _, r := range results {
				if r.Item == "Network" && r.Detail == "Atlantic" {
					isAtlantic = true
					break
				}
			}
			if isAtlantic {
				rpcEndpoint = "https://atlantic.dplabs-internal.com"
			} else {
				rpcEndpoint = "https://rpc.pharos.xyz"
			}
		}
		results = append(results, checkValidatorStatus(cmd, hcKeysDir, rpcEndpoint))

		// Print table
		fmt.Println()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "CHECK ITEM\tSTATUS\tDETAIL")
		fmt.Fprintln(w, "----------\t------\t------")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Item, r.Status, r.Detail)
		}
		w.Flush()
		fmt.Println()

		return nil
	},
}

// ==================== 1. ulimit check ====================

func checkUlimit() []checkResult {
	var results []checkResult

	// Use ulimit -n to get per-process open file limit
	out, err := exec.Command("bash", "-c", "ulimit -n").Output()
	if err != nil {
		results = append(results, checkResult{"Ulimit (open files)", "❌", fmt.Sprintf("failed to get ulimit: %v", err)})
		return results
	}
	ulimitStr := strings.TrimSpace(string(out))
	ulimitVal, _ := strconv.ParseUint(ulimitStr, 10, 64)

	status := "✅"
	detail := ulimitStr
	if ulimitVal < 655350 {
		status = "❌"
		detail = fmt.Sprintf("%s (required >= 655350)", ulimitStr)
	}
	results = append(results, checkResult{"Ulimit (open files)", status, detail})
	return results
}

// ==================== CPU & Memory ====================

func checkSystemResources() []checkResult {
	var results []checkResult

	// CPU cores
	cpuCores := runtime.NumCPU()
	results = append(results, checkResult{"CPU Cores", "✅", fmt.Sprintf("%d", cpuCores)})

	// Memory - try /proc/meminfo (Linux), fallback to sysctl (macOS)
	memStr := "unknown"
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kbVal, _ := strconv.ParseUint(fields[1], 10, 64)
					gbVal := float64(kbVal) / 1024 / 1024
					memStr = fmt.Sprintf("%.1f GB", gbVal)
				}
				break
			}
		}
	} else {
		// macOS fallback
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			bytesVal, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
			gbVal := float64(bytesVal) / 1024 / 1024 / 1024
			memStr = fmt.Sprintf("%.1f GB", gbVal)
		}
	}
	results = append(results, checkResult{"Memory", "✅", memStr})

	return results
}

// ==================== 2. Spec Version check ====================

func checkSpecVersion(binDir string) []checkResult {
	var results []checkResult

	versionPath := filepath.Join(binDir, "VERSION")
	localData, err := os.ReadFile(versionPath)
	if err != nil {
		results = append(results, checkResult{"Spec Version", "❌", fmt.Sprintf("failed to read %s: %v", versionPath, err)})
		return results
	}

	localContent := strings.TrimSpace(string(localData))

	// Parse local version JSON
	var localVersions map[string]json.RawMessage
	if err := json.Unmarshal([]byte(localContent), &localVersions); err != nil {
		results = append(results, checkResult{"Spec Version", "❌", fmt.Sprintf("failed to parse local VERSION: %v", err)})
		return results
	}

	// Detect network type by checking keys
	isAtlantic := false
	for key := range localVersions {
		if strings.Contains(strings.ToLower(key), "atlantic") {
			isAtlantic = true
			break
		}
	}

	var remoteURL string
	var networkName string
	if isAtlantic {
		remoteURL = atlanticVersionURL
		networkName = "Atlantic"
	} else {
		remoteURL = mainnetVersionURL
		networkName = "Mainnet"
	}

	results = append(results, checkResult{"Network", "✅", networkName})

	// Fetch remote version
	resp, err := http.Get(remoteURL)
	if err != nil {
		results = append(results, checkResult{"Spec Version", "❌", fmt.Sprintf("failed to fetch remote version: %v", err)})
		return results
	}
	defer resp.Body.Close()

	remoteData, err := io.ReadAll(resp.Body)
	if err != nil {
		results = append(results, checkResult{"Spec Version", "❌", fmt.Sprintf("failed to read remote version: %v", err)})
		return results
	}

	remoteContent := strings.TrimSpace(string(remoteData))

	// Parse both as map[string]map[string]interface{} for comparison
	var localMap, remoteMap map[string]map[string]interface{}
	if err := json.Unmarshal([]byte(localContent), &localMap); err != nil {
		results = append(results, checkResult{"Spec Version", "❌", fmt.Sprintf("failed to parse local VERSION: %v", err)})
		return results
	}
	if err := json.Unmarshal([]byte(remoteContent), &remoteMap); err != nil {
		results = append(results, checkResult{"Spec Version", "❌", fmt.Sprintf("failed to parse remote version: %v", err)})
		return results
	}

	// Compare
	matched := true
	var diffs []string

	// Check all remote entries exist in local with same values
	for key, remoteVal := range remoteMap {
		localVal, exists := localMap[key]
		if !exists {
			matched = false
			diffs = append(diffs, fmt.Sprintf("missing local entry: %s", key))
			continue
		}
		remoteJSON, _ := json.Marshal(remoteVal)
		localJSON, _ := json.Marshal(localVal)
		if string(remoteJSON) != string(localJSON) {
			matched = false
			diffs = append(diffs, fmt.Sprintf("%s: local=%s remote=%s", key, string(localJSON), string(remoteJSON)))
		}
	}

	// Check local entries not in remote
	for key := range localMap {
		if _, exists := remoteMap[key]; !exists {
			matched = false
			diffs = append(diffs, fmt.Sprintf("extra local entry: %s", key))
		}
	}

	if matched {
		results = append(results, checkResult{"Spec Version", "✅", "matches remote"})
	} else {
		results = append(results, checkResult{"Spec Version", "❌", fmt.Sprintf("MISMATCH: %s", strings.Join(diffs, "; "))})
	}

	return results
}

// ==================== 3. Binary version ====================

func checkBinaryVersion(binDir string) checkResult {
	// Run: LD_PRELOAD=./bin/libevmone.so ./bin/pharos_light --version
	binaryPath := filepath.Join(binDir, "pharos_light")
	libPath := filepath.Join(binDir, "libevmone.so")
	cmdExec := exec.Command(binaryPath, "--version")
	cmdExec.Env = append(os.Environ(), fmt.Sprintf("LD_PRELOAD=%s", libPath))

	out, err := cmdExec.CombinedOutput()
	if err != nil {
		return checkResult{"Binary Version", "❌", fmt.Sprintf("failed to get version: %v (%s)", err, strings.TrimSpace(string(out)))}
	}

	versionStr := strings.TrimSpace(string(out))
	// Extract commit ID: "72eeb262f-dirty" -> "72eeb262f"
	commitID := versionStr
	if idx := strings.Index(versionStr, "-"); idx > 0 {
		commitID = versionStr[:idx]
	}

	return checkResult{"Binary Version", "✅", fmt.Sprintf("%s (commit: %s)", versionStr, commitID)}
}

// ==================== 4. Node ID ====================

func checkNodeID(keysDir string) checkResult {
	pubKeyPath := filepath.Join(keysDir, "domain.pub")
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return checkResult{"Node ID", "❌", fmt.Sprintf("failed to read domain.pub: %v", err)}
	}

	pubKeyHex := strings.TrimSpace(string(pubKeyData))

	// Strip prefix
	rawPubKey := pubKeyHex
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
		return checkResult{"Node ID", "❌", fmt.Sprintf("failed to decode public key: %v", err)}
	}

	hash := sha256.Sum256(pubKeyBytes)
	nodeID := hex.EncodeToString(hash[:])

	return checkResult{"Node ID", "✅", fmt.Sprintf("0x%s", nodeID)}
}

// ==================== 5. Validator status ====================

func checkValidatorStatus(cmd *cobra.Command, keysDir string, rpcEndpoint string) checkResult {
	pubKeyPath := filepath.Join(keysDir, "domain.pub")

	// Compute pool ID
	poolIDHex, err := computePoolID(pubKeyPath)
	if err != nil {
		return checkResult{"Validator", "❌", fmt.Sprintf("failed to compute pool ID: %v", err)}
	}

	poolIDHex = strings.TrimPrefix(poolIDHex, "0x")
	poolIDBytes, err := hex.DecodeString(poolIDHex)
	if err != nil {
		return checkResult{"Validator", "❌", fmt.Sprintf("invalid pool ID: %v", err)}
	}

	var poolIDBytes32 [32]byte
	copy(poolIDBytes32[:], poolIDBytes)

	// Connect to RPC
	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		return checkResult{"Validator", "❌", fmt.Sprintf("failed to connect to RPC: %v", err)}
	}
	defer client.Close()

	parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
	if err != nil {
		return checkResult{"Validator", "❌", fmt.Sprintf("failed to parse ABI: %v", err)}
	}

	contractAddr := common.HexToAddress(stakingAddress)

	data, err := parsedABI.Pack("getValidator", poolIDBytes32)
	if err != nil {
		return checkResult{"Validator", "❌", fmt.Sprintf("failed to pack call: %v", err)}
	}

	result, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return checkResult{"Validator", "❌", fmt.Sprintf("contract call failed: %v", err)}
	}

	results, err := parsedABI.Unpack("getValidator", result)
	if err != nil {
		return checkResult{"Validator", "❌", fmt.Sprintf("failed to unpack: %v", err)}
	}

	if len(results) == 0 {
		return checkResult{"Validator", "❌", "no result from getValidator"}
	}

	v := reflect.ValueOf(results[0])
	if v.Kind() != reflect.Struct {
		return checkResult{"Validator", "❌", "unexpected result type"}
	}

	statusField := v.FieldByName("Status")
	if !statusField.IsValid() {
		return checkResult{"Validator", "❌", "status field not found"}
	}

	status := uint8(statusField.Uint())
	if status > 0 {
		return checkResult{"Validator", "✅", fmt.Sprintf("status=%d (active)", status)}
	}
	return checkResult{"Validator", "❌", "not a validator (status=0)"}
}

func init() {
	rootCmd.AddCommand(healthCheckCmd)

	healthCheckCmd.Flags().StringVarP(&hcKeysDir, "keys-dir", "k", "./keys", "Directory containing domain.pub")
	healthCheckCmd.Flags().StringVar(&hcBinDir, "bin-dir", "./bin", "Directory containing pharos_light and VERSION")
	healthCheckCmd.Flags().StringVar(&hcRPCEndpoint, "rpc-endpoint", "", "RPC endpoint URL (auto-detect if empty: atlantic->atlantic-rpc.dplabs-internal.com, mainnet->rpc.pharos.xyz)")
}
