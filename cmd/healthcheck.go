package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

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

	atlanticChainID = 0xa8231 // 689713
	mainnetChainID  = 0x688   // 1672
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
	Long:  "Perform a series of self-checks on the node: system info, ulimit, spec version, binary version, node ID, validator status, block production",
	RunE: func(cmd *cobra.Command, args []string) error {
		var infos []infoItem
		var checks []checkItem

		// === INFO section ===
		localRPC := "http://127.0.0.1:18100"
		network, netErr := detectNetworkByChainID(localRPC)
		if netErr != nil {
			network = "unknown (" + netErr.Error() + ")"
		}
		infos = append(infos, infoItem{"Network", network})
		infos = append(infos, infoItem{"CPU Cores", fmt.Sprintf("%d", runtime.NumCPU())})
		infos = append(infos, infoItem{"Memory", getMemoryInfo()})

		nodeID, nodeIDErr := getNodeIDFromKeys(hcKeysDir)
		if nodeIDErr != nil {
			infos = append(infos, infoItem{"Node ID", fmt.Sprintf("error: %v", nodeIDErr)})
		} else {
			infos = append(infos, infoItem{"Node ID", nodeID})
		}

		// Determine remote RPC endpoint for validator check
		remoteRPC := hcRPCEndpoint
		if remoteRPC == "" {
			if network == "Atlantic" {
				remoteRPC = "https://atlantic.dplabs-internal.com"
			} else {
				remoteRPC = "https://rpc.pharos.xyz"
			}
		}
		validatorStr := getValidatorStatus(cmd, hcKeysDir, remoteRPC)
		infos = append(infos, infoItem{"Validator", validatorStr})

		// === CHECK section ===
		checks = append(checks, checkUlimit()...)
		checks = append(checks, checkSpecVersion(hcBinDir)...)
		checks = append(checks, checkBinaryVersion(hcBinDir))
		checks = append(checks, checkBlockProduction(localRPC))

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

// detectNetworkByChainID connects to local RPC and returns network name based on chainID
func detectNetworkByChainID(rpcURL string) (string, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return "", fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to get chainID: %w", err)
	}

	switch chainID.Int64() {
	case atlanticChainID:
		return "Atlantic", nil
	case mainnetChainID:
		return "Mainnet", nil
	default:
		return fmt.Sprintf("unknown (chainID=%d)", chainID.Int64()), nil
	}
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
		return fmt.Sprintf("error: %v", err)
	}

	poolIDHex = strings.TrimPrefix(poolIDHex, "0x")
	poolIDBytes, err := hex.DecodeString(poolIDHex)
	if err != nil {
		return fmt.Sprintf("error: invalid pool ID: %v", err)
	}

	var poolIDBytes32 [32]byte
	copy(poolIDBytes32[:], poolIDBytes)

	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		return fmt.Sprintf("error: RPC %v", err)
	}
	defer client.Close()

	parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
	if err != nil {
		return fmt.Sprintf("error: ABI %v", err)
	}

	contractAddr := common.HexToAddress(stakingAddress)
	data, err := parsedABI.Pack("getValidator", poolIDBytes32)
	if err != nil {
		return fmt.Sprintf("error: pack %v", err)
	}

	result, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return fmt.Sprintf("error: call %v", err)
	}

	results, err := parsedABI.Unpack("getValidator", result)
	if err != nil {
		return fmt.Sprintf("error: unpack %v", err)
	}

	if len(results) == 0 {
		return "no result"
	}

	v := reflect.ValueOf(results[0])
	if v.Kind() != reflect.Struct {
		return "unexpected type"
	}

	statusField := v.FieldByName("Status")
	if !statusField.IsValid() {
		return "status field not found"
	}

	status := uint8(statusField.Uint())
	if status > 0 {
		return fmt.Sprintf("✅ (status=%d)", status)
	}
	return "not registered"
}

// ==================== CHECK: ulimit ====================

func checkUlimit() []checkItem {
	out, err := exec.Command("bash", "-c", "ulimit -n").Output()
	if err != nil {
		return []checkItem{{"Ulimit (open files)", "❌", fmt.Sprintf("failed to get: %v", err)}}
	}
	ulimitStr := strings.TrimSpace(string(out))
	ulimitVal, _ := strconv.ParseUint(ulimitStr, 10, 64)

	if ulimitVal >= 10000000 {
		return []checkItem{{"Ulimit (open files)", "✅", ulimitStr}}
	}
	return []checkItem{{"Ulimit (open files)", "❌", fmt.Sprintf("%s (required >= 10000000)", ulimitStr)}}
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

	var localMap, remoteMap map[string]map[string]any
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

// ==================== CHECK: Block Production ====================

// getBlockNumber calls eth_blockNumber via JSON-RPC and returns the block number
func getBlockNumber(rpcURL string) (uint64, error) {
	payload := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}
	if result.Error != nil {
		return 0, fmt.Errorf("rpc error: %s", result.Error.Message)
	}

	// Parse hex block number (e.g. "0x1a2b3c")
	hexStr := strings.TrimPrefix(result.Result, "0x")
	blockNum, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse block number %q: %v", result.Result, err)
	}
	return blockNum, nil
}

func checkBlockProduction(rpcURL string) checkItem {
	block1, err := getBlockNumber(rpcURL)
	if err != nil {
		return checkItem{"Block Production", "❌", fmt.Sprintf("failed to get block number: %v", err)}
	}

	// Wait 3 seconds and check again
	time.Sleep(3 * time.Second)

	block2, err := getBlockNumber(rpcURL)
	if err != nil {
		return checkItem{"Block Production", "❌", fmt.Sprintf("failed to get block number (2nd): %v", err)}
	}

	if block2 > block1 {
		return checkItem{"Block Production", "✅", fmt.Sprintf("block %d → %d (+%d in 3s)", block1, block2, block2-block1)}
	}
	return checkItem{"Block Production", "❌", fmt.Sprintf("block stuck at %d (no increase in 3s)", block1)}
}

// ==================== network-test command ====================

var (
	ntRPCEndpoint string
	ntKeysDir     string
	ntPort        string
	ntCount       int
)

var networkTestCmd = &cobra.Command{
	Use:   "network-test",
	Short: "TCP latency test to all validator endpoints",
	Long:  "Fetch all validator endpoints from the staking contract and measure TCP connection latency (like nping but pure Go, no extra tools needed)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Auto-detect RPC endpoint from chainID if not explicitly set
		rpcEndpoint := ntRPCEndpoint
		if !cmd.Flags().Changed("rpc-endpoint") {
			localRPC := "http://127.0.0.1:18100"
			network, err := detectNetworkByChainID(localRPC)
			if err != nil {
				return fmt.Errorf("failed to detect network: %w (use --rpc-endpoint to specify manually)", err)
			}
			if network == "Atlantic" {
				rpcEndpoint = "https://atlantic.dplabs-internal.com"
			} else {
				rpcEndpoint = "https://rpc.pharos.xyz"
			}
			fmt.Printf("Auto-detected network: %s, RPC: %s\n", network, rpcEndpoint)
		}

		// Get all active validators from contract
		client, err := ethclient.Dial(rpcEndpoint)
		if err != nil {
			return fmt.Errorf("failed to connect to RPC: %w", err)
		}
		defer client.Close()

		parsedABI, err := abi.JSON(strings.NewReader(stakingABI))
		if err != nil {
			return fmt.Errorf("failed to parse ABI: %w", err)
		}

		contractAddr := common.HexToAddress(stakingAddress)

		// We need to get the list of active validators
		// Try calling getActiveValidators if available, otherwise use epoch info
		// For now, we'll read from a validators file or use admin_peers
		// Actually, let's try admin_peers first via RPC
		fmt.Println("🌐 Fetching validator endpoints...")
		fmt.Println()

		type validatorEndpoint struct {
			Tag      string
			Endpoint string
			PoolID   string
		}

		var endpoints []validatorEndpoint

		// Try to get active validators from getActiveValidators
		activeData, err := parsedABI.Pack("getActiveValidators")
		if err == nil {
			activeResult, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
				To:   &contractAddr,
				Data: activeData,
			}, nil)
			if err == nil && len(activeResult) > 0 {
				activeResults, err := parsedABI.Unpack("getActiveValidators", activeResult)
				if err == nil && len(activeResults) > 0 {
					// activeResults[0] should be []bytes32
					poolIDs, ok := activeResults[0].([][32]byte)
					if ok {
						for _, pid := range poolIDs {
							// Get validator info for each pool ID
							vData, err := parsedABI.Pack("getValidator", pid)
							if err != nil {
								continue
							}
							vResult, err := client.CallContract(cmd.Context(), ethereum.CallMsg{
								To:   &contractAddr,
								Data: vData,
							}, nil)
							if err != nil {
								continue
							}
							vResults, err := parsedABI.Unpack("getValidator", vResult)
							if err != nil || len(vResults) == 0 {
								continue
							}
							v := reflect.ValueOf(vResults[0])
							if v.Kind() != reflect.Struct {
								continue
							}
							ep := v.FieldByName("Endpoint").String()
							desc := v.FieldByName("Description").String()
							if ep != "" {
								endpoints = append(endpoints, validatorEndpoint{
									Tag:      desc,
									Endpoint: ep,
									PoolID:   "0x" + hex.EncodeToString(pid[:]),
								})
							}
						}
					}
				}
			}
		}

		if len(endpoints) == 0 {
			return fmt.Errorf("no validator endpoints found. Make sure the staking contract has getActiveValidators method or validators have endpoints set")
		}

		// TCP latency test
		// Filter out validators with invalid endpoints
		var validEndpoints []validatorEndpoint
		var skippedCount int
		for _, ep := range endpoints {
			target := parseEndpoint(ep.Endpoint, ntPort)
			if target == "" {
				skippedCount++
				continue
			}
			validEndpoints = append(validEndpoints, ep)
		}

		fmt.Printf("Found %d validators (%d with valid endpoints, %d skipped), TCP latency test (%d probes each)...\n\n",
			len(endpoints), len(validEndpoints), skippedCount, ntCount)

		type testResult struct {
			Tag    string
			Target string
			Min    time.Duration
			Avg    time.Duration
			Max    time.Duration
			Lost   int
			Ok     bool // has at least one successful probe
		}

		var results []testResult

		for _, ep := range validEndpoints {
			target := parseEndpoint(ep.Endpoint, ntPort)

			var latencies []time.Duration
			var failCount int

			for i := 0; i < ntCount; i++ {
				start := time.Now()
				conn, err := net.DialTimeout("tcp", target, 5*time.Second)
				elapsed := time.Since(start)
				if err != nil {
					failCount++
					continue
				}
				conn.Close()
				latencies = append(latencies, elapsed)
			}

			if len(latencies) == 0 {
				results = append(results, testResult{Tag: ep.Tag, Target: target, Ok: false})
				continue
			}

			minL, maxL, totalL := latencies[0], latencies[0], time.Duration(0)
			for _, l := range latencies {
				totalL += l
				if l < minL {
					minL = l
				}
				if l > maxL {
					maxL = l
				}
			}
			avgL := totalL / time.Duration(len(latencies))
			results = append(results, testResult{Tag: ep.Tag, Target: target, Min: minL, Avg: avgL, Max: maxL, Lost: failCount, Ok: true})
		}

		// Sort by AVG latency (unreachable at the end)
		sort.Slice(results, func(i, j int) bool {
			if results[i].Ok != results[j].Ok {
				return results[i].Ok // reachable before unreachable
			}
			return results[i].Avg < results[j].Avg
		})

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "VALIDATOR\tENDPOINT\tMIN\tAVG\tMAX\tSTATUS")
		fmt.Fprintln(w, "---------\t--------\t---\t---\t---\t------")

		for _, r := range results {
			if !r.Ok {
				fmt.Fprintf(w, "%s\t%s\t-\t-\t-\t❌ unreachable\n", r.Tag, r.Target)
				continue
			}
			status := "✅"
			if r.Lost > 0 {
				status = fmt.Sprintf("⚠️ %d/%d lost", r.Lost, ntCount)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				r.Tag, r.Target,
				formatDuration(r.Min), formatDuration(r.Avg), formatDuration(r.Max),
				status)
		}
		w.Flush()
		fmt.Println()

		return nil
	},
}

// parseEndpoint extracts host:port from endpoint string like "tcp://1.2.3.4:19000"
// Returns empty string if endpoint is invalid (no IP/hostname)
func parseEndpoint(endpoint string, defaultPort string) string {
	host := endpoint
	// Strip protocol prefixes
	host = strings.TrimPrefix(host, "tcp://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	// Strip path
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}

	// Try to split host:port
	h, p, err := net.SplitHostPort(host)
	if err == nil {
		host = h
		if p != "" {
			defaultPort = p
		}
	}

	// Validate: must have a real hostname or IP (not empty, not just "tcp", etc.)
	host = strings.TrimSpace(host)
	if host == "" || host == "tcp" || host == "http" || host == "https" {
		return ""
	}

	return net.JoinHostPort(host, defaultPort)
}

func formatDuration(d time.Duration) string {
	ms := float64(d.Microseconds()) / 1000.0
	if ms < 1 {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	return fmt.Sprintf("%.1fms", ms)
}

func init() {
	rootCmd.AddCommand(healthCheckCmd)
	rootCmd.AddCommand(networkTestCmd)

	healthCheckCmd.Flags().StringVarP(&hcKeysDir, "keys-dir", "k", "./keys", "Directory containing domain.pub")
	healthCheckCmd.Flags().StringVar(&hcBinDir, "bin-dir", "./bin", "Directory containing pharos_light and VERSION")
	healthCheckCmd.Flags().StringVar(&hcRPCEndpoint, "rpc-endpoint", "", "RPC endpoint URL (auto-detect if empty)")

	networkTestCmd.Flags().StringVar(&ntRPCEndpoint, "rpc-endpoint", "", "RPC endpoint URL (auto-detect: atlantic->atlantic.dplabs-internal.com, mainnet->rpc.pharos.xyz)")
	networkTestCmd.Flags().StringVarP(&ntKeysDir, "keys-dir", "k", "./keys", "Directory containing domain.pub")
	networkTestCmd.Flags().StringVar(&ntPort, "port", "18100", "TCP port to test")
	networkTestCmd.Flags().IntVar(&ntCount, "count", 3, "Number of TCP probes per endpoint")
}
