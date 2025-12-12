package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

// DeployConfig matches the Python schema structure
type DeployConfig struct {
	BuildRoot         string                   `json:"build_root"`
	ChainID           string                   `json:"chain_id"`
	ChainProtocol     string                   `json:"chain_protocol"`
	Version           string                   `json:"version"`
	RunUser           string                   `json:"run_user"`
	DeployRoot        string                   `json:"deploy_root"`
	AdminAddr         string                   `json:"admin_addr"`
	ProxyAdminAddr    string                   `json:"proxy_admin_addr"`
	GenesisTpl        string                   `json:"genesis_tpl"`
	Mygrid            MyGridConfig             `json:"mygrid"`
	DomainKeyType     string                   `json:"domain_key_type"`
	ClientKeyType     string                   `json:"client_key_type"`
	UseGeneratedKeys  bool                     `json:"use_generated_keys"`
	UseLatestVersion  bool                     `json:"use_latest_version"`
	EnableDora        bool                     `json:"enable_dora"`
	Docker            DockerConfig             `json:"docker"`
	Common            CommonConfig             `json:"common"`
	Pharos            ServiceConfig            `json:"pharos"`
	Storage           ServiceConfig            `json:"storage"`
	Domains           map[string]DomainConfig  `json:"domains"`
}

type MyGridConfig struct {
	Conf map[string]interface{} `json:"conf"`
	Env  map[string]interface{} `json:"env"`
}

type DockerConfig struct {
	Enable   bool   `json:"enable"`
	Registry string `json:"registry"`
}

type CommonConfig struct {
	Env    map[string]interface{} `json:"env"`
	Log    map[string]interface{} `json:"log"`
	Config map[string]interface{} `json:"config"`
	Gflags map[string]interface{} `json:"gflags"`
}

type ServiceConfig struct {
	Args   []string                `json:"args"`
	Env    map[string]interface{} `json:"env"`
	Log    map[string]interface{} `json:"log"`
	Config map[string]interface{} `json:"config"`
	Gflags map[string]interface{} `json:"gflags"`
}

type DomainConfig struct {
	DeployDir           string        `json:"deploy_dir"`
	DomainRole          int           `json:"domain_role"`
	KeyPasswd           string        `json:"key_passwd"`
	DomainPort          int           `json:"domain_port"`
	ClientTCPPort       int           `json:"client_tcp_port"`
	ClientWSPort        int           `json:"client_ws_port"`
	ClientWSSPort       int           `json:"client_wss_port"`
	ClientHTTPPort      int           `json:"client_http_port"`
	Cluster             []ClusterNode `json:"cluster"`
	InitialStakeInGwei  int64         `json:"initial_stake_in_gwei"`
}

type ClusterNode struct {
	Host      string `json:"host"`
	StartPort int    `json:"start_port"`
	Instances string `json:"instances"`
	DeployIP  string `json:"deploy_ip"`
}

var generateCmd = &cobra.Command{
	Use:   "generate [deploy_file]",
	Short: "Generate domain files from deploy configuration",
	Long:  "Generate individual domain configuration files from a deploy.json file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		deployFile := "deploy.light.json"
		if len(args) > 0 {
			deployFile = args[0]
		}

		genesis, _ := cmd.Flags().GetBool("genesis")

		utils.Info("Generating domain files from: %s", deployFile)

		// Read deploy file
		data, err := os.ReadFile(deployFile)
		if err != nil {
			return fmt.Errorf("failed to read deploy file: %w", err)
		}

		var deploy DeployConfig
		if err := json.Unmarshal(data, &deploy); err != nil {
			return fmt.Errorf("failed to parse deploy file: %w", err)
		}

		// Generate domain files - one per domain like Python version
		for domainName, domainConfig := range deploy.Domains {
			domainFile := fmt.Sprintf("%s.json", domainName)
			utils.Info("Generating domain file: %s", domainFile)

			if err := generateDomainFile(domainFile, domainName, domainConfig, deploy); err != nil {
				utils.Error("Failed to generate %s: %v", domainFile, err)
				continue
			}
		}

		if genesis {
			utils.Info("Genesis flag enabled - would generate genesis files")
			// TODO: Implement genesis generation
		}

		return nil
	},
}

func generateDomainFile(filename, domainName string, domainConfig DomainConfig, deploy DeployConfig) error {
	// Generate NODE_ID - in Python this is generated from the public key
	// For now, generate a deterministic one based on domain name
	nodeID := generateNodeIDFromDomain(domainName, deploy)

	// Determine deploy_dir - use from domainConfig if set, otherwise construct it
	deployDir := domainConfig.DeployDir
	if deployDir == "" {
		if deploy.DeployRoot != "" {
			deployDir = filepath.Join(deploy.DeployRoot, domainName)
		} else {
			deployDir = filepath.Join("/data/pharos-node", domainName)
		}
	}

	// Determine key_passwd - use from domainConfig if set, otherwise default
	keyPasswd := domainConfig.KeyPasswd
	if keyPasswd == "" {
		keyPasswd = "123abc"
	}

	// Create domain structure matching Python output exactly
	domain := make(map[string]interface{})

	// Basic fields from deploy config
	domain["build_root"] = deploy.BuildRoot
	domain["chain_id"] = deploy.ChainID
	domain["chain_protocol"] = deploy.ChainProtocol
	domain["domain_label"] = domainName
	domain["version"] = deploy.Version
	domain["run_user"] = deploy.RunUser
	domain["deploy_dir"] = deployDir
	domain["genesis_conf"] = "../genesis.conf"

	// Mygrid config
	domain["mygrid"] = deploy.Mygrid

	// Secret configuration - use struct to maintain order
	secretDomain := struct {
		KeyType string             `json:"key_type"`
		Files   map[string]string  `json:"files"`
	}{
		KeyType: deploy.DomainKeyType,
		Files: map[string]string{
			"key":             fmt.Sprintf("../scripts/resources/domain_keys/%s/%s/new.key", deploy.DomainKeyType, domainName),
			"key_pub":         fmt.Sprintf("../scripts/resources/domain_keys/%s/%s/new.pub", deploy.DomainKeyType, domainName),
			"stabilizing_key": fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/new.key", domainName),
			"stabilizing_pk":  fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/new.pub", domainName),
		},
	}

	secretClient := struct {
		KeyType string             `json:"key_type"`
		Files   map[string]string  `json:"files"`
	}{
		KeyType: deploy.ClientKeyType,
		Files: map[string]string{
			"ca_cert": fmt.Sprintf("../conf/resources/portal/%s/client/ca.crt", deploy.ClientKeyType),
			"cert":    fmt.Sprintf("../conf/resources/portal/%s/client/client.crt", deploy.ClientKeyType),
			"key":     fmt.Sprintf("../conf/resources/portal/%s/client/client.key", deploy.ClientKeyType),
		},
	}

	domain["secret"] = map[string]interface{}{
		"domain": secretDomain,
		"client": secretClient,
	}

	// Feature flags
	domain["use_generated_keys"] = deploy.UseGeneratedKeys
	domain["enable_dora"] = deploy.EnableDora
	domain["key_passwd"] = keyPasswd

	// Docker config
	domain["docker"] = deploy.Docker

	// Common config - use struct to maintain order
	// Add metrics field that's expected in domain.json but not in deploy.common
	common := struct {
		Env    map[string]interface{} `json:"env"`
		Log    map[string]interface{} `json:"log"`
		Config map[string]interface{} `json:"config"`
		Gflags map[string]interface{} `json:"gflags"`
		Metrics map[string]interface{} `json:"metrics"`
	}{
		Env:    deploy.Common.Env,
		Log:    deploy.Common.Log,
		Config: deploy.Common.Config,
		Gflags: deploy.Common.Gflags,
		Metrics: map[string]interface{}{
			"push_address":  "",
			"push_interval": "",
			"enable":        false,
			"push_port":     "",
			"job_name":      "",
		},
	}
	domain["common"] = common

	// Create cluster configuration
	cluster := make(map[string]interface{})

	// Process each instance from the cluster nodes
	for _, clusterNode := range domainConfig.Cluster {
		// Split instances string like "light" or "controller1,storage1,storage2"
		instances := strings.Split(clusterNode.Instances, ",")

		for _, instanceName := range instances {
			instanceName = strings.TrimSpace(instanceName)
			if instanceName == "" {
				continue
			}

			// Extract service type by removing numeric suffix
			service := instanceName
			for i := len(instanceName) - 1; i >= 0; i-- {
				if instanceName[i] >= '0' && instanceName[i] <= '9' {
					service = instanceName[:i]
				} else {
					break
				}
			}

			// Extract numeric suffix if any
			idxSuffix := ""
			for i := 0; i < len(instanceName); i++ {
				if instanceName[i] >= '0' && instanceName[i] <= '9' {
					idxSuffix = instanceName[i:]
					break
				}
			}

			// Convert index suffix to integer, default to 0
			idx := 0
			if idxSuffix != "" {
				if parsedIdx, err := strconv.Atoi(idxSuffix); err == nil {
					idx = parsedIdx
				}
			}

			// Calculate port based on service type and index
			// Port calculation matches Python _start_port logic
			rpcPort := clusterNode.StartPort
			if service != "light" {
				// Find service index for port calculation
				services := []string{"etcd", "storage", "txpool", "controller", "dog", "portal", "light"}
				serviceIndex := 0
				for i, s := range services {
					if strings.Contains(service, s) {
						serviceIndex = i
						break
					}
				}
				rpcPort = clusterNode.StartPort + serviceIndex*1000 + idx
			}

			// Build instance configuration
			instance := map[string]interface{}{
				"service": service,
				"ip":      clusterNode.DeployIP,
				"host":    clusterNode.Host,
				"args":    []string{"-d"},
				"env":     make(map[string]string),
				"log":     make(map[string]interface{}),
				"config":  make(map[string]interface{}),
				"gflags":  make(map[string]interface{}),
			}

			// Build environment variables based on service type
			env := instance["env"].(map[string]string)

			// Common env vars for all services
			env[strings.ToUpper(service)+"_RPC_LISTEN_URL"] = fmt.Sprintf("0.0.0.0:%d", rpcPort)
			env[strings.ToUpper(service)+"_RPC_ADVERTISE_URL"] = fmt.Sprintf("%s:%d", clusterNode.Host, rpcPort)

			// Service-specific environment variables
			if service == "etcd" {
				env["ETCD_NAME"] = fmt.Sprintf("etcd%d", idx)
				env["ETCD_DATA_DIR"] = "../data/etcd"
				env["ETCD_LOG_OUTPUTS"] = "../log/etcd.log"
				env["ETCD_ENABLE_V2"] = "true"
				peerPort := rpcPort
				clientPort := peerPort + 100
				env["ETCD_LISTEN_PEER_URLS"] = fmt.Sprintf("http://0.0.0.0:%d", peerPort)
				env["ETCD_INITIAL_ADVERTISE_PEER_URLS"] = fmt.Sprintf("http://%s:%d", clusterNode.Host, peerPort)
				env["ETCD_LISTEN_CLIENT_URLS"] = fmt.Sprintf("http://0.0.0.0:%d", clientPort)
				env["ETCD_ADVERTISE_CLIENT_URLS"] = fmt.Sprintf("http://%s:%d", clusterNode.Host, clientPort)
			} else if service == "storage" {
				env["STORAGE_ID"] = idxSuffix
				env["STORAGE_RPC_LISTEN_URL"] = fmt.Sprintf("0.0.0.0:%d", rpcPort)
				env["STORAGE_RPC_ADVERTISE_URL"] = fmt.Sprintf("%s:%d", clusterNode.Host, rpcPort)
				env["STORAGE_MSU"] = fmt.Sprintf("%d-%d", idx*255, (idx+1)*255-1)
			} else if service == "txpool" {
				env["TXPOOL_PARTITION_LIST"] = fmt.Sprintf("%d-%d", idx*255, (idx+1)*255-1)
			} else if service == "controller" || service == "dog" || service == "light" {
				// Remove ID env var for these services
				delete(env, strings.ToUpper(service)+"_ID")
			}

			// Client URL configuration for portal and light
			if service == "portal" || service == "light" {
				tcpPort := domainConfig.ClientTCPPort + idx
				wsPort := domainConfig.ClientWSPort + idx
				wssPort := domainConfig.ClientWSSPort + idx
				httpPort := domainConfig.ClientHTTPPort + idx

				var clientUrls []string
				var clientListenUrls []string

				clientUrls = append(clientUrls, fmt.Sprintf("tls://%s:%d", clusterNode.Host, tcpPort))
				clientListenUrls = append(clientListenUrls, fmt.Sprintf("tls://0.0.0.0:%d", tcpPort))

				if httpPort > 0 {
					clientUrls = append(clientUrls, fmt.Sprintf("http://%s:%d", clusterNode.Host, httpPort))
					clientListenUrls = append(clientListenUrls, fmt.Sprintf("http://0.0.0.0:%d", httpPort))
				}

				if wsPort > 0 {
					clientUrls = append(clientUrls, fmt.Sprintf("ws://%s:%d", clusterNode.Host, wsPort))
					clientListenUrls = append(clientListenUrls, fmt.Sprintf("ws://0.0.0.0:%d", wsPort))
				}

				if wssPort > 0 {
					clientUrls = append(clientUrls, fmt.Sprintf("wss://%s:%d", clusterNode.Host, wssPort))
					clientListenUrls = append(clientListenUrls, fmt.Sprintf("wss://0.0.0.0:%d", wssPort))
				}

				env["CLIENT_ADVERTISE_URLS"] = strings.Join(clientUrls, ",")
				env["CLIENT_LISTEN_URLS"] = strings.Join(clientListenUrls, ",")
				env["PORTAL_UUID"] = fmt.Sprintf("%d", 100+idx)
			}

			// Domain endpoint configuration for dog and light
			if service == "dog" || service == "light" {
				env["DOMAIN_LISTEN_URLS0"] = fmt.Sprintf("tcp://0.0.0.0:%d", domainConfig.DomainPort)
				env["DOMAIN_LISTEN_URLS1"] = fmt.Sprintf("tcp://0.0.0.0:%d", domainConfig.DomainPort+1)
				env["DOMAIN_LISTEN_URLS2"] = fmt.Sprintf("tcp://0.0.0.0:%d", domainConfig.DomainPort+2)
			}

			// Special handling for light service
			if service == "light" {
				env["STORAGE_RPC_ADVERTISE_URL"] = fmt.Sprintf("%s:%d", clusterNode.Host, rpcPort)
				env["STORAGE_ID"] = "0"
				env["STORAGE_MSU"] = "0-255"
				env["TXPOOL_PARTITION_LIST"] = "0-255"
			}

			// Add NODE_ID to all instances
			env["NODE_ID"] = nodeID

			cluster[instanceName] = instance
		}
	}

	domain["cluster"] = cluster
	domain["initial_stake_in_gwei"] = domainConfig.InitialStakeInGwei

	// Write domain file with proper formatting and field order
	// Create a complete ordered structure matching Python output

	// Create ordered secret structure
	secretFilesDomain := map[string]string{
		"key":             fmt.Sprintf("../scripts/resources/domain_keys/%s/%s/new.key", deploy.DomainKeyType, domainName),
		"key_pub":         fmt.Sprintf("../scripts/resources/domain_keys/%s/%s/new.pub", deploy.DomainKeyType, domainName),
		"stabilizing_key": fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/new.key", domainName),
		"stabilizing_pk":  fmt.Sprintf("../scripts/resources/domain_keys/bls12381/%s/new.pub", domainName),
	}

	secretFilesClient := map[string]string{
		"ca_cert": fmt.Sprintf("../conf/resources/portal/%s/client/ca.crt", deploy.ClientKeyType),
		"cert":    fmt.Sprintf("../conf/resources/portal/%s/client/client.crt", deploy.ClientKeyType),
		"key":     fmt.Sprintf("../conf/resources/portal/%s/client/client.key", deploy.ClientKeyType),
	}

	// Create the final ordered structure directly
	orderedData := map[string]interface{}{
		"build_root":       deploy.BuildRoot,
		"chain_id":         deploy.ChainID,
		"chain_protocol":   deploy.ChainProtocol,
		"domain_label":     domainName,
		"version":          deploy.Version,
		"run_user":         deploy.RunUser,
		"deploy_dir":       deployDir,
		"genesis_conf":     "../genesis.conf",
		"mygrid":           deploy.Mygrid,
		"secret": map[string]interface{}{
			"domain": map[string]interface{}{
				"key_type": deploy.DomainKeyType,
				"files":   secretFilesDomain,
			},
			"client": map[string]interface{}{
				"key_type": deploy.ClientKeyType,
				"files":   secretFilesClient,
			},
		},
		"use_generated_keys":  deploy.UseGeneratedKeys,
		"enable_dora":         deploy.EnableDora,
		"key_passwd":          keyPasswd,
		"docker":              deploy.Docker,
		"common": map[string]interface{}{
			"env":    deploy.Common.Env,
			"log":    deploy.Common.Log,
			"config": deploy.Common.Config,
			"gflags": deploy.Common.Gflags,
			"metrics": map[string]interface{}{
				"push_address":  "",
				"push_interval": "",
				"enable":        false,
				"push_port":     "",
				"job_name":      "",
			},
		},
		"cluster":             cluster,
		"initial_stake_in_gwei": domainConfig.InitialStakeInGwei,
	}

	data, err := json.MarshalIndent(orderedData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain config: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func generateNodeIDFromDomain(domainName string, deploy DeployConfig) string {
	// Generate NODE_ID by reading the actual public key file and hashing it
	// This matches the Python implementation exactly

	// Construct the private key file path
	keyDir := filepath.Join(deploy.BuildRoot, "scripts/resources/domain_keys", deploy.DomainKeyType, domainName)
	prikeyPath := filepath.Join(keyDir, "new.key")

	// Default password
	keyPasswd := "123abc"

	// Check if we have a password from domain config
	if domainConfig, exists := deploy.Domains[domainName]; exists && domainConfig.KeyPasswd != "" {
		keyPasswd = domainConfig.KeyPasswd
	}

	// If use_generated_keys is true, generate the keys first
	if deploy.UseGeneratedKeys {
		if err := generatePrivateKey(deploy.DomainKeyType, keyDir, keyPasswd); err != nil {
			utils.Warn("Failed to generate private key: %v", err)
		}

		// Also generate BLS key
		blsKeyDir := filepath.Join(deploy.BuildRoot, "scripts/resources/domain_keys/bls12381", domainName)
		if err := generateBLSKey(blsKeyDir); err != nil {
			utils.Warn("Failed to generate BLS key: %v", err)
		}
	}

	// Get public key from private key file
	pubkey, err := getPubkeyFromFile(deploy.DomainKeyType, prikeyPath, keyPasswd)
	if err != nil {
		// Fallback to domain-based generation if key file doesn't exist
		utils.Warn("Failed to read key file %s, using fallback NODE_ID: %v", prikeyPath, err)
		data := []byte(domainName + "-pharos-key")
		hash := sha256.Sum256(data)
		return fmt.Sprintf("%x", hash)
	}

	// Calculate SHA256 hash of the public key bytes
	hash := sha256.Sum256(pubkey)
	return fmt.Sprintf("%x", hash)
}

// generatePrivateKey generates a private key file using OpenSSL
// This matches Python's _generate_prikey function for prime256v1 and RSA
func generatePrivateKey(keyType, keyDir, keyPasswd string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	prikeyPath := filepath.Join(keyDir, "new.key")
	switch strings.ToLower(keyType) {
	case "prime256v1", "p256v1":
		// Generate EC key with prime256v1 curve
		// openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -outform pem -out {prikey_path} -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:{key_passwd}
		ecCmd := exec.Command("openssl", "ecparam", "-name", "prime256v1", "-genkey")
		pkcs8Cmd := exec.Command("openssl", "pkcs8", "-topk8", "-outform", "pem", "-out", prikeyPath,
			"-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-passout", "pass:"+keyPasswd)

		// Pipe the output of ecparam to pkcs8
		pkcs8Cmd.Stdin, _ = ecCmd.StdoutPipe()
		if err := pkcs8Cmd.Start(); err != nil {
			return fmt.Errorf("failed to start pkcs8 command: %w", err)
		}
		if err := ecCmd.Run(); err != nil {
			return fmt.Errorf("failed to generate EC parameters: %w", err)
		}
		if err := pkcs8Cmd.Wait(); err != nil {
			return fmt.Errorf("failed to convert to PKCS8: %w", err)
		}

	case "rsa", "rsa2048":
		// Generate RSA key
		// openssl genrsa 2048 | openssl pkcs8 -topk8 -outform pem -out {prikey_path} -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:{key_passwd}
		rsaCmd := exec.Command("openssl", "genrsa", "2048")
		pkcs8Cmd := exec.Command("openssl", "pkcs8", "-topk8", "-outform", "pem", "-out", prikeyPath,
			"-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-passout", "pass:"+keyPasswd)

		// Pipe the output of genrsa to pkcs8
		pkcs8Cmd.Stdin, _ = rsaCmd.StdoutPipe()
		if err := pkcs8Cmd.Start(); err != nil {
			return fmt.Errorf("failed to start pkcs8 command: %w", err)
		}
		if err := rsaCmd.Run(); err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		if err := pkcs8Cmd.Wait(); err != nil {
			return fmt.Errorf("failed to convert to PKCS8: %w", err)
		}

	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Extract public key and save to .pub file
	pubkey, err := getPubkeyFromFile(keyType, prikeyPath, keyPasswd)
	if err != nil {
		return fmt.Errorf("failed to extract public key: %w", err)
	}

	// Convert back to hex string with prefix
	var pubkeyHex string
	switch strings.ToLower(keyType) {
	case "prime256v1", "p256v1":
		pubkeyHex = "1003" + hex.EncodeToString(pubkey)[8:] // Remove the 1003 prefix we added
	case "rsa", "rsa2048":
		pubkeyHex = "1023" + hex.EncodeToString(pubkey)[8:] // Remove the 1023 prefix we added
	}

	// Write public key to file
	pubkeyPath := filepath.Join(keyDir, "new.pub")
	if err := os.WriteFile(pubkeyPath, []byte(pubkeyHex), 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}

// generateBLSKey generates a BLS key
// This matches Python's implementation which uses pharos_cli
func generateBLSKey(keyDir string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		return fmt.Errorf("failed to create BLS key directory: %w", err)
	}

	// Look for pharos_cli in build_root/bin
	buildRoot := "../" // Default relative path, should be determined from context
	pharosCliPath := filepath.Join(buildRoot, "bin", "pharos_cli")
	evmonePath := filepath.Join(buildRoot, "bin", "libevmone.so")

	// Check if pharos_cli exists
	if _, err := os.Stat(pharosCliPath); err != nil {
		utils.Warn("pharos_cli not found at %s, creating placeholder BLS keys", pharosCliPath)
		return createPlaceholderBLSKeys(keyDir)
	}

	// Generate BLS keys using pharos_cli (matching Python)
	// Command: LD_PRELOAD={evmone_so_path} {pharos_cli_path} crypto -t gen-key -a bls12381
	cmd := exec.Command("sh", "-c", fmt.Sprintf("LD_PRELOAD=%s %s crypto -t gen-key -a bls12381", evmonePath, pharosCliPath))
	output, err := cmd.Output()
	if err != nil {
		utils.Warn("Failed to generate BLS keys using pharos_cli: %v, creating placeholder keys", err)
		return createPlaceholderBLSKeys(keyDir)
	}

	// Parse output - should contain PRIVKEY and PUBKEY lines
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	var prikey, pubkey string
	for _, line := range lines {
		if strings.HasPrefix(line, "PRIVKEY:") {
			prikey = strings.TrimSpace(strings.TrimPrefix(line, "PRIVKEY:"))
		} else if strings.HasPrefix(line, "PUBKEY:") {
			pubkey = strings.TrimSpace(strings.TrimPrefix(line, "PUBKEY:"))
		}
	}

	if prikey == "" || pubkey == "" {
		utils.Warn("Failed to parse BLS keys from output, creating placeholder keys")
		return createPlaceholderBLSKeys(keyDir)
	}

	// Write keys to files
	prikeyPath := filepath.Join(keyDir, "new.key")
	pubkeyPath := filepath.Join(keyDir, "new.pub")

	if err := os.WriteFile(prikeyPath, []byte(prikey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS private key: %w", err)
	}
	if err := os.WriteFile(pubkeyPath, []byte(pubkey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS public key: %w", err)
	}

	return nil
}

// createPlaceholderBLSKeys creates placeholder BLS keys when pharos_cli is not available
func createPlaceholderBLSKeys(keyDir string) error {
	prikeyPath := filepath.Join(keyDir, "new.key")
	pubkeyPath := filepath.Join(keyDir, "new.pub")

	// Create placeholder BLS keys
	prikey := "4002" + strings.Repeat("00", 62)
	pubkey := "4003" + strings.Repeat("00", 62)

	if err := os.WriteFile(prikeyPath, []byte(prikey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS private key: %w", err)
	}
	if err := os.WriteFile(pubkeyPath, []byte(pubkey), 0644); err != nil {
		return fmt.Errorf("failed to write BLS public key: %w", err)
	}

	utils.Warn("Created placeholder BLS keys. Replace them with proper keys for production use.")
	return nil
}

// getPubkeyFromFile reads a private key file and extracts the public key
// This matches Python's _get_pubkey function
func getPubkeyFromFile(keyType, prikeyPath, keyPasswd string) ([]byte, error) {
	// Build OpenSSL command
	var cmd *exec.Cmd
	switch strings.ToLower(keyType) {
	case "prime256v1", "p256v1":
		cmd = exec.Command("openssl", "ec", "-in", prikeyPath, "-noout", "-text", "-passin", "pass:"+keyPasswd)
	case "rsa", "rsa2048":
		cmd = exec.Command("openssl", "rsa", "-in", prikeyPath, "-noout", "-text", "-passin", "pass:"+keyPasswd)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Execute the command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute openssl: %v, output: %s", err, string(output))
	}

	// Parse the output to extract the public key
	// The OpenSSL output has the public key in hex format after line 3
	lines := strings.Split(string(output), "\n")

	// Filter lines that start with whitespace (contain the hex data)
	var hexLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			hexLines = append(hexLines, line)
		}
	}

	if len(hexLines) < 4 {
		return nil, fmt.Errorf("invalid openssl output format")
	}

	// Skip first 3 lines and take the rest
	hexLines = hexLines[3:]

	// Remove all whitespace and join
	hexStr := strings.Join(hexLines, "")
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, ":", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")

	// Add prefix based on key type
	var pubkeyHex string
	switch strings.ToLower(keyType) {
	case "prime256v1", "p256v1":
		pubkeyHex = "1003" + hexStr // p256v1 prefix
	case "rsa", "rsa2048":
		pubkeyHex = "1023" + hexStr // rsa prefix
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Convert hex string to bytes
	pubkeyBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %v", err)
	}

	return pubkeyBytes, nil
}

// deepCopyMap creates a deep copy of a map[string]interface{}
func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	copy := make(map[string]interface{})
	for k, v := range m {
		switch t := v.(type) {
		case map[string]interface{}:
			copy[k] = deepCopyMap(t)
		case []interface{}:
			copy[k] = deepCopySlice(t)
		default:
			copy[k] = v
		}
	}
	return copy
}

// deepCopySlice creates a deep copy of a []interface{}
func deepCopySlice(s []interface{}) []interface{} {
	copy := make([]interface{}, len(s))
	for i, v := range s {
		switch t := v.(type) {
		case map[string]interface{}:
			copy[i] = deepCopyMap(t)
		case []interface{}:
			copy[i] = deepCopySlice(t)
		default:
			copy[i] = v
		}
	}
	return copy
}

func init() {
	generateCmd.Flags().BoolP("genesis", "g", false, "Generate genesis files")
	rootCmd.AddCommand(generateCmd)
}