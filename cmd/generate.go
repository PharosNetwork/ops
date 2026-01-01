package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"pharos-ops/pkg/utils"

	"github.com/spf13/cobra"
)

// DeployConfig matches the Python schema structure
type DeployConfig struct {
	BuildRoot        string                  `json:"build_root"`
	ChainID          string                  `json:"chain_id"`
	ChainProtocol    string                  `json:"chain_protocol"`
	Version          string                  `json:"version"`
	RunUser          string                  `json:"run_user"`
	DeployRoot       string                  `json:"deploy_root"`
	AdminAddr        string                  `json:"admin_addr"`
	ProxyAdminAddr   string                  `json:"proxy_admin_addr"`
	GenesisTpl       string                  `json:"genesis_tpl"`
	RunningConf      string                  `json:"running_conf"`
	Mygrid           MyGridConfig            `json:"mygrid"`
	DomainKeyType    string                  `json:"domain_key_type"`
	ClientKeyType    string                  `json:"client_key_type"`
	UseGeneratedKeys bool                    `json:"use_generated_keys"`
	UseLatestVersion bool                    `json:"use_latest_version"`
	EnableDora       bool                    `json:"enable_dora"`
	Docker           DockerConfig            `json:"docker"`
	Common           CommonConfig            `json:"common"`
	Aldaba           ServiceConfig           `json:"aldaba"`
	Storage          ServiceConfig           `json:"storage"`
	Domains          map[string]DomainConfig `json:"domains"`
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
	Env           map[string]interface{} `json:"env"`
	Log           map[string]interface{} `json:"log"`
	Config        map[string]interface{} `json:"config"`
	Gflags        map[string]interface{} `json:"gflags"`
	MonitorConfig map[string]interface{} `json:"monitor_config"`
}

type ServiceConfig struct {
	Args   []string               `json:"args"`
	Env    map[string]interface{} `json:"env"`
	Log    map[string]interface{} `json:"log"`
	Config map[string]interface{} `json:"config"`
	Gflags map[string]interface{} `json:"gflags"`
}

type DomainConfig struct {
	DeployDir          string        `json:"deploy_dir"`
	DomainRole         int           `json:"domain_role"`
	KeyPasswd          string        `json:"key_passwd"`
	PortalSSLPass      string        `json:"portal_ssl_pass"`
	DomainPort         int           `json:"domain_port"`
	ClientTCPPort      int           `json:"client_tcp_port"`
	ClientWSPort       int           `json:"client_ws_port"`
	ClientWSSPort      int           `json:"client_wss_port"`
	ClientHTTPPort     int           `json:"client_http_port"`
	Cluster            []ClusterNode `json:"cluster"`
	InitialStakeInGwei int64         `json:"initial_stake_in_gwei"`
	EnableSetkeyEnv    bool          `json:"enable_setkey_env"`
}

type ClusterNode struct {
	Host      string `json:"host"`
	StartPort int    `json:"start_port"`
	Instances string `json:"instances"`
	DeployIP  string `json:"deploy_ip"`
}

// DomainGenerator handles domain file generation
type DomainGenerator struct {
	deploy          DeployConfig
	deployFilePath  string
	genesisFile     string
	domainEndpoints map[string]string
	isLight         bool
	keyGenerator    *KeyGenerator
}

// NewDomainGenerator creates a new DomainGenerator
func NewDomainGenerator(deploy DeployConfig, deployFilePath string) *DomainGenerator {
	genesisFile := fmt.Sprintf("../conf/genesis.%s.conf", deploy.ChainID)
	return &DomainGenerator{
		deploy:          deploy,
		deployFilePath:  deployFilePath,
		genesisFile:     genesisFile,
		domainEndpoints: make(map[string]string),
		keyGenerator:    NewKeyGenerator(deploy.BuildRoot),
	}
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

		// Get deploy file directory path
		deployFilePath, _ := filepath.Abs(filepath.Dir(deployFile))

		// Create generator
		generator := NewDomainGenerator(deploy, deployFilePath)

		// Generate domain files - one per domain like Python version
		// Sort domain names for consistent output
		var domainNames []string
		for name := range deploy.Domains {
			domainNames = append(domainNames, name)
		}
		sort.Strings(domainNames)

		for _, domainName := range domainNames {
			domainConfig := deploy.Domains[domainName]
			domainFile := fmt.Sprintf("%s.json", domainName)
			utils.Info("Generating domain file: %s", domainFile)

			if err := generator.generateDomainFile(domainFile, domainName, domainConfig); err != nil {
				utils.Error("Failed to generate %s: %v", domainFile, err)
				continue
			}
		}

		// Generate genesis file
		if err := generator.generateGenesisFile(); err != nil {
			utils.Warn("Failed to generate genesis file: %v", err)
		}

		return nil
	},
}

// getStartPort calculates the RPC port for a service
func (g *DomainGenerator) getStartPort(startPort int, service string) int {
	if service == SERVICE_LIGHT {
		return startPort
	}
	idx := GetServiceIndex(service)
	if idx < 0 {
		return startPort
	}
	return startPort + idx*1000
}

// generateDomainFile generates a single domain configuration file
func (g *DomainGenerator) generateDomainFile(filename, domainName string, domainConfig DomainConfig) error {
	// Determine key file suffix based on use_generated_keys
	keySuffix := GetKeyFileName(g.deploy.UseGeneratedKeys)

	// Determine deploy_dir
	deployDir := domainConfig.DeployDir
	if deployDir == "" {
		if g.deploy.DeployRoot != "" {
			deployDir = filepath.Join(g.deploy.DeployRoot, domainName)
		} else {
			deployDir = filepath.Join("/data/pharos-node", domainName)
		}
	}

	// Determine key_passwd
	keyPasswd := domainConfig.KeyPasswd
	if keyPasswd == "" {
		keyPasswd = DEFAULT_KEY_PASSWD
	}

	// Determine portal_ssl_pass
	portalSSLPass := domainConfig.PortalSSLPass
	if portalSSLPass == "" {
		portalSSLPass = keyPasswd
	}

	// Build key directory paths
	keyDir := filepath.Join(g.deploy.BuildRoot, "scripts/resources/domain_keys", g.deploy.DomainKeyType, domainName)
	blsKeyDir := filepath.Join(g.deploy.BuildRoot, "scripts/resources/domain_keys/bls12381", domainName)

	// Generate NODE_ID
	nodeID, err := g.keyGenerator.GenerateNodeID(g.deploy.DomainKeyType, keyDir, keySuffix+".key", keyPasswd, g.deploy.UseGeneratedKeys)
	if err != nil {
		utils.Warn("Failed to generate NODE_ID: %v", err)
	}

	// Build secret files paths (relative paths like Python)
	secretFiles := map[string]string{
		"key":             fmt.Sprintf("%s/%s.key", keyDir, keySuffix),
		"key_pub":         fmt.Sprintf("%s/%s.pub", keyDir, keySuffix),
		"stabilizing_key": fmt.Sprintf("%s/%s.key", blsKeyDir, keySuffix),
		"stabilizing_pk":  fmt.Sprintf("%s/%s.pub", blsKeyDir, keySuffix),
	}

	// Process cluster to detect if this is light mode
	isLight := false
	for _, cluster := range domainConfig.Cluster {
		for _, inst := range strings.Split(cluster.Instances, ",") {
			inst = strings.TrimSpace(inst)
			service := strings.TrimRight(inst, "0123456789")
			if service == SERVICE_LIGHT {
				isLight = true
				break
			}
		}
		if isLight {
			break
		}
	}
	g.isLight = isLight

	// Calculate partition and MSU sizes
	serviceCount := make(map[string]int)
	for _, cluster := range domainConfig.Cluster {
		for _, inst := range strings.Split(cluster.Instances, ",") {
			inst = strings.TrimSpace(inst)
			service := strings.TrimRight(inst, "0123456789")
			serviceCount[service]++
		}
	}

	avrPartition := 255
	avrMsu := 255
	if !isLight {
		if count, ok := serviceCount[SERVICE_TXPOOL]; ok && count > 0 {
			avrPartition = PARTITION_SIZE / count
		}
		if count, ok := serviceCount[SERVICE_STORAGE]; ok && count > 0 {
			avrMsu = MSU_SIZE / count
		}
	}

	// Build cluster configuration
	cluster := make(map[string]interface{})
	etcdInitialCluster := make(map[string]string)

	for _, clusterNode := range domainConfig.Cluster {
		instances := strings.Split(clusterNode.Instances, ",")

		for _, instanceName := range instances {
			instanceName = strings.TrimSpace(instanceName)
			if instanceName == "" {
				continue
			}

			// Extract service type and index
			service := strings.TrimRight(instanceName, "0123456789")
			idxSuffix := strings.TrimLeft(instanceName, service)
			idx := 0
			if idxSuffix != "" {
				idx, _ = strconv.Atoi(idxSuffix)
			}

			// Calculate RPC port
			rpcPort := g.getStartPort(clusterNode.StartPort, service) + idx

			// Build instance configuration
			instance := map[string]interface{}{
				"service": service,
				"ip":      clusterNode.DeployIP,
			}

			// Build args based on service type (matching Python)
			var args []string
			switch service {
			case SERVICE_ETCD:
				args = []string{"1>stderr", "2>stdout", "&"}
			case SERVICE_STORAGE:
				args = append(g.deploy.Storage.Args, "-c", "../conf/svc.conf", "-d")
			case SERVICE_LIGHT:
				args = append(g.deploy.Aldaba.Args, "-d")
			default:
				args = append(g.deploy.Aldaba.Args, "-s", service, "-d")
			}
			instance["args"] = args

			// Build environment variables
			env := make(map[string]string)

			switch service {
			case SERVICE_ETCD:
				peerPort := rpcPort
				clientPort := peerPort + 100
				env["ETCD_NAME"] = fmt.Sprintf("etcd%d", idx)
				env["ETCD_DATA_DIR"] = "../data/etcd"
				env["ETCD_LOG_OUTPUTS"] = "../log/etcd.log"
				env["ETCD_ENABLE_V2"] = "true"
				env["ETCD_LISTEN_PEER_URLS"] = fmt.Sprintf("http://0.0.0.0:%d", peerPort)
				env["ETCD_INITIAL_ADVERTISE_PEER_URLS"] = fmt.Sprintf("http://%s:%d", clusterNode.Host, peerPort)
				env["ETCD_LISTEN_CLIENT_URLS"] = fmt.Sprintf("http://0.0.0.0:%d", clientPort)
				env["ETCD_ADVERTISE_CLIENT_URLS"] = fmt.Sprintf("http://%s:%d", clusterNode.Host, clientPort)
				etcdInitialCluster[env["ETCD_NAME"]] = env["ETCD_INITIAL_ADVERTISE_PEER_URLS"]

			case SERVICE_STORAGE:
				// Copy storage env from deploy config
				for k, v := range g.deploy.Storage.Env {
					if s, ok := v.(string); ok {
						env[k] = s
					}
				}
				startMsu := avrMsu * idx
				stopMsu := avrMsu*(idx+1) - 1
				env["STORAGE_ID"] = idxSuffix
				env["STORAGE_RPC_LISTEN_URL"] = fmt.Sprintf("0.0.0.0:%d", rpcPort)
				env["STORAGE_RPC_ADVERTISE_URL"] = fmt.Sprintf("%s:%d", clusterNode.Host, rpcPort)
				env["STORAGE_MSU"] = fmt.Sprintf("%d-%d", startMsu, stopMsu)

			default:
				// Copy aldaba env from deploy config
				for k, v := range g.deploy.Aldaba.Env {
					if s, ok := v.(string); ok {
						env[k] = s
					}
				}

				// Common service env
				upperService := strings.ToUpper(service)
				env[upperService+"_RPC_LISTEN_URL"] = fmt.Sprintf("0.0.0.0:%d", rpcPort)
				env[upperService+"_RPC_ADVERTISE_URL"] = fmt.Sprintf("%s:%d", clusterNode.Host, rpcPort)

				// Service-specific ID (except controller, dog, light)
				if service != SERVICE_CONTROLLER && service != SERVICE_DOG && service != SERVICE_LIGHT {
					env[upperService+"_ID"] = idxSuffix
				}

				// Client URLs for portal and light
				if service == SERVICE_PORTAL || service == SERVICE_LIGHT {
					var clientUrls, clientListenUrls []string
					if domainConfig.ClientHTTPPort > 0 {
						httpPort := domainConfig.ClientHTTPPort + idx
						clientUrls = append(clientUrls, fmt.Sprintf("http://%s:%d", clusterNode.Host, httpPort))
						clientListenUrls = append(clientListenUrls, fmt.Sprintf("http://0.0.0.0:%d", httpPort))
					}
					if domainConfig.ClientWSPort > 0 {
						wsPort := domainConfig.ClientWSPort + idx
						clientUrls = append(clientUrls, fmt.Sprintf("ws://%s:%d", clusterNode.Host, wsPort))
						clientListenUrls = append(clientListenUrls, fmt.Sprintf("ws://0.0.0.0:%d", wsPort))
					}
					env["CLIENT_ADVERTISE_URLS"] = strings.Join(clientUrls, ",")
					env["CLIENT_LISTEN_URLS"] = strings.Join(clientListenUrls, ",")
					env["PORTAL_UUID"] = fmt.Sprintf("%d", 100+idx)
				}

				// Domain listen URLs for dog and light
				if service == SERVICE_DOG || service == SERVICE_LIGHT {
					env["DOMAIN_LISTEN_URLS0"] = fmt.Sprintf("tcp://0.0.0.0:%d", domainConfig.DomainPort)
					env["DOMAIN_LISTEN_URLS1"] = fmt.Sprintf("tcp://0.0.0.0:%d", domainConfig.DomainPort+1)
					env["DOMAIN_LISTEN_URLS2"] = fmt.Sprintf("tcp://0.0.0.0:%d", domainConfig.DomainPort+2)
					g.domainEndpoints[domainName] = fmt.Sprintf("tcp://%s:%d", clusterNode.Host, domainConfig.DomainPort)
				}

				// TxPool partition
				if service == SERVICE_TXPOOL {
					startPartition := avrPartition * idx
					stopPartition := avrPartition*(idx+1) - 1
					env["TXPOOL_PARTITION_LIST"] = fmt.Sprintf("%d-%d", startPartition, stopPartition)
				}

				// Light service special handling
				if service == SERVICE_LIGHT {
					env["STORAGE_RPC_ADVERTISE_URL"] = env["LIGHT_RPC_ADVERTISE_URL"]
					env["STORAGE_ID"] = "0"
					env["STORAGE_MSU"] = "0-255"
					env["TXPOOL_PARTITION_LIST"] = "0-255"
				}
			}

			// Add NODE_ID to all instances
			env["NODE_ID"] = nodeID

			instance["env"] = env
			cluster[instanceName] = instance
		}
	}

	// Set ETCD_INITIAL_CLUSTER for all ETCD instances
	if len(etcdInitialCluster) > 0 {
		var clusterParts []string
		// Sort for consistent output
		var etcdNames []string
		for name := range etcdInitialCluster {
			etcdNames = append(etcdNames, name)
		}
		sort.Strings(etcdNames)
		for _, name := range etcdNames {
			clusterParts = append(clusterParts, fmt.Sprintf("%s=%s", name, etcdInitialCluster[name]))
		}
		initialCluster := strings.Join(clusterParts, ",")

		for instName, inst := range cluster {
			if m, ok := inst.(map[string]interface{}); ok {
				if m["service"] == SERVICE_ETCD {
					if env, ok := m["env"].(map[string]string); ok {
						env["ETCD_INITIAL_CLUSTER"] = initialCluster
						cluster[instName] = m
					}
				}
			}
		}
	}

	// Build ordered domain data structure
	domainData := map[string]interface{}{
		"build_root":     g.deploy.BuildRoot,
		"chain_id":       g.deploy.ChainID,
		"chain_protocol": g.deploy.ChainProtocol,
		"domain_label":   domainName,
		"version":        g.deploy.Version,
		"run_user":       g.deploy.RunUser, // Use deploy config, not hardcoded
		"deploy_dir":     deployDir,
		"genesis_conf":   g.genesisFile, // Use dynamic chain_id
		"mygrid":         g.deploy.Mygrid,
		"secret": map[string]interface{}{
			"domain": map[string]interface{}{
				"key_type": g.deploy.DomainKeyType,
				"files":    secretFiles,
			},
		},
		"use_generated_keys": g.deploy.UseGeneratedKeys,
		"key_passwd":         keyPasswd,
		"enable_setkey_env":  domainConfig.EnableSetkeyEnv,
		"portal_ssl_pass":    portalSSLPass,
		"running_conf":       g.deploy.RunningConf, // Use deploy config
		"docker":             g.deploy.Docker,
		"common": map[string]interface{}{
			"env":            g.deploy.Common.Env,
			"log":            g.deploy.Common.Log,
			"config":         g.deploy.Common.Config,
			"gflags":         g.deploy.Common.Gflags,
			"monitor_config": g.deploy.Common.MonitorConfig,
		},
		"cluster":             cluster,
		"initial_stake_in_gwei": domainConfig.InitialStakeInGwei,
	}

	// Write domain file
	data, err := json.MarshalIndent(domainData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write domain file: %w", err)
	}

	absPath, _ := filepath.Abs(filename)
	utils.Info("dump %s file at: %s", filename, absPath)
	return nil
}

// generateGenesisFile generates the genesis configuration file with full storage slot generation
func (g *DomainGenerator) generateGenesisFile() error {
	// Load genesis template
	templatePath := g.deploy.GenesisTpl
	utils.Info("Looking for genesis template at: %s", templatePath)

	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		return fmt.Errorf("genesis template file not found: %s", templatePath)
	}

	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read genesis template %s: %w", templatePath, err)
	}

	var genesis map[string]interface{}
	if err := json.Unmarshal(templateData, &genesis); err != nil {
		return fmt.Errorf("failed to parse genesis template: %w", err)
	}

	// Get key suffix
	keySuffix := GetKeyFileName(g.deploy.UseGeneratedKeys)

	// Create slot generator
	slotGenerator := NewGenesisSlotGenerator(g.deploy.AdminAddr)

	// Generate genesis domains and storage slots
	genesisDomains := make(map[string]interface{})
	allStorageSlots := make(map[string]string)
	var totalStakeWei int64 = 0
	genesisTimestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Sort domain names for consistent output
	var domainNames []string
	for name := range g.deploy.Domains {
		domainNames = append(domainNames, name)
	}
	sort.Strings(domainNames)

	for domainIndex, domainName := range domainNames {
		domainConfig := g.deploy.Domains[domainName]

		// Build key paths
		keyDir := filepath.Join(g.deploy.BuildRoot, "scripts/resources/domain_keys", g.deploy.DomainKeyType, domainName)
		blsKeyDir := filepath.Join(g.deploy.BuildRoot, "scripts/resources/domain_keys/bls12381", domainName)

		keyPasswd := domainConfig.KeyPasswd
		if keyPasswd == "" {
			keyPasswd = DEFAULT_KEY_PASSWD
		}

		// Read domain public key
		prikeyPath := filepath.Join(keyDir, keySuffix+".key")
		pubkeyHex, pubkeyBytes, err := g.keyGenerator.GetPubkeyWithPrefix(g.deploy.DomainKeyType, prikeyPath, keyPasswd)
		if err != nil {
			return fmt.Errorf("failed to get public key for %s: %w", domainName, err)
		}

		// Read BLS public key
		blsPubkeyPath := filepath.Join(blsKeyDir, keySuffix+".pub")
		blsPubkey, err := ReadPubkeyFile(blsPubkeyPath)
		if err != nil {
			return fmt.Errorf("failed to read BLS public key for %s: %w", domainName, err)
		}

		// Read PoP files
		pkPopPath := filepath.Join(keyDir, keySuffix+".pop")
		pkPop, _ := ReadPopFile(pkPopPath)
		if pkPop == "" {
			pkPop = "placeholder_pop"
		}

		blsPopPath := filepath.Join(blsKeyDir, keySuffix+".pop")
		blsPop, _ := ReadPopFile(blsPopPath)
		if blsPop == "" {
			blsPop = "placeholder_bls_pop"
		}

		// Calculate node ID
		nodeID := fmt.Sprintf("%x", sha256.Sum256(pubkeyBytes))

		// Get endpoint
		endpoint := g.domainEndpoints[domainName]
		if endpoint == "" {
			// Build from first cluster node
			if len(domainConfig.Cluster) > 0 {
				endpoint = fmt.Sprintf("tcp://%s:%d", domainConfig.Cluster[0].Host, domainConfig.DomainPort)
			}
		}

		// Build genesis domain entry
		genesisDomains[domainName] = map[string]interface{}{
			"pubkey":             "0x" + pubkeyHex,
			"stabilizing_pubkey": blsPubkey,
			"owner":              "root",
			"endpoints":          []string{endpoint},
			"staking":            "200000000",
			"commission_rate":    "10",
			"node_id":            nodeID,
		}

		// Generate storage slots for this domain
		stakeWei := domainConfig.InitialStakeInGwei * GWEI_TO_WEI
		totalStakeWei += stakeWei

		domainSlots := slotGenerator.GenerateDomainSlots(
			len(g.deploy.Domains),
			domainIndex,
			pubkeyHex,
			blsPubkey,
			endpoint,
			stakeWei,
			pkPop,
			blsPop,
		)

		for k, v := range domainSlots {
			allStorageSlots[k] = v
		}
	}

	// Add extra staking slots
	extraSlots := slotGenerator.GenerateStakingExtraSlots(totalStakeWei, genesisTimestamp)
	for k, v := range extraSlots {
		allStorageSlots[k] = v
	}

	// Add access control and initializers for staking contract
	adminSlots := slotGenerator.GenerateAccessControlAdmin(g.deploy.AdminAddr, true)
	for k, v := range adminSlots {
		allStorageSlots[k] = v
	}
	intrinsicSlots := slotGenerator.GenerateAccessControlAdmin(INTRINSIC_TX_SENDER, false)
	for k, v := range intrinsicSlots {
		allStorageSlots[k] = v
	}
	initSlots := slotGenerator.GenerateDisableInitializers()
	for k, v := range initSlots {
		allStorageSlots[k] = v
	}

	// Update staking contract in genesis
	alloc := genesis["alloc"].(map[string]interface{})
	stakingContract := alloc[SYS_STAKING_ADDR].(map[string]interface{})

	// Merge with existing storage if present
	if existingStorage, ok := stakingContract["storage"].(map[string]interface{}); ok {
		for k, v := range allStorageSlots {
			existingStorage[k] = v
		}
		stakingContract["storage"] = existingStorage
	} else {
		stakingContract["storage"] = allStorageSlots
	}
	stakingContract["balance"] = fmt.Sprintf("0x%x", totalStakeWei)

	// Update epoch_start_timestamp in configs
	if configs, ok := genesis["configs"].(map[string]interface{}); ok {
		configs["chain.epoch_start_timestamp"] = fmt.Sprintf("%d", genesisTimestamp)
	}

	// Generate ChainConfig slots
	chainCfgSlots := make(map[string]string)
	if configs, ok := genesis["configs"].(map[string]interface{}); ok {
		configStrings := make(map[string]string)
		for k, v := range configs {
			configStrings[k] = fmt.Sprintf("%v", v)
		}
		chainCfgSlots = slotGenerator.GenerateChainCfgSlots(configStrings)
	}

	// Add access control for chaincfg
	for k, v := range slotGenerator.GenerateAccessControlAdmin(g.deploy.AdminAddr, true) {
		chainCfgSlots[k] = v
	}
	for k, v := range slotGenerator.GenerateAccessControlAdmin(INTRINSIC_TX_SENDER, false) {
		chainCfgSlots[k] = v
	}
	for k, v := range slotGenerator.GenerateDisableInitializers() {
		chainCfgSlots[k] = v
	}

	// Update chaincfg contract
	chaincfgContract := alloc[SYS_CHAINCFG_ADDR].(map[string]interface{})
	if existingStorage, ok := chaincfgContract["storage"].(map[string]interface{}); ok {
		for k, v := range chainCfgSlots {
			existingStorage[k] = v
		}
		chaincfgContract["storage"] = existingStorage
	} else {
		chaincfgContract["storage"] = chainCfgSlots
	}

	// Generate RuleManager slots
	ruleMngSlots := slotGenerator.GenerateRuleMngSlots()
	for k, v := range slotGenerator.GenerateAccessControlAdmin(g.deploy.AdminAddr, true) {
		ruleMngSlots[k] = v
	}
	for k, v := range slotGenerator.GenerateAccessControlAdmin(INTRINSIC_TX_SENDER, false) {
		ruleMngSlots[k] = v
	}
	for k, v := range slotGenerator.GenerateDisableInitializers() {
		ruleMngSlots[k] = v
	}

	// Update rulemng contract
	rulemngContract := alloc[SYS_RULEMNG_ADDR].(map[string]interface{})
	if existingStorage, ok := rulemngContract["storage"].(map[string]interface{}); ok {
		for k, v := range ruleMngSlots {
			existingStorage[k] = v
		}
		rulemngContract["storage"] = existingStorage
	} else {
		rulemngContract["storage"] = ruleMngSlots
	}

	// Update genesis with domains
	genesis["domains"] = genesisDomains

	// Write genesis file
	genesisPath := filepath.Join(filepath.Dir(g.deployFilePath), g.genesisFile)
	confDir := filepath.Dir(genesisPath)
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("failed to create conf directory: %w", err)
	}

	genesisData, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal genesis data: %w", err)
	}

	// Replace default admin address
	if g.deploy.AdminAddr != "" {
		adminAddr := g.deploy.AdminAddr
		if strings.HasPrefix(adminAddr, "0x") {
			adminAddr = adminAddr[2:]
		}
		genesisStr := string(genesisData)
		genesisStr = strings.ReplaceAll(genesisStr, DEFAULT_ADMIN_ADDR, adminAddr)
		genesisData = []byte(genesisStr)
	}

	if err := os.WriteFile(genesisPath, genesisData, 0644); err != nil {
		return fmt.Errorf("failed to write genesis file: %w", err)
	}

	utils.Info("Generated genesis file: %s", genesisPath)
	return nil
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
