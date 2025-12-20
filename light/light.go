package light

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"pharos-ops/light/types"
	"pharos-ops/light/utils"
)

func GenerateDomainSlots(totalDomains int, domainIndex int, publicKey string, blsPubkey string, endpoint string, stake *big.Int, adminAddr string) map[string]string {
	slots := make(map[string]string)

	// Remove '0x' prefix if present
	if len(publicKey) > 2 && publicKey[:2] == "0x" {
		publicKey = publicKey[2:]
	}

	if len(blsPubkey) > 2 && blsPubkey[:2] == "0x" {
		blsPubkey = blsPubkey[2:]
	}

	// Compute the SHA256 hash of the public key
	pubkeyBytes, _ := hex.DecodeString(publicKey)
	poolid := sha256.Sum256(pubkeyBytes)

	// 1. for `mapping(bytes32 => Validator) public validators`
	validatorsMapBaseSlot := 1
	validatorsMapBaseSlotBytes := utils.IntToBigEndian(validatorsMapBaseSlot)
	validatorsMapValidatorSlot := utils.Keccak(append(poolid[:], validatorsMapBaseSlotBytes...))

	// 2. for `Validator.description`
	validatorDescriptionBaseSlot := 0
	validatorDescriptionMapBaseSlot := utils.BytesAddNum(validatorsMapValidatorSlot, validatorDescriptionBaseSlot)
	description := "domain" + fmt.Sprint(domainIndex)
	descriptionLength := len(description) * 2
	descriptionLengthBytes := utils.ToBytes(descriptionLength)
	hexSlot := utils.StringToHexSlots(description)[0]
	hexstr, _ := hex.DecodeString(hexSlot)
	finalBytes, _ := utils.BytesBitwiseAdd(hexstr, descriptionLengthBytes)
	slots["0x"+hex.EncodeToString(validatorDescriptionMapBaseSlot)] = "0x" + hex.EncodeToString(finalBytes)

	// 3. for `Validator.publicKey`
	validatorPublicKeyBaseSlot := 1
	validatorPublicKeyMapBaseSlot := utils.BytesAddNum(validatorsMapValidatorSlot, validatorPublicKeyBaseSlot)

	// 3.1 Store string length
	publicKeyLength := len(publicKey)*2 + 1 // larger than long bytes
	publicKeyLengthBytes := utils.ToBytes(publicKeyLength)
	slots["0x"+hex.EncodeToString(validatorPublicKeyMapBaseSlot)] = "0x" + hex.EncodeToString(publicKeyLengthBytes)

	// 3.2 Set string
	publicKeyFinalBaseSlot := utils.Keccak(validatorPublicKeyMapBaseSlot)
	hexSlots := utils.StringToHexSlots(publicKey)
	for i, slot := range hexSlots {
		publicKeySlot := utils.BytesAddNum(publicKeyFinalBaseSlot, i)
		slots["0x"+hex.EncodeToString(publicKeySlot)] = "0x" + slot
	}

	// 4. for `Validator.blsPublicKey`
	validatorBlsPublicKeyBaseSlot := 3
	validatorBlsPublicKeyMapBaseSlot := utils.BytesAddNum(validatorsMapValidatorSlot, validatorBlsPublicKeyBaseSlot)

	// 4.1 Store string length
	blsPublicKeyLength := len(blsPubkey)*2 + 1 // larger than long bytes
	blsPublicKeyLengthBytes := utils.ToBytes(blsPublicKeyLength)
	slots["0x"+hex.EncodeToString(validatorBlsPublicKeyMapBaseSlot)] = "0x" + hex.EncodeToString(blsPublicKeyLengthBytes)

	// 4.2 Set string
	blsPublicKeyFinalBaseSlot := utils.Keccak(validatorBlsPublicKeyMapBaseSlot)
	blsHexSlots := utils.StringToHexSlots(blsPubkey)
	for i, slot := range blsHexSlots {
		blsPublicKeySlot := utils.BytesAddNum(blsPublicKeyFinalBaseSlot, i)
		slots["0x"+hex.EncodeToString(blsPublicKeySlot)] = "0x" + slot
	}

	// 5. for `Validator.endpoint`
	validatorEndpointBaseSlot := 5
	validatorEndpointMapBaseSlot := utils.BytesAddNum(validatorsMapValidatorSlot, validatorEndpointBaseSlot)
	endpointsBytes := []byte(endpoint)
	endpointBytesLen := len(endpointsBytes)
	if endpointBytesLen <= 31 {
		// Less than or equal to 31 bytes: store directly
		endpointSlotValue := make([]byte, 32)
		copy(endpointSlotValue, endpointsBytes)
		endpointSlotValue[31] = byte(endpointBytesLen * 2) // Store length in the last byte
		slots["0x"+hex.EncodeToString(validatorEndpointMapBaseSlot)] = "0x" + hex.EncodeToString(endpointSlotValue)
	} else {
		// 1. Store length (same encoding as publicKey)
		endpointBytesLenEncoded := endpointBytesLen*2 + 1
		slots["0x"+hex.EncodeToString(validatorEndpointMapBaseSlot)] = "0x" + hex.EncodeToString(utils.IntToBigEndian(endpointBytesLenEncoded))

		// 2. Calculate data location using keccak on the base slot
		dataLocation := new(big.Int).SetBytes(utils.Keccak(validatorEndpointMapBaseSlot)).Int64()

		for i := 0; i < endpointBytesLen; i += 32 {
			end := i + 32
			if end > endpointBytesLen {
				end = endpointBytesLen
			}
			chunk := endpointsBytes[i:end]
			slotKey := dataLocation + int64(i/32)
			slotKeyBytes := utils.IntToBigEndian(int(slotKey)) // Convert slot key to bytes
			slots["0x"+hex.EncodeToString(slotKeyBytes)] = "0x" + hex.EncodeToString(utils.PadChunk(chunk, 32))
		}
	}

	// 6. for `Validator.status`
	validatorStatusSlot := 6
	validatorStatusMapBaseSlot := utils.BytesAddNum(validatorsMapValidatorSlot, validatorStatusSlot)
	status := 1
	statusBytes := utils.IntToBigEndian(status)
	slots["0x"+hex.EncodeToString(validatorStatusMapBaseSlot)] = "0x" + hex.EncodeToString(statusBytes)

	// 7. for `Validator.poolId`
	validatorPoolIDBaseSlot := 7
	validatorPoolIDMapBaseSlot := utils.BytesAddNum(validatorsMapValidatorSlot, validatorPoolIDBaseSlot)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(poolid[:])

	// 8. for `Validator.totalStake`
	validatorStakeBaseSlot := 8
	validatorPoolIDMapBaseSlot = utils.BytesAddNum(validatorsMapValidatorSlot, validatorStakeBaseSlot)
	stakeBytes := utils.BigIntToBigEndian(stake)
	stakeBytes = utils.PadTo32Bytes(stakeBytes)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(stakeBytes)

	// 9. for `validator.owner`
	validatorOwnerBaseSlot := 9
	validatorPoolIDMapBaseSlot = utils.BytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	rootSysAddr := adminAddr
	if len(rootSysAddr) > 2 && rootSysAddr[:2] == "0x" {
		rootSysAddr = rootSysAddr[2:] // Remove the '0x' prefix
	}
	rootSysAddrSlotValue := fmt.Sprintf("%064s", rootSysAddr) // Pad to 64 characters
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + rootSysAddrSlotValue

	validatorOwnerBaseSlot = 10
	validatorPoolIDMapBaseSlot = utils.BytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	snapshotStakeBytes := utils.BigIntToBigEndian(stake)
	snapshotStakeBytes = utils.PadTo32Bytes(snapshotStakeBytes)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(snapshotStakeBytes)

	// 11. for `validator.pendingWithdrawStake`
	validatorOwnerBaseSlot = 11
	validatorPoolIDMapBaseSlot = utils.BytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	pendingWithdrawStake := utils.IntToBigEndian(0)
	pendingWithdrawStake = utils.PadTo32Bytes(pendingWithdrawStake)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(pendingWithdrawStake)

	// 12. for `validator.pendingWithdrawWindow`
	validatorOwnerBaseSlot = 12
	validatorPoolIDMapBaseSlot = utils.BytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	pendingWithdrawWindow := utils.IntToBigEndian(0)
	pendingWithdrawWindow = utils.PadTo32Bytes(pendingWithdrawWindow)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(pendingWithdrawWindow)

	// 13. for `bytes32[] public activePoolIds;`
	activePoolIdsBaseSlot := 2
	// 13.1 put array length
	activePoolIdsBaseSlotBytes := utils.ToBytes(activePoolIdsBaseSlot)
	activePoolIdsBaseSlotBytes = utils.PadTo32Bytes(activePoolIdsBaseSlotBytes)
	activePoolIdsLength := utils.ToBytes(totalDomains)
	activePoolIdsLength = utils.PadTo32Bytes(activePoolIdsLength)
	slots["0x"+hex.EncodeToString(activePoolIdsBaseSlotBytes)] = "0x" + hex.EncodeToString(activePoolIdsLength)

	// 13.2 put array value
	activePoolIDFinalSlot := utils.Keccak(activePoolIdsBaseSlotBytes)
	activePoolIDFinalValidatorSlot := utils.BytesAddNum(activePoolIDFinalSlot, domainIndex)
	slots["0x"+hex.EncodeToString(activePoolIDFinalValidatorSlot)] = "0x" + hex.EncodeToString(poolid[:])

	return slots
}

func GenerateChaincfgSlots(configs map[string]string, adminAddr string) map[string]string {
	slots := make(map[string]string)

	// 1. put `configCps` length in `config_cps_base_slot`
	configCpsBaseSlot := 0
	configCpsBaseSlotBytes := utils.IntToBigEndian(configCpsBaseSlot)
	configCpsLength := 1 // put the genesis configs
	configCpsLengthBytes := utils.IntToBigEndian(configCpsLength)
	slots["0x"+hex.EncodeToString(configCpsBaseSlotBytes)] = "0x" + hex.EncodeToString(configCpsLengthBytes)

	// 2. put genesis `ConfigCheckpoint`
	genesisConfigCpBaseSlot := utils.Keccak(configCpsBaseSlotBytes)

	// 3. put `ConfigCheckpoint.blockNum` and `ConfigCheckpoint.effectiveBlockNum`
	blockNums := uint64(0)
	blockNumsBytes := utils.IntToBigEndian(int(blockNums))
	slots["0x"+hex.EncodeToString(genesisConfigCpBaseSlot)] = "0x" + hex.EncodeToString(utils.PadTo32Bytes(blockNumsBytes))

	// 4. put `Config[] configs`
	// 4.1 put `Config[] configs` length
	configsBaseSlot := 1
	configsBaseSlotBytes := utils.BytesAddNum(genesisConfigCpBaseSlot, configsBaseSlot)
	configNums := len(configs)
	configNumsBytes := utils.IntToBigEndian(configNums)
	slots["0x"+hex.EncodeToString(configsBaseSlotBytes)] = "0x" + hex.EncodeToString(utils.PadTo32Bytes(configNumsBytes))

	// 4.2 put real genesis configs
	configKvsBaseSlot := utils.Keccak(configsBaseSlotBytes)
	slotIndex := 0
	for configKey, configValue := range configs {
		// key
		configKeySlot := utils.BytesAddNum(configKvsBaseSlot, slotIndex)
		utils.GenerateStringSlot(configKey, configKeySlot, slots)
		slotIndex++

		// value
		configValueSlot := utils.BytesAddNum(configKvsBaseSlot, slotIndex)
		utils.GenerateStringSlot(configValue, configValueSlot, slots)
		slotIndex++
	}

	// 5. put init rootSys
	configRootSysBaseSlot := 1
	configRootSysBaseSlotBytes := utils.IntToBigEndian(configRootSysBaseSlot)
	rootSysAddr := adminAddr
	if len(rootSysAddr) > 2 && rootSysAddr[:2] == "0x" {
		rootSysAddr = rootSysAddr[2:] // Remove the '0x' prefix
	}

	rootSysAddrSlotValue := fmt.Sprintf("%064s", rootSysAddr) // Pad to 64 characters
	slots["0x"+hex.EncodeToString(configRootSysBaseSlotBytes)] = "0x" + rootSysAddrSlotValue

	return slots
}

func GenerateRuleMngSlots(configs map[string]string, adminAddr string) map[string]string {
	rootSysBaseSlot := 5
	rootSysBaseSlotBytes := utils.IntToBigEndian(rootSysBaseSlot)
	adminSlotHexKey := "0x" + hex.EncodeToString(rootSysBaseSlotBytes)
	adminSlotValue := configs[adminSlotHexKey]

	if len(adminAddr) > 2 && adminAddr[:2] == "0x" {
		adminAddr = adminAddr[2:] // Remove the '0x' prefix
	}

	adminSlotValue = adminSlotValue[:len(adminSlotValue)-len(adminAddr)] + adminAddr

	configs["0x"+hex.EncodeToString(rootSysBaseSlotBytes)] = adminSlotValue

	return configs
}

func GenerateDomain(deployFilePath string) error {
	domain, err := generateDomain(deployFilePath)
	if err != nil {
		return err
	}
	domainPath, err := filepath.Abs("domain0.json")
	if err != nil {
		return err
	}
	file, err := os.Create(domainPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %s", err)
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(domain); err != nil {
		return fmt.Errorf("failed to write JSON data: %s", err)
	}
	return nil
}

func generateDomain(deployFilePath string) (*types.Domain, error) {
	data, err := os.ReadFile(deployFilePath)
	if err != nil {
		return nil, err
	}
	deploy := utils.NewDefaultDeploy()
	if err = json.Unmarshal(data, deploy); err != nil {
		return nil, fmt.Errorf("invalid json format for deploy.light.json: %v", err)
	}
	absPath, err := filepath.Abs(deployFilePath)
	if err != nil {
		return nil, err
	}
	if absPath != deploy.BuildRoot {
		return nil, fmt.Errorf("deploy file should be in $build_root/scripts")
	}
	deploy.GenesisTpl, err = filepath.Abs(deploy.GenesisTpl)
	if err != nil {
		return nil, err
	}
	if len(deploy.Domains) <= 0 {
		return nil, fmt.Errorf("no domains items")
	}
	domain := utils.NewDefaultDomain()

	for k, v := range deploy.Domains {
		if len(v.Cluster) != 1 && v.Cluster[0].Instances != "light" {
			return nil, fmt.Errorf("only support light mode")
		}
		if deploy.UseGeneratedKeys {
			domain.UseGeneratedKeys = true
			domain.KeyPasswd = v.KeyPasswd
			if domain.KeyPasswd == "" {
				domain.KeyPasswd = "123abc"
			}
			domain.PortalSslPass = v.PortalSslPass
			if domain.PortalSslPass == "" {
				domain.PortalSslPass = "123abc"
			}
		}
		domain.EnableSetkeyEnv = v.EnableSetkeyEnv
		domain.DeployDir = v.DeployDir
		if domain.DeployDir == "" {
			domain.DeployDir = deploy.DeployRoot + "domain0"
		}
		keyDir := domain.BuildRoot + "scripts/resources/domain_keys/" + deploy.DomainKeyType + "/domain0"
		stabilizingKeyDir := domain.BuildRoot + "'scripts/resources/domain_keys/bls12381/domain0"
		keyFile := "generate.key"
		pkeyFile := "generate.pub"
		if domain.UseGeneratedKeys {
			keyFile = "new.key"
			pkeyFile = "new.pub"
		}
		utils.GeneratePrivateKey(deploy.DomainKeyType, keyDir, keyFile, domain.KeyPasswd, "")
		utils.GeneratePrivateKey("bls12381", stabilizingKeyDir, keyFile, domain.KeyPasswd, deploy.DeployRoot)
		domain.AdminAddr = deploy.AdminAddr
		domain.Secret.Domain.Files["key"] = keyDir + "/" + keyFile
		domain.Secret.Domain.Files["key_pub"] = keyDir + "/" + pkeyFile
		domain.Secret.Domain.Files["stabilizing_key"] = stabilizingKeyDir + "/" + keyFile
		domain.Secret.Domain.Files["stabilizing_pk"] = stabilizingKeyDir + "/" + pkeyFile
		domain.Secret.Client.Files["ca_cert"] = "../conf/resources/portal/" + deploy.ClientKeyType + "/client/ca.crt"
		domain.Secret.Client.Files["cert"] = "../conf/resources/portal/" + deploy.ClientKeyType + "/client/client.crt"
		domain.Secret.Client.Files["key"] = "../conf/resources/portal/" + deploy.ClientKeyType + "/client/client.key"
		domain.GenesisConf = "../conf/genesis" + deploy.ChainID + "conf"
		domain.BuildRoot = deploy.BuildRoot
		domain.ChainID = deploy.ChainID
		domain.DomainLabel = k
		domain.Version = deploy.Version
		domain.RunUser = deploy.RunUser
		domain.Docker = deploy.Docker
		domain.Common.Log = deploy.Common.Log
		domain.Common.Config = deploy.Common.Config
		domain.Common.Gflags = deploy.Common.Gflags
		domain.Mygrid = deploy.Mygrid
		domain.ChainProtocol = deploy.ChainProtocol
		var ins types.Instance
		ins.IP = v.Cluster[0].DeployIP
		ins.Service = "light"
		ins.Args = []string{"-d"}
		ins.Env["LIGHT_RPC_LISTEN_URL"] = fmt.Sprintf("%v:%v", v.Cluster[0].Host, v.Cluster[0].StartPort)
		ins.Env["LIGHT_RPC_ADVERTISE_URL"] = fmt.Sprintf("%v:%v", v.Cluster[0].Host, v.Cluster[0].StartPort)
		// Only include HTTP and WebSocket URLs to match Python implementation
		var clientUrls []string
		var clientListenUrls []string

		// Add HTTP URL
		if v.ClientHttpPort > 0 {
			clientUrls = append(clientUrls, fmt.Sprintf("http://%v:%v", v.Cluster[0].Host, v.ClientHttpPort))
			clientListenUrls = append(clientListenUrls, fmt.Sprintf("http://0.0.0.0:%v", v.ClientHttpPort))
		}

		// Add WebSocket URL
		if v.ClientWsPort > 0 {
			clientUrls = append(clientUrls, fmt.Sprintf("ws://%v:%v", v.Cluster[0].Host, v.ClientWsPort))
			clientListenUrls = append(clientListenUrls, fmt.Sprintf("ws://0.0.0.0:%v", v.ClientWsPort))
		}

		ins.Env["CLIENT_ADVERTISE_URLS"] = strings.Join(clientUrls, ",")
		ins.Env["CLIENT_LISTEN_URLS"] = strings.Join(clientListenUrls, ",")
		ins.Env["PORTAL_UUID"] = "100"
		ins.Env["DOMAIN_LISTEN_URLS0"] = fmt.Sprintf("tcp://%v,%v", v.Cluster[0].Host, v.DomainPort)
		ins.Env["DOMAIN_LISTEN_URLS1"] = fmt.Sprintf("tcp://%v,%v", v.Cluster[0].Host, v.DomainPort+1)
		ins.Env["DOMAIN_LISTEN_URLS2"] = fmt.Sprintf("tcp://%v,%v", v.Cluster[0].Host, v.DomainPort+2)
		ins.Env["STORAGE_RPC_ADVERTISE_URL"] = fmt.Sprintf("%v:%v", v.Cluster[0].Host, v.Cluster[0].StartPort)
		ins.Env["STORAGE_ID"] = "0"
		ins.Env["STORAGE_MSU"] = "0-255"
		ins.Env["TXPOOL_PARTITION_LIST"] = "0-255"
		content, err := os.ReadFile(domain.Secret.Domain.Files["key_pub"])
		if err != nil {
			return nil, err
		}

		ins.Env["NODE_ID"] = utils.GenerateNodeID(string(content))
		domain.Cluster["light"] = ins
		// only generate domain0 for pharos use case
		break
	}
	return domain, nil
}

func GenerateGenesis(deployFilePath string, domain *types.Domain) error {
	spk, err := os.ReadFile(domain.Secret.Domain.Files["stabilizing_key"])
	if err != nil {
		return err
	}
	pk, err := os.ReadFile(domain.Secret.Domain.Files["key_pub"])
	if err != nil {
		return err
	}
	data, err := os.ReadFile(deployFilePath)
	if err != nil {
		return err
	}
	deploy := utils.NewDefaultDeploy()
	if err = json.Unmarshal(data, deploy); err != nil {
		return fmt.Errorf("invalid json format for deploy.light.json: %v", err)
	}
	genesis := make(map[string]interface{})
	tpl, err := os.ReadFile(deploy.GenesisTpl)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(tpl, &genesis); err != nil {
		return fmt.Errorf("invalid json format for genesis.tpl: %v", err)
	}
	genesisDomain := make(map[string]string)
	genesisDomain["pubkey"] = string(pk)
	genesisDomain["stabilizing_pubkey"] = string(spk)
	genesisDomain["owner"] = "root"
	genesisDomain["endpoints"] = domain.Cluster["light"].Env["LIGHT_RPC_ADVERTISE_URL"]
	genesisDomain["staking"] = "200000000"
	genesisDomain["commission_rate"] = "10"
	genesisDomain["node_id"] = domain.Cluster["light"].Env["NODE_ID"]
	genesis["domains"] = genesisDomain
	weiAmount := big.NewInt(int64(domain.InitialStakeInGwei)).Mul(big.NewInt(int64(domain.InitialStakeInGwei)), big.NewInt(int64(1000000000)))
	storageSlotKvs := GenerateDomainSlots(1, 0, string(pk), string(spk), domain.Cluster["light"].Env["LIGHT_RPC_ADVERTISE_URL"], weiAmount, domain.AdminAddr)
	epochBaseSlot := 5
	epochBaseSlotBytes := utils.ToBytes(epochBaseSlot)
	epochNum := 0
	epochNumBytes := utils.ToBytes(epochNum)
	storageSlotKvs["0x"+hex.EncodeToString(epochBaseSlotBytes)] = "0x" + hex.EncodeToString(epochNumBytes)
	totalStakeBaseSlot := 6
	totalStakeBaseSlotBytes := utils.ToBytes(totalStakeBaseSlot)
	totalStakeBytes := utils.BigIntToBigEndian(weiAmount)
	storageSlotKvs["0x"+hex.EncodeToString(totalStakeBaseSlotBytes)] = "0x" + hex.EncodeToString(totalStakeBytes)
	sysStakingAddr := "4100000000000000000000000000000000000000"
	sysStaking := make(map[string]interface{})
	sysStaking["storage"] = storageSlotKvs
	sysStaking["balance"] = hex.EncodeToString(totalStakeBytes)
	alloc := make(map[string]interface{})
	alloc[sysStakingAddr] = sysStaking

	sysChainCfgAddr := "3100000000000000000000000000000000000000"
	chainCfgSlotKvs := GenerateChaincfgSlots(genesis["configs"].(map[string]string), deploy.AdminAddr)
	chainCfg := make(map[string]interface{})
	chainCfg["storage"] = chainCfgSlotKvs
	alloc[sysChainCfgAddr] = chainCfg

	sysRuleMngAddr := "2100000000000000000000000000000000000000"
	mngStorageSlotKvs := GenerateRuleMngSlots(storageSlotKvs, deploy.AdminAddr)
	sysRuleMng := make(map[string]interface{})
	sysRuleMng["storage"] = mngStorageSlotKvs
	alloc[sysRuleMngAddr] = sysRuleMng
	genesis["alloc"] = alloc

	genesisPath, err := filepath.Abs(domain.GenesisConf)
	if err != nil {
		return err
	}
	file, err := os.Create(genesisPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %s", err)
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(genesis); err != nil {
		return fmt.Errorf("failed to write JSON data: %s", err)
	}

	// 获取admin_addr和proxy_admin_addr
	confAdminAddr := strings.TrimPrefix(deploy.AdminAddr, "0x")
	confProxyAdminAddr := strings.TrimPrefix(deploy.ProxyAdminAddr, "0x")

	// 默认地址
	defaultAdminAddr := "2cc298bdee7cfeac9b49f9659e2f3d637e149696"
	defaultProxyAdminAddr := "0278872d3f68b15156e486da1551bcd34493220d"

	// 替换文件内容
	if err := utils.ReplaceInFile(genesisPath, defaultAdminAddr, confAdminAddr); err != nil {
		return err
	}
	if err := utils.ReplaceInFile(genesisPath, defaultProxyAdminAddr, confProxyAdminAddr); err != nil {
		return err
	}

	return nil
}

func InitializeConf(domain *types.Domain) error {
	cliBinDir := domain.DeployDir + "/client/bin/"

	jsonFiles := map[string]string{
		fmt.Sprintf("/%s/global/config", domain.ChainID):              domain.BuildRoot + "/conf/global.conf",
		fmt.Sprintf("/%s/services/portal/config", domain.ChainID):     domain.BuildRoot + "/conf/portal.conf",
		fmt.Sprintf("/%s/services/dog/config", domain.ChainID):        domain.BuildRoot + "/conf/dog.conf",
		fmt.Sprintf("/%s/services/txpool/config", domain.ChainID):     domain.BuildRoot + "/conf/txpool.conf",
		fmt.Sprintf("/%s/services/controller/config", domain.ChainID): domain.BuildRoot + "/conf/controller.conf",
		fmt.Sprintf("/%s/services/compute/config", domain.ChainID):    domain.BuildRoot + "/conf/compute.conf",
	}

	for key, file := range jsonFiles {
		fmt.Printf("Setting %s\n", key)

		fileContent, err := os.ReadFile((file))
		if err != nil {
			return err
		}

		// Using the command to set the configuration in etcd
		cmd := fmt.Sprintf("cd %s; ./meta_tool -conf %s -set -key=%s -value='%s'",
			cliBinDir,
			"const.META_SERVICE_CONFIG_FILENAME", // Replace with actual constant
			key,
			fileContent,
		)

		if _, err := exec.Command("bash", "-c", cmd).CombinedOutput(); err != nil {
			return err
		}
	}

	// Handling secrets
	confs := map[string]interface{}{
		fmt.Sprintf("/%s/secrets/domain.key", domain.ChainID): map[string]string{
			"domain_key":      base64.StdEncoding.EncodeToString([]byte(domain.Secret.Domain.Files["key"])),
			"stabilizing_key": base64.StdEncoding.EncodeToString([]byte(domain.Secret.Domain.Files["key"])),
		},
	}

	for name, instance := range domain.Cluster {
		if len(instance.Log) > 0 || len(instance.Config) > 0 {
			confs[fmt.Sprintf("/%s/services/%s/instance_config/%s", domain.ChainID, instance.Service, name)] = map[string]interface{}{
				"log":        instance.Log,
				"parameters": map[string]interface{}{fmt.Sprintf("/GlobalFlag/%s", instance.Gflags): instance.Gflags},
				"config":     instance.Config,
			}
		}
	}

	for key, value := range confs {
		fmt.Printf("Setting %s\n", key)

		valueJSON, _ := json.Marshal(value) // Convert to JSON
		cmd := fmt.Sprintf("cd %s; ./meta_tool -conf %s -set -key=%s -value='%s'",
			cliBinDir,
			"const.META_SERVICE_CONFIG_FILENAME", // Replace with actual constant
			key,
			valueJSON,
		)

		if _, err := exec.Command("bash", "-c", cmd).CombinedOutput(); err != nil {
			return err
		}
	}

	// TODO: Save domain files to etcd

	return nil
}

func BootStrap(domainPath string) error {
	data, err := os.ReadFile(domainPath)
	if err != nil {
		return err
	}
	domain := utils.NewDefaultDomain()
	if err = json.Unmarshal(data, domain); err != nil {
		return fmt.Errorf("invalid json format for domain0.json: %v", err)
	}
	err = InitializeConf(domain)
	if err != nil {
		return err
	}
	cliBinDir := domain.DeployDir + "/client/bin/"
	command := "cd " + cliBinDir + "; LD_PRELOAD=./libevmone.so ./aldaba_cli genesis -g ../conf/genesis.conf -s mygrid_genesis.conf'"
	if _, err := exec.Command("bash", "-c", command).CombinedOutput(); err != nil {
		return err
	}
	return nil
}

func Start(domainPath string) error {
	data, err := os.ReadFile(domainPath)
	if err != nil {
		return err
	}
	domain := utils.NewDefaultDomain()
	if err = json.Unmarshal(data, domain); err != nil {
		return fmt.Errorf("invalid json format for domain0.json: %v", err)
	}
	cmd := "cd " + domain.DeployDir + "/light/bin" + "; LD_PRELOAD=./libevmone.so ./aldaba_light -c ../conf/launch.conf -d"
	if _, err := exec.Command("bash", "-c", cmd).CombinedOutput(); err != nil {
		return err
	}
	return nil
}

func Stop(domainPath string) error {
	data, err := os.ReadFile(domainPath)
	if err != nil {
		return err
	}
	domain := utils.NewDefaultDomain()
	if err = json.Unmarshal(data, domain); err != nil {
		return fmt.Errorf("invalid json format for domain0.json: %v", err)
	}
	cmd := utils.PspidGrep("aldaba_light",
		"awk '{system(\"pwdx \"$1\" 2>&1\")}'",
		"grep -v MATCH_MATCH",
		fmt.Sprintf(`sed "s#%s#MATCH_MATCH#g"`, domain.DeployDir+"/light/bin"),
		"grep MATCH_MATCH",
		"awk -F: '{system(\"kill -15 \"$1\" 2>&1\")}'",
	)
	if _, err := exec.Command("bash", "-c", cmd).CombinedOutput(); err != nil {
		return err
	}
	return nil
}
