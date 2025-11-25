package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Domain struct {
	BuildRoot          string              `json:"build_root"`
	ChainID            string              `json:"chain_id"`
	ChainProtocol      string              `json:"chain_protocol"` // default: native
	DomainLabel        string              `json:"domain_label"`
	Version            string              `json:"version"`
	RunUser            string              `json:"run_user"`
	DeployDir          string              `json:"deploy_dir"`
	AdminAddr          string              `json:"admin_addr"`
	GenesisConf        string              `json:"genesis_conf"` // default: ../conf/genesis.conf
	Mygrid             MygridConfig        `json:"mygrid"`
	Secret             Secret              `json:"secret"`
	UseGeneratedKeys   bool                `json:"use_generated_keys"` // default: false
	KeyPasswd          string              `json:"key_passwd"`         // default: 123abc
	PortalSslPass      string              `json:"portal_ssl_pass"`    // default: 123abc
	EnableSetkeyEnv    bool                `json:"enable_setkey_env"`  // default: true
	Docker             Docker              `json:"docker"`
	Common             Common              `json:"common"`
	Cluster            map[string]Instance `json:"cluster"`
	InitialStakeInGwei uint64              `json:"initial_stake_in_gwei"` // default: 1000000000
}

type Deploy struct {
	BuildRoot        string                   `json:"build_root"`         // required
	ChainID          string                   `json:"chain_id"`           // required
	ChainProtocol    string                   `json:"chain_protocol"`     // default: "native"
	Version          string                   `json:"version"`            // required
	RunUser          string                   `json:"run_user"`           // required
	DeployRoot       string                   `json:"deploy_root"`        // optional
	AdminAddr        string                   `json:"admin_addr"`         // optional
	ProxyAdminAddr   string                   `json:"proxy_admin_addr"`   // optional
	GenesisTpl       string                   `json:"genesis_tpl"`        // required
	Mygrid           MygridConfig             `json:"mygrid"`             // required
	DomainKeyType    string                   `json:"domain_key_type"`    // required
	ClientKeyType    string                   `json:"client_key_type"`    // optional
	UseGeneratedKeys bool                     `json:"use_generated_keys"` // optional
	UseLatestVersion bool                     `json:"use_latest_version"` // optional
	Docker           Docker                   `json:"docker"`             // required
	Common           *Common                  `json:"common"`             // optional
	Aldaba           *Extra                   `json:"aldaba"`             // optional
	Storage          *StorageExtra            `json:"storage"`            // optional
	Domains          map[string]DomainSummary `json:"domains"`            // optional
}

type MygridConfig struct {
	Conf MygridCommonConfig `json:"conf"`
	Env  MygridCommonConfig `json:"env"`
}

type MygridCommonConfig struct {
	EnableAdaptive bool   `json:"enable_adaptive"` // default: true
	FilePath       string `json:"filepath"`
}

type SecretFiles struct {
	KeyType string            `json:"key_type"` // default: prime256v1
	Files   map[string]string `json:"files"`
}

type Secret struct {
	Domain SecretFiles `json:"domain"`
	Client SecretFiles `json:"client"`
}

type Docker struct {
	Enable   bool   `json:"enable"` // default: false
	Registry string `json:"registry"`
}

type Common struct {
	Env     map[string]string      `json:"env"`
	Log     map[string]LogConfig   `json:"log"`
	Config  map[string]interface{} `json:"config"`
	Gflags  map[string]string      `json:"gflags"`
	Metrics Metrics                `json:"metrics"`
}

type LogConfig struct {
	Filename    string `json:"filename"`
	MaxFileSize uint64 `json:"max_file_size"`
	MaxFiles    int    `json:"max_files"`
	Level       string `json:"level"`
	Flush       bool   `json:"flush"`
}

type Metrics struct {
	Enable       bool   `json:"enable"`
	PushAddress  string `json:"push_address"`
	JobName      string `json:"job_name"`
	PushInterval string `json:"push_interval"`
	PushPort     string `json:"push_port"`
}

type Instance struct {
	Service string                 `json:"service"`
	Name    string                 `json:"name"`
	IP      string                 `json:"ip"`
	Dir     string                 `json:"dir"`
	Args    []string               `json:"args"`
	Env     map[string]string      `json:"env"`
	Log     map[string]interface{} `json:"log"`
	Config  map[string]interface{} `json:"config"`
	Gflags  map[string]string      `json:"gflags"`
}

type StorageExtra struct {
	Args []string          `json:"args"` // default: empty slice
	Env  map[string]string `json:"env"`  // default: empty map
}

type Extra struct {
	Args   []string               `json:"args"`   // default: empty slice
	Env    map[string]string      `json:"env"`    // default: empty map
	Log    map[string]interface{} `json:"log"`    // default: empty map
	Config map[string]interface{} `json:"config"` // default: empty map
	Gflags map[string]string      `json:"gflags"` // default: empty map
}

type Node struct {
	DeployIP  string `json:"deploy_ip"`  // default: "127.0.0.1"
	Host      string `json:"host"`       // default: "127.0.0.1"
	StartPort int    `json:"start_port"` // default: 20000
	Instances string `json:"instances"`  // default: ""
}

type DomainSummary struct {
	DeployDir          string `json:"deploy_dir"`            // default: ""
	DomainRole         int    `json:"domain_role"`           // default: 0
	KeyPasswd          string `json:"key_passwd"`            // default: ""
	PortalSslPass      string `json:"portal_ssl_pass"`       // default: ""
	DomainPort         int    `json:"domain_port"`           // default: 19000
	ClientTcpPort      int    `json:"client_tcp_port"`       // default: 18000
	ClientWsPort       int    `json:"client_ws_port"`        // default: 0
	ClientWssPort      int    `json:"client_wss_port"`       // default: 0
	ClientHttpPort     int    `json:"client_http_port"`      // default: 0
	Cluster            []Node `json:"cluster"`               // default: empty slice
	InitialStakeInGwei int    `json:"initial_stake_in_gwei"` // default: 1000000000
	EnableSetkeyEnv    bool   `json:"enable_setkey_env"`     // default: true
}

type GenesisDomain struct {
	Pubkey            string `json:"pubkey"`
	StabilizingPubkey string `json:"stabilizing_pubkey"`
	Owner             string `json:"owner"`
	Endpoints         string `json:"endpoints"`
	Staking           string `json:"staking"`
	CommissionRate    string `json:"commission_rate"`
	NodeID            string `json:"node_id"`
}

func GenerateNodeID(pk string) string {
	hash := sha256.Sum256([]byte(pk))
	return fmt.Sprintf("%x", hash)
}

func NewDefaultDomain() *Domain {
	return &Domain{
		BuildRoot:     "",
		ChainID:       "",
		ChainProtocol: "native",
		DomainLabel:   "",
		Version:       "",
		RunUser:       "",
		DeployDir:     "",
		GenesisConf:   "../conf/genesis.conf",
		Mygrid: MygridConfig{
			Conf: MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
			Env: MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
		},
		Secret: Secret{
			Domain: SecretFiles{
				KeyType: "prime256v1",
				Files:   make(map[string]string),
			},
			Client: SecretFiles{
				KeyType: "prime256v1",
				Files:   make(map[string]string),
			},
		},
		UseGeneratedKeys: false,
		KeyPasswd:        "123abc",
		PortalSslPass:    "123abc",
		EnableSetkeyEnv:  true,
		Docker: Docker{
			Enable:   false,
			Registry: "",
		},
		Common: Common{
			Env:    make(map[string]string),
			Log:    make(map[string]LogConfig),
			Config: make(map[string]interface{}),
			Gflags: make(map[string]string),
			Metrics: Metrics{
				Enable:       false,
				PushAddress:  "",
				JobName:      "",
				PushInterval: "",
				PushPort:     "",
			},
		},
		Cluster:            make(map[string]Instance),
		InitialStakeInGwei: 1000000000,
	}
}

func getPubKey(keyType string, prikeyPath string, keyPasswd string) (string, []byte, error) {
	// Check if the private key file exists
	if _, err := os.Stat(prikeyPath); os.IsNotExist(err) {
		return "", nil, fmt.Errorf("%s does not exist", prikeyPath)
	}

	// Supported key types check
	if keyType != "prime256v1" {
		return "", nil, fmt.Errorf("%s is not supported, only PRIME256V1 is allowed", keyType)
	}

	// Generate public key
	pubkeyHex, err := readKeyFileToHex("ec", prikeyPath, keyPasswd) // Implementation needs to be provided
	if err != nil {
		return "", nil, err
	}

	pubkey := "1003" + pubkeyHex // Prefix for PRIME256V1

	// Convert pubkey hex to bytes
	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode public key: %s", err)
	}

	return pubkey, pubkeyBytes, nil
}

func readKeyFileToHex(keyType string, prikeyPath string, keyPasswd string) (string, error) {
	// Build the openssl command
	cmd := exec.Command("bash", "-c", fmt.Sprintf("openssl %s -in %s -noout -text -passin pass:%s", keyType, prikeyPath, keyPasswd))
	output, err := cmd.CombinedOutput() // Get combined stdout and stderr

	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command: %s: %s", err, output)
	}

	outputLines := strings.Split(string(output), "\n")
	var filteredLines []string

	// Filter lines that start with whitespace
	for _, line := range outputLines {
		if regexp.MustCompile(`^\s`).MatchString(line) {
			filteredLines = append(filteredLines, line)
		}
	}

	if len(filteredLines) < 4 {
		return "", fmt.Errorf("invalid openssl return: %v", filteredLines)
	}

	// Skip the first three lines
	filteredLines = filteredLines[3:]

	// Join the lines, remove spaces and colons
	out := strings.Join(filteredLines, "")
	out = strings.ReplaceAll(out, " ", "")
	out = strings.ReplaceAll(out, ":", "")

	return out, nil
}

func GeneratePrivateKey(keyType string, keyDir, keyFile, keyPasswd string, buildRoot string) error {
	prikeyPath := filepath.Join(keyDir, keyFile)
	pubkeyFile := keyFile[:len(keyFile)-4] + ".pub" // Assuming the .key extension

	if _, err := os.Stat(prikeyPath); err == nil {
		log.Printf("existed key: %s, override it with new key", prikeyPath)
	} else {
		log.Printf("generate new key %s", prikeyPath)
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %s", err)
		}
	}

	if keyType != "prime256v1" && keyType != "bls12381" {
		log.Printf("%s is not supported", keyType)
		return nil
	}

	if keyType == "prime256v1" {
		cmd := exec.Command("bash", "-c", fmt.Sprintf("openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -outform pem -out %s -v2 aes-256-cbc -passout pass:%s", prikeyPath, keyPasswd))
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("command execution failed: %s: %s", err, output)
		}

		// Get public key
		pubkey, _, err := getPubKey("prime256v1", prikeyPath, keyPasswd)
		if err != nil {
			return err
		}

		if err := os.WriteFile(filepath.Join(keyDir, pubkeyFile), []byte(pubkey), 0644); err != nil {
			return fmt.Errorf("failed to write public key to file: %s", err)
		}
	} else {
		cmd := exec.Command("bash", "-c", fmt.Sprintf("LD_PRELOAD=%s %s crypto -t gen-key -a bls12381 | tail -n 2", buildRoot+"bin/libevmone.so", buildRoot+"bin/aldaba_cli"))

		// Run the command and capture the output
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute command: %s: %s", err, string(output))
		}

		// Process the output to retrieve private and public keys
		outputLines := strings.Split(string(output), "\n")
		if len(outputLines) < 2 {
			return fmt.Errorf("unexpected output format: %s", string(output))
		}

		blsPrikey := strings.Split(outputLines[0], ":")[1]
		blsPubkey := strings.Split(outputLines[1], ":")[1]

		// Write the private key to the file
		if err := os.WriteFile(fmt.Sprintf("%s/%s", keyDir, keyFile), []byte(blsPrikey), 0644); err != nil {
			return fmt.Errorf("failed to write private key to file: %s", err)
		}

		// Write the public key to the file
		if err := os.WriteFile(fmt.Sprintf("%s/%s", keyDir, pubkeyFile), []byte(blsPubkey), 0644); err != nil {
			return fmt.Errorf("failed to write public key to file: %s", err)
		}

		return nil
	}

	return nil
}

func replaceInFile(filePath string, oldStr string, newStr string) error {
	path, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %s", err)
	}

	// 替换内容
	newContent := strings.ReplaceAll(string(content), oldStr, newStr)
	if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write updated content to file: %s", err)
	}

	return nil
}

func padChunk(chunk []byte, length int) []byte {
	padded := make([]byte, length)
	copy(padded, chunk)
	return padded
}

func stringToHexSlots(s string) []string {
	// 将字符串转换为十六进制表示
	hexString := hex.EncodeToString([]byte(s))

	// 按 32 字节（64 个十六进制字符）分割
	slots := []string{}
	for i := 0; i < len(hexString); i += 64 {
		end := i + 64
		if end > len(hexString) {
			end = len(hexString)
		}
		slot := hexString[i:end]
		// 如果最后一个 slot 不足 64 个字符，用 0 填充
		slot = fmt.Sprintf("%-64s", slot) // Pass padded to the right
		slots = append(slots, slot)
	}

	return slots
}

func shortStringToSlot(s string) []byte {
	sLength := len([]byte(s)) * 2 // short string
	sLengthBytes := toBytes(sLength)

	// Pad with 0 to 32 bytes
	sLengthBytes = padTo32Bytes(sLengthBytes)

	hexSlots := stringToHexSlots(s)[0]
	hexBytes, _ := hex.DecodeString(hexSlots)

	finalBytes, _ := bytesBitwiseAdd(hexBytes, sLengthBytes)
	return finalBytes
}

func generateStringSlot(s string, baseSlot []byte, stringSlot map[string]string) {
	sLength := len([]byte(s))
	if sLength <= 31 { // short string
		sSlotBytes := shortStringToSlot(s)
		stringSlot[fmt.Sprintf("0x%s", hex.EncodeToString(baseSlot))] = fmt.Sprintf("0x%s", hex.EncodeToString(sSlotBytes))
	} else { // long string
		// Put length
		sSlotLength := sLength*2 + 1 // larger than long bytes
		sSlotLengthBytes := toBytes(sSlotLength)
		sSlotLengthBytes = padTo32Bytes(sSlotLengthBytes)

		stringSlot[fmt.Sprintf("0x%s", hex.EncodeToString(baseSlot))] = fmt.Sprintf("0x%s", hex.EncodeToString(sSlotLengthBytes))

		// Put values
		stringFinalBaseSlot := keccak(baseSlot)
		hexSlots := stringToHexSlots(s)
		for i, slot := range hexSlots {
			slotKey := bytesAddNum(stringFinalBaseSlot, i)
			stringSlot[fmt.Sprintf("0x%s", hex.EncodeToString(slotKey))] = fmt.Sprintf("0x%s", slot)
		}
	}
}

func bytesAddNum(a []byte, b int) []byte {
	aNum := bytesToInt(a)
	resultNum := aNum + b
	return intToBytes(resultNum, 32)
}

func bytesBitwiseAdd(bytes1, bytes2 []byte) ([]byte, error) {
	if len(bytes1) != len(bytes2) {
		return nil, fmt.Errorf("both byte arrays must have the same length")
	}

	result := make([]byte, len(bytes1))
	for i := range bytes1 {
		result[i] = bytes1[i] | bytes2[i]
	}
	return result, nil
}

// Helper functions
func toBytes(length int) []byte {
	// Convert int to byte array
	return intToBytes(length, 32) // 32 bytes long
}

func padTo32Bytes(b []byte) []byte {
	if len(b) < 32 {
		return append(b, make([]byte, 32-len(b))...) // Pad with zeros
	}
	return b
}

func bytesToInt(b []byte) int {
	return int(new(big.Int).SetBytes(b).Int64())
}

func intToBytes(num int, length int) []byte {
	n := big.NewInt(int64(num))
	return n.Bytes()
}

func keccak(data []byte) []byte {
	// Placeholder for keccak implementation
	return data // Replace with actual keccak hash function
}

func intToBigEndian(value int) []byte {
	// 创建一个字节缓冲区
	buf := new(bytes.Buffer)
	// 将整数以大端字节序写入缓冲区
	err := binary.Write(buf, binary.BigEndian, int64(value)) // 可以使用int64表示更大的整数
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return nil
	}
	// 返回字节切片
	return buf.Bytes()
}

func bigIntToBigEndian(value *big.Int) []byte {
	// 将大整数值转换为字节切片
	bytesValue := value.Bytes()

	// 创建一个字节缓冲区，并写入到固定长度（32字节）的字节切片中
	buf := make([]byte, 32)                    // 32字节的缓冲区
	copy(buf[32-len(bytesValue):], bytesValue) // 以大端顺序填充
	return buf
}

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
	validatorsMapBaseSlotBytes := intToBigEndian(validatorsMapBaseSlot)
	validatorsMapValidatorSlot := keccak(append(poolid[:], validatorsMapBaseSlotBytes...))

	// 2. for `Validator.description`
	validatorDescriptionBaseSlot := 0
	validatorDescriptionMapBaseSlot := bytesAddNum(validatorsMapValidatorSlot, validatorDescriptionBaseSlot)
	description := "domain" + fmt.Sprint(domainIndex)
	descriptionLength := len(description) * 2
	descriptionLengthBytes := toBytes(descriptionLength)
	hexSlot := stringToHexSlots(description)[0]
	hexstr, _ := hex.DecodeString(hexSlot)
	finalBytes, _ := bytesBitwiseAdd(hexstr, descriptionLengthBytes)
	slots["0x"+hex.EncodeToString(validatorDescriptionMapBaseSlot)] = "0x" + hex.EncodeToString(finalBytes)

	// 3. for `Validator.publicKey`
	validatorPublicKeyBaseSlot := 1
	validatorPublicKeyMapBaseSlot := bytesAddNum(validatorsMapValidatorSlot, validatorPublicKeyBaseSlot)

	// 3.1 Store string length
	publicKeyLength := len(publicKey)*2 + 1 // larger than long bytes
	publicKeyLengthBytes := toBytes(publicKeyLength)
	slots["0x"+hex.EncodeToString(validatorPublicKeyMapBaseSlot)] = "0x" + hex.EncodeToString(publicKeyLengthBytes)

	// 3.2 Set string
	publicKeyFinalBaseSlot := keccak(validatorPublicKeyMapBaseSlot)
	hexSlots := stringToHexSlots(publicKey)
	for i, slot := range hexSlots {
		publicKeySlot := bytesAddNum(publicKeyFinalBaseSlot, i)
		slots["0x"+hex.EncodeToString(publicKeySlot)] = "0x" + slot
	}

	// 4. for `Validator.blsPublicKey`
	validatorBlsPublicKeyBaseSlot := 3
	validatorBlsPublicKeyMapBaseSlot := bytesAddNum(validatorsMapValidatorSlot, validatorBlsPublicKeyBaseSlot)

	// 4.1 Store string length
	blsPublicKeyLength := len(blsPubkey)*2 + 1 // larger than long bytes
	blsPublicKeyLengthBytes := toBytes(blsPublicKeyLength)
	slots["0x"+hex.EncodeToString(validatorBlsPublicKeyMapBaseSlot)] = "0x" + hex.EncodeToString(blsPublicKeyLengthBytes)

	// 4.2 Set string
	blsPublicKeyFinalBaseSlot := keccak(validatorBlsPublicKeyMapBaseSlot)
	blsHexSlots := stringToHexSlots(blsPubkey)
	for i, slot := range blsHexSlots {
		blsPublicKeySlot := bytesAddNum(blsPublicKeyFinalBaseSlot, i)
		slots["0x"+hex.EncodeToString(blsPublicKeySlot)] = "0x" + slot
	}

	// 5. for `Validator.endpoint`
	validatorEndpointBaseSlot := 5
	validatorEndpointMapBaseSlot := bytesAddNum(validatorsMapValidatorSlot, validatorEndpointBaseSlot)
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
		slots["0x"+hex.EncodeToString(validatorEndpointMapBaseSlot)] = "0x" + hex.EncodeToString(intToBigEndian(endpointBytesLenEncoded))

		// 2. Calculate data location using keccak on the base slot
		dataLocation := new(big.Int).SetBytes(keccak(validatorEndpointMapBaseSlot)).Int64()

		for i := 0; i < endpointBytesLen; i += 32 {
			end := i + 32
			if end > endpointBytesLen {
				end = endpointBytesLen
			}
			chunk := endpointsBytes[i:end]
			slotKey := dataLocation + int64(i/32)
			slotKeyBytes := intToBigEndian(int(slotKey)) // Convert slot key to bytes
			slots["0x"+hex.EncodeToString(slotKeyBytes)] = "0x" + hex.EncodeToString(padChunk(chunk, 32))
		}
	}

	// 6. for `Validator.status`
	validatorStatusSlot := 6
	validatorStatusMapBaseSlot := bytesAddNum(validatorsMapValidatorSlot, validatorStatusSlot)
	status := 1
	statusBytes := intToBigEndian(status)
	slots["0x"+hex.EncodeToString(validatorStatusMapBaseSlot)] = "0x" + hex.EncodeToString(statusBytes)

	// 7. for `Validator.poolId`
	validatorPoolIDBaseSlot := 7
	validatorPoolIDMapBaseSlot := bytesAddNum(validatorsMapValidatorSlot, validatorPoolIDBaseSlot)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(poolid[:])

	// 8. for `Validator.totalStake`
	validatorStakeBaseSlot := 8
	validatorPoolIDMapBaseSlot = bytesAddNum(validatorsMapValidatorSlot, validatorStakeBaseSlot)
	stakeBytes := bigIntToBigEndian(stake)
	stakeBytes = padTo32Bytes(stakeBytes)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(stakeBytes)

	// 9. for `validator.owner`
	validatorOwnerBaseSlot := 9
	validatorPoolIDMapBaseSlot = bytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	rootSysAddr := adminAddr
	if len(rootSysAddr) > 2 && rootSysAddr[:2] == "0x" {
		rootSysAddr = rootSysAddr[2:] // Remove the '0x' prefix
	}
	rootSysAddrSlotValue := fmt.Sprintf("%064s", rootSysAddr) // Pad to 64 characters
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + rootSysAddrSlotValue

	validatorOwnerBaseSlot = 10
	validatorPoolIDMapBaseSlot = bytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	snapshotStakeBytes := bigIntToBigEndian(stake)
	snapshotStakeBytes = padTo32Bytes(snapshotStakeBytes)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(snapshotStakeBytes)

	// 11. for `validator.pendingWithdrawStake`
	validatorOwnerBaseSlot = 11
	validatorPoolIDMapBaseSlot = bytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	pendingWithdrawStake := intToBigEndian(0)
	pendingWithdrawStake = padTo32Bytes(pendingWithdrawStake)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(pendingWithdrawStake)

	// 12. for `validator.pendingWithdrawWindow`
	validatorOwnerBaseSlot = 12
	validatorPoolIDMapBaseSlot = bytesAddNum(validatorsMapValidatorSlot, validatorOwnerBaseSlot)
	pendingWithdrawWindow := intToBigEndian(0)
	pendingWithdrawWindow = padTo32Bytes(pendingWithdrawWindow)
	slots["0x"+hex.EncodeToString(validatorPoolIDMapBaseSlot)] = "0x" + hex.EncodeToString(pendingWithdrawWindow)

	// 13. for `bytes32[] public activePoolIds;`
	activePoolIdsBaseSlot := 2
	// 13.1 put array length
	activePoolIdsBaseSlotBytes := toBytes(activePoolIdsBaseSlot)
	activePoolIdsBaseSlotBytes = padTo32Bytes(activePoolIdsBaseSlotBytes)
	activePoolIdsLength := toBytes(totalDomains)
	activePoolIdsLength = padTo32Bytes(activePoolIdsLength)
	slots["0x"+hex.EncodeToString(activePoolIdsBaseSlotBytes)] = "0x" + hex.EncodeToString(activePoolIdsLength)

	// 13.2 put array value
	activePoolIDFinalSlot := keccak(activePoolIdsBaseSlotBytes)
	activePoolIDFinalValidatorSlot := bytesAddNum(activePoolIDFinalSlot, domainIndex)
	slots["0x"+hex.EncodeToString(activePoolIDFinalValidatorSlot)] = "0x" + hex.EncodeToString(poolid[:])

	return slots
}

func GenerateChaincfgSlots(configs map[string]string, adminAddr string) map[string]string {
	slots := make(map[string]string)

	// 1. put `configCps` length in `config_cps_base_slot`
	configCpsBaseSlot := 0
	configCpsBaseSlotBytes := intToBigEndian(configCpsBaseSlot)
	configCpsLength := 1 // put the genesis configs
	configCpsLengthBytes := intToBigEndian(configCpsLength)
	slots["0x"+hex.EncodeToString(configCpsBaseSlotBytes)] = "0x" + hex.EncodeToString(configCpsLengthBytes)

	// 2. put genesis `ConfigCheckpoint`
	genesisConfigCpBaseSlot := keccak(configCpsBaseSlotBytes)

	// 3. put `ConfigCheckpoint.blockNum` and `ConfigCheckpoint.effectiveBlockNum`
	blockNums := uint64(0)
	blockNumsBytes := intToBigEndian(int(blockNums))
	slots["0x"+hex.EncodeToString(genesisConfigCpBaseSlot)] = "0x" + hex.EncodeToString(padTo32Bytes(blockNumsBytes))

	// 4. put `Config[] configs`
	// 4.1 put `Config[] configs` length
	configsBaseSlot := 1
	configsBaseSlotBytes := bytesAddNum(genesisConfigCpBaseSlot, configsBaseSlot)
	configNums := len(configs)
	configNumsBytes := intToBigEndian(configNums)
	slots["0x"+hex.EncodeToString(configsBaseSlotBytes)] = "0x" + hex.EncodeToString(padTo32Bytes(configNumsBytes))

	// 4.2 put real genesis configs
	configKvsBaseSlot := keccak(configsBaseSlotBytes)
	slotIndex := 0
	for configKey, configValue := range configs {
		// key
		configKeySlot := bytesAddNum(configKvsBaseSlot, slotIndex)
		generateStringSlot(configKey, configKeySlot, slots)
		slotIndex++

		// value
		configValueSlot := bytesAddNum(configKvsBaseSlot, slotIndex)
		generateStringSlot(configValue, configValueSlot, slots)
		slotIndex++
	}

	// 5. put init rootSys
	configRootSysBaseSlot := 1
	configRootSysBaseSlotBytes := intToBigEndian(configRootSysBaseSlot)
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
	rootSysBaseSlotBytes := intToBigEndian(rootSysBaseSlot)
	adminSlotHexKey := "0x" + hex.EncodeToString(rootSysBaseSlotBytes)
	adminSlotValue := configs[adminSlotHexKey]

	if len(adminAddr) > 2 && adminAddr[:2] == "0x" {
		adminAddr = adminAddr[2:] // Remove the '0x' prefix
	}

	adminSlotValue = adminSlotValue[:len(adminSlotValue)-len(adminAddr)] + adminAddr

	configs["0x"+hex.EncodeToString(rootSysBaseSlotBytes)] = adminSlotValue

	return configs
}

func NewDefaultDeploy() *Deploy {
	return &Deploy{
		BuildRoot:      "",
		ChainID:        "",
		ChainProtocol:  "native",
		Version:        "",
		RunUser:        "",
		DeployRoot:     "",
		AdminAddr:      "2cc298bdee7cfeac9b49f9659e2f3d637e149696",
		ProxyAdminAddr: "0278872d3f68b15156e486da1551bcd34493220d",
		GenesisTpl:     "../conf/genesis.tpl.conf",
		Mygrid: MygridConfig{
			Conf: MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
			Env: MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
		},
		DomainKeyType:    "",
		ClientKeyType:    "",
		UseGeneratedKeys: false,
		UseLatestVersion: false,
		Docker: Docker{
			Enable:   false,
			Registry: "",
		},
		Common: &Common{
			Env:    make(map[string]string),
			Log:    make(map[string]LogConfig),
			Config: make(map[string]interface{}),
			Gflags: make(map[string]string),
		},
		Aldaba: &Extra{
			Args:   []string{},
			Env:    make(map[string]string),
			Log:    make(map[string]interface{}),
			Config: make(map[string]interface{}),
			Gflags: make(map[string]string),
		},
		Storage: &StorageExtra{
			Args: []string{},
			Env:  make(map[string]string),
		},
		Domains: make(map[string]DomainSummary),
	}
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

func generateDomain(deployFilePath string) (*Domain, error) {
	data, err := os.ReadFile(deployFilePath)
	if err != nil {
		return nil, err
	}
	deploy := NewDefaultDeploy()
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
	domain := NewDefaultDomain()

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
		GeneratePrivateKey(deploy.DomainKeyType, keyDir, keyFile, domain.KeyPasswd, "")
		GeneratePrivateKey("bls12381", stabilizingKeyDir, keyFile, domain.KeyPasswd, deploy.DeployRoot)
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
		var ins Instance
		ins.IP = v.Cluster[0].DeployIP
		ins.Service = "light"
		ins.Args = []string{"-d"}
		ins.Env["LIGHT_RPC_LISTEN_URL"] = fmt.Sprintf("%v:%v", v.Cluster[0].Host, v.Cluster[0].StartPort)
		ins.Env["LIGHT_RPC_ADVERTISE_URL"] = fmt.Sprintf("%v:%v", v.Cluster[0].Host, v.Cluster[0].StartPort)
		ins.Env["CLIENT_ADVERTISE_URLS"] = fmt.Sprintf("tls://%v:%v,http://%v:%v,ws://%v:%v,wss://%v:%v", v.Cluster[0].Host, v.ClientTcpPort, v.Cluster[0].Host, v.ClientHttpPort, v.Cluster[0].Host, v.ClientWsPort, v.Cluster[0].Host, v.ClientWssPort)
		ins.Env["CLIENT_LISTEN_URLS"] = fmt.Sprintf("tls://%v:%v,http://%v:%v,ws://%v:%v,wss://%v:%v", v.Cluster[0].Host, v.ClientTcpPort, v.Cluster[0].Host, v.ClientHttpPort, v.Cluster[0].Host, v.ClientWsPort, v.Cluster[0].Host, v.ClientWssPort)
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

		ins.Env["NODE_ID"] = GenerateNodeID(string(content))
		domain.Cluster["light"] = ins
		// only generate domain0 for pharos use case
		break
	}
	return domain, nil
}

func GenerateGenesis(deployFilePath string, domain *Domain) error {
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
	deploy := NewDefaultDeploy()
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
	epochBaseSlotBytes := toBytes(epochBaseSlot)
	epochNum := 0
	epochNumBytes := toBytes(epochNum)
	storageSlotKvs["0x"+hex.EncodeToString(epochBaseSlotBytes)] = "0x" + hex.EncodeToString(epochNumBytes)
	totalStakeBaseSlot := 6
	totalStakeBaseSlotBytes := toBytes(totalStakeBaseSlot)
	totalStakeBytes := bigIntToBigEndian(weiAmount)
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
	if err := replaceInFile(genesisPath, defaultAdminAddr, confAdminAddr); err != nil {
		return err
	}
	if err := replaceInFile(genesisPath, defaultProxyAdminAddr, confProxyAdminAddr); err != nil {
		return err
	}

	return nil
}
