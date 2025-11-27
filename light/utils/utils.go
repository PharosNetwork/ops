package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"pharos-ops/light/types"
	"regexp"
	"strings"
)

func PspidGrep(s string, cmds ...string) string {
	commands := []string{"ps -eo pid,cmd", fmt.Sprintf("grep '%s'", s)}
	commands = append(commands, cmds...)
	return strings.Join(commands, " | ")
}

func GenerateNodeID(pk string) string {
	hash := sha256.Sum256([]byte(pk))
	return fmt.Sprintf("%x", hash)
}

func NewDefaultDomain() *types.Domain {
	return &types.Domain{
		BuildRoot:     "",
		ChainID:       "",
		ChainProtocol: "native",
		DomainLabel:   "",
		Version:       "",
		RunUser:       "",
		DeployDir:     "",
		GenesisConf:   "../conf/genesis.conf",
		Mygrid: types.MygridConfig{
			Conf: types.MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
			Env: types.MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
		},
		Secret: types.Secret{
			Domain: types.SecretFiles{
				KeyType: "prime256v1",
				Files:   make(map[string]string),
			},
			Client: types.SecretFiles{
				KeyType: "prime256v1",
				Files:   make(map[string]string),
			},
		},
		UseGeneratedKeys: false,
		KeyPasswd:        "123abc",
		PortalSslPass:    "123abc",
		EnableSetkeyEnv:  true,
		Docker: types.Docker{
			Enable:   false,
			Registry: "",
		},
		Common: types.Common{
			Env:    make(map[string]string),
			Log:    make(map[string]types.LogConfig),
			Config: make(map[string]interface{}),
			Gflags: make(map[string]string),
			Metrics: types.Metrics{
				Enable:       false,
				PushAddress:  "",
				JobName:      "",
				PushInterval: "",
				PushPort:     "",
			},
		},
		Cluster:            make(map[string]types.Instance),
		InitialStakeInGwei: 1000000000,
	}
}

func NewDefaultDeploy() *types.Deploy {
	return &types.Deploy{
		BuildRoot:      "",
		ChainID:        "",
		ChainProtocol:  "native",
		Version:        "",
		RunUser:        "",
		DeployRoot:     "",
		AdminAddr:      "2cc298bdee7cfeac9b49f9659e2f3d637e149696",
		ProxyAdminAddr: "0278872d3f68b15156e486da1551bcd34493220d",
		GenesisTpl:     "../conf/genesis.tpl.conf",
		Mygrid: types.MygridConfig{
			Conf: types.MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
			Env: types.MygridCommonConfig{
				EnableAdaptive: true,
				FilePath:       "",
			},
		},
		DomainKeyType:    "",
		ClientKeyType:    "",
		UseGeneratedKeys: false,
		UseLatestVersion: false,
		Docker: types.Docker{
			Enable:   false,
			Registry: "",
		},
		Common: &types.Common{
			Env:    make(map[string]string),
			Log:    make(map[string]types.LogConfig),
			Config: make(map[string]interface{}),
			Gflags: make(map[string]string),
		},
		Aldaba: &types.Extra{
			Args:   []string{},
			Env:    make(map[string]string),
			Log:    make(map[string]interface{}),
			Config: make(map[string]interface{}),
			Gflags: make(map[string]string),
		},
		Storage: &types.StorageExtra{
			Args: []string{},
			Env:  make(map[string]string),
		},
		Domains: make(map[string]types.DomainSummary),
	}
}

func GetPubKey(keyType string, prikeyPath string, keyPasswd string) (string, []byte, error) {
	// Check if the private key file exists
	if _, err := os.Stat(prikeyPath); os.IsNotExist(err) {
		return "", nil, fmt.Errorf("%s does not exist", prikeyPath)
	}

	// Supported key types check
	if keyType != "prime256v1" {
		return "", nil, fmt.Errorf("%s is not supported, only PRIME256V1 is allowed", keyType)
	}

	// Generate public key
	pubkeyHex, err := ReadKeyFileToHex("ec", prikeyPath, keyPasswd) // Implementation needs to be provided
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

func ReadKeyFileToHex(keyType string, prikeyPath string, keyPasswd string) (string, error) {
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
		pubkey, _, err := GetPubKey("prime256v1", prikeyPath, keyPasswd)
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

func ReplaceInFile(filePath string, oldStr string, newStr string) error {
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

func PadChunk(chunk []byte, length int) []byte {
	padded := make([]byte, length)
	copy(padded, chunk)
	return padded
}

func StringToHexSlots(s string) []string {
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

func ShortStringToSlot(s string) []byte {
	sLength := len([]byte(s)) * 2 // short string
	sLengthBytes := ToBytes(sLength)

	// Pad with 0 to 32 bytes
	sLengthBytes = PadTo32Bytes(sLengthBytes)

	hexSlots := StringToHexSlots(s)[0]
	hexBytes, _ := hex.DecodeString(hexSlots)

	finalBytes, _ := BytesBitwiseAdd(hexBytes, sLengthBytes)
	return finalBytes
}

func GenerateStringSlot(s string, baseSlot []byte, stringSlot map[string]string) {
	sLength := len([]byte(s))
	if sLength <= 31 { // short string
		sSlotBytes := ShortStringToSlot(s)
		stringSlot[fmt.Sprintf("0x%s", hex.EncodeToString(baseSlot))] = fmt.Sprintf("0x%s", hex.EncodeToString(sSlotBytes))
	} else { // long string
		// Put length
		sSlotLength := sLength*2 + 1 // larger than long bytes
		sSlotLengthBytes := ToBytes(sSlotLength)
		sSlotLengthBytes = PadTo32Bytes(sSlotLengthBytes)

		stringSlot[fmt.Sprintf("0x%s", hex.EncodeToString(baseSlot))] = fmt.Sprintf("0x%s", hex.EncodeToString(sSlotLengthBytes))

		// Put values
		stringFinalBaseSlot := Keccak(baseSlot)
		hexSlots := StringToHexSlots(s)
		for i, slot := range hexSlots {
			slotKey := BytesAddNum(stringFinalBaseSlot, i)
			stringSlot[fmt.Sprintf("0x%s", hex.EncodeToString(slotKey))] = fmt.Sprintf("0x%s", slot)
		}
	}
}

func BytesAddNum(a []byte, b int) []byte {
	aNum := BytesToInt(a)
	resultNum := aNum + b
	return IntToBytes(resultNum, 32)
}

func BytesBitwiseAdd(bytes1, bytes2 []byte) ([]byte, error) {
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
func ToBytes(length int) []byte {
	// Convert int to byte array
	return IntToBytes(length, 32) // 32 bytes long
}

func PadTo32Bytes(b []byte) []byte {
	if len(b) < 32 {
		return append(b, make([]byte, 32-len(b))...) // Pad with zeros
	}
	return b
}

func BytesToInt(b []byte) int {
	return int(new(big.Int).SetBytes(b).Int64())
}

func IntToBytes(num int, length int) []byte {
	n := big.NewInt(int64(num))
	return n.Bytes()
}

func Keccak(data []byte) []byte {
	// Placeholder for keccak implementation
	return data // Replace with actual keccak hash function
}

func IntToBigEndian(value int) []byte {
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

func BigIntToBigEndian(value *big.Int) []byte {
	// 将大整数值转换为字节切片
	bytesValue := value.Bytes()

	// 创建一个字节缓冲区，并写入到固定长度（32字节）的字节切片中
	buf := make([]byte, 32)                    // 32字节的缓冲区
	copy(buf[32-len(bytesValue):], bytesValue) // 以大端顺序填充
	return buf
}
