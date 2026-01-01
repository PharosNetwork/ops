package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// GenesisSlotGenerator handles Solidity storage slot generation for genesis
type GenesisSlotGenerator struct {
	adminAddr string
}

// NewGenesisSlotGenerator creates a new generator
func NewGenesisSlotGenerator(adminAddr string) *GenesisSlotGenerator {
	if len(adminAddr) > 2 && adminAddr[:2] == "0x" {
		adminAddr = adminAddr[2:]
	}
	return &GenesisSlotGenerator{adminAddr: adminAddr}
}

// keccak256 computes keccak256 hash
func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// bytesAddNum adds a number to a 32-byte array (big-endian)
func bytesAddNum(a []byte, b int) []byte {
	aNum := new(big.Int).SetBytes(a)
	result := new(big.Int).Add(aNum, big.NewInt(int64(b)))
	return padLeft(result.Bytes(), 32)
}

// padLeft pads bytes to specified length with zeros on the left
func padLeft(data []byte, length int) []byte {
	if len(data) >= length {
		return data[len(data)-length:]
	}
	result := make([]byte, length)
	copy(result[length-len(data):], data)
	return result
}

// padRight pads bytes to specified length with zeros on the right
func padRight(data []byte, length int) []byte {
	if len(data) >= length {
		return data[:length]
	}
	result := make([]byte, length)
	copy(result, data)
	return result
}

// bytesBitwiseOr performs bitwise OR on two byte arrays
func bytesBitwiseOr(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("byte arrays must have same length")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] | b[i]
	}
	return result
}

// stringToHexSlots converts string to 32-byte hex slots
func stringToHexSlots(s string) []string {
	hexStr := hex.EncodeToString([]byte(s))
	var slots []string
	for i := 0; i < len(hexStr); i += 64 {
		end := i + 64
		if end > len(hexStr) {
			end = len(hexStr)
		}
		slot := hexStr[i:end]
		// Pad to 64 characters with zeros on right
		for len(slot) < 64 {
			slot += "0"
		}
		slots = append(slots, slot)
	}
	if len(slots) == 0 {
		slots = append(slots, "0000000000000000000000000000000000000000000000000000000000000000")
	}
	return slots
}

// shortStringToSlot encodes a short string (<= 31 bytes) to a storage slot
func shortStringToSlot(s string) []byte {
	sLength := len([]byte(s)) * 2 // short string encoding: length * 2
	lengthBytes := padLeft([]byte{byte(sLength)}, 32)
	hexSlots := stringToHexSlots(s)
	slotData, _ := hex.DecodeString(hexSlots[0])
	slotData = padRight(slotData, 32)
	return bytesBitwiseOr(slotData, lengthBytes)
}

// generateStringSlot generates storage slots for a string (handles both short and long strings)
func (g *GenesisSlotGenerator) generateStringSlot(s string, baseSlot []byte, slots map[string]string) {
	sLength := len([]byte(s))
	if sLength <= 31 {
		// Short string: value and length encoded together
		slotBytes := shortStringToSlot(s)
		slots["0x"+hex.EncodeToString(baseSlot)] = "0x" + hex.EncodeToString(slotBytes)
	} else {
		// Long string
		// Store length (length * 2 + 1 for long strings)
		slotLength := sLength*2 + 1
		lengthBytes := padLeft(big.NewInt(int64(slotLength)).Bytes(), 32)
		slots["0x"+hex.EncodeToString(baseSlot)] = "0x" + hex.EncodeToString(lengthBytes)

		// Store values starting at keccak256(baseSlot)
		dataSlot := keccak256(baseSlot)
		hexSlots := stringToHexSlots(s)
		for i, slot := range hexSlots {
			slotKey := bytesAddNum(dataSlot, i)
			slots["0x"+hex.EncodeToString(slotKey)] = "0x" + slot
		}
	}
}

// GenerateDomainSlots generates storage slots for a validator in the Staking contract
func (g *GenesisSlotGenerator) GenerateDomainSlots(
	totalDomains int,
	domainIndex int,
	publicKey string,
	blsPubkey string,
	endpoint string,
	stake int64,
	publicKeyPop string,
	blsPubkeyPop string,
) map[string]string {
	slots := make(map[string]string)

	// Remove 0x prefix if present
	if len(publicKey) > 2 && publicKey[:2] == "0x" {
		publicKey = publicKey[2:]
	}
	if len(blsPubkey) > 2 && blsPubkey[:2] == "0x" {
		blsPubkey = blsPubkey[2:]
	}

	// Compute pool ID as SHA256 of public key bytes
	pubkeyBytes, _ := hex.DecodeString(publicKey)
	poolID := sha256.Sum256(pubkeyBytes)

	// 1. Calculate base slot for validators mapping
	// mapping(bytes32 => Validator) public validators at slot 0
	validatorsMapBaseSlot := padLeft([]byte{0}, 32)
	validatorSlot := keccak256(append(poolID[:], validatorsMapBaseSlot...))

	// 2. Validator.description (slot offset 0)
	descriptionSlot := bytesAddNum(validatorSlot, 0)
	description := fmt.Sprintf("domain%d", domainIndex)
	descBytes := shortStringToSlot(description)
	slots["0x"+hex.EncodeToString(descriptionSlot)] = "0x" + hex.EncodeToString(descBytes)

	// 3. Validator.publicKey (slot offset 1) - long string
	publicKeySlot := bytesAddNum(validatorSlot, 1)
	pkLength := len(publicKey)*2 + 1
	pkLengthBytes := padLeft(big.NewInt(int64(pkLength)).Bytes(), 32)
	slots["0x"+hex.EncodeToString(publicKeySlot)] = "0x" + hex.EncodeToString(pkLengthBytes)

	pkDataSlot := keccak256(publicKeySlot)
	pkHexSlots := stringToHexSlots(publicKey)
	for i, slot := range pkHexSlots {
		slotKey := bytesAddNum(pkDataSlot, i)
		slots["0x"+hex.EncodeToString(slotKey)] = "0x" + slot
	}

	// 4. Validator.publicKeyPop (slot offset 2)
	publicKeyPopSlot := bytesAddNum(validatorSlot, 2)
	g.generateStringSlot(publicKeyPop, publicKeyPopSlot, slots)

	// 5. Validator.blsPublicKey (slot offset 3) - long string
	blsPublicKeySlot := bytesAddNum(validatorSlot, 3)
	blsLength := len(blsPubkey)*2 + 1
	blsLengthBytes := padLeft(big.NewInt(int64(blsLength)).Bytes(), 32)
	slots["0x"+hex.EncodeToString(blsPublicKeySlot)] = "0x" + hex.EncodeToString(blsLengthBytes)

	blsDataSlot := keccak256(blsPublicKeySlot)
	blsHexSlots := stringToHexSlots(blsPubkey)
	for i, slot := range blsHexSlots {
		slotKey := bytesAddNum(blsDataSlot, i)
		slots["0x"+hex.EncodeToString(slotKey)] = "0x" + slot
	}

	// 6. Validator.blsPublicKeyPop (slot offset 4)
	blsPublicKeyPopSlot := bytesAddNum(validatorSlot, 4)
	g.generateStringSlot(blsPubkeyPop, blsPublicKeyPopSlot, slots)

	// 7. Validator.endpoint (slot offset 5)
	endpointSlot := bytesAddNum(validatorSlot, 5)
	endpointBytes := []byte(endpoint)
	if len(endpointBytes) <= 31 {
		// Short string encoding
		slotValue := make([]byte, 32)
		copy(slotValue, endpointBytes)
		slotValue[31] = byte(len(endpointBytes) * 2)
		slots["0x"+hex.EncodeToString(endpointSlot)] = "0x" + hex.EncodeToString(slotValue)
	} else {
		// Long string encoding
		lengthEncoded := len(endpointBytes)*2 + 1
		slots["0x"+hex.EncodeToString(endpointSlot)] = "0x" + hex.EncodeToString(padLeft(big.NewInt(int64(lengthEncoded)).Bytes(), 32))

		dataLocation := new(big.Int).SetBytes(keccak256(endpointSlot))
		for i := 0; i < len(endpointBytes); i += 32 {
			end := i + 32
			if end > len(endpointBytes) {
				end = len(endpointBytes)
			}
			chunk := padRight(endpointBytes[i:end], 32)
			slotKey := new(big.Int).Add(dataLocation, big.NewInt(int64(i/32)))
			slots["0x"+hex.EncodeToString(padLeft(slotKey.Bytes(), 32))] = "0x" + hex.EncodeToString(chunk)
		}
	}

	// 8. Validator.status (slot offset 6)
	statusSlot := bytesAddNum(validatorSlot, 6)
	statusBytes := padLeft([]byte{1}, 32) // status = 1 (active)
	slots["0x"+hex.EncodeToString(statusSlot)] = "0x" + hex.EncodeToString(statusBytes)

	// 9. Validator.poolId (slot offset 7)
	poolIdSlot := bytesAddNum(validatorSlot, 7)
	slots["0x"+hex.EncodeToString(poolIdSlot)] = "0x" + hex.EncodeToString(poolID[:])

	// 10. Validator.totalStake (slot offset 8)
	stakeSlot := bytesAddNum(validatorSlot, 8)
	stakeBytes := padLeft(big.NewInt(stake).Bytes(), 32)
	slots["0x"+hex.EncodeToString(stakeSlot)] = "0x" + hex.EncodeToString(stakeBytes)

	// 11. Validator.owner (slot offset 9)
	ownerSlot := bytesAddNum(validatorSlot, 9)
	ownerBytes, _ := hex.DecodeString(g.adminAddr)
	ownerBytes = padLeft(ownerBytes, 32)
	slots["0x"+hex.EncodeToString(ownerSlot)] = "0x" + hex.EncodeToString(ownerBytes)

	// 12. Validator.stakeSnapshot (slot offset 10)
	stakeSnapshotSlot := bytesAddNum(validatorSlot, 10)
	slots["0x"+hex.EncodeToString(stakeSnapshotSlot)] = "0x" + hex.EncodeToString(stakeBytes)

	// 13. Validator.pendingWithdrawStake (slot offset 11)
	pendingWithdrawSlot := bytesAddNum(validatorSlot, 11)
	slots["0x"+hex.EncodeToString(pendingWithdrawSlot)] = "0x" + hex.EncodeToString(padLeft([]byte{0}, 32))

	// 14. Validator.pendingWithdrawWindow (slot offset 12)
	pendingWindowSlot := bytesAddNum(validatorSlot, 12)
	slots["0x"+hex.EncodeToString(pendingWindowSlot)] = "0x" + hex.EncodeToString(padLeft([]byte{0}, 32))

	// 15. activePoolIds array (slot 1)
	activePoolIdsBaseSlot := padLeft([]byte{1}, 32)
	// Array length
	slots["0x"+hex.EncodeToString(activePoolIdsBaseSlot)] = "0x" + hex.EncodeToString(padLeft(big.NewInt(int64(totalDomains)).Bytes(), 32))
	// Array element at index domainIndex
	activePoolIdDataSlot := keccak256(activePoolIdsBaseSlot)
	activePoolIdSlot := bytesAddNum(activePoolIdDataSlot, domainIndex)
	slots["0x"+hex.EncodeToString(activePoolIdSlot)] = "0x" + hex.EncodeToString(poolID[:])

	// 16. config address (slot 7)
	cfgSlot := padLeft([]byte{7}, 32)
	cfgAddr, _ := hex.DecodeString(SYS_CHAINCFG_ADDR)
	slots["0x"+hex.EncodeToString(cfgSlot)] = "0x" + hex.EncodeToString(padLeft(cfgAddr, 32))

	// 17. totalSupply (slot 9)
	totalSupplySlot := padLeft([]byte{9}, 32)
	totalSupply := new(big.Int).Mul(big.NewInt(DEFAULT_TOTAL_SUPPLY), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	slots["0x"+hex.EncodeToString(totalSupplySlot)] = "0x" + hex.EncodeToString(padLeft(totalSupply.Bytes(), 32))

	// 18. currentInflationRate (slot 10)
	inflationSlot := padLeft([]byte{10}, 32)
	slots["0x"+hex.EncodeToString(inflationSlot)] = "0x" + hex.EncodeToString(padLeft(big.NewInt(DEFAULT_INFLATION_RATE).Bytes(), 32))

	// 19. lastInflationTotalSupplySnapshot (slot 12)
	lastSnapshotSlot := padLeft([]byte{12}, 32)
	slots["0x"+hex.EncodeToString(lastSnapshotSlot)] = "0x" + hex.EncodeToString(padLeft(totalSupply.Bytes(), 32))

	// 20. implAddress (slot 13)
	implSlot := padLeft([]byte{13}, 32)
	implAddr, _ := hex.DecodeString(STAKING_IMPL_ADDR)
	slots["0x"+hex.EncodeToString(implSlot)] = "0x" + hex.EncodeToString(padLeft(implAddr, 32))

	return slots
}

// GenerateStakingExtraSlots generates additional staking contract slots
func (g *GenesisSlotGenerator) GenerateStakingExtraSlots(totalStake int64, genesisTimestamp int64) map[string]string {
	slots := make(map[string]string)

	// epoch_num (slot 5)
	epochSlot := padLeft([]byte{5}, 32)
	slots["0x"+hex.EncodeToString(epochSlot)] = "0x" + hex.EncodeToString(padLeft([]byte{0}, 32))

	// totalStake (slot 6)
	totalStakeSlot := padLeft([]byte{6}, 32)
	slots["0x"+hex.EncodeToString(totalStakeSlot)] = "0x" + hex.EncodeToString(padLeft(big.NewInt(totalStake).Bytes(), 32))

	// config addr (slot 7) - already set in domain slots but needs to be here too
	cfgSlot := padLeft([]byte{7}, 32)
	cfgAddr, _ := hex.DecodeString(SYS_CHAINCFG_ADDR)
	slots["0x"+hex.EncodeToString(cfgSlot)] = "0x" + hex.EncodeToString(padLeft(cfgAddr, 32))

	// lastInflationAdjustmentTime (slot 11)
	lastAdjustSlot := padLeft([]byte{11}, 32)
	timestampSec := genesisTimestamp / 1000
	slots["0x"+hex.EncodeToString(lastAdjustSlot)] = "0x" + hex.EncodeToString(padLeft(big.NewInt(timestampSec).Bytes(), 32))

	return slots
}

// GenerateChainCfgSlots generates ChainConfig contract storage slots
func (g *GenesisSlotGenerator) GenerateChainCfgSlots(configs map[string]string) map[string]string {
	slots := make(map[string]string)

	// ConfigCheckpoint[] configCps (slot 1)
	configCpsBaseSlot := padLeft([]byte{1}, 32)

	// Array length = 1 (genesis config)
	slots["0x"+hex.EncodeToString(configCpsBaseSlot)] = "0x" + hex.EncodeToString(padLeft([]byte{1}, 32))

	// Genesis ConfigCheckpoint base slot
	genesisConfigCpSlot := keccak256(configCpsBaseSlot)

	// ConfigCheckpoint.blockNum and effectiveBlockNum (both 0)
	slots["0x"+hex.EncodeToString(genesisConfigCpSlot)] = "0x" + hex.EncodeToString(padLeft([]byte{0}, 32))

	// Config[] configs (offset 1 from checkpoint)
	configsBaseSlot := bytesAddNum(genesisConfigCpSlot, 1)
	configNum := len(configs)
	slots["0x"+hex.EncodeToString(configsBaseSlot)] = "0x" + hex.EncodeToString(padLeft(big.NewInt(int64(configNum)).Bytes(), 32))

	// Put config key-value pairs
	configKvsBaseSlot := keccak256(configsBaseSlot)
	slotIndex := 0
	for key, value := range configs {
		// Key
		keySlot := bytesAddNum(configKvsBaseSlot, slotIndex)
		g.generateStringSlot(key, keySlot, slots)
		slotIndex++

		// Value
		valueSlot := bytesAddNum(configKvsBaseSlot, slotIndex)
		g.generateStringSlot(value, valueSlot, slots)
		slotIndex++
	}

	// stakingAddress (slot 0)
	stakingSlot := padLeft([]byte{0}, 32)
	stakingAddr, _ := hex.DecodeString(SYS_STAKING_ADDR)
	slots["0x"+hex.EncodeToString(stakingSlot)] = "0x" + hex.EncodeToString(padLeft(stakingAddr, 32))

	// implAddress (slot 3)
	implSlot := padLeft([]byte{3}, 32)
	implAddr, _ := hex.DecodeString(CHAINCFG_IMPL_ADDR)
	slots["0x"+hex.EncodeToString(implSlot)] = "0x" + hex.EncodeToString(padLeft(implAddr, 32))

	return slots
}

// GenerateRuleMngSlots generates RuleManager contract storage slots
func (g *GenesisSlotGenerator) GenerateRuleMngSlots() map[string]string {
	slots := make(map[string]string)

	// slot 5 contains: nextId_ (uint64), proveThreshold_ (uint32), implAddress (address)
	// All packed into one slot
	ruleBaseSlot := padLeft([]byte{5}, 32)

	nextId := uint64(1)
	proveThreshold := uint32(DEFAULT_PROVE_THRESHOLD)
	implAddr, _ := hex.DecodeString(RULEMNG_IMPL_ADDR)

	// Build packed slot value (big-endian, right-aligned)
	slotValue := make([]byte, 32)
	// nextId_ at offset 0 (8 bytes)
	copy(slotValue[32-8:32], padLeft(big.NewInt(int64(nextId)).Bytes(), 8))
	// proveThreshold_ at offset 8 (4 bytes)
	copy(slotValue[32-8-4:32-8], padLeft(big.NewInt(int64(proveThreshold)).Bytes(), 4))
	// implAddress at offset 12 (20 bytes)
	copy(slotValue[32-8-4-20:32-8-4], implAddr)

	slots["0x"+hex.EncodeToString(ruleBaseSlot)] = "0x" + hex.EncodeToString(slotValue)

	return slots
}

// GenerateAccessControlAdmin generates OpenZeppelin AccessControl admin slots
func (g *GenesisSlotGenerator) GenerateAccessControlAdmin(account string, setAdminRole bool) map[string]string {
	slots := make(map[string]string)

	if len(account) > 2 && account[:2] == "0x" {
		account = account[2:]
	}

	// AccessControl storage location
	baseSlot, _ := hex.DecodeString(ACCESS_CONTROL_STORAGE_LOCATION)

	// DEFAULT_ADMIN_ROLE = 0x00
	defaultAdminRoleIndex := padLeft([]byte{0}, 32)

	// RoleData slot = keccak256(role + baseSlot)
	roleDataSlot := keccak256(append(defaultAdminRoleIndex, baseSlot...))

	// hasRole[account] = keccak256(account + roleDataSlot)
	accountBytes, _ := hex.DecodeString(account)
	accountPadded := padLeft(accountBytes, 32)
	hasRoleSlot := keccak256(append(accountPadded, roleDataSlot...))

	// Set hasRole to true (1)
	slots["0x"+hex.EncodeToString(hasRoleSlot)] = "0x" + hex.EncodeToString(padLeft([]byte{1}, 32))

	// Set adminRole if this is the primary admin
	if setAdminRole {
		adminRoleSlot := bytesAddNum(roleDataSlot, 1)
		slots["0x"+hex.EncodeToString(adminRoleSlot)] = "0x" + hex.EncodeToString(padLeft([]byte{0}, 32))
	}

	return slots
}

// GenerateDisableInitializers generates OpenZeppelin Initializable disable slots
func (g *GenesisSlotGenerator) GenerateDisableInitializers() map[string]string {
	slots := make(map[string]string)

	// Initializable storage location
	baseSlot, _ := hex.DecodeString(INITIALIZABLE_STORAGE_LOCATION)

	// _initialized = 1 (version 1 to enable future reinitializers)
	// _initializing = false (0)
	// Both packed in same slot: _initialized (uint64) at offset 0, _initializing (bool) at offset 8
	slotValue := padLeft([]byte{1}, 32) // _initialized = 1, _initializing = 0
	slots["0x"+hex.EncodeToString(baseSlot)] = "0x" + hex.EncodeToString(slotValue)

	return slots
}

// MergeSlots merges multiple slot maps into one
func MergeSlots(base map[string]string, others ...map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range base {
		result[k] = v
	}
	for _, other := range others {
		for k, v := range other {
			result[k] = v
		}
	}
	return result
}
