package genesis

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// Constants for system-contract storage roots — copied verbatim from
// the OZ contracts' ERC-7201 locations and the Aldaba contract addrs.
const (
	// AccessControl storage root (OpenZeppelin):
	// keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControl")) - 1)) & ~bytes32(uint256(0xff))
	accessControlStorageBaseSlot = "02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800"

	// Initializable storage root (OpenZeppelin):
	// keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
	initializableStorageBaseSlot = "f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"

	// TransactionDeny Ownable2Step owner storage slot.
	transactionDenyOwnerSlot = "9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300"

	// System contract addresses.
	sysStakingAddr  = "4100000000000000000000000000000000000000"
	sysChainCfgImpl = "3100000000000000000000000000000000000001"
	sysRuleMngImpl  = "2100000000000000000000000000000000000001"
)

// GenerateChainCfgSlots ports conf.py:612-672. Returns the storage map
// for the ChainConfig contract at 0x3100...0000.
//
// configs must be in the order Python iterates over it (deploy.json
// + template's configs field) because slot keys depend on insertion
// position (slot_index advances by 2 per entry — one for key, one for
// value).
func GenerateChainCfgSlots(configs *OrderedStringMap) *OrderedStringMap {
	slots := NewOrderedStringMap()

	// ConfigCheckpoint[] configCps at base slot 1.
	configCpsBaseSlot := uint64Slot(1)

	// 1. configCps length = 1 (just the genesis CP).
	slots.Set(hex0x(configCpsBaseSlot), hex0x(uint64Slot(1)))

	// 2. The single genesis ConfigCheckpoint lives at keccak(slot 1).
	genesisCpBase := keccak256(configCpsBaseSlot)

	// 3. ConfigCheckpoint.{blockNum, effectiveBlockNum} share slot 0 of
	//    the struct (both uint64) — both = 0 at genesis.
	slots.Set(hex0x(genesisCpBase), hex0x(uint64Slot(0)))

	// 4. Config[] configs array at offset 1 within the CP.
	configsArrayBaseSlot := bytesAddNum(genesisCpBase, 1)
	configNums := uint64(configs.Len())
	slots.Set(hex0x(configsArrayBaseSlot),
		hex0x(leftPad32(big.NewInt(int64(configNums)).Bytes())))

	// 4.2 Per-entry string slots at keccak(configsArrayBaseSlot) + N.
	configKvsBaseSlot := keccak256(configsArrayBaseSlot)
	slotIndex := uint64(0)
	for _, key := range configs.Keys() {
		value, _ := configs.Get(key)
		// key slot
		generateStringSlot(key, bytesAddNum(configKvsBaseSlot, slotIndex), slots)
		slotIndex++
		// value slot
		generateStringSlot(value, bytesAddNum(configKvsBaseSlot, slotIndex), slots)
		slotIndex++
	}

	// 5. stakingAddress at slot 0.
	stakingAddrSlot := uint64Slot(0)
	stakingAddrBytes, _ := hex.DecodeString(sysStakingAddr)
	slots.Set(hex0x(stakingAddrSlot), hex0x(leftPad32(stakingAddrBytes)))

	// 6. implAddress at slot 3.
	implSlot := uint64Slot(3)
	implBytes, _ := hex.DecodeString(sysChainCfgImpl)
	slots.Set(hex0x(implSlot), hex0x(leftPad32(implBytes)))

	return slots
}

// GenerateRuleMngSlots ports conf.py:674-726. Returns the storage map
// for the RuleManager contract at 0x2100...0000.
//
// Slot 5 packs three values: uint64 nextId_=1 at offset 0, uint32
// proveThreshold_=1000 at offset 8, address implAddress at offset 12.
func GenerateRuleMngSlots() *OrderedStringMap {
	slots := NewOrderedStringMap()

	ruleBaseSlot := uint64Slot(5)

	nextID := []byte{0, 0, 0, 0, 0, 0, 0, 1}   // uint64 1
	proveThreshold := []byte{0, 0, 0x03, 0xe8} // uint32 1000
	implAddrBytes, _ := hex.DecodeString(sysRuleMngImpl)

	packed := packSlot([]SlotItem{
		{Offset: 0, Value: nextID},
		{Offset: 8, Value: proveThreshold},
		{Offset: 12, Value: implAddrBytes},
	}, 32)

	slots.Set(hex0x(ruleBaseSlot), packed)
	return slots
}

// GenerateAccessControlAdmin ports conf.py:728-797. Mutates `slots` to
// grant DEFAULT_ADMIN_ROLE to `account`. If account is empty (Python:
// None), the admin address from deploy.json is used and an additional
// adminRole = DEFAULT_ADMIN_ROLE assignment is written.
//
// adminAddr is required (it's the chain-level admin). When `account`
// equals "" or the explicit admin address, the function writes both
// hasRole AND adminRole slots; otherwise (e.g. for the intrinsic
// 0x1111… sender) only hasRole is written.
func GenerateAccessControlAdmin(slots *OrderedStringMap, adminAddr, account string) {
	// Resolve which address is being granted the role.
	target := account
	isChainAdmin := false
	if target == "" {
		target = adminAddr
		isChainAdmin = true
	}
	target = stripHex0x(target)

	baseSlotBytes, err := hex.DecodeString(accessControlStorageBaseSlot)
	if err != nil {
		panic(fmt.Sprintf("GenerateAccessControlAdmin: %v", err))
	}
	baseSlot := leftPad32(baseSlotBytes)

	// RoleData for DEFAULT_ADMIN_ROLE (key = 0x00) lives at
	// keccak(uint256(0) || base_slot).
	defaultAdminRoleIndex := uint64Slot(0)
	roleDataSlot := keccak256(append(append([]byte{}, defaultAdminRoleIndex...), baseSlot...))

	// hasRole[target] = true at keccak(target_padded || roleDataSlot).
	targetBytes, err := hex.DecodeString(target)
	if err != nil {
		panic(fmt.Sprintf("GenerateAccessControlAdmin: bad target %q: %v", target, err))
	}
	targetPadded := leftPad32(targetBytes)
	hasRoleSlot := keccak256(append(append([]byte{}, targetPadded...), roleDataSlot...))
	slots.Set(hex0x(hasRoleSlot), hex0x(uint64Slot(1)))

	// adminRole = DEFAULT_ADMIN_ROLE (0x00) at roleDataSlot+1 — only
	// when granting to the chain admin (account == nil in Python).
	if isChainAdmin {
		adminRoleSlot := bytesAddNum(roleDataSlot, 1)
		slots.Set(hex0x(adminRoleSlot), hex0x(uint64Slot(0)))
	}
}

// GenerateDisableInitializers ports conf.py:799-860. Mutates `slots`
// to mark the OpenZeppelin Initializable storage as "initialized = 1,
// initializing = 0", preventing re-initialisation after genesis.
//
// The whole slot at INITIALIZABLE_STORAGE collapses to 0x00...001 —
// the Python computes it via OR of two padded byte arrays but the
// end result is "1" in the low byte.
func GenerateDisableInitializers(slots *OrderedStringMap) {
	baseSlotBytes, err := hex.DecodeString(initializableStorageBaseSlot)
	if err != nil {
		panic(fmt.Sprintf("GenerateDisableInitializers: %v", err))
	}
	baseSlot := leftPad32(baseSlotBytes)
	slots.Set(hex0x(baseSlot), hex0x(uint64Slot(1)))
}

// GenerateTransactionDenySlots ports conf.py:862-874. Mutates `slots`
// to set the Ownable2Step owner to `ownerAddr` on the TransactionDeny
// contract.
func GenerateTransactionDenySlots(slots *OrderedStringMap, ownerAddr string) {
	ownerAddr = stripHex0x(ownerAddr)
	ownerBytes, err := hex.DecodeString(ownerAddr)
	if err != nil {
		panic(fmt.Sprintf("GenerateTransactionDenySlots: bad owner %q: %v", ownerAddr, err))
	}
	ownerSlotBytes, err := hex.DecodeString(transactionDenyOwnerSlot)
	if err != nil {
		panic(fmt.Sprintf("GenerateTransactionDenySlots: %v", err))
	}
	slots.Set(hex0x(ownerSlotBytes), hex0x(leftPad32(ownerBytes)))
}
