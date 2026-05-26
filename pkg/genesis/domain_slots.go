package genesis

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// Constants used by domain-slot generation, lifted verbatim from
// conf.py:303-502.
const (
	// validators[poolId] map base slot (in Staking contract storage).
	validatorsMapBaseSlot = 0

	// activePoolIds[] (legacy v1) base slot.
	activePoolIdsBaseSlot = 1

	// System contract addresses referenced from validator storage.
	chainCfgImplAddr  = "3100000000000000000000000000000000000000"
	stakingImplAddr   = "4100000000000000000000000000000000000001"
	ruleMngImplAddrV2 = "2100000000000000000000000000000000000001"
)

// Total chain supply embedded into per-validator slots.
// 1_000_000_000 * 10^18 (1B tokens, 18 decimals).
var totalSupplyWei = func() *big.Int {
	out := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	return out.Mul(out, big.NewInt(1_000_000_000))
}()

// Initial inflation rate (basis points × 100; conf.py:474 calls it
// `current_inflation_rate = 9125`).
const currentInflationRate = 9125

// GenerateDomainSlots ports conf.py:303-502. Returns a new
// OrderedStringMap of storage-slot KVs for the staking contract at
// 0x4100... corresponding to ONE validator.
//
//	totalDomains   — number of validators in this genesis (sets activePoolIds[] length on idx 0)
//	domainIndex    — this validator's position (0-based)
//	publicKey      — prime256v1 pubkey hex (no 0x), expected to start with "1003"
//	blsPubkey      — BLS12-381 pubkey hex (no 0x), expected to start with "4003"
//	endpoint       — "tcp://host:port" baked into Validator.endpoint
//	stake          — initial stake in wei (must be >= 0)
//	publicKeyPop   — PoP for publicKey (hex, no 0x)
//	blsPubkeyPop   — PoP for blsPubkey (hex, no 0x)
func GenerateDomainSlots(
	totalDomains, domainIndex int,
	publicKey, blsPubkey, endpoint string,
	stake *big.Int,
	publicKeyPop, blsPubkeyPop string,
) *OrderedStringMap {
	slots := NewOrderedStringMap()

	publicKey = stripHex0x(publicKey)
	blsPubkey = stripHex0x(blsPubkey)

	pubkeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		panic(fmt.Sprintf("GenerateDomainSlots: bad publicKey hex %q: %v", publicKey, err))
	}
	// poolId is sha256(pubkeyBytes) — NOT keccak (conf.py:318).
	poolID := sha256Sum(pubkeyBytes)

	// validators[poolId] base slot location.
	validatorsBaseSlotBytes := uint64Slot(validatorsMapBaseSlot)
	validatorSlot := keccak256(append(append([]byte{}, poolID...), validatorsBaseSlotBytes...))

	// (2) Validator.description = "domain<idx>" (short string at offset 0)
	description := fmt.Sprintf("domain%d", domainIndex)
	descriptionSlot := bytesAddNum(validatorSlot, 0)
	descriptionLen := uint64(len(description)) * 2
	descLenBytes := leftPad32(big.NewInt(int64(descriptionLen)).Bytes())
	hexChunk := stringToHexSlots(description)[0]
	hexChunkBytes, _ := hex.DecodeString(hexChunk)
	descPacked := bytesBitwiseOR(hexChunkBytes, descLenBytes)
	slots.Set(hex0x(descriptionSlot), hex0x(descPacked))

	// (3) Validator.publicKey at offset 1.
	pubkeySlot := bytesAddNum(validatorSlot, 1)
	// 3.1 length = len*2 + 1 (long string encoding)
	pubkeyLen := uint64(len(publicKey))*2 + 1
	pubkeyLenBytes := leftPad32(big.NewInt(int64(pubkeyLen)).Bytes())
	slots.Set(hex0x(pubkeySlot), hex0x(pubkeyLenBytes))
	// 3.2 data slots at keccak(pubkeySlot)+i
	pubkeyDataBase := keccak256(pubkeySlot)
	for i, chunk := range stringToHexSlots(publicKey) {
		k := bytesAddNum(pubkeyDataBase, uint64(i))
		slots.Set(hex0x(k), "0x"+chunk)
	}

	// (3b) Validator.publicKeyPop at offset 2 — uses generateStringSlot
	// (handles short vs long).
	pubkeyPopSlot := bytesAddNum(validatorSlot, 2)
	generateStringSlot(publicKeyPop, pubkeyPopSlot, slots)

	// (4) Validator.blsPublicKey at offset 3.
	blsSlot := bytesAddNum(validatorSlot, 3)
	blsLen := uint64(len(blsPubkey))*2 + 1
	blsLenBytes := leftPad32(big.NewInt(int64(blsLen)).Bytes())
	slots.Set(hex0x(blsSlot), hex0x(blsLenBytes))
	blsDataBase := keccak256(blsSlot)
	for i, chunk := range stringToHexSlots(blsPubkey) {
		k := bytesAddNum(blsDataBase, uint64(i))
		slots.Set(hex0x(k), "0x"+chunk)
	}

	// (4b) Validator.blsPublicKeyPop at offset 4.
	blsPopSlot := bytesAddNum(validatorSlot, 4)
	generateStringSlot(blsPubkeyPop, blsPopSlot, slots)

	// (5) Validator.endpoint at offset 5 — short vs long branches matter
	// because endpoints like "tcp://127.0.0.1:19000" are 22 bytes (short).
	endpointSlot := bytesAddNum(validatorSlot, 5)
	endpointBytes := []byte(endpoint)
	if len(endpointBytes) <= 31 {
		// Short: store length*2 in last byte, data in high bytes.
		slotValue := make([]byte, 32)
		copy(slotValue, endpointBytes)
		slotValue[31] = byte(len(endpointBytes) * 2)
		slots.Set(hex0x(endpointSlot), hex0x(slotValue))
	} else {
		// Long: length*2+1 at base, data at keccak(base)+i.
		encLen := uint64(len(endpointBytes))*2 + 1
		slots.Set(hex0x(endpointSlot), hex0x(leftPad32(big.NewInt(int64(encLen)).Bytes())))
		dataBase := keccak256(endpointSlot)
		for i := 0; i < len(endpointBytes); i += 32 {
			end := i + 32
			if end > len(endpointBytes) {
				end = len(endpointBytes)
			}
			chunk := make([]byte, 32)
			copy(chunk, endpointBytes[i:end])
			slotKey := bytesAddNum(dataBase, uint64(i/32))
			slots.Set(hex0x(slotKey), hex0x(chunk))
		}
	}

	// (6) Validator.status at offset 6 — status = 1 (Active).
	statusSlot := bytesAddNum(validatorSlot, 6)
	slots.Set(hex0x(statusSlot), hex0x(uint64Slot(1)))

	// (7) Validator.poolId at offset 7.
	poolIDSlot := bytesAddNum(validatorSlot, 7)
	slots.Set(hex0x(poolIDSlot), hex0x(poolID))

	// (8) Validator.totalStake at offset 8.
	totalStakeSlot := bytesAddNum(validatorSlot, 8)
	slots.Set(hex0x(totalStakeSlot), hex0x(bigIntSlot(stake)))

	// (9) Validator.owner at offset 9 = admin addr (already set by run()
	// — we get it from a package-level constant when called).
	// NOTE: the Python code reads self._deploy.admin_addr here. We pass
	// it in via a separate parameter so this function stays
	// admin-agnostic for unit testing. The caller (Run) wires it up.
	// See conf.py:419-424 — implementation deferred to caller-provided
	// adminAddr via a closure helper below.

	// (10) Validator.stakeSnapshot at offset 10 = stake.
	stakeSnapshotSlot := bytesAddNum(validatorSlot, 10)
	slots.Set(hex0x(stakeSnapshotSlot), hex0x(bigIntSlot(stake)))

	// (11) Validator.pendingWithdrawStake at offset 11 = 0.
	pendingWithdrawStakeSlot := bytesAddNum(validatorSlot, 11)
	slots.Set(hex0x(pendingWithdrawStakeSlot), hex0x(uint64Slot(0)))

	// (12) Validator.pendingWithdrawWindow at offset 12 = 0.
	pendingWithdrawWindowSlot := bytesAddNum(validatorSlot, 12)
	slots.Set(hex0x(pendingWithdrawWindowSlot), hex0x(uint64Slot(0)))

	// (13) activePoolIds[] @ slot 1.
	activeBaseSlot := uint64Slot(activePoolIdsBaseSlot)
	// 13.1 length on every validator (Python writes it inside the
	// per-validator loop unconditionally, so the LAST domain wins —
	// but the value is `total_domains`, so it's idempotent).
	slots.Set(hex0x(activeBaseSlot),
		hex0x(leftPad32(big.NewInt(int64(totalDomains)).Bytes())))
	// 13.2 element at keccak(activeBaseSlot) + domain_index.
	activeBase := keccak256(activeBaseSlot)
	activeElemSlot := bytesAddNum(activeBase, uint64(domainIndex))
	slots.Set(hex0x(activeElemSlot), hex0x(poolID))

	// (15) config addr at slot 7.
	cfgBase := uint64Slot(7)
	cfgAddrBytes, _ := hex.DecodeString(chainCfgImplAddr)
	slots.Set(hex0x(cfgBase), hex0x(leftPad32(cfgAddrBytes)))

	// totalSupply at slot 9.
	totalSupplyBase := uint64Slot(9)
	slots.Set(hex0x(totalSupplyBase), hex0x(bigIntSlot(totalSupplyWei)))

	// currentInflationRate at slot 10.
	inflationBase := uint64Slot(10)
	slots.Set(hex0x(inflationBase),
		hex0x(leftPad32(big.NewInt(currentInflationRate).Bytes())))

	// lastInflationTotalSupplySnapshot at slot 12.
	snapshotBase := uint64Slot(12)
	slots.Set(hex0x(snapshotBase), hex0x(bigIntSlot(totalSupplyWei)))

	// implAddress at slot 13 — staking proxy impl.
	implBase := uint64Slot(13)
	implBytes, _ := hex.DecodeString(stakingImplAddr)
	slots.Set(hex0x(implBase), hex0x(leftPad32(implBytes)))

	return slots
}

// generateStakingV2Slots ports conf.py:504-611. Mutates `slots` in
// place with v2 delegation state for the given pool and owner.
func generateStakingV2Slots(
	totalDomains, domainIndex int,
	poolID []byte,
	ownerAddr string,
	stake *big.Int,
	slots *OrderedStringMap,
) {
	// Step 1: activePoolSets (EnumerableSet) at base slot 21.
	activePoolSetsBase := uint64Slot(21)

	// 1.1 _values array length — only set on first validator.
	if domainIndex == 0 {
		arrayLen := leftPad32(big.NewInt(int64(totalDomains)).Bytes())
		slots.Set(hex0x(activePoolSetsBase), hex0x(arrayLen))
	}

	// 1.2 element at keccak(activePoolSetsBase) + domainIndex.
	valuesStorageBase := keccak256(activePoolSetsBase)
	elementSlot := bytesAddNum(valuesStorageBase, uint64(domainIndex))
	slots.Set(hex0x(elementSlot), hex0x(poolID))

	// 1.3 _positions mapping at slot 22; key = keccak(poolID || 22).
	positionsBase := uint64Slot(22)
	positionKey := keccak256(append(append([]byte{}, poolID...), positionsBase...))
	positionValue := leftPad32(big.NewInt(int64(domainIndex + 1)).Bytes())
	slots.Set(hex0x(positionKey), hex0x(positionValue))

	// Step 2: commission + delegation per pool.
	// commissionRates[poolId] = 1000 at base slot 17.
	commissionBase := uint64Slot(17)
	commissionKey := keccak256(append(append([]byte{}, poolID...), commissionBase...))
	slots.Set(hex0x(commissionKey),
		hex0x(leftPad32(big.NewInt(1000).Bytes())))

	// delegationEnabledMapping[poolId] = true at base slot 18.
	delegationBase := uint64Slot(18)
	delegationKey := keccak256(append(append([]byte{}, poolID...), delegationBase...))
	slots.Set(hex0x(delegationKey), hex0x(uint64Slot(1)))

	// delegatorCounts[poolId] = 1 at base slot 19.
	delegatorCountsBase := uint64Slot(19)
	delegatorCountsKey := keccak256(append(append([]byte{}, poolID...), delegatorCountsBase...))
	slots.Set(hex0x(delegatorCountsKey), hex0x(uint64Slot(1)))

	// accumulatedRewardPerShares[poolId] = 0 at base slot 16.
	rewardBase := uint64Slot(16)
	rewardKey := keccak256(append(append([]byte{}, poolID...), rewardBase...))
	slots.Set(hex0x(rewardKey), hex0x(uint64Slot(0)))

	// Step 3: owner Delegator struct at base slot 14.
	delegatorsBase := uint64Slot(14)
	delegatorsPoolIDSlot := keccak256(append(append([]byte{}, poolID...), delegatorsBase...))

	ownerAddr = stripHex0x(ownerAddr)
	ownerBytes, err := hex.DecodeString(ownerAddr)
	if err != nil {
		panic(fmt.Sprintf("generateStakingV2Slots: bad ownerAddr hex %q: %v", ownerAddr, err))
	}
	ownerPadded := leftPad32(ownerBytes)
	delegatorStructBase := keccak256(append(append([]byte{}, ownerPadded...), delegatorsPoolIDSlot...))

	stakeBytes := bigIntSlot(stake)

	// offset 0: principalStake
	slots.Set(hex0x(delegatorStructBase), hex0x(stakeBytes))
	// offset 1: stake
	slots.Set(hex0x(bytesAddNum(delegatorStructBase, 1)), hex0x(stakeBytes))
	// offset 2-8: zeros (accumulatedRewardPerShare/rewards/pendingStake/
	// pendingWithdrawStake/pendingWithdrawWindow/totalRewardsClaimed/
	// isPendingUndelegate).
	for off := uint64(2); off <= 8; off++ {
		slots.Set(hex0x(bytesAddNum(delegatorStructBase, off)), hex0x(uint64Slot(0)))
	}
}

// applyOwnerSlot writes the `Validator.owner` slot (offset 9) for a
// specific domain's validator entry, then runs the v2 delegation init.
// Split out from GenerateDomainSlots so that admin_addr — which is a
// chain-level deploy field, not a per-validator field — can be applied
// by the orchestrator without polluting the slot generator's signature.
//
// Mirrors the section of conf.py:419-500 that depends on admin_addr.
func applyOwnerSlot(
	slots *OrderedStringMap,
	totalDomains, domainIndex int,
	publicKey string,
	adminAddr string,
	stake *big.Int,
) {
	publicKey = stripHex0x(publicKey)
	pubkeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		panic(fmt.Sprintf("applyOwnerSlot: bad publicKey hex: %v", err))
	}
	poolID := sha256Sum(pubkeyBytes)

	// validators[poolID] map slot.
	validatorsBaseSlotBytes := uint64Slot(validatorsMapBaseSlot)
	validatorSlot := keccak256(append(append([]byte{}, poolID...), validatorsBaseSlotBytes...))

	// (9) Validator.owner = adminAddr at offset 9.
	ownerSlot := bytesAddNum(validatorSlot, 9)
	addrHex := stripHex0x(adminAddr)
	ownerBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		panic(fmt.Sprintf("applyOwnerSlot: bad adminAddr hex %q: %v", adminAddr, err))
	}
	slots.Set(hex0x(ownerSlot), hex0x(leftPad32(ownerBytes)))

	// Append staking v2 delegation state (also depends on owner).
	generateStakingV2Slots(totalDomains, domainIndex, poolID, adminAddr, stake, slots)
}
