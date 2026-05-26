package genesis

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// leftPad32 returns b left-padded with zero bytes to 32 bytes.
// Mirrors `int_to_big_endian(n).rjust(32, b'\0')` in Python.
func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// uint64Slot returns the 32-byte big-endian encoding of n. Used for
// constant slot indices like uint256(0), uint256(1), ...
func uint64Slot(n uint64) []byte {
	out := make([]byte, 32)
	out[24] = byte(n >> 56)
	out[25] = byte(n >> 48)
	out[26] = byte(n >> 40)
	out[27] = byte(n >> 32)
	out[28] = byte(n >> 24)
	out[29] = byte(n >> 16)
	out[30] = byte(n >> 8)
	out[31] = byte(n)
	return out
}

// bigIntSlot returns the 32-byte big-endian encoding of n.
// Equivalent of `int_to_big_endian(n).rjust(32, b'\0')` for arbitrary-
// width integers (stake in wei exceeds uint64).
func bigIntSlot(n *big.Int) []byte {
	return leftPad32(n.Bytes())
}

// bytesAddNum returns a + b as 32-byte big-endian bytes.
// Mirrors Python's `_bytes_add_num(a, b)`. `a` is treated as a 32-byte
// big-endian integer; the result is wrapped at 256 bits via
// `.to_bytes(32, 'big')` which panics on overflow — we mirror by
// truncating to the low 32 bytes if a + b exceeds 256 bits.
func bytesAddNum(a []byte, b uint64) []byte {
	acc := new(big.Int).SetBytes(a)
	acc.Add(acc, new(big.Int).SetUint64(b))
	// Mask to 256 bits.
	mask := new(big.Int).Lsh(big.NewInt(1), 256)
	acc.Mod(acc, mask)
	return leftPad32(acc.Bytes())
}

// bytesBitwiseOR returns a | b. The two slices must have the same
// length. Mirrors Python's `_bytes_bitwise_add`.
func bytesBitwiseOR(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(fmt.Sprintf("bytesBitwiseOR: length mismatch %d vs %d", len(a), len(b)))
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] | b[i]
	}
	return out
}

// stringToHexSlots returns 64-hex-char chunks of s's UTF-8 encoding.
// Each chunk represents one 32-byte storage slot's worth. The last
// chunk is right-padded with '0' (hex zeros). Mirrors
// `_string_to_hex_slots`.
func stringToHexSlots(s string) []string {
	hexString := hex.EncodeToString([]byte(s))
	var slots []string
	for i := 0; i < len(hexString); i += 64 {
		end := i + 64
		if end > len(hexString) {
			end = len(hexString)
		}
		slot := hexString[i:end]
		// Right-pad with '0' to 64 hex chars (32 bytes).
		for len(slot) < 64 {
			slot += "0"
		}
		slots = append(slots, slot)
	}
	return slots
}

// shortStringToSlot packs a string (<=31 bytes) into a single 32-byte
// slot using Solidity's short-string encoding: data in the high bytes,
// length*2 in the last byte. Mirrors `_short_string_to_slot`.
//
// Caller must ensure len([]byte(s)) <= 31.
func shortStringToSlot(s string) []byte {
	sLen := len([]byte(s)) * 2 // Python: len(s.encode('utf-8')) * 2
	sLenBytes := leftPad32(big.NewInt(int64(sLen)).Bytes())

	hexSlot := stringToHexSlots(s)[0]
	slotBytes, err := hex.DecodeString(hexSlot)
	if err != nil {
		// stringToHexSlots only emits valid hex; this is unreachable.
		panic(fmt.Sprintf("shortStringToSlot: %v", err))
	}
	return bytesBitwiseOR(slotBytes, sLenBytes)
}

// generateStringSlot writes Solidity-style string storage for `s` rooted
// at `baseSlot`. Short strings (<=31 bytes) occupy a single slot at
// `baseSlot` (data | length encoded together). Long strings (>31 bytes)
// write length*2+1 at baseSlot, then place the data at
// keccak(baseSlot), keccak(baseSlot)+1, ...
//
// Mirrors `_generate_string_slot`.
func generateStringSlot(s string, baseSlot []byte, sink *OrderedStringMap) {
	sLen := len([]byte(s))
	if sLen <= 31 {
		slotBytes := shortStringToSlot(s)
		sink.Set("0x"+hex.EncodeToString(baseSlot),
			"0x"+hex.EncodeToString(slotBytes))
		return
	}

	// Long string: encode length as 2L+1 at baseSlot.
	encodedLen := uint64(sLen)*2 + 1
	sink.Set("0x"+hex.EncodeToString(baseSlot),
		"0x"+hex.EncodeToString(leftPad32(big.NewInt(int64(encodedLen)).Bytes())))

	// Data slots at keccak(baseSlot), +1, ...
	dataBase := keccak256(baseSlot)
	for i, chunk := range stringToHexSlots(s) {
		slotKey := bytesAddNum(dataBase, uint64(i))
		sink.Set("0x"+hex.EncodeToString(slotKey), "0x"+chunk)
	}
}

// SlotItem is one (offset, value) pair that packSlot writes into a
// 32-byte slot. `Offset` is measured from the LOW end (LSB-first), as
// Solidity packs fields right-to-left.
type SlotItem struct {
	Offset int    // bytes from the low end
	Value  []byte // raw bytes
}

// packSlot returns a 0x-prefixed hex string for one packed Solidity
// storage slot, with each item placed at its `Offset` from the low end.
// Items are written in order; later items overwriting earlier ones at
// overlapping ranges is the caller's bug.
//
// Mirrors `_generate_slot(items, slot_size=32)`. Python places each
// item at `slot_size - (offset + length)`, working from the high end
// of a fixed-size slot — same effect, different framing.
func packSlot(items []SlotItem, slotSize int) string {
	if slotSize <= 0 {
		slotSize = 32
	}
	slot := make([]byte, slotSize)
	for _, item := range items {
		length := len(item.Value)
		if item.Offset+length > slotSize {
			panic(fmt.Sprintf("packSlot: value at offset %d length %d exceeds slot size %d",
				item.Offset, length, slotSize))
		}
		startIdx := slotSize - (item.Offset + length)
		copy(slot[startIdx:startIdx+length], item.Value)
	}
	return "0x" + hex.EncodeToString(slot)
}

// hex0x returns "0x" + hex-encoded b. Convenience.
func hex0x(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// stripHex0x returns s with any "0x"/"0X" prefix removed.
func stripHex0x(s string) string {
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		return s[2:]
	}
	return s
}
