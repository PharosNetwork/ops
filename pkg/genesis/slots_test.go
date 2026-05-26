package genesis

import (
	"encoding/hex"
	"reflect"
	"testing"
)

// All expected values produced by running the equivalent Python helpers
// (eth_utils.keccak / hashlib.sha256 / the conf.py methods extracted
// inline). See the commit message and the steps captured in
// /Users/Zhuanz1/.claude/plans/luminous-growing-frost.md.

func TestStringToHexSlots(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"hello", []string{"68656c6c6f000000000000000000000000000000000000000000000000000000"}},
		{repeat("a", 31), []string{"6161616161616161616161616161616161616161616161616161616161616100"}},
		{repeat("a", 32), []string{"6161616161616161616161616161616161616161616161616161616161616161"}},
		{repeat("a", 64), []string{
			"6161616161616161616161616161616161616161616161616161616161616161",
			"6161616161616161616161616161616161616161616161616161616161616161",
		}},
	}
	for _, c := range cases {
		got := stringToHexSlots(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("stringToHexSlots(%q):\n got  %v\n want %v", c.in, got, c.want)
		}
	}
}

func TestShortStringToSlot(t *testing.T) {
	got := hex.EncodeToString(shortStringToSlot("domain0"))
	want := "646f6d61696e300000000000000000000000000000000000000000000000000e"
	if got != want {
		t.Errorf("shortStringToSlot('domain0') = %s\n want                          %s", got, want)
	}
}

func TestBytesAddNum(t *testing.T) {
	a, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000ff")
	got := hex.EncodeToString(bytesAddNum(a, 1))
	want := "0000000000000000000000000000000000000000000000000000000000000100"
	if got != want {
		t.Errorf("bytesAddNum(0xff, 1) = %s\n want                 %s", got, want)
	}
}

func TestBytesBitwiseOR(t *testing.T) {
	a, _ := hex.DecodeString("ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00")
	b, _ := hex.DecodeString("00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff")
	got := hex.EncodeToString(bytesBitwiseOR(a, b))
	want := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if got != want {
		t.Errorf("bytesBitwiseOR = %s\n want           %s", got, want)
	}
}

func TestPackSlot(t *testing.T) {
	items := []SlotItem{
		{Offset: 0, Value: []byte{0, 0, 0, 0, 0, 0, 0, 1}}, // uint64 nextId=1
		{Offset: 8, Value: []byte{0, 0, 0x03, 0xe8}},       // uint32 1000
		{Offset: 12, Value: hexMustDecode("2100000000000000000000000000000000000001")},
	}
	got := packSlot(items, 32)
	want := "0x2100000000000000000000000000000000000001000003e80000000000000001"
	if got != want {
		t.Errorf("packSlot = %s\n want     %s", got, want)
	}
}

func TestGenerateStringSlotShort(t *testing.T) {
	sink := NewOrderedStringMap()
	base, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	generateStringSlot("hello", base, sink)

	key := "0x0000000000000000000000000000000000000000000000000000000000000001"
	want := "0x68656c6c6f00000000000000000000000000000000000000000000000000000a"
	got, ok := sink.Get(key)
	if !ok || got != want {
		t.Errorf("short string slot:\n  got  %q -> %q\n  want %q -> %q", key, got, key, want)
	}
	if sink.Len() != 1 {
		t.Errorf("short string should occupy 1 slot, got %d", sink.Len())
	}
}

func TestGenerateStringSlotLong(t *testing.T) {
	sink := NewOrderedStringMap()
	base, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	generateStringSlot(repeat("a", 100), base, sink)

	expectedKVs := []struct {
		key, val string
	}{
		// length slot
		{"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x00000000000000000000000000000000000000000000000000000000000000c9"},
		{"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6",
			"0x6161616161616161616161616161616161616161616161616161616161616161"},
		{"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf7",
			"0x6161616161616161616161616161616161616161616161616161616161616161"},
		{"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf8",
			"0x6161616161616161616161616161616161616161616161616161616161616161"},
		{"0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf9",
			"0x6161616100000000000000000000000000000000000000000000000000000000"},
	}
	if sink.Len() != len(expectedKVs) {
		t.Fatalf("long string slot count = %d, want %d", sink.Len(), len(expectedKVs))
	}
	for _, kv := range expectedKVs {
		got, ok := sink.Get(kv.key)
		if !ok {
			t.Errorf("missing slot %s", kv.key)
			continue
		}
		if got != kv.val {
			t.Errorf("slot %s:\n  got  %s\n  want %s", kv.key, got, kv.val)
		}
	}

	// Keys must appear in the order Python writes them (length first,
	// then data slots in ascending index).
	gotKeys := sink.Keys()
	for i, kv := range expectedKVs {
		if gotKeys[i] != kv.key {
			t.Errorf("key order [%d] = %s, want %s", i, gotKeys[i], kv.key)
		}
	}
}

func TestKeccak256(t *testing.T) {
	got := hex.EncodeToString(keccak256(make([]byte, 32)))
	want := "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
	if got != want {
		t.Errorf("keccak256(uint256(0)) = %s\n want                  %s", got, want)
	}
}

func TestSha256Sum(t *testing.T) {
	got := hex.EncodeToString(sha256Sum([]byte("abc")))
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("sha256(abc) = %s\n want        %s", got, want)
	}
}

func TestLeftPad32(t *testing.T) {
	got := hex.EncodeToString(leftPad32([]byte{0xab, 0xcd}))
	want := "000000000000000000000000000000000000000000000000000000000000abcd"
	if got != want {
		t.Errorf("leftPad32(0xabcd) = %s\n want              %s", got, want)
	}
}

func TestUint64Slot(t *testing.T) {
	got := hex.EncodeToString(uint64Slot(0x1234))
	want := "0000000000000000000000000000000000000000000000000000000000001234"
	if got != want {
		t.Errorf("uint64Slot(0x1234) = %s\n want               %s", got, want)
	}
}

// repeat helper — strings.Repeat would also work, but inlining keeps the
// test file self-contained.
func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func hexMustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
