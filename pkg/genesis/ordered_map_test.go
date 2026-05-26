package genesis

import (
	"encoding/json"
	"testing"
)

func TestOrderedStringMapPreservesOrder(t *testing.T) {
	m := NewOrderedStringMap()
	m.Set("b", "1")
	m.Set("a", "2")
	m.Set("c", "3")

	got, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"b":"1","a":"2","c":"3"}`
	if string(got) != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestOrderedStringMapSetExistingKeepsPosition(t *testing.T) {
	m := NewOrderedStringMap()
	m.Set("a", "1")
	m.Set("b", "2")
	m.Set("a", "9")

	got, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"a":"9","b":"2"}`
	if string(got) != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestOrderedStringMapEmpty(t *testing.T) {
	m := NewOrderedStringMap()
	got, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != "{}" {
		t.Errorf("got %s, want {}", got)
	}
}

func TestOrderedStringMapRoundTrip(t *testing.T) {
	input := `{"z":"first","a":"second","m":"third"}`
	m := NewOrderedStringMap()
	if err := json.Unmarshal([]byte(input), m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got := m.Keys(); len(got) != 3 || got[0] != "z" || got[1] != "a" || got[2] != "m" {
		t.Errorf("keys not preserved: %v", got)
	}

	got, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != input {
		t.Errorf("round-trip mismatch:\ngot  %s\nwant %s", got, input)
	}
}

func TestOrderedStringMapUpdate(t *testing.T) {
	a := NewOrderedStringMap()
	a.Set("x", "1")
	a.Set("y", "2")

	b := NewOrderedStringMap()
	b.Set("y", "20")
	b.Set("z", "3")

	a.Update(b)

	got, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"x":"1","y":"20","z":"3"}`
	if string(got) != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}
