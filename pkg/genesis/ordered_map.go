package genesis

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// OrderedStringMap is a string→string map that preserves insertion order
// when marshaled as JSON. Required because Python's json.dump output
// preserves dict insertion order (Python 3.7+) and the genesis bytes
// must match Python's output byte-for-byte where possible.
//
// Only the methods we actually need for genesis generation are
// implemented; this is not a general-purpose ordered map.
type OrderedStringMap struct {
	keys   []string
	values map[string]string
}

// NewOrderedStringMap returns an empty OrderedStringMap.
func NewOrderedStringMap() *OrderedStringMap {
	return &OrderedStringMap{
		keys:   make([]string, 0),
		values: make(map[string]string),
	}
}

// Set inserts or updates a key. Existing keys keep their position;
// new keys are appended.
func (m *OrderedStringMap) Set(key, value string) {
	if _, exists := m.values[key]; !exists {
		m.keys = append(m.keys, key)
	}
	m.values[key] = value
}

// Get returns the value for key and whether it was present.
func (m *OrderedStringMap) Get(key string) (string, bool) {
	v, ok := m.values[key]
	return v, ok
}

// Keys returns the keys in insertion order. The returned slice is a
// copy; callers may mutate it freely.
func (m *OrderedStringMap) Keys() []string {
	out := make([]string, len(m.keys))
	copy(out, m.keys)
	return out
}

// Len returns the number of entries.
func (m *OrderedStringMap) Len() int {
	return len(m.keys)
}

// Update merges every entry from other into m (other's order is
// preserved for new keys).
func (m *OrderedStringMap) Update(other *OrderedStringMap) {
	if other == nil {
		return
	}
	for _, k := range other.keys {
		m.Set(k, other.values[k])
	}
}

// MarshalJSON emits entries in insertion order.
func (m *OrderedStringMap) MarshalJSON() ([]byte, error) {
	if m == nil || len(m.keys) == 0 {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("marshal key %q: %w", k, err)
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(m.values[k])
		if err != nil {
			return nil, fmt.Errorf("marshal value for %q: %w", k, err)
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON reads a JSON object, preserving insertion order using
// json.Decoder's streaming token reader.
func (m *OrderedStringMap) UnmarshalJSON(data []byte) error {
	m.keys = m.keys[:0]
	if m.values == nil {
		m.values = make(map[string]string)
	} else {
		for k := range m.values {
			delete(m.values, k)
		}
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("OrderedStringMap: expected object, got %v", tok)
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("OrderedStringMap: non-string key %v", keyTok)
		}
		valTok, err := dec.Token()
		if err != nil {
			return err
		}
		val, ok := valTok.(string)
		if !ok {
			return fmt.Errorf("OrderedStringMap: non-string value for %q (got %T)", key, valTok)
		}
		m.Set(key, val)
	}

	// consume closing '}'
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}
