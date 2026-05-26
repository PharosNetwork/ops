package genesis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// GenesisTemplate is an order-preserving representation of
// genesis.tpl.conf. The structure is rich enough that we can mutate
// the parts the generator needs (domains map, account balances, alloc
// storage) without serialising/deserialising the rest, but plain enough
// that round-tripping is straightforward.
//
// Top-level keys must appear in the order Python emits them. Same for
// alloc, alloc[addr].storage, and configs.
type GenesisTemplate struct {
	topOrder []string
	top      map[string]json.RawMessage

	configs *OrderedStringMap // top["configs"]
	alloc   *OrderedAllocMap  // top["alloc"]
	domains *RawDomainMap     // top["domains"] — written by Run, read as-is on load
}

// Account is one entry under alloc[]. Fields are ordered as Python
// emits them (per shape). We keep raw bytes for non-storage fields so
// hex casing and any quirks survive round-trip.
type Account struct {
	keys    []string                   // field order: subset of "code","balance","nonce"
	fields  map[string]json.RawMessage // raw bytes for non-storage fields
	storage *OrderedStringMap          // nil if account has no storage key
}

// HasField reports whether the given top-level field exists on the
// account.
func (a *Account) HasField(name string) bool {
	_, ok := a.fields[name]
	return ok
}

// SetRawField sets a raw JSON value for a top-level field (e.g.,
// SetRawField("balance", json.RawMessage(`"0x123"`))). New fields are
// appended; existing fields keep their position.
func (a *Account) SetRawField(name string, raw json.RawMessage) {
	if _, exists := a.fields[name]; !exists {
		a.keys = append(a.keys, name)
	}
	if a.fields == nil {
		a.fields = make(map[string]json.RawMessage)
	}
	a.fields[name] = raw
}

// SetBalance is a convenience wrapper for SetRawField("balance", ...)
// with hex encoding. The hex string is quoted as a JSON string.
func (a *Account) SetBalance(hexValue string) {
	a.SetRawField("balance", json.RawMessage(fmt.Sprintf("%q", hexValue)))
}

// Storage returns the account's storage map. If the account had no
// storage key in the template, an empty OrderedStringMap is created
// and "storage" is appended to the field order (after the existing
// non-storage fields), matching how Python's `genesis_data['alloc'][addr]['storage'] = ...`
// assignment behaves on a fresh key.
func (a *Account) Storage() *OrderedStringMap {
	if a.storage == nil {
		a.storage = NewOrderedStringMap()
	}
	return a.storage
}

// MarshalJSON emits {code, balance, nonce, ...} fields in their stored
// order, then "storage" last if present. This matches Python's emission
// order: non-storage fields keep template order, storage appears last
// when it exists (or was added by the generator).
func (a *Account) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	for _, k := range a.keys {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&buf, "%q:", k)
		buf.Write(a.fields[k])
	}
	if a.storage != nil {
		if !first {
			buf.WriteByte(',')
		}
		buf.WriteString(`"storage":`)
		sb, err := a.storage.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("marshal storage: %w", err)
		}
		buf.Write(sb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON parses an Account, preserving field insertion order
// for code/balance/nonce/etc. The "storage" field, if present, is
// pulled out into the typed OrderedStringMap so the generator can
// mutate it.
func (a *Account) UnmarshalJSON(data []byte) error {
	a.keys = a.keys[:0]
	a.fields = make(map[string]json.RawMessage)
	a.storage = nil

	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("Account: expected object, got %v", tok)
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("Account: non-string key %v", keyTok)
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("Account[%s]: %w", key, err)
		}

		if key == "storage" {
			a.storage = NewOrderedStringMap()
			if err := json.Unmarshal(raw, a.storage); err != nil {
				return fmt.Errorf("Account.storage: %w", err)
			}
		} else {
			a.keys = append(a.keys, key)
			a.fields[key] = raw
		}
	}

	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// OrderedAllocMap preserves alloc[addr] insertion order.
type OrderedAllocMap struct {
	keys   []string
	values map[string]*Account
}

// Get returns the account at address.
func (m *OrderedAllocMap) Get(addr string) (*Account, bool) {
	a, ok := m.values[addr]
	return a, ok
}

// MustGet returns the account at address or panics. Use for known
// system contracts (0x4100..., 0x3100..., etc.).
func (m *OrderedAllocMap) MustGet(addr string) *Account {
	a, ok := m.values[addr]
	if !ok {
		panic(fmt.Sprintf("alloc has no entry for %q", addr))
	}
	return a
}

// MarshalJSON emits alloc in insertion order.
func (m *OrderedAllocMap) MarshalJSON() ([]byte, error) {
	if m == nil || len(m.keys) == 0 {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, "%q:", k)
		b, err := m.values[k].MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("alloc[%s]: %w", k, err)
		}
		buf.Write(b)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON streams the alloc object to preserve order.
func (m *OrderedAllocMap) UnmarshalJSON(data []byte) error {
	m.keys = m.keys[:0]
	m.values = make(map[string]*Account)

	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("alloc: expected object, got %v", tok)
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		addr, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("alloc: non-string key %v", keyTok)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("alloc[%s] raw: %w", addr, err)
		}
		var acct Account
		if err := json.Unmarshal(raw, &acct); err != nil {
			return fmt.Errorf("alloc[%s]: %w", addr, err)
		}
		m.keys = append(m.keys, addr)
		m.values[addr] = &acct
	}

	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// RawDomainMap is the genesis "domains" object — written verbatim by
// the generator. We don't need ordered ops on read because the template
// starts with an empty {} domains map; the generator entirely overwrites
// it from deploy.json's domain iteration order.
type RawDomainMap struct {
	keys   []string
	values map[string]json.RawMessage
}

// Set appends or updates a domain entry. Raw bytes are emitted verbatim.
func (m *RawDomainMap) Set(label string, value json.RawMessage) {
	if m.values == nil {
		m.values = make(map[string]json.RawMessage)
	}
	if _, exists := m.values[label]; !exists {
		m.keys = append(m.keys, label)
	}
	m.values[label] = value
}

// MarshalJSON emits domains in insertion order.
func (m *RawDomainMap) MarshalJSON() ([]byte, error) {
	if m == nil || len(m.keys) == 0 {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, "%q:", k)
		buf.Write(m.values[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON loads any pre-existing domain entries from the template
// (typically empty {}).
func (m *RawDomainMap) UnmarshalJSON(data []byte) error {
	m.keys = m.keys[:0]
	m.values = make(map[string]json.RawMessage)

	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("domains: expected object, got %v", tok)
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		label, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("domains: non-string key %v", keyTok)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		m.keys = append(m.keys, label)
		m.values[label] = raw
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// LoadGenesisTemplate reads + parses genesis.tpl.conf.
func LoadGenesisTemplate(path string) (*GenesisTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}
	tpl := &GenesisTemplate{
		top: make(map[string]json.RawMessage),
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("template root: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("template: expected object root, got %v", tok)
	}

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("template: non-string key %v", keyTok)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("template[%s]: %w", key, err)
		}
		tpl.topOrder = append(tpl.topOrder, key)
		tpl.top[key] = raw
	}

	// Extract typed views.
	if cfg, ok := tpl.top["configs"]; ok {
		tpl.configs = NewOrderedStringMap()
		if err := json.Unmarshal(cfg, tpl.configs); err != nil {
			return nil, fmt.Errorf("template configs: %w", err)
		}
	}
	if al, ok := tpl.top["alloc"]; ok {
		var amap OrderedAllocMap
		if err := json.Unmarshal(al, &amap); err != nil {
			return nil, fmt.Errorf("template alloc: %w", err)
		}
		tpl.alloc = &amap
	}
	if dm, ok := tpl.top["domains"]; ok {
		var dmap RawDomainMap
		if err := json.Unmarshal(dm, &dmap); err != nil {
			return nil, fmt.Errorf("template domains: %w", err)
		}
		tpl.domains = &dmap
	} else {
		tpl.domains = &RawDomainMap{}
	}
	return tpl, nil
}

// Configs returns the chain-level configs map. Mutating the returned
// map is reflected in the marshal output.
func (t *GenesisTemplate) Configs() *OrderedStringMap {
	return t.configs
}

// Alloc returns the alloc map. Use Alloc().MustGet(addr).Storage() etc.
func (t *GenesisTemplate) Alloc() *OrderedAllocMap {
	return t.alloc
}

// Domains returns the domains map. The generator populates this from
// deploy.json's domain iteration; the loaded template is typically empty.
func (t *GenesisTemplate) Domains() *RawDomainMap {
	return t.domains
}

// Marshal emits the genesis JSON with Python json.dump(indent=2)-like
// formatting. We delegate to encoding/json's Indent for the indentation
// step, after a custom compact pass that preserves key order.
func (t *GenesisTemplate) Marshal() ([]byte, error) {
	// Rebuild the top-level object in original key order, substituting
	// typed views for the three keys we manage.
	var compact bytes.Buffer
	compact.WriteByte('{')
	for i, k := range t.topOrder {
		if i > 0 {
			compact.WriteByte(',')
		}
		fmt.Fprintf(&compact, "%q:", k)

		switch k {
		case "configs":
			b, err := t.configs.MarshalJSON()
			if err != nil {
				return nil, fmt.Errorf("configs: %w", err)
			}
			compact.Write(b)
		case "alloc":
			b, err := t.alloc.MarshalJSON()
			if err != nil {
				return nil, fmt.Errorf("alloc: %w", err)
			}
			compact.Write(b)
		case "domains":
			b, err := t.domains.MarshalJSON()
			if err != nil {
				return nil, fmt.Errorf("domains: %w", err)
			}
			compact.Write(b)
		default:
			compact.Write(t.top[k])
		}
	}
	compact.WriteByte('}')

	// Python's json.dump(indent=2) is equivalent to json.Indent with
	// prefix="" indent="  ".
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact.Bytes(), "", "  "); err != nil {
		return nil, fmt.Errorf("json.Indent: %w", err)
	}
	return indented.Bytes(), nil
}
