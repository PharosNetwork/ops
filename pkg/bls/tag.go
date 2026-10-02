package bls

import "strings"

// Aldaba key type tags. These 2-byte prefixes label the key type in the
// hex-string on-disk format; they are NOT part of the cryptographic material.
const (
	TagPrivKey = "4002" // BLS12-381 private key
	TagPubKey  = "4003" // BLS12-381 public key
)

// StripTag removes a leading "0x", then a known BLS type tag (4002/4003) if
// present, returning the raw hex payload. It is tolerant: input may or may not
// carry "0x" and may or may not carry a tag.
func StripTag(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	switch {
	case strings.HasPrefix(s, TagPrivKey):
		return s[len(TagPrivKey):]
	case strings.HasPrefix(s, TagPubKey):
		return s[len(TagPubKey):]
	default:
		return s
	}
}

// AddPrivTag returns the legacy on-disk private-key string: "0x" + 4002 tag +
// raw hex payload (payload must be tag-free).
func AddPrivTag(rawHex string) string {
	return "0x" + TagPrivKey + strings.TrimPrefix(strings.TrimSpace(rawHex), "0x")
}

// AddPubTag returns the legacy on-disk public-key string: "0x" + 4003 tag +
// raw hex payload.
func AddPubTag(rawHex string) string {
	return "0x" + TagPubKey + strings.TrimPrefix(strings.TrimSpace(rawHex), "0x")
}
