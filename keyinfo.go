package main

// NullAddress - Ethereum 0x0 address
const NullAddress = "0x0000000000000000000000000000000000000000"

// KeyInfo - Metadata about key
type KeyInfo struct {
	// timestamp int
	// revokedBy string
	Replaces string
	// recovery string
	Revoked bool
}

// NewKeyInfo - Create a KeyInfo instance
func NewKeyInfo(replaces string, revokedBy string) *KeyInfo {
	return &KeyInfo{
		Replaces: replaces,
		Revoked:  revokedBy != NullAddress,
	}
}
