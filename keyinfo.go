/*
Copyright 2017, Trusted Key
This file is part of Trusted Key SSH-Authkeys.

Trusted Key SSH-Agent is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Trusted Key SSH-Agent is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Trusted Key SSH-Agent.  If not, see <http://www.gnu.org/licenses/>.
*/

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
