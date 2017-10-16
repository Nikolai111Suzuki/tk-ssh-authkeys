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

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"reflect"
)

// PublicKey - Encapsulate a ssh.PublicKey and a blockchain address
type PublicKey struct {
	Pub  ssh.PublicKey
	Addr string
}

// Equals - Compare two public keys
func (p *PublicKey) Equals(pub *PublicKey) bool {
	return p.Addr == pub.Addr
}

// Base64KeyToPublicKey - Convert base64 encoded SSH pubkey to PublicKey
func Base64KeyToPublicKey(in []byte) (*PublicKey, error) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, err
	}
	key = key[:n]

	var w struct {
		Curve    string
		Rest     []byte
		KeyBytes []byte
	}

	if err := ssh.Unmarshal(key, &w); err != nil {
		return nil, err
	}

	digest := sha256.Sum256(w.KeyBytes[1:])
	addr := "0x" + hex.EncodeToString(digest[:])[2*12:]

	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		Pub:  pub,
		Addr: addr,
	}, nil
}

// AuthorizedKeysToPublicKey - Parse authorized keys file
func AuthorizedKeysToPublicKey(filePath string) ([]*PublicKey, error) {

	var contents []byte
	var err error

	if filePath == "-" {
		stat, err := os.Stdin.Stat()
		if err != nil {
			return nil, err
		}
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, errors.New("No data being piped to stdin")
		}

		contents, err = ioutil.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return nil, err
		}

	} else {
		contents, err = ioutil.ReadFile(filePath)
		if err != nil {
			return nil, err
		}

		statInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, err
		}

		if statInfo.Mode() != 0600 {
			return nil, fmt.Errorf("Bad file permissions for %s (%s)", statInfo.Mode(), filePath)
		}

	}

	keys := []*PublicKey{}

	lines := bytes.Split(contents, []byte("\n"))
	for _, l := range lines {
		// Skip empty lines
		if len(l) == 0 {
			continue
		}

		// Skip comments (35 == hash sign)
		if l[0] == 35 {
			continue
		}

		keyLine := bytes.Split(l, []byte(" "))
		if !reflect.DeepEqual(keyLine[0], []byte("ecdsa-sha2-nistp256")) {
			continue
		}

		key, err := Base64KeyToPublicKey(keyLine[1])
		if err != nil {
			StdErr.Println(err)
			continue
		}

		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, errors.New("No keys found")
	}

	return keys, nil
}
