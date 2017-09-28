package main

import (
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

type PublicKey struct {
	Pub  ssh.PublicKey
	Addr string
}

func (p *PublicKey) Equals(pub *PublicKey) bool {
	return p.Addr == pub.Addr
}

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

func AuthorizedKeysToPublicKey(filePath string) ([]*PublicKey, error) {
	statInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	if statInfo.Mode() != 0600 {
		return nil, fmt.Errorf("Bad file permissions for %s (%s)", statInfo.Mode(), filePath)
	}

	contents, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
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
