package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"golang.org/x/crypto/ssh"
)

func Base64KeyToAddress(in []byte) (pub ssh.PublicKey, addr string, err error) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, "", err
	}
	key = key[:n]

	var w struct {
		Curve    string
		Rest     []byte
		KeyBytes []byte
	}

	if err := ssh.Unmarshal(key, &w); err != nil {
		return nil, "", err
	}

	digest := sha256.Sum256(w.KeyBytes[1:])
	addr = "0x" + hex.EncodeToString(digest[:])[2*12:]

	pub, err = ssh.ParsePublicKey(key)
	if err != nil {
		return nil, "", err
	}

	return pub, addr, nil
}
