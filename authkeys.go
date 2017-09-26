package main

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

func ParseAuthorizedKeysFile(filePath string) ([]ssh.PublicKey, error) {
	contents, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	keys := []ssh.PublicKey{}

	lines := bytes.Split(contents, []byte("\n"))
	for _, l := range lines {
		// Skip empty lines
		if len(l) == 0 {
			continue
		}

		// Skip comments
		if l[0] == 35 {
			continue
		}

		key, _, _, _, err := ssh.ParseAuthorizedKey(l)
		if err != nil {
			return nil, err
		}

		// Unhandled key type
		if key.Type() != "ecdsa-sha2-nistp256" {
			continue
		}

		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, errors.New("No keys found")
	}

	return keys, nil
}
