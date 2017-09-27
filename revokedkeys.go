package main

import (
	"golang.org/x/crypto/ssh"
	"os"
)

func CacheRevocation(cacheFile string, key ssh.PublicKey) error {
	f, err := os.OpenFile(cacheFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	keyString := string(ssh.MarshalAuthorizedKey(key))
	if _, err = f.WriteString(keyString); err != nil {
		return err
	}

	return nil
}
