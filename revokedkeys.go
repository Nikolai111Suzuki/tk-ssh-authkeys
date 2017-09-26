package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
)

func CacheRevocation(cacheFile string, key ssh.PublicKey) error {
	statInfo, err := os.Stat(cacheFile)
	if err != nil {
		return err
	}

	if statInfo.Mode() != 0600 {
		return fmt.Errorf("Bad file permissions for %s (%s)", statInfo.Mode(), cacheFile)
	}

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
