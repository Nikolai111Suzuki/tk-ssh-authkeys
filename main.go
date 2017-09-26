package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"reflect"
)

func main() {
	stderr := log.New(os.Stderr, "", 0)

	base64key := flag.String("key", "", "Base64 encoded public key (required)")
	keyType := flag.String("type", "", "OpenSSH key type (required) (only ecdsa-sha2-nistp256 allowed)")
	sshUser := flag.String("user", "", "Local user (required)")
	authkeysFile := flag.String("authkeys", "", "Which authorized keys file to read (required)")
	issuerURL := flag.String("issuer", "https://issuer.trustedkey.com", "Issuer URL to check key with")
	revokedkeysFile := flag.String("revokedkeys", "", "Which file to cache revocations in")

	flag.Parse()

	if *base64key == "" || *keyType == "" || *sshUser == "" || *authkeysFile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *keyType != "ecdsa-sha2-nistp256" {
		stderr.Println("Key not ecdsa-sha2-nistp256")
		os.Exit(1)
	}

	pubKey, pubAddr, err := Base64KeyToAddress([]byte(*base64key))
	if err != nil {
		panic(err)
	}

	authorizedKeys, err := ParseAuthorizedKeysFile(*authkeysFile)
	if err != nil {
		panic(err)
	}

	// Get key info from issuer
	keyInfo, err := GetKeyInfo(*issuerURL, pubAddr)
	if err != nil {
		panic(err)
	}

	// Handle revoked key
	if keyInfo.revoked {
		if *revokedkeysFile != "" {
			err := CacheRevocation(*revokedkeysFile, pubKey)
			if err != nil {
				stderr.Println(err)
			}
		}

		stderr.Println(fmt.Sprintf("Key with address %s was revoked", pubAddr))
		os.Exit(1)
	}

	pubkeyBytes := []byte(pubKey.Marshal())
	for _, authKey := range authorizedKeys {
		if reflect.DeepEqual(authKey.Marshal(), pubkeyBytes) {
			fmt.Print(string(ssh.MarshalAuthorizedKey(authKey)))
		}
	}
}
