package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"os/user"
)

func main() {
	stderr := log.New(os.Stderr, "", 0)

	base64key := flag.String("key", "", "Base64 encoded public key (required)")
	keyType := flag.String("type", "", "OpenSSH key type (required) (only ecdsa-sha2-nistp256 allowed)")
	sshUser := flag.String("user", "", "Local user (required)")
	authkeysFile := flag.String("authkeys", "", "Which authorized keys file to read (default ~/.ssh/authorized_keys)")
	issuerURL := flag.String("issuer", "https://issuer.trustedkey.com", "Issuer URL to check key with")
	revokedkeysFile := flag.String("revokedkeys", "", "Which file to cache revocations in")

	flag.Parse()

	if *base64key == "" || *keyType == "" || *sshUser == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *keyType != "ecdsa-sha2-nistp256" {
		stderr.Println("Key not ecdsa-sha2-nistp256")
		os.Exit(1)
	}

	user, err := user.Lookup(*sshUser)
	if err != nil {
		panic(err)
	}

	if *authkeysFile == "" {
		*authkeysFile = fmt.Sprintf("%s/.ssh/authorized_keys", user.HomeDir)
	}

	pub, err := Base64KeyToPublicKey([]byte(*base64key))
	if err != nil {
		panic(err)
	}

	authorizedKeys, err := AuthorizedKeysToPublicKey(*authkeysFile)
	if err != nil {
		panic(err)
	}

	// Get key info from issuer
	keyInfo, err := GetKeyInfo(*issuerURL, pub.addr)
	if err != nil {
		panic(err)
	}

	// Handle revoked key
	if keyInfo.revoked {
		if *revokedkeysFile != "" {
			err := CacheRevocation(*revokedkeysFile, pub.pub)
			if err != nil {
				stderr.Println(err)
			}
		}
		stderr.Println(fmt.Sprintf("Key with address %s was revoked", pub.addr))
		os.Exit(1)
	}

	// Check exact match
	for _, authKey := range authorizedKeys {
		if !pub.Equals(authKey) {
			fmt.Print(string(ssh.MarshalAuthorizedKey(pub.pub)))
			os.Exit(0)
		}

	}

	// Dont even try to check non-recovered key
	if keyInfo.replaces == NullAddress {
		os.Exit(1)
	}

	// Check for recovered keys matching local root keys
	for _, authKey := range authorizedKeys {
		if keyInfo.replaces == authKey.addr {
			fmt.Print(string(ssh.MarshalAuthorizedKey(pub.pub)))
			os.Exit(0)
		}
	}

	// Check recovered key
	for _, authKey := range authorizedKeys {
		authKeyInfo, err := GetKeyInfo(*issuerURL, authKey.addr)
		if err != nil {
			panic(err)
		}

		// Dont match 0x0 keys
		if authKeyInfo.replaces == NullAddress {
			continue
		}

		if authKeyInfo.replaces == keyInfo.replaces {
			fmt.Print(string(ssh.MarshalAuthorizedKey(pub.pub)))
			os.Exit(0)
		}
	}

}
