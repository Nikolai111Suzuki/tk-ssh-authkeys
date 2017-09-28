package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"os/user"
)

// StdErr ...
var StdErr = log.New(os.Stderr, "", 0)

func main() {
	base64key := flag.String("key", "", "Base64 encoded public key (required)")
	keyType := flag.String("type", "", "OpenSSH key type (required) (only ecdsa-sha2-nistp256 allowed)")
	sshUser := flag.String("user", "", "Local user (required)")
	authkeysFile := flag.String("authkeys", "", "Which authorized keys file to read (default ~/.ssh/authorized_keys)")
	revokedkeysFile := flag.String("revokedkeys", "", "Which file to cache revocations in")

	issuerURL := flag.String("issuer", "https://issuer.trustedkey.com", "Get key info with this issuer")

	rpcURL := flag.String("rpc", "", "Get key info from blockchain directly over geth RPC")
	contractAddr := flag.String("contract", "", "Contract address of RevokeList (required if -rpc is used)")

	flag.Parse()

	if (*base64key == "" || *keyType == "" || *sshUser == "") ||
		(*rpcURL != "" && *contractAddr == "") {

		StdErr.Println(fmt.Sprintf("Usage of %s:", os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *keyType != "ecdsa-sha2-nistp256" {
		StdErr.Println("Key not ecdsa-sha2-nistp256")
		os.Exit(1)
	}

	user, err := user.Lookup(*sshUser)
	if err != nil {
		panic(err)
	}

	if *authkeysFile == "" {
		*authkeysFile = fmt.Sprintf("%s/.ssh/authorized_keys", user.HomeDir)
	}

	// Abstraction for getting key information from issuer/geth
	getKeyInfo := func(keys []*PublicKey) (map[string]*KeyInfo, error) {
		pubAddrs := []string{}
		for _, key := range keys {
			pubAddrs = append(pubAddrs, key.Addr)
		}

		var keyInfo []*KeyInfo
		if *rpcURL != "" {
			keyInfo, err = EthGetKeyInfo(*rpcURL, *contractAddr, pubAddrs)
			if err != nil {
				return nil, err
			}

		} else {
			keyInfo, err = IssuerGetKeyInfo(*issuerURL, pubAddrs)
			if err != nil {
				return nil, err
			}
		}

		ret := make(map[string]*KeyInfo)
		for idx, pubAddr := range pubAddrs {
			ret[pubAddr] = keyInfo[idx]
		}
		return ret, nil
	}

	pub, err := Base64KeyToPublicKey([]byte(*base64key))
	if err != nil {
		panic(err)
	}

	authorizedKeys, err := AuthorizedKeysToPublicKey(*authkeysFile)
	if err != nil {
		panic(err)
	}

	allKeyInfo, err := getKeyInfo(append(authorizedKeys, []*PublicKey{pub}...))
	if err != nil {
		panic(err)
	}

	keyInfo := allKeyInfo[pub.Addr]
	if keyInfo.Revoked {
		if *revokedkeysFile != "" {
			err := CacheRevocation(*revokedkeysFile, pub.Pub)
			if err != nil {
				StdErr.Println(err)
			}
		}
		StdErr.Println(fmt.Sprintf("Key with address %s was revoked", pub.Addr))
		os.Exit(1)
	}

	// Check exact match
	for _, authKey := range authorizedKeys {
		if pub.Equals(authKey) {
			fmt.Print(string(ssh.MarshalAuthorizedKey(pub.Pub)))
			os.Exit(0)
		}

	}

	// Dont even try to check non-recovered key
	if keyInfo.Replaces == NullAddress {
		panic("Key is not matching locally known keys and is not recovered")
	}

	// Check for recovered keys matching local root keys
	for _, authKey := range authorizedKeys {
		if keyInfo.Replaces == authKey.Addr {
			fmt.Print(string(ssh.MarshalAuthorizedKey(pub.Pub)))
			os.Exit(0)
		}
	}

	// Check recovered key
	for _, authKey := range authorizedKeys {
		authKeyInfo := allKeyInfo[authKey.Addr]

		// Dont match 0x0 keys
		if authKeyInfo.Revoked || authKeyInfo.Replaces == NullAddress {
			StdErr.Println(fmt.Sprintf("Key with address %s was revoked", authKey.Addr))
			continue
		}

		if authKeyInfo.Replaces == keyInfo.Replaces {
			fmt.Print(string(ssh.MarshalAuthorizedKey(pub.Pub)))
			os.Exit(0)
		}
	}

}
