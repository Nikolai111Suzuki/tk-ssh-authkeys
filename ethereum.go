package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rpc"
)

var keyInfoAddr = ethSha3([]byte("keyInfo(address)"))

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func ethSha3(input []byte) string {
	h := sha3.NewKeccak256()
	h.Write(input)
	return hex.EncodeToString(h.Sum(nil))
}

// EthGetKeyInfo - Get key info from blockchain node
func EthGetKeyInfo(ethURL string, contractAddr string, pubAddr string) (*KeyInfo, error) {
	ethClient, err := rpc.Dial(ethURL)
	if err != nil {
		return nil, err
	}

	param := make(map[string]string)
	param["to"] = contractAddr
	param["data"] = fmt.Sprintf("0x%s000000000000000000000000%s", keyInfoAddr[:8], pubAddr[2:])

	result := ""
	ethClient.Call(&result, "eth_call", param, "latest")
	if len(result) == 0 {
		return nil, errors.New("Result from geth RPC empty, is RPC running?")
	}

	// Using fixed offsets is quite crude but at least we can avoid
	// using the cgo dependent code that abigen outputs
	result = reverseString(result[2:])
	replaces := fmt.Sprintf("0x%s", reverseString(result[:40]))
	revokedBy := fmt.Sprintf("0x%s", reverseString(result[64:64+40]))

	return NewKeyInfo(replaces, revokedBy), nil
}
