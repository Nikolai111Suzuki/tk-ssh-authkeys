package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func formatURL(issuerURL string, pubAddrs []string) (string, error) {
	url, err := url.Parse(issuerURL)
	if err != nil {
		return "", err
	}
	url.Path = "keyInfo"
	url.RawQuery = fmt.Sprintf("address=%s", strings.Join(pubAddrs, ","))

	return url.String(), nil
}

// IssuerGetKeyInfo - Get key info from issuer API
func IssuerGetKeyInfo(issuerURL string, pubAddrs []string) ([]*KeyInfo, error) {
	requestURL, err := formatURL(issuerURL, pubAddrs)
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(requestURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Server returned HTTP status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	data = data["data"].(map[string]interface{})

	keys := []*KeyInfo{}
	for _, pubAddr := range pubAddrs {
		keyInfo := data[pubAddr].(map[string]interface{})
		keys = append(keys, NewKeyInfo(keyInfo["replaces"].(string), keyInfo["revokedBy"].(string)))
	}

	return keys, nil
}
