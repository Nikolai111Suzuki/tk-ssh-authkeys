/*
Copyright 2017, Trusted Key
This file is part of Trusted Key SSH-Authkeys.

Trusted Key SSH-Agent is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Trusted Key SSH-Agent is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Trusted Key SSH-Agent.  If not, see <http://www.gnu.org/licenses/>.
*/

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
