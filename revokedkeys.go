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
	"golang.org/x/crypto/ssh"
	"os"
)

// CacheRevocation ...
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
