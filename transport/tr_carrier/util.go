package tr_carrier

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
)

const (
	cr        = '\r'
	escapedCR = cr + 1
)

var crlf = []byte{'\r', '\n'}

// escape CR because the Trojan protocol uses CR or CRLF
// to distinguish HTTP requests from proxy requests.
func escapeLineBreaks(passwordRaw [16]byte) [16]byte {
	var newPw [16]byte

	for i, b := range passwordRaw {
		switch {
		case b == cr:
			newPw[i] = escapedCR
		default:
			newPw[i] = b
		}
	}
	return newPw
}

func toTrojanPasswordHash(password string) [56]byte {
	var key [56]byte
	hash := sha256.New224()
	err := ioutil.Write_(hash, []byte(password))
	if err != nil {
		log.Fatal("unexpected code path", err)
	}
	hex.Encode(key[:], hash.Sum(nil))
	return key
}
