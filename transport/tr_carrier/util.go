package tr_carrier

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
)

var crlf = []byte{'\r', '\n'}

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
