package tr_carrier

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/passwordutil"
)

var crlf = []byte{'\r', '\n'}

func toTrojanPasswordHash(password *conf.Password) [56]byte {
	var key [56]byte
	hash := sha256.New224()
	err := ioutil.Write_(hash, []byte(AuthPassword(password)))
	if err != nil {
		log.Fatal("unexpected code path", err)
	}
	hex.Encode(key[:], hash.Sum(nil))
	return key
}

func AuthPassword(password *conf.Password) string {
	return passwordutil.DeriveBase64(password[:], "hg/trojan/auth-password/v1")
}
