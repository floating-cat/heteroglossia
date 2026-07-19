package sq_carrier

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
)

func toSunnyQUICAuthHash(password string) [64]byte {
	var key [64]byte
	hash := sha256.New()
	err := ioutil.Write_(hash, []byte("hg:"+password))
	if err != nil {
		log.Fatal("unexpected code path", err)
	}
	hex.Encode(key[:], hash.Sum(nil))
	return key
}
