package ss_carrier

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/passwordutil"
	"github.com/floating-cat/heteroglossia/util/randutil"
	"lukechampine.com/blake3"
)

const (
	gcmTagOverhead = 16

	// Method is the Shadowsocks 2022 method name that clients need to use.
	Method = "2022-blake3-aes-128-gcm"
)

func toShadowsocksSharedKey(password *conf.Password) []byte {
	return passwordutil.Derive(password[:], "hg/shadowsocks/auth-shared-key/v1")
}

func AuthPassword(password *conf.Password) string {
	return base64.StdEncoding.EncodeToString(toShadowsocksSharedKey(password))
}

func generateSalt(preSharedKey []byte) []byte {
	saltSize := len(preSharedKey)
	return randutil.RandNBytes(saltSize)
}

func aeadCipher(psk, salt []byte) (cipher.AEAD, error) {
	subkey := deriveSubkey(psk, salt)
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return errors.WithStack2(cipher.NewGCM(block))
}

func deriveSubkey(psk, salt []byte) []byte {
	keyMaterial := make([]byte, len(psk)+len(salt))
	copy(keyMaterial, psk)
	copy(keyMaterial[len(psk):], salt)
	key := make([]byte, len(psk))
	blake3.DeriveKey(key, "shadowsocks 2022 session subkey", keyMaterial)
	return key
}

// weighted1ToN returns a function that picks an int in [0, n), where each
// number has a random chance fixed at creation time. n must be > 0.
func weightedIntN(n int) func() int {
	cumulativeWeights := make([]uint64, n)
	var totalWeight uint64
	for i := range n {
		// +1 keeps every weight, and so totalWeight, above 0
		totalWeight += uint64(rand.Uint32()) + 1
		cumulativeWeights[i] = totalWeight
	}

	return func() int {
		r := rand.N(totalWeight)
		return sort.Search(n, func(i int) bool { return r < cumulativeWeights[i] })
	}
}

const maxAllowedUnixTimeDiffInSecond = 30

func validateUnixTimeInRange(bs []byte) error {
	compared := int64(binary.BigEndian.Uint64(bs))
	now := time.Now().Unix()
	diff := max(compared, now) - min(compared, now)
	if diff > maxAllowedUnixTimeDiffInSecond {
		return errors.Newf("unix time difference is over 30 seconds: received time was '%v' and now it is %v",
			compared, now)
	}
	return nil
}
