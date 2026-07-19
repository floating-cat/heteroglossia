package sq_carrier

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"

	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/quic-go/quic-go"
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

// toStatelessResetKey deterministically derives the QUIC stateless reset key
// from the server password. Deriving it from the stable password keeps the key
// constant across reboots (so previously issued reset tokens stay valid) without
// persisting extra state, while a dedicated HKDF info string keeps it separate
// from the authentication hash.
// https://quic-go.net/docs/quic/transport/#stateless-reset
func toStatelessResetKey(password string) *quic.StatelessResetKey {
	var key = new(quic.StatelessResetKey)
	derived, err := hkdf.Key(sha256.New, []byte(password), nil, "hg:sunnyquic:stateless-reset-key", len(key))
	if err != nil {
		log.Fatal("unexpected code path", err)
	}
	copy(key[:], derived)
	return key
}
