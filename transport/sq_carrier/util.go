package sq_carrier

import (
	"crypto/sha256"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/util/passwordutil"
	"github.com/quic-go/quic-go"
)

func toSunnyQUICAuthHash(password *conf.Password) [64]byte {
	var key [64]byte
	derived := passwordutil.DeriveBase64(password[:], "hg/sunnyquic/auth-password/v1")
	sum := sha256.Sum256([]byte(passwordutil.DefaultUsername + ":" + derived))
	copy(key[:], sum[:])
	return key
}

// toStatelessResetKey deterministically derives the QUIC stateless reset key
// from the server password. Deriving it from the stable password keeps the
// key constant across reboots (so previously issued reset tokens stay valid)
// without persisting extra state, while a dedicated HKDF info string keeps
// it separate from the authentication hash.
// https://quic-go.net/docs/quic/transport/#stateless-reset
func toStatelessResetKey(password *conf.Password) *quic.StatelessResetKey {
	var key = new(quic.StatelessResetKey)
	derived := passwordutil.DeriveN(password[:], "hg/sunnyquic/quic-stateless-reset-key/v1", len(key))
	copy(key[:], derived)
	return key
}
