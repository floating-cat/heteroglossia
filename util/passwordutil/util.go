package passwordutil

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"

	"github.com/floating-cat/heteroglossia/util/log"
)

const (
	defaultKeyLen = 16
	// DefaultUsername is non-empty because some servers reject empty usernames
	// in Basic authentication
	DefaultUsername = "hg"
)

var salt = []byte("hg-app-salt-v1")

func DeriveN(password []byte, info string, keyLen int) []byte {
	derived, err := hkdf.Key(sha256.New, password, salt, info, keyLen)
	if err != nil {
		log.Fatal("unexpected code path", err)
	}
	return derived
}

func DeriveBase64(password []byte, info string) string {
	derived := DeriveN(password, info, defaultKeyLen)
	return base64.StdEncoding.EncodeToString(derived)
}
