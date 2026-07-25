package passwordutil

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"

	"github.com/floating-cat/heteroglossia/util/log"
)

const defaultKeyLen = 16

func Derive(password []byte, info string) []byte {
	return DeriveN(password, info, defaultKeyLen)
}

func DeriveN(password []byte, info string, keyLen int) []byte {
	derived, err := hkdf.Key(sha256.New, password, nil, info, keyLen)
	if err != nil {
		log.Fatal("unexpected code path", err)
	}
	return derived
}

func DeriveBase64(password []byte, info string) string {
	derived := DeriveN(password, info, defaultKeyLen)
	return base64.StdEncoding.EncodeToString(derived)
}
