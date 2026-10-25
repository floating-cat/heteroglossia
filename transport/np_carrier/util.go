package np_carrier

import (
	"crypto/subtle"
	"encoding/base64"
	"math/rand/v2"
	"strings"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/util/passwordutil"
)

func basicAuthEqual(header string, authToken string) bool {
	// auth scheme is case-insensitive
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Proxy-Authorization#auth-scheme
	if len(header) < len(basicAuthPrefix) || !strings.EqualFold(header[:len(basicAuthPrefix)], basicAuthPrefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header[len(basicAuthPrefix):]), []byte(authToken)) == 1
}

const (
	// The CONNECT request and response frames are too short and too uncommon.
	// To make its length similar to realistic HEADERS frames, a padding header
	// is filled with a sequence of symbols that are not Huffman coded and are
	// pseudo-random enough to avoid being indexed. The length of the padding
	// sequence is randomly distributed in [16, 32] (request) or [30, 62] (response).
	// https://github.com/klzgrad/naiveproxy/#h2-headers-frame-padding
	minReqPaddingHeaderLen  = 16
	maxReqPaddingHeaderLen  = 32
	minRespPaddingHeaderLen = 30
	maxRespPaddingHeaderLen = 62

	// According to the NaiveProxy source code, the first 16 padding characters
	// are randomly selected from paddingHeaderRandChars, and the rest are
	// filled with paddingHeaderFillChar.
	// https://github.com/klzgrad/naiveproxy/blob/0539676ac91d9607caa00869b709e66643b91ac5/src/net/tools/naive/padding_utils.cc#L36
	// https://github.com/klzgrad/naiveproxy/blob/0539676ac91d9607caa00869b709e66643b91ac5/src/net/third_party/quiche/src/quiche/http2/hpack/hpack_constants.cc#L25
	paddingHeaderRandLen  = 16
	paddingHeaderFillChar = 'X'
)

// paddingHeaderRandChars is the ASCII set the random prefix of the "Padding"
// header is drawn from.
var paddingHeaderRandChars = []byte(`!"#$&'()*+,;<>?@`)

// generatePaddingHeader builds a random "Padding" header value that
// randomizes the size of the initial HEADERS frame of a request or response.
// https://github.com/klzgrad/naiveproxy#opt-in-of-padding-protocol
func generatePaddingHeader(request bool) string {
	minLen, maxLen := minRespPaddingHeaderLen, maxRespPaddingHeaderLen
	if request {
		minLen, maxLen = minReqPaddingHeaderLen, maxReqPaddingHeaderLen
	}
	length := minLen + rand.N(maxLen-minLen+1)
	buf := make([]byte, length)
	for i := range paddingHeaderRandLen {
		buf[i] = paddingHeaderRandChars[rand.N(len(paddingHeaderRandChars))]
	}
	for i := paddingHeaderRandLen; i < length; i++ {
		buf[i] = paddingHeaderFillChar
	}
	return string(buf)
}

func basicAuthToken(password *conf.Password) string {
	return base64.StdEncoding.EncodeToString([]byte(passwordutil.DefaultUsername + ":" + AuthPassword(password)))
}

func AuthPassword(password *conf.Password) string {
	return passwordutil.DeriveBase64(password[:], "hg/naiveproxy/auth-password/v1")
}
