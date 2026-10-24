package http_socks

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/util/testutil"
)

func TestHTTPSOCKSServer(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		testutil.TestHTTPSOCKSServer(t, "http", newServeFunc)
	})

	t.Run("SOCKS5", func(t *testing.T) {
		testutil.TestHTTPSOCKSServer(t, "socks5", newServeFunc)
	})
}

func newServeFunc(authInfo *conf.HTTPSOCKSAuthInfo) testutil.ServeFunc {
	httpSOCKS := &conf.HTTPSOCKS{Username: authInfo.Username, Password: authInfo.Password}
	return NewServer(httpSOCKS, direct.Client).(*server).serve
}
