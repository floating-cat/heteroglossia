package http

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/util/testutil"
)

func TestHTTPServer(t *testing.T) {
	testutil.TestHTTPSOCKSServer(t, "http", newServeFunc)
}

func newServeFunc(authInfo *conf.HTTPSOCKSAuthInfo) testutil.ServeFunc {
	return NewServer(authInfo, direct.Client).Serve
}
