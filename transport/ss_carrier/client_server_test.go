package ss_carrier

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/util/testutil"
)

func TestSSClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newClient, newServer)
}

func newClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return NewClient(proxyNode), nil
}

func newServer(hg *conf.Hg, targetClient transport.Client, _ *fallback_http.Server) transport.Server {
	return NewServer(hg, targetClient)
}
