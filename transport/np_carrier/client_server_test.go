package np_carrier

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/util/testutil"
)

func TestNPClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newClient, newServer)
}

func TestNPServerServesFallbackWithWrongProtocol(t *testing.T) {
	testutil.TestServerServesFallbackWithWrongProtocol(t, newServer)
}

func TestNPServerRejectsPlainHTTP(t *testing.T) {
	testutil.TestServerRejectsPlainHTTP(t, newServer)
}

func newClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return NewClient(proxyNode, false)
}

func newServer(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) transport.Server {
	return NewServer(hg, targetClient, fallbackHttpServer)
}
