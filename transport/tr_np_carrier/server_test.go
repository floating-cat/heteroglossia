package tr_np_carrier

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/transport/np_carrier"
	"github.com/floating-cat/heteroglossia/transport/tr_carrier"
	"github.com/floating-cat/heteroglossia/util/testutil"
)

func TestTRNPClientServerConnection(t *testing.T) {
	t.Run("Trojan", func(t *testing.T) {
		testutil.TestClientServerConnection(t, newTRClient, newServer)
	})

	t.Run("NaiveProxy", func(t *testing.T) {
		testutil.TestClientServerConnection(t, newNPClient, newServer)
	})
}

func TestTRNPServerServesFallbackWithWrongProtocol(t *testing.T) {
	testutil.TestServerServesFallbackWithWrongProtocol(t, newServer)
}

func TestTRNPServerRejectsPlainHTTP(t *testing.T) {
	testutil.TestServerRejectsPlainHTTP(t, newServer)
}

func newTRClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return tr_carrier.NewClient(proxyNode, false)
}

func newNPClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return np_carrier.NewClient(proxyNode, false)
}

func newServer(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) transport.Server {
	return NewServer(hg, targetClient, fallbackHttpServer)
}
