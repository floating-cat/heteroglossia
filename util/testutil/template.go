package testutil

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/shoenig/test/must"
)

func TestClientServerConnection(t *testing.T,
	newClient func(proxyNode *conf.ProxyNode) (transport.Client, error),
	newServer func(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) transport.Server) {
	t.Helper()
	hg := startTestServer(t, newServer)
	client, err := newClient(toProxyNode(hg))
	must.NoError(t, err)

	server := startWebServer()
	defer server.Close()
	httpClient := transport.HTTPClientThroughRouter(client)
	testRequestSuccess(t, httpClient, server.URL)
}

// TestServerServesFallbackWithWrongProtocol A request with invalid protocols
// should be served the fallback site as if the server were a normal HTTPS
// server.
func TestServerServesFallbackWithWrongProtocol(t *testing.T,
	newServer func(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) transport.Server) {
	t.Helper()
	t.Helper()
	hg := startTestServer(t, newServer)
	url := "https://" + netutil.JoinHostPort(hg.Host, hg.TLSPort)

	tlsConfig, err := netutil.TLSClientConfig(hg.Host, hg.TLSCertKeyPair.CertFile, false, false)
	must.NoError(t, err)
	tr := netutil.NewHTTPTransport()
	tr.TLSClientConfig = tlsConfig
	httpClient := netutil.NewHTTPClient(tr)

	testRequestSuccess(t, httpClient, url)
}
