package tr_carrier

import (
	"net/http"
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/floating-cat/heteroglossia/util/testutil"
	"github.com/shoenig/test/must"
)

func TestTRClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newTRClient, NewServer)
}

// A request with invalid protocols should be served the fallback site
// as if the server were a normal HTTPS server.
func TestTRServerServesFallbackHomePageOverHTTPS(t *testing.T) {
	hg := testutil.StartTestServer(t, NewServer)
	url := "https://" + netutil.JoinHostPort(hg.Host, hg.TLSPort)

	// The TLS listener advertises ALPN "h2" and "http/1.1", so verify both are
	// served (HTTP/2 relies on the fallback server speaking cleartext HTTP/2).
	t.Run("HTTP/1.1", func(t *testing.T) {
		httpClient := newHTTPSClientWithCert(t, hg, false)
		testutil.TestRequestSuccess(t, httpClient, url)
	})

	t.Run("HTTP/2", func(t *testing.T) {
		httpClient := newHTTPSClientWithCert(t, hg, true)
		testutil.TestRequestSuccess(t, httpClient, url)
	})
}

func newTRClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return NewClient(proxyNode, false)
}

func newHTTPSClientWithCert(t *testing.T, hg *conf.Hg, forceHTTP2 bool) *http.Client {
	proxyNode := &conf.ProxyNode{Host: hg.Host, TLSCustomCertFile: hg.TLSCertKeyPair.CertFile}
	tlsConfig, err := netutil.TLSClientConfig(proxyNode.Host, proxyNode.TLSCustomCertFile, false, false)
	must.NoError(t, err)
	return netutil.HTTPClient(&http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: forceHTTP2})
}
