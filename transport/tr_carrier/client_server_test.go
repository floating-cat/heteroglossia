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

// a request with invalid protocols should be served the fallback site
// as if the server were a normal HTTPS server
func TestTRServerServesFallbackHomePageOverHTTPS(t *testing.T) {
	hg := testutil.StartTestServer(t, NewServer)
	httpClient := newHTTPSClientWithCert(t, hg)
	url := "https://" + netutil.JoinHostPort(hg.Host, hg.TLSPort)
	testutil.TestRequestSuccess(t, httpClient, url)
}

func newTRClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return NewClient(proxyNode, false)
}

func newHTTPSClientWithCert(t *testing.T, hg *conf.Hg) *http.Client {
	proxyNode := &conf.ProxyNode{Host: hg.Host, TLSCustomCertFile: hg.TLSCertKeyPair.CertFile}
	tlsConfig, err := netutil.TLSClientConfig(proxyNode.Host, proxyNode.TLSCustomCertFile, false, false)
	must.NoError(t, err)
	return netutil.HTTPClient(&http.Transport{TLSClientConfig: tlsConfig})
}
