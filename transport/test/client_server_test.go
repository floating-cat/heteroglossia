package test

import (
	"net/http"
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/ss_carrier"
	"github.com/floating-cat/heteroglossia/transport/tr_carrier"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/floating-cat/heteroglossia/util/strutil"
	"github.com/floating-cat/heteroglossia/util/testutil"
	"github.com/shoenig/test/must"
)

// put all transport client & server connection tests in the same package
// since they share the same configuration with fixed server port

func TestTRClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newTRClient, tr_carrier.NewServer)
}

// a request with invalid protocols should be served the fallback site
// as if the server were a normal HTTPS server
func TestTRServerServesFallbackHomePageOverHTTPS(t *testing.T) {
	hg := testutil.StartTestServer(t, tr_carrier.NewServer)
	httpClient := newHTTPSClientWithCert(t, hg)
	url := "https://" + hg.Host + ":" + strutil.ToA(hg.TLSPort)
	testutil.TestRequestSuccess(t, httpClient, url)
}

func TestSSClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newSSClient, ss_carrier.NewServer)
}

func newTRClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return tr_carrier.NewClient(proxyNode, false)
}
func newSSClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return ss_carrier.NewClient(proxyNode), nil
}

func newHTTPSClientWithCert(t *testing.T, hg *conf.Hg) *http.Client {
	proxyNode := &conf.ProxyNode{Host: hg.Host, TLSCustomCertFile: hg.TLSCertKeyPair.CertFile}
	tlsConfig, err := netutil.TLSClientConfig(proxyNode, false)
	must.NoError(t, err)
	return netutil.HTTPClient(&http.Transport{TLSClientConfig: tlsConfig})
}
