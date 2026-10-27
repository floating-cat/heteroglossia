package testutil

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/shoenig/test/must"
)

type newClientFunc func(proxyNode *conf.ProxyNode) (transport.Client, error)
type newServerFunc func(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) transport.Server

func TestClientServerConnection(t *testing.T, newClient newClientFunc, newServer newServerFunc) {
	t.Helper()
	hg := startTestServer(t, newServer)
	client, err := newClient(toProxyNode(hg))
	must.NoError(t, err)

	server := startHTTPServer()
	defer server.Close()
	httpClient := transport.HTTPClientThroughRouter(client)
	testRequestSuccess(t, httpClient, server.URL)
}

// TestServerServesFallbackWithWrongProtocol A request with invalid protocols
// should be served the fallback site as if the server were a normal HTTPS
// server.
func TestServerServesFallbackWithWrongProtocol(t *testing.T, newServer newServerFunc) {
	t.Helper()
	hg := startTestServer(t, newServer)
	addr := "https://" + netutil.JoinHostPort(hg.Host, hg.TLSPort)

	tlsConfig, err := netutil.TLSClientConfig(hg.Host, hg.TLSCertKeyPair.CertFile, false, false)
	must.NoError(t, err)
	tr := netutil.NewHTTPTransport()
	tr.TLSClientConfig = tlsConfig
	httpClient := netutil.NewHTTPClient(tr)

	testRequestSuccess(t, httpClient, addr)
}

// TestServerRejectsPlainHTTP A plain HTTP request sent to the TLS port should
// get the 400 response that net/http's HTTPS server sends, as if the server
// were a normal HTTPS server.
func TestServerRejectsPlainHTTP(t *testing.T, newServer newServerFunc) {
	t.Helper()
	hg := startTestServer(t, newServer)
	addr := "http://" + netutil.JoinHostPort(hg.Host, hg.TLSPort)

	resp := testRequest(t, netutil.NewHTTPClient(netutil.NewHTTPTransport()), addr)
	defer func() {
		_ = resp.Body.Close()
	}()

	must.EqOp(t, http.StatusBadRequest, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	must.NoError(t, err)
	must.EqOp(t, "Client sent an HTTP request to an HTTPS server.\n", string(body))
}

// ServeFunc serves a single proxy connection.
type ServeFunc func(ctx context.Context, conn net.Conn) error

// TestHTTPSOCKSServer checks that the proxy server created by newServeFunc,
// which speaks the protocol of proxyScheme, forwards a request only when the
// client sends the authentication info the server requires.
func TestHTTPSOCKSServer(t *testing.T, proxyScheme string,
	newServeFunc func(authInfo *conf.HTTPSOCKSAuthInfo) ServeFunc) {
	t.Helper()
	httpServer := startHTTPServer()
	defer httpServer.Close()
	// An HTTP proxy server forwards a request to the HTTP server, but
	// tunnels a request to an HTTPS server after a CONNECT request.
	httpsServer := startHTTPSServer()
	defer httpsServer.Close()

	noAuthInfo := &conf.HTTPSOCKSAuthInfo{}
	authInfo := &conf.HTTPSOCKSAuthInfo{Username: "username", Password: "password"}
	user := url.UserPassword("username", "password")
	wrongUser := url.UserPassword("username", "password1")
	tests := []struct {
		name         string
		serverAuth   *conf.HTTPSOCKSAuthInfo
		clientUser   *url.Userinfo
		targetServer *httptest.Server
		// socksErr is the error a SOCKS5 client gets when the server rejects
		// it, and is empty when the server accepts it. An HTTP client gets a
		// 407 response instead.
		socksErr string
	}{
		{"no auth", noAuthInfo, nil, httpServer, ""},
		{"unneeded auth", noAuthInfo, user, httpServer, ""},
		{"correct auth", authInfo, user, httpServer, ""},
		{"correct auth with HTTPS", authInfo, user, httpsServer, ""},
		{"missing auth", authInfo, nil, httpServer, "no acceptable authentication methods"},
		{"wrong auth", authInfo, wrongUser, httpServer, "username/password authentication failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyAddr := StartProxyServer(t, newServeFunc(tt.serverAuth))
			proxyURL := &url.URL{Scheme: proxyScheme, User: tt.clientUser, Host: proxyAddr}
			resp, err := requestThroughProxy(proxyURL, tt.targetServer)
			if err == nil {
				_ = resp.Body.Close()
			}

			switch {
			case tt.socksErr == "":
				must.NoError(t, err)
				must.EqOp(t, http.StatusNoContent, resp.StatusCode)
			case proxyScheme == "http":
				must.NoError(t, err)
				must.EqOp(t, http.StatusProxyAuthRequired, resp.StatusCode)
				must.EqOp(t, "Basic", resp.Header.Get("Proxy-Authenticate"))
			default:
				must.ErrorContains(t, err, tt.socksErr)
			}
		})
	}
}
