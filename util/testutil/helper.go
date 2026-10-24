package testutil

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/shoenig/test/must"
)

func startTestServer(t *testing.T, newServer newServerFunc) *conf.Hg {
	t.Helper()
	serverConf, err := conf.Parse("../../server_example.conf.json", "../../domain-ip-set-rules-sample.db")
	must.NoError(t, err)
	hg := serverConf.Inbounds.Hg
	must.NotNil(t, hg)
	useFreePorts(t, hg)

	ctx, cancel := context.WithCancel(t.Context())
	serverErr := make(chan error, 1)
	go func() {
		targetClient := direct.Client
		fallbackHttpServer, err := fallback_http.Start(ctx, hg, targetClient)
		if err != nil {
			serverErr <- err
		} else {
			server := newServer(hg, targetClient, fallbackHttpServer)
			serverErr <- server.ListenAndServe(ctx)
		}
	}()
	// Wait for the server to shut down, so it doesn't outlive the test and its
	// error is still checked.
	t.Cleanup(func() {
		cancel()
		must.NoError(t, <-serverErr)
	})
	return hg
}

var noContentHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
})

func startHTTPServer() *httptest.Server {
	return httptest.NewServer(noContentHandler)
}

func startHTTPSServer() *httptest.Server {
	return httptest.NewTLSServer(noContentHandler)
}

// startProxyServer serves every connection to a free local port with serve,
// and returns the address of that port.
func startProxyServer(t *testing.T, serve ServeFunc) string {
	t.Helper()
	ctx := t.Context()
	listenAddr := make(chan string, 1)
	listenErr := make(chan error, 1)
	go func() {
		listenErr <- netutil.ListenTCPAndServeWithListenerCallback(ctx,
			netutil.JoinHostPort(netutil.IPv4Localhost, 0),
			func(conn *net.TCPConn) {
				_ = serve(ctx, conn)
				_ = conn.Close()
			},
			func(ln net.Listener) {
				listenAddr <- ln.Addr().String()
			}, nil)
	}()

	select {
	case addr := <-listenAddr:
		// ctx is canceled before the cleanup runs, which stops the server, so
		// wait for the server to stop and check its error.
		t.Cleanup(func() {
			must.NoError(t, <-listenErr)
		})
		return addr
	case err := <-listenErr:
		must.NoError(t, err)
		return ""
	}
}

// requestThroughProxy sends a GET request to HTTP server through proxyURL, and
// returns the response.
func requestThroughProxy(proxyURL *url.URL, httpServer *httptest.Server) (*http.Response, error) {
	tr := netutil.NewHTTPTransport()
	tr.Proxy = http.ProxyURL(proxyURL)
	// trust the certificate of the HTTPS server
	tr.TLSClientConfig = httpServer.Client().Transport.(*http.Transport).TLSClientConfig
	// close the connection after the request, so the proxy server's handler
	// returns instead of waiting for the next request
	tr.DisableKeepAlives = true
	return netutil.NewHTTPClient(tr).Get(httpServer.URL)
}

func testRequest(t *testing.T, client *http.Client, addr string) *http.Response {
	t.Helper()
	// sleep briefly for the server to start up
	time.Sleep(20 * time.Millisecond)
	resp, err := client.Get(addr)
	must.NoError(t, err)
	return resp
}

func testRequestSuccess(t *testing.T, client *http.Client, addr string) {
	t.Helper()
	resp := testRequest(t, client, addr)
	_ = resp.Body.Close()
	must.Between(t, 200, resp.StatusCode, 299)
}

// useFreePorts replaces the fixed ports from the example config with free
// ones, so test packages that go test runs in parallel don't collide on them.
func useFreePorts(t *testing.T, hg *conf.Hg) {
	t.Helper()
	tcpPorts := freeTCPPorts(t, 2)
	hg.TCPPort = &tcpPorts[0]
	hg.TLSPort = tcpPorts[1]
	hg.QUICPort = freeUDPPort(t)
}

func freeTCPPorts(t *testing.T, n int) []uint16 {
	t.Helper()
	ports := make([]uint16, n)
	for i := range ports {
		ln, err := net.Listen("tcp", ":0")
		must.NoError(t, err)
		// Close all listeners only after every port has been picked, so the OS
		// is unlikely to assign the same port twice.
		//goland:noinspection GoDeferInLoop
		defer func(ln net.Listener) {
			_ = ln.Close()
		}(ln)
		ports[i] = uint16(ln.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp", ":0")
	must.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func toProxyNode(hg *conf.Hg) *conf.ProxyNode {
	return &conf.ProxyNode{
		Host:              hg.Host,
		Password:          hg.Password,
		TCPPort:           hg.TCPPort,
		TLSPort:           hg.TLSPort,
		TLSCustomCertFile: hg.TLSCertKeyPair.CertFile,
		QUICPort:          hg.QUICPort,
	}
}
