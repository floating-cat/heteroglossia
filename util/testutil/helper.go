package testutil

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/shoenig/test/must"
)

func startTestServer(t *testing.T,
	newServer func(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) transport.Server) *conf.Hg {
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

func startWebServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(handler)
}

func testRequest(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	// sleep briefly for the server to start up
	time.Sleep(20 * time.Millisecond)
	resp, err := client.Get(url)
	must.NoError(t, err)
	return resp
}

func testRequestSuccess(t *testing.T, client *http.Client, url string) {
	t.Helper()
	resp := testRequest(t, client, url)
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
