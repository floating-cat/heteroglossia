package testutil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/shoenig/test/must"
)

func TestClientServerConnection(t *testing.T,
	newClient func(proxyNode *conf.ProxyNode) (transport.Client, error),
	newServer func(hg *conf.Hg, targetClient transport.Client) transport.Server) {
	t.Helper()
	hg := StartTestServer(t, newServer)
	client, err := newClient(ToProxyNode(hg))
	must.NoError(t, err)

	server := startWebServer()
	defer server.Close()
	httpClient := transport.HTTPClientThroughRouter(client)
	TestRequestSuccess(t, httpClient, server.URL)
}

func StartTestServer(t *testing.T,
	newServer func(hg *conf.Hg, targetClient transport.Client) transport.Server) *conf.Hg {
	t.Helper()
	serverConf, err := conf.Parse("../../server_example.conf.json", "../../domain-ip-set-rules-sample.db")
	must.NoError(t, err)
	hg := serverConf.Inbounds.Hg
	must.NotNil(t, hg)

	ctx, cancel := context.WithCancel(t.Context())
	serverErr := make(chan error, 1)
	go func() {
		server := newServer(hg, direct.Client)
		serverErr <- server.ListenAndServe(ctx)
	}()
	// Tests in one package share the fixed server port from the config file,
	// so wait for the server to shut down and release its port before the
	// next test starts
	t.Cleanup(func() {
		cancel()
		must.NoError(t, <-serverErr)
	})
	return hg
}

func TestRequestSuccess(t *testing.T, client *http.Client, url string) {
	t.Helper()
	// sleep briefly for the server to start up
	time.Sleep(10 * time.Millisecond)
	resp, err := client.Get(url)
	must.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	must.Between(t, 200, resp.StatusCode, 299)
}

func startWebServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(handler)
}

func ToProxyNode(hg *conf.Hg) *conf.ProxyNode {
	return &conf.ProxyNode{
		Host:              hg.Host,
		Password:          hg.Password,
		TCPPort:           hg.TCPPort,
		TLSPort:           hg.TLSPort,
		TLSCustomCertFile: hg.TLSCertKeyPair.CertFile,
		QUICPort:          hg.QUICPort,
	}
}
