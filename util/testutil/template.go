package testutil

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/shoenig/test/must"
)

func TestClientServerConnection(t *testing.T, newClient func(proxyNode *conf.ProxyNode) (transport.Client, error),
	newServer func(hg *conf.Hg, targetClient transport.Client) transport.Server) {
	serverConf, err := conf.Parse("../../server_example.conf.json", "../../domain-ip-set-rules-sample.db")
	must.NoError(t, err)
	hg := serverConf.Inbounds.Hg
	must.NotNil(t, hg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		server := newServer(hg, direct.NewClient())
		err := server.ListenAndServe(ctx)
		must.NoError(t, err)
	}()
	client, err := newClient(toProxyNode(hg))
	must.NoError(t, err)

	server := startWebServer()
	defer server.Close()
	httpClient := transport.HTTPClientThroughRouter(client)
	resp, err := httpClient.Get(server.URL)
	defer func() { _ = resp.Body.Close() }()

	must.NoError(t, err)
	must.Between(t, 200, resp.StatusCode, 299)
}

func startWebServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(handler)
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
