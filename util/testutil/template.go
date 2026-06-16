package testutil

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/stretchr/testify/assert"
)

func TestClientServerConnection(t *testing.T, newClient func(proxyNode *conf.ProxyNode) (transport.Client, error),
	newServer func(hg *conf.Hg, targetClient transport.Client) transport.Server) {
	hg, err := newHg()
	assert.Nil(t, err)
	assert.NotNil(t, hg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		server := newServer(hg, direct.NewClient())
		err := server.ListenAndServe(ctx)
		assert.Nil(t, err)
	}()
	client, err := newClient(toProxyNode(hg))
	assert.Nil(t, err)

	server := startWebServer()
	defer server.Close()
	httpClient := transport.HTTPClientThroughRouter(client)
	resp, err := httpClient.Get(server.URL)
	defer func() { _ = resp.Body.Close() }()

	assert.Nil(t, err)
	assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 300)
}

func startWebServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(handler)
}

func newHg() (*conf.Hg, error) {
	// need to change the current working directory to the project root for the config to work.
	// https://stackoverflow.com/a/58294680
	_, filename, _, _ := runtime.Caller(0)
	err := os.Chdir(filepath.Join(filepath.Dir(filename), "../.."))
	if err != nil {
		return nil, err
	}

	bs, err := ioutil.ReadFile("server_example.conf.json")
	if err != nil {
		return nil, err
	}

	config := &conf.Config{}
	err = json.Unmarshal(bs, config)
	if err != nil {
		return nil, err
	}
	return config.Inbounds.Hg, nil
}

func toProxyNode(hg *conf.Hg) *conf.ProxyNode {
	return &conf.ProxyNode{
		Host:        hg.Host,
		Password:    hg.Password,
		TCPPort:     hg.TCPPort,
		TLSPort:     hg.TLSPort,
		TLSCertFile: hg.TLSCertKeyPair.CertFile,
		QUICPort:    hg.QUICPort,
	}
}
