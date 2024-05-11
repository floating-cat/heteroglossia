package tr_carrier

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/test"
)

func TestClientServerConnection(t *testing.T) {
	test.TestClientServerConnection(t, newClient, NewServer)
}

func newClient(serverConf *conf.Config) (transport.Client, error) {
	return NewClient(toProxyNode(serverConf.Inbounds.Hg), false)
}

func toProxyNode(hg *conf.Hg) *conf.ProxyNode {
	return &conf.ProxyNode{
		Host:        hg.Host,
		Password:    hg.Password,
		TLSPort:     hg.TLSPort,
		TLSCertFile: hg.TLSCertKeyPair.CertFile,
	}
}
