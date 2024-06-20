package tu_carrier

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
	return NewClient(test.ToProxyNode(serverConf.Inbounds.Hg), false)
}
