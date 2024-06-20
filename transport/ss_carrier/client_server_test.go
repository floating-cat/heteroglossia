package ss_carrier

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/testutil"
)

func TestClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newClient, NewServer)
}

func newClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return NewClient(proxyNode), nil
}
