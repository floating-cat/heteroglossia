package ss_carrier

import (
	"testing"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/testutil"
)

func TestSSClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newSSClient, NewServer)
}

func newSSClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return NewClient(proxyNode), nil
}
