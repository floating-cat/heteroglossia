package direct

import (
	"context"
	"net"

	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type client struct{}

var Client transport.Client = new(client)

func (*client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	return netutil.DialTCP(ctx, addr.ToHostStr())
}
