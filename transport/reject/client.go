package reject

import (
	"context"
	"net"

	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
)

type Client struct{}

var _ transport.Client = new(Client)
var rejectedErr = errors.New("rejected")

func (_ *Client) Dial(_ context.Context, _ string, _ *transport.SocketAddress) (net.Conn, error) {
	return nil, rejectedErr
}
