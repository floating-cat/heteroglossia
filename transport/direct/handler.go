package direct

import (
	"io"
	"net"

	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type Handler struct{}

var _ transport.ConnectionContinuationHandler = new(Handler)

func (_ *Handler) CreateConnection(accessAddr *transport.SocketAddress) (net.Conn, error) {
	return netutil.DialTCP(accessAddr.ToHostStr())
}

func (h *Handler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	targetConn, err := h.CreateConnection(accessAddr)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(targetConn)
	return ioutil.Pipe(srcRWC, targetConn)
}
