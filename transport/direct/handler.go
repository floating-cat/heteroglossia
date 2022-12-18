package direct

import (
	"io"
	"net"

	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type TCPReplayHandler struct{}

func (_ *TCPReplayHandler) CreateConnection(accessAddr *transport.SocketAddress) (net.Conn, error) {
	return netutil.DialTCP(accessAddr.ToHostStr())
}

func (handler *TCPReplayHandler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	targetConn, err := handler.CreateConnection(accessAddr)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(targetConn)
	return ioutil.Pipe(srcRWC, targetConn)
}
