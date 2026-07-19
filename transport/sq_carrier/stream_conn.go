package sq_carrier

import (
	"net"

	"github.com/quic-go/quic-go"
)

// streamConn adapts a QUIC bistream into a net.Conn. A *quic.Stream already
// provides Read/Write/SetDeadline, but lacks LocalAddr/RemoteAddr, which come
// from the owning connection.
type streamConn struct {
	*quic.Stream
	quicConn *quic.Conn
}

var _ net.Conn = (*streamConn)(nil)

func newStreamConn(stream *quic.Stream, conn *quic.Conn) *streamConn {
	return &streamConn{Stream: stream, quicConn: conn}
}

func (c *streamConn) LocalAddr() net.Addr  { return c.quicConn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.quicConn.RemoteAddr() }

// Close shuts down both directions of the stream. quic.Stream.Close only closes
// the send side and leaves reads pending, so we also cancel the receive side
// to give net.Conn close semantics and unblock any in-flight Read.
func (c *streamConn) Close() error {
	c.Stream.CancelRead(streamConnCloseErrCode)
	return c.Stream.Close()
}
