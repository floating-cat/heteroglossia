package np_carrier

import (
	"io"
	"net"
	"net/http"
	"time"

	"github.com/floating-cat/heteroglossia/util/ioutil"
)

// conn adapts a NaiveProxy CONNECT stream (a read side, a write side and
// optional close hooks) into a net.Conn, applying the payload padding in both
// directions when the peer opted into it.
type conn struct {
	r          io.Reader
	w          io.Writer
	closeFn    func() error
	closeWrite func() error
	localAddr  net.Addr
	remoteAddr net.Addr
}

var _ net.Conn = (*conn)(nil)
var _ ioutil.CloseWriter = (*conn)(nil)

func newConn(r io.Reader, w io.Writer, padding bool, closeFn, closeWrite func() error, local, remote net.Addr) *conn {
	if padding {
		r = &paddingReader{r: r}
		w = &paddingWriter{w: w}
	}
	return &conn{
		r:          r,
		w:          w,
		closeFn:    closeFn,
		closeWrite: closeWrite,
		localAddr:  local,
		remoteAddr: remote,
	}
}

func (c *conn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *conn) Write(p []byte) (n int, err error) {
	return c.w.Write(p)
}

func (c *conn) Close() error {
	if c.closeFn == nil {
		return nil
	}
	return c.closeFn()
}

func (c *conn) CloseWrite() error {
	if c.closeWrite == nil {
		return nil
	}
	return c.closeWrite()
}

func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// Deadlines are no-ops. The client's HTTP/2 stream has none to set, and nothing
// sets them on the server's one, although http.ResponseController supports
// that. Transport and connection timeouts handle liveness instead.

func (c *conn) SetDeadline(time.Time) error      { return nil }
func (c *conn) SetReadDeadline(time.Time) error  { return nil }
func (c *conn) SetWriteDeadline(time.Time) error { return nil }

// flushWriter flushes the HTTP/2 response after every write so tunneled bytes
// are delivered immediately instead of being buffered.
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, fw.rc.Flush()
}

type tcpStringAddr struct {
	addr string
}

func (a tcpStringAddr) Network() string { return "tcp" }
func (a tcpStringAddr) String() string  { return a.addr }
