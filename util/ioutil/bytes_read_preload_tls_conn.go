package ioutil

import (
	"crypto/tls"
	"net"
)

// bytesReadPreloadTLSConn is a bytesReadPreloadConn over a TLS connection that
// also exposes its ConnectionState, so net/http still serves HTTP/2 over it
// when "h2" was negotiated by ALPN.
type bytesReadPreloadTLSConn struct {
	*bytesReadPreloadConn
	tlsConn *tls.Conn
}

func NewBytesReadPreloadTLSConn(preloadBs []byte, conn *tls.Conn) net.Conn {
	if len(preloadBs) > 0 {
		return &bytesReadPreloadTLSConn{&bytesReadPreloadConn{preloadBs, conn}, conn}
	}
	return conn
}

func (c *bytesReadPreloadTLSConn) ConnectionState() tls.ConnectionState {
	return c.tlsConn.ConnectionState()
}
