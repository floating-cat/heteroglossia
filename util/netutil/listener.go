package netutil

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/quic-go/quic-go"
)

var (
	listenConfig   = net.ListenConfig{KeepAliveConfig: keepAliveConfig}
	serverListener = sync.Map{}
)

func listenTCPAndAccept(ctx context.Context, addr string,
	listenHandler func(ln net.Listener) error, listenFinishedCallback func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// https://github.com/golang/go/issues/28120
	// ctx in Listen func doesn't cancel listener,
	// so we use cancel() with ln.Close() to close
	ln, err := listenConfig.Listen(ctx, "tcp", addr)
	if err != nil {
		return errors.WithStack(err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	addServerListener(ln)
	defer func() {
		removeServerListener(ln)
		if listenFinishedCallback != nil {
			listenFinishedCallback()
		}
	}()

	err = listenHandler(ln)
	if errors.IsErrClosedOrContextCanceled(err) {
		return nil
	}
	return err
}

func ListenTCPAndServe(ctx context.Context, addr string, connHandler func(tcpConn *net.TCPConn)) error {
	return ListenTCPAndServeWithListenerCallback(ctx, addr, connHandler, nil, nil)
}

func ListenTCPAndServeWithListenerCallback(ctx context.Context, addr string,
	connHandler func(tcpConn *net.TCPConn), listenSuccessCallback func(ln net.Listener), listenFinishedCallback func()) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		if listenSuccessCallback != nil {
			listenSuccessCallback(ln)
		}
		return acceptNetConn(ln, func(conn net.Conn) {
			connHandler(conn.(*net.TCPConn))
		})
	}, listenFinishedCallback)
}

func ListenUnencryptedHTTPAndServe(ctx context.Context, addr string, httpHandler http.Handler) error {
	return ListenUnencryptedHTTPAndServeWithListenerCallback(ctx, addr, httpHandler, nil)
}

func ListenUnencryptedHTTPAndServeWithListenerCallback(ctx context.Context, addr string,
	httpHandler http.Handler, listenerCallback func(ln net.Listener)) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		if listenerCallback != nil {
			listenerCallback(ln)
		}
		server := NewUnencryptedHTTPServer(ctx, httpHandler)
		return server.Serve(ln)
	}, nil)
}

func ListenTLSAndAccept(ctx context.Context, addr string, tlsConfig *tls.Config,
	connHandler func(conn *tls.Conn)) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		tlsLn := tls.NewListener(ln, tlsConfig)
		return acceptNetConn(tlsLn, func(conn net.Conn) {
			connHandler(conn.(*tls.Conn))
		})
	}, nil)
}

func ListenTLSAndServe(ctx context.Context, addr string, tlsConfig *tls.Config, server *http.Server) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		return server.Serve(tls.NewListener(ln, tlsConfig))
	}, nil)
}

func ListenQUICEarlyAndServe(ctx context.Context, addr string, tlsConf *tls.Config,
	statelessResetKey *quic.StatelessResetKey, connHandler func(quicConn *quic.Conn)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// https://quic-go.net/docs/quic/server/
	// Closing the listener associated with Transport doesn’t
	// close QUIC connections accepted from this listener.
	conn, err := listenConfig.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return errors.WithStack(err)
	}

	// Transport.Close doesn't close a packet connection it didn't create, so we
	// close conn ourselves to release the UDP port.
	tr := &quic.Transport{Conn: conn, StatelessResetKey: statelessResetKey}
	// https://quic-go.net/docs/quic/server/#0-rtt
	ln, err := tr.ListenEarly(tlsConf, newQUICConfig())
	if err != nil {
		_ = tr.Close()
		_ = conn.Close()
		return errors.WithStack(err)
	}
	closer := &quicServerCloser{conn, tr, ln}
	go func() {
		<-ctx.Done()
		_ = closer.Close()
	}()
	// Register the closer rather than ln, so StopAllServerListeners returns
	// only after the UDP port is released.
	addServerListener(closer)
	defer func() {
		removeServerListener(closer)
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.IsErrClosedOrContextCanceled(err) {
				return nil
			}
			return errors.WithStack(err)
		}

		go connHandler(conn)
	}
}

type quicServerCloser struct {
	conn net.PacketConn
	tr   *quic.Transport
	ln   *quic.EarlyListener
}

func (c *quicServerCloser) Close() error {
	_ = c.ln.Close()
	_ = c.tr.Close()
	return c.conn.Close()
}

func StopAllServerListeners() {
	serverListener.Range(func(key, value any) bool {
		_ = key.(io.Closer).Close()
		return true
	})
}

func addServerListener(listenerCloser io.Closer) {
	serverListener.Store(listenerCloser, struct{}{})
}

func removeServerListener(listenerCloser io.Closer) {
	serverListener.Delete(listenerCloser)
}

func acceptNetConn(ln net.Listener, connHandler func(conn net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return errors.WithStack(err)
		}

		go connHandler(conn)
	}
}

// ConnListener is a net.Listener that accepts the connections handed to Push
// instead of ones from the network, so a server's accept loop can pass
// connections to another server that only serves listeners, such as
// http.Server.
type ConnListener struct {
	conn chan net.Conn
	// ctx is done once l is closed, either by Close or by the parent context
	// passed to NewConnListener being done.
	ctx    context.Context
	cancel context.CancelFunc
}

var _ net.Listener = (*ConnListener)(nil)

// NewConnListener returns a listener that is closed when ctx is done. Close
// must still be called to release it if ctx may never be done.
func NewConnListener(ctx context.Context) *ConnListener {
	ctx, cancel := context.WithCancel(ctx)
	return &ConnListener{conn: make(chan net.Conn), ctx: ctx, cancel: cancel}
}

// Push blocks until conn is accepted from l, or closes conn if l is closed
// first.
func (l *ConnListener) Push(conn net.Conn) {
	select {
	case l.conn <- conn:
	case <-l.ctx.Done():
		_ = conn.Close()
	}
}

func (l *ConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conn:
		return conn, nil
	case <-l.ctx.Done():
		return nil, errors.WithStack(net.ErrClosed)
	}
}

func (l *ConnListener) Close() error {
	l.cancel()
	return nil
}

// Addr returns a placeholder because l isn't bound to an address; each
// connection reports its own addresses.
func (l *ConnListener) Addr() net.Addr {
	return connListenerAddr{}
}

type connListenerAddr struct{}

func (connListenerAddr) Network() string { return "conn" }
func (connListenerAddr) String() string  { return "conn" }
