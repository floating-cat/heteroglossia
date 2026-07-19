package netutil

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/quic-go/quic-go"
)

var (
	listenConfig   = net.ListenConfig{KeepAliveConfig: KeepAliveConfig}
	serverListener = sync.Map{}

	httpReadTimeout  = 10 * time.Second
	httpWriteTimeout = 10 * time.Second
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
	if errors.IsNetErrClosedOrContextCanceled(err) {
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

func ListenHTTPAndServe(ctx context.Context, addr string, httpHandler http.Handler) error {
	return ListenHTTPAndServeWithListenerCallback(ctx, addr, httpHandler, nil)
}

func ListenHTTPAndServeWithListenerCallback(ctx context.Context, addr string,
	httpHandler http.Handler, listenerCallback func(ln net.Listener)) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		if listenerCallback != nil {
			listenerCallback(ln)
		}
		server := &http.Server{
			Handler:      httpHandler,
			ReadTimeout:  httpReadTimeout,
			WriteTimeout: httpWriteTimeout,
		}
		return server.Serve(ln)
	}, nil)
}

func ListenTLSAndAccept(ctx context.Context, addr string, tlsConfig *tls.Config,
	connHandler func(conn net.Conn)) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		tlsLn := tls.NewListener(ln, tlsConfig)
		return acceptNetConn(tlsLn, connHandler)
	}, nil)
}

func ListenQUICAndServe(ctx context.Context, addr string, tlsConf *tls.Config,
	connHandler func(quicConn *quic.Conn)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// https://quic-go.net/docs/quic/server/
	// closing the listener associated with a Transport doesn’t
	// close QUIC connections accepted from this listener
	conn, err := listenConfig.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return errors.WithStack(err)
	}

	// Transport.Close closes the underlying packet connection, so we don't close
	// conn separately once the transport owns it.
	tr := &quic.Transport{Conn: conn}
	ln, err := tr.Listen(tlsConf, newQUICConfig())
	if err != nil {
		_ = tr.Close()
		return errors.WithStack(err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = tr.Close()
	}()
	addServerListener(ln)
	defer func() {
		removeServerListener(ln)
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.IsNetErrClosedOrContextCanceled(err) {
				return nil
			}
			return errors.WithStack(err)
		}

		go connHandler(conn)
	}
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
