package netutil

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/quic-go/quic-go"
)

var (
	dialer        = net.Dialer{Timeout: dialerTimeout, KeepAliveConfig: KeepAliveConfig}
	dialerTimeout = 10 * time.Second
)

func dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return errors.WithStack2(dialer.DialContext(ctx, network, addr))
}

func DialTCP(ctx context.Context, addr string) (*net.TCPConn, error) {
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func DialTLS(ctx context.Context, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
	//goland:noinspection GoResourceLeak
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.Client(conn, tlsConfig), nil
}

func DialQUIC(ctx context.Context, addr string, tlsConf *tls.Config) (*quic.Conn, error) {
	return errors.WithStack2(quic.DialAddr(ctx, addr, tlsConf, newQUICConfig()))
}

// newQUICConfig can't be reused
func newQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           dialerTimeout,
		MaxIdleTimeout:                 KeepAliveIdleTimeout,
		KeepAlivePeriod:                KeepAliveInterval,
		MaxIncomingStreams:             200,
		InitialStreamReceiveWindow:     1 << 20,        // 1 MB
		MaxStreamReceiveWindow:         12 * (1 << 20), // 12 MB
		InitialConnectionReceiveWindow: 1 * (1 << 20),  // 1 MB
		MaxConnectionReceiveWindow:     30 * (1 << 20), // 30 MB
	}
}
