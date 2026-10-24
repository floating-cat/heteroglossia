package netutil

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/quic-go/quic-go"
)

var dialer = net.Dialer{Timeout: dialerTimeout, KeepAliveConfig: keepAliveConfig}

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

func HandshakeTLS(ctx context.Context, tlsConn *tls.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, dialerTimeout)
	defer cancel()
	return errors.WithStack(tlsConn.HandshakeContext(ctx))
}

// DialQUICEarly dials a QUIC connection with 0-RTT support.
// https://quic-go.net/docs/quic/client/#0-rtt
func DialQUICEarly(ctx context.Context, addr string, tlsConf *tls.Config) (*quic.Conn, error) {
	return errors.WithStack2(quic.DialAddrEarly(ctx, addr, tlsConf, newQUICConfig()))
}
