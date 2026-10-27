package netutil

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/floating-cat/heteroglossia/util/strutil"
	"github.com/quic-go/quic-go"
)

const (
	IPv4Localhost        = "127.0.0.1"
	IPv4LocalhostAnyPort = "127.0.0.1:0"
)

var (
	// Linux uses 7200sec for tcp_keepalive_time, 75sec for tcp_keepalive_intvl,
	// but we use much shorter times.
	// https://github.com/golang/go/issues/62254
	// https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt

	keepAliveIdleTimeout = 120 * time.Second
	keepAliveInterval    = 30 * time.Second
	keepAliveConfig      = net.KeepAliveConfig{Enable: true, Idle: keepAliveIdleTimeout, Interval: keepAliveInterval}

	dialerTimeout     = 15 * time.Second
	httpClientTimeout = 120 * time.Second

	httpReadHeaderTimeout         = 15 * time.Second
	httpClientTLSHandshakeTimeout = 10 * time.Second
	httpClientIdleConnTimeout     = 2 * time.Minute
	httpServerIdleTimeout         = 5 * time.Minute

	quicMaxIdleTimeout = 60 * time.Second
)

func NewHTTPClient(tr *http.Transport) *http.Client {
	return &http.Client{Transport: tr, Timeout: httpClientTimeout}
}

func NewHTTPServer(ctx context.Context, connContext func(ctx context.Context, c net.Conn) context.Context,
	handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpServerIdleTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext:       connContext,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          200,
			MaxReceiveBufferPerConnection: 30 << 20, // 30 MB
			MaxReceiveBufferPerStream:     2 << 20,  // 2 MB
			SendPingTimeout:               keepAliveInterval,
		},
	}
}

func newUnencryptedHTTPServer(ctx context.Context, handler http.Handler) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpServerIdleTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Protocols:         protocols,
	}
}

func NewHTTPTransport() *http.Transport {
	return &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		IdleConnTimeout:       httpClientIdleConnTimeout,
		TLSHandshakeTimeout:   httpClientTLSHandshakeTimeout,
		ResponseHeaderTimeout: httpReadHeaderTimeout,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: keepAliveInterval,
		},
	}
}

// newQUICConfig can't be reused
func newQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           dialerTimeout,
		MaxIdleTimeout:                 quicMaxIdleTimeout,
		KeepAlivePeriod:                keepAliveInterval,
		MaxIncomingStreams:             200,
		InitialStreamReceiveWindow:     1 << 20,  // 1 MB
		MaxStreamReceiveWindow:         12 << 20, // 12 MB
		InitialConnectionReceiveWindow: 1 << 20,  // 1 MB
		MaxConnectionReceiveWindow:     30 << 20, // 30 MB
		Allow0RTT:                      true,
	}
}

func JoinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strutil.ToA(port))
}
