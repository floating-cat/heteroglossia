package netutil

import (
	"net"
	"net/http"
	"time"

	"github.com/floating-cat/heteroglossia/util/strutil"
	"github.com/quic-go/quic-go"
)

var (
	// Linux uses 7200sec for tcp_keepalive_time, 75sec for tcp_keepalive_intvl,
	// but we use much shorter times.
	// https://github.com/golang/go/issues/62254
	// https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt

	KeepAliveIdleTimeout = 120 * time.Second
	KeepAliveInterval    = 30 * time.Second
	KeepAliveConfig      = net.KeepAliveConfig{Enable: true, Idle: KeepAliveIdleTimeout, Interval: KeepAliveInterval}

	dialerTimeout     = 15 * time.Second
	httpClientTimeout = 120 * time.Second

	HTTPReadHeaderTimeout     = 15 * time.Second
	HTTPClientIdleConnTimeout = 2 * time.Minute
	HTTPServerIdleTimeout     = 5 * time.Minute

	quicMaxIdleTimeout = 60 * time.Second
)

func HTTPClient(tr *http.Transport) *http.Client {
	return &http.Client{Transport: tr, Timeout: httpClientTimeout}
}

var HTTP2Config = &http.HTTP2Config{
	MaxConcurrentStreams:          200,
	MaxReceiveBufferPerConnection: 30 << 20, // 30 MB
	MaxReceiveBufferPerStream:     2 << 20,  // 2 MB
}

// newQUICConfig can't be reused
func newQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           dialerTimeout,
		MaxIdleTimeout:                 quicMaxIdleTimeout,
		KeepAlivePeriod:                KeepAliveInterval,
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
