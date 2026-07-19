package netutil

import (
	"net"
	"net/http"
	"time"

	"github.com/floating-cat/heteroglossia/util/strutil"
)

var (
	// https://github.com/golang/go/issues/62254
	// https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
	// Linux uses 7200sec for tcp_keepalive_time, 75sec for tcp_keepalive_intvl by default,
	// but we use much smaller values

	KeepAliveIdleTimeout = 120 * time.Second
	KeepAliveInterval    = 30 * time.Second
	KeepAliveConfig      = net.KeepAliveConfig{Enable: true, Idle: KeepAliveIdleTimeout, Interval: KeepAliveInterval}

	httpClientTimeout = 60 * time.Second
)

func HTTPClient(tr *http.Transport) *http.Client {
	return &http.Client{Transport: tr, Timeout: httpClientTimeout}
}

func JoinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strutil.ToA(port))
}
