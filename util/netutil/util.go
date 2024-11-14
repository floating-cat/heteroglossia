package netutil

import (
	"net"
	"net/http"
	"time"
)

var (
	// https://github.com/golang/go/issues/62254
	// https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
	// Linux uses 7200sec for tcp_keepalive_time by default, but we use a smaller value
	// Linux uses 75sec for tcp_keepalive_intvl by default so we use the same value

	IdleTimeout     = 720 * time.Second
	Interval        = 75 * time.Second
	KeepAliveConfig = net.KeepAliveConfig{Enable: true, Idle: IdleTimeout, Interval: Interval}

	httpClientTimeout = 60 * time.Second
)

func HTTPClient(tr *http.Transport) *http.Client {
	return &http.Client{Transport: tr, Timeout: httpClientTimeout}
}
