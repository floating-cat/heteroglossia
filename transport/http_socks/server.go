package http_socks

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/http"
	"github.com/floating-cat/heteroglossia/transport/socks"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/floating-cat/heteroglossia/util/osutil"
	"github.com/floating-cat/heteroglossia/util/proxy"
)

type server struct {
	httpSOCKS *conf.HTTPSOCKS

	http         *http.Server
	socks        *socks.Server
	targetClient transport.Client
}

var _ transport.Server = (*server)(nil)

func NewServer(httpSOCKS *conf.HTTPSOCKS, targetClient transport.Client) transport.Server {
	authInfo := httpSOCKS.ToHTTPSOCKSAuthInfo()
	return &server{
		httpSOCKS,
		http.NewServer(authInfo, targetClient),
		socks.NewServer(authInfo, targetClient),
		targetClient,
	}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	// When one listener returns, cancel the context, so the sibling listener
	// shuts down instead of running unsupervised.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// can't listen to IPv4 & IPv6 together, so also listen to IPv4 one
	// when using '::1' or '::'.
	// https://github.com/golang/go/issues/9334
	host := s.httpSOCKS.Host
	connHandler := func(conn *net.TCPConn) {
		err := s.serve(ctx, conn)
		_ = conn.Close()
		if err != nil && ctx.Err() == nil {
			log.InfoWithError("fail to handle a HTTP/SOCKS request", err)
		}
	}

	var ipv4RequestsHandlerForDualStack func() error
	if host == "::1" {
		ipv4Localhost := netutil.JoinHostPort(netutil.IPv4Localhost, s.httpSOCKS.Port)
		ipv4RequestsHandlerForDualStack = func() error {
			return netutil.ListenTCPAndServe(ctx, ipv4Localhost, connHandler)
		}
	} else if host == "::" {
		// It would listen both IPv4 & IPv6 when using the empty string for host.
		host = ""
	}

	return parRunWithFirstErrReturn(cancel, func() error {
		var unsetProxy func()
		var hasUnsetProxy atomic.Bool
		addr := netutil.JoinHostPort(host, s.httpSOCKS.Port)
		return netutil.ListenTCPAndServeWithListenerCallback(ctx, addr, connHandler, func(net.Listener) {
			if s.httpSOCKS.SystemProxy {
				log.Info("try to set the system proxy")
				// do not use the 'host' variable directly because we changed it for '::'
				var err error
				unsetProxyFunc, err := proxy.SetSystemProxy(s.httpSOCKS.Host, s.httpSOCKS.Port, s.httpSOCKS.ToHTTPSOCKSAuthInfo())
				if err != nil {
					log.WarnWithError("fail to set the system proxy", err)
				}
				if unsetProxyFunc != nil {
					unsetProxy = func() {
						if hasUnsetProxy.CompareAndSwap(false, true) {
							unsetProxyFunc()
						}
					}
					osutil.RegisterProgramTerminationHandler(func() {
						unsetProxy()
					})
				}
			}
		}, func() {
			if unsetProxy != nil {
				unsetProxy()
			}
		})
	}, ipv4RequestsHandlerForDualStack)
}

func (s *server) serve(ctx context.Context, conn net.Conn) error {
	b, err := ioutil.Read1(conn)
	if err != nil {
		return err
	}
	// put the byte back, so the SOCKS or HTTP server can read the whole request
	//goland:noinspection GoResourceLeak
	conn = ioutil.NewBytesReadPreloadConn([]byte{b}, conn)
	switch b {
	case socks.Version4, socks.Version5:
		return s.socks.Serve(ctx, conn)
	default:
		// assume this is an HTTP proxy request
		return s.http.Serve(ctx, conn)
	}
}

func parRunWithFirstErrReturn(cancel context.CancelFunc, f1 func() error, f2 func() error) error {
	if f1 == nil {
		return f2()
	}
	if f2 == nil {
		return f1()
	}

	ch := make(chan error, 2)
	go func() {
		ch <- f1()
	}()
	go func() {
		ch <- f2()
	}()

	err := <-ch
	// Stop the sibling listener so it doesn't keep its socket bound and its
	// goroutine running after the first one has returned.
	cancel()
	// Drain the sibling's result so its goroutine doesn't leak.
	<-ch
	return err
}
