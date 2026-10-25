package http_socks

import (
	"cmp"
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
	connHandler := func(conn *net.TCPConn) {
		err := s.serve(ctx, conn)
		_ = conn.Close()
		if err != nil && ctx.Err() == nil {
			log.InfoWithError("fail to handle a HTTP/SOCKS request", err)
		}
	}

	var unsetProxy func()
	var hasUnsetProxy atomic.Bool
	listenHost := s.httpSOCKS.ListenHost
	addr := netutil.JoinHostPort(listenHost, s.httpSOCKS.Port)
	return netutil.ListenTCPAndServeWithListenerCallback(ctx, addr, connHandler, func(net.Listener) {
		if s.httpSOCKS.SystemProxy {
			log.Info("try to set the system proxy")
			unsetProxyFunc, err := proxy.SetSystemProxy(cmp.Or(s.httpSOCKS.ListenHost, netutil.IPv4Localhost), s.httpSOCKS.Port, s.httpSOCKS.ToHTTPSOCKSAuthInfo())
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
