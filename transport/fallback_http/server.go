package fallback_http

import (
	"context"
	"net"
	"net/http"
	"net/netip"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type Server struct {
	tlsBadAuthFallbackSitePort uint16
	httpHandler                http.Handler
	targetClient               transport.Client
}

// Start starts the fallback site on a random loopback port and returns once
// it's listening, so carriers started afterward can forward connections to it.
// The site keeps serving in the background until ctx is done, so unlike
// transport.Server.ListenAndServe, Start doesn't block.
func Start(ctx context.Context, hg *conf.Hg, targetClient transport.Client) (*Server, error) {
	var httpHandler http.Handler
	if hg.TLSBadAuthFallbackSiteDir != "" {
		httpHandler = http.FileServer(http.Dir(hg.TLSBadAuthFallbackSiteDir))
	} else {
		httpHandler = http.NotFoundHandler()
	}
	port := make(chan uint16, 1)
	listenErr := make(chan error, 1)
	go func() {
		listenAddr := netutil.JoinHostPort("127.0.0.1", 0)
		err := netutil.ListenUnencryptedHTTPAndServeWithListenerCallback(ctx, listenAddr, httpHandler, func(ln net.Listener) {
			port <- uint16(ln.Addr().(*net.TCPAddr).Port)
		})
		if err != nil {
			listenErr <- err
		}
	}()

	select {
	case tlsBadAuthFallbackSitePort := <-port:
		return new(Server{tlsBadAuthFallbackSitePort, httpHandler, targetClient}), nil
	case err := <-listenErr:
		return nil, err
	}
}

const policy = "fallback (e.g., wrong protocol or auth)"

func (s *Server) Handle(ctx context.Context, conn net.Conn, inbound string) error {
	ctx = contextutil.WithValues(ctx, contextutil.InboundTag, inbound)
	ctx = contextutil.WithValues(ctx, contextutil.PolicyTag, policy)
	fallbackHost := netip.MustParseAddr(netutil.IPv4Localhost)
	fallbackAddr := transport.NewSocketAddressByIP(&fallbackHost, s.tlsBadAuthFallbackSitePort)
	return transport.ForwardTCP(ctx, fallbackAddr, conn, s.targetClient)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request, targetAddr string, inbound string) {
	log.Info("routing",
		contextutil.SourceTag, r.RemoteAddr,
		contextutil.InboundTag, inbound,
		"access", targetAddr, contextutil.PolicyTag, policy)
	s.httpHandler.ServeHTTP(w, r)
}
