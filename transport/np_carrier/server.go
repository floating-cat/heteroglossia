package np_carrier

import (
	"context"
	"net"
	"net/http"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type server struct {
	host      string
	port      uint16
	authToken string

	tlsCertKeyPair      *conf.TLSCertKeyPair
	targetClient        transport.Client
	fallbackSiteHandler http.Handler
}

var _ transport.Server = (*server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	s := &server{
		host:           hg.Host,
		port:           hg.TLSPort,
		authToken:      basicAuthToken(hg.Password[:]),
		tlsCertKeyPair: hg.TLSCertKeyPair,
		targetClient:   targetClient,
	}
	if hg.TLSBadAuthFallbackSiteDir != "" {
		s.fallbackSiteHandler = http.FileServer(http.Dir(hg.TLSBadAuthFallbackSiteDir))
	}
	return s
}

func (s *server) ListenAndServe(ctx context.Context) error {
	tlsConfig, err := netutil.TLSServerConfig(s.host, s.tlsCertKeyPair, false)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: netutil.HTTPReadHeaderTimeout,
		IdleTimeout:       netutil.HTTPServerIdleTimeout,
		HTTP2:             netutil.HTTP2Config,
		ErrorLog:          log.NewStdLogger(),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "NaiveProxy carrier")
		},
	}
	return netutil.ListenHTTPSAndServe(ctx, netutil.JoinHostPort(s.host, s.port), tlsConfig, server)
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	// NaiveProxy speaks HTTP/2, but a real web server answers HTTP/1.1 too, so
	// HTTP/1.1 is accepted as well and always gets the fallback site.
	if r.ProtoMajor != 2 ||
		r.Method != http.MethodConnect || !basicAuthEqual(r.Header.Get(proxyAuthHeaderKey), s.authToken) {
		s.serveFallback(w, r)
		return
	}

	// similar logic to transport/http/server/Serve
	targetAddr, err := transport.ToSocketAddr(r.URL.Host, true, 0)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// The padding protocol is opt-in: it's enabled only if the client sends the
	// "Padding" header, and the client in turn enables it only if the response
	// has one.
	padding := r.Header.Get(paddingHeaderKey) != ""
	if padding {
		w.Header().Set(paddingHeaderKey, generatePaddingHeader(false))
	}
	// Enable "Fast Open" to send OK status before the upstream TCP/UDP
	// connection is fully established.
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	err = rc.Flush()
	if err != nil {
		log.InfoWithError("fail to flush the OK response", err)
		return
	}

	// The net/http server can't end the response body (our write side) before
	// the handler returns, so CloseWrite closes the request body instead. That
	// unblocks the client-to-target copy so the handler returns and the client
	// sees EOF. It's a full close, not a true half-close, so the client can't
	// continue uploading after CloseWrite is called.
	conn := newConn(r.Body, &flushWriter{w, rc}, padding, r.Body.Close, r.Body.Close,
		tcpStringAddr{netutil.JoinHostPort(s.host, s.port)}, tcpStringAddr{r.RemoteAddr},
	)
	err = transport.ForwardTCP(r.Context(), targetAddr, conn, s.targetClient)
	if err != nil && !errors.IsIoEof(err) {
		log.InfoWithError("fail to forward the connection", err)
	}
}

// serveFallback makes the server look like an ordinary web server to
// unauthenticated clients and active probes.
func (s *server) serveFallback(w http.ResponseWriter, r *http.Request) {
	log.Info("routing", contextutil.SourceTag, r.RemoteAddr,
		contextutil.InboundTag, "NaiveProxy carrier without HTTP/2, the HTTP CONNECT method, or proper auth",
		"access", netutil.JoinHostPort(s.host, s.port), contextutil.PolicyTag, conf.FallbackPolicy)
	if s.fallbackSiteHandler != nil {
		s.fallbackSiteHandler.ServeHTTP(w, r)
		return
	}
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}
