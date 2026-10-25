package np_carrier

import (
	"context"
	"net"
	"net/http"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type Server struct {
	host           string
	port           uint16
	authToken      string
	tlsCertKeyPair *conf.TLSCertKeyPair

	targetClient       transport.Client
	fallbackHttpServer *fallback_http.Server
}

var _ transport.Server = (*Server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) *Server {
	return &Server{
		hg.Host,
		hg.TLSPort,
		basicAuthToken(hg.Password),
		hg.TLSCertKeyPair,
		targetClient,
		fallbackHttpServer,
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	tlsConfig, err := netutil.TLSServerConfig(s.host, s.tlsCertKeyPair, false)
	if err != nil {
		return err
	}
	return netutil.ListenTLSAndServe(ctx, netutil.JoinHostPort(s.host, s.port), tlsConfig, s.newHTTPServer(ctx))
}

// Serve serves the connections accepted from ln until ln is closed. They must
// be TLS connections that are either *tls.Conn or have finished their
// handshakes and expose ConnectionState like *tls.Conn, so ALPN still picks
// HTTP/2.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	err := s.newHTTPServer(ctx).Serve(ln)
	if errors.IsErrClosedOrContextCanceled(err) {
		return nil
	}
	return errors.WithStack(err)
}

func (s *Server) newHTTPServer(ctx context.Context) *http.Server {
	return netutil.NewHTTPServer(ctx,
		func(ctx context.Context, c net.Conn) context.Context {
			return contextutil.WithSourceAndInboundValues(ctx, c.RemoteAddr().String(), "NaiveProxy carrier")
		},
		http.HandlerFunc(s.handle))
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// NaiveProxy speaks HTTP/2, but a real web server answers HTTP/1.1 too, so
	// HTTP/1.1 is accepted as well and always gets the fallback site.
	if r.ProtoMajor != 2 ||
		r.Method != http.MethodConnect || !basicAuthEqual(r.Header.Get(proxyAuthHeaderKey), s.authToken) {
		s.fallbackHttpServer.ServeHTTP(w, r, netutil.JoinHostPort(s.host, s.port), "NaiveProxy carrier")
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

	conn := newConn(r.Body, &flushWriter{w, rc}, padding, r.Body.Close, nil,
		tcpStringAddr{netutil.JoinHostPort(s.host, s.port)}, tcpStringAddr{r.RemoteAddr},
	)
	err = transport.ForwardTCP(r.Context(), targetAddr, conn, s.targetClient)
	if err != nil && !errors.IsIoEof(err) {
		log.InfoWithError("fail to forward the connection", err)
	}
}
