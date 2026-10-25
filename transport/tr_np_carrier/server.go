package tr_np_carrier

import (
	"bytes"
	"context"
	"crypto/tls"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/transport/np_carrier"
	"github.com/floating-cat/heteroglossia/transport/tr_carrier"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
	pool "github.com/libp2p/go-buffer-pool"
)

// server serves Trojan and NaiveProxy on the same TLS port. After the TLS
// handshake, it peeks at the first bytes of each connection: one that starts
// with the Trojan password hash goes to the Trojan server, and any other goes
// to the NaiveProxy server, which serves the fallback site to everything but
// authenticated HTTP/2 CONNECT requests.
type server struct {
	listenHostWithPort string
	host               string
	tlsCertKeyPair     *conf.TLSCertKeyPair

	trojan     *tr_carrier.Server
	naiveproxy *np_carrier.Server
}

var _ transport.Server = (*server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) transport.Server {
	return &server{
		netutil.JoinHostPort(hg.ListenHost, hg.TLSPort),
		hg.Host,
		hg.TLSCertKeyPair,
		tr_carrier.NewServer(hg, targetClient, fallbackHttpServer),
		np_carrier.NewServer(hg, targetClient, fallbackHttpServer),
	}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	tlsConfig, err := netutil.TLSServerConfig(s.host, s.tlsCertKeyPair, false)
	if err != nil {
		return err
	}

	// net/http serves listeners, so serve hands the NaiveProxy server its
	// connections through naiveproxyLn.
	naiveproxyLn := netutil.NewConnListener(ctx)
	defer func() { _ = naiveproxyLn.Close() }()
	go func() {
		err := s.naiveproxy.Serve(ctx, naiveproxyLn)
		if err != nil {
			log.Fatal("fail to serve the NaiveProxy server", err)
		}
	}()

	return netutil.ListenTLSAndAccept(ctx, s.listenHostWithPort, tlsConfig, func(conn *tls.Conn) {
		err := s.serve(ctx, conn, naiveproxyLn)
		if err != nil && ctx.Err() == nil {
			log.InfoWithError("fail to handle a connection", err)
		}
	})
}

// serve hands conn to the Trojan carrier when the first few bytes match the
// Trojan protocol, unless it hands conn to the NaiveProxy server.
func (s *server) serve(ctx context.Context, conn *tls.Conn, naiveproxyLn *netutil.ConnListener) error {
	buf := pool.Get(ioutil.BufSize)
	defer pool.Put(buf)
	bufReader := ioutil.NewBufioReader(buf, conn)

	isTrojan, err := s.trojan.HasPasswordHash(bufReader)
	if err != nil {
		netutil.RespondToPlainHTTP(err)
		_ = conn.Close()
		return err
	}
	if isTrojan {
		ctx = contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "Trojan carrier")
		err = s.trojan.ServeAuthenticated(ctx, bufReader, conn)
		_ = conn.Close()
		return err
	}

	unreadBs, err := bufReader.Peek(bufReader.Buffered())
	if err != nil {
		_ = conn.Close()
		return errors.WithStack(err)
	}
	// The NaiveProxy server keeps reading conn after buf goes back to the pool,
	// so it gets a copy of the peeked bytes.
	naiveproxyLn.Push(ioutil.NewBytesReadPreloadTLSConn(bytes.Clone(unreadBs), conn))
	return nil
}
