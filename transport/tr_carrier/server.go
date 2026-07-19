package tr_carrier

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/socks"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
	pool "github.com/libp2p/go-buffer-pool"
)

type server struct {
	host                      string
	port                      uint16
	passwordHash              [56]byte
	tlsCertKeyPair            *conf.TLSCertKeyPair
	tlsBadAuthFallbackSiteDir string

	tlsConfig                    *tls.Config
	tlsBadAuthFallbackServerPort uint16
	targetClient                 transport.Client
}

var _ transport.Server = (*server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	return &server{host: hg.Host, port: hg.TLSPort,
		tlsCertKeyPair: hg.TLSCertKeyPair, tlsBadAuthFallbackSiteDir: hg.TLSBadAuthFallbackSiteDir,
		passwordHash: toTrojanPasswordHash(hg.Password.String),
		targetClient: targetClient}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	var err error
	s.tlsConfig, err = netutil.TLSServerConfig(s.host, s.tlsCertKeyPair, false)
	if err != nil {
		return err
	}

	port := make(chan uint16, 1)
	go func() {
		var httpHandler http.Handler
		if s.tlsBadAuthFallbackSiteDir != "" {
			httpHandler = http.FileServer(http.Dir(s.tlsBadAuthFallbackSiteDir))
		}
		err := netutil.ListenHTTPAndServeWithListenerCallback(ctx, ":0", httpHandler, func(ln net.Listener) {
			port <- uint16(ln.Addr().(*net.TCPAddr).Port)
		})
		if err != nil {
			log.Fatal("fail to serve a fallback server", err)
		}
	}()
	s.tlsBadAuthFallbackServerPort = <-port

	hostWithPort := netutil.JoinHostPort(s.host, s.port)
	return netutil.ListenTLSAndAccept(ctx, hostWithPort, s.tlsConfig, func(conn net.Conn) {
		connCtx := contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "Trojan carrier")
		err := s.Serve(connCtx, conn)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a connection", err)
		}
	})
}

func (s *server) Serve(ctx context.Context, conn net.Conn) error {
	buf := pool.Get(ioutil.BufSize)
	defer pool.Put(buf)
	bufReader := ioutil.NewBufioReader(buf, conn)
	textProtoReader := textproto.NewReader(bufReader)

	// read one line to make our server like a normal HTTP server
	lineBs, err := textProtoReader.ReadLineBytes()
	if err != nil {
		return errors.WithStack(err)
	}

	if len(lineBs) != 56 || [56]byte(lineBs[0:56]) != s.passwordHash {
		unreadBufSize := bufReader.Buffered()
		unreadBs, err := bufReader.Peek(unreadBufSize)
		if err != nil {
			return errors.WithStack(err)
		}
		// assume CRLF line endings (length = 2). This also works if the original
		// request uses only LF and won't cause any security issues because we only
		// forward the request to our internal web server
		unrelatedBs := pool.Get(len(lineBs) + 2 + len(unreadBs))[:0]
		defer pool.Put(unrelatedBs)
		unrelatedBs = append(unrelatedBs, lineBs...)
		unrelatedBs = append(unrelatedBs, crlf...)
		unrelatedBs = append(unrelatedBs, unreadBs...)
		fallbackAddr := transport.NewSocketAddressByIP(new(netip.IPv6Loopback()), s.tlsBadAuthFallbackServerPort)
		ctx := contextutil.WithValues(ctx, contextutil.InboundTag, "Trojan carrier with wrong auth")
		return transport.ForwardTCP(ctx, fallbackAddr, ioutil.NewBytesReadPreloadConn(unrelatedBs, conn), s.targetClient)
	}

	commandType, err := ioutil.Read1(bufReader)
	if err != nil {
		return err
	}
	if commandType != socks.ConnectionCommandConnect {
		return errors.Newf("unsupported command type %v", commandType)
	}
	accessAddr, err := socks.ReadSOCKS5Address(bufReader)
	if err != nil {
		return err
	}
	crlfBs := make([]byte, 2)
	_, err = ioutil.ReadFull(bufReader, crlfBs)
	if err != nil {
		return errors.WithStack(err)
	}

	unreadSize := bufReader.Buffered()
	unreadBs, err := bufReader.Peek(unreadSize)
	if err != nil {
		return errors.WithStack(err)
	}
	return transport.ForwardTCP(ctx, accessAddr, ioutil.NewBytesReadPreloadConn(unreadBs, conn), s.targetClient)
}
