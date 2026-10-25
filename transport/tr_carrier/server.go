package tr_carrier

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"net"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/fallback_http"
	"github.com/floating-cat/heteroglossia/transport/socks"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
	pool "github.com/libp2p/go-buffer-pool"
)

type Server struct {
	listenHostWithPort string
	host               string
	passwordHash       [56]byte
	tlsCertKeyPair     *conf.TLSCertKeyPair

	targetClient       transport.Client
	fallbackHttpServer *fallback_http.Server
}

var _ transport.Server = (*Server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client, fallbackHttpServer *fallback_http.Server) *Server {
	return &Server{
		netutil.JoinHostPort(hg.ListenHost, hg.TLSPort),
		hg.Host,
		toTrojanPasswordHash(hg.Password),
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

	return netutil.ListenTLSAndAccept(ctx, s.listenHostWithPort, tlsConfig, func(conn *tls.Conn) {
		connCtx := contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "Trojan carrier")
		err := s.serve(connCtx, conn)
		_ = conn.Close()
		if err != nil && ctx.Err() == nil {
			log.InfoWithError("fail to handle a connection", err)
		}
	})
}

func (s *Server) serve(ctx context.Context, conn net.Conn) error {
	buf := pool.Get(ioutil.BufSize)
	defer pool.Put(buf)
	bufReader := ioutil.NewBufioReader(buf, conn)

	authenticated, err := s.HasPasswordHash(bufReader)
	if err != nil {
		netutil.RespondToPlainHTTP(err)
		return err
	}
	if !authenticated {
		unreadBs, err := bufReader.Peek(bufReader.Buffered())
		if err != nil {
			return errors.WithStack(err)
		}
		//goland:noinspection GoResourceLeak
		return s.fallbackHttpServer.Handle(ctx, ioutil.NewBytesReadPreloadConn(unreadBs, conn), "Trojan carrier")
	}

	return s.ServeAuthenticated(ctx, bufReader, conn)
}

// HasPasswordHash reports whether r starts with the Trojan password hash
// followed by CRLF. It only peeks at the data, so the data remains unread
// afterward. It returns false as soon as it encounters a byte that cannot
// occur in the password-hash-and-CRLF sequence. This prevents clients using
// another protocol, such as those sending a normal HTTP request, from being
// left waiting for bytes they will never send. It also returns false without
// an error if r reaches EOF before all of the header like data arrives.
func (s *Server) HasPasswordHash(r *bufio.Reader) (bool, error) {
	hashLen := len(s.passwordHash)
	var header []byte
	var wasCR bool
	for i := range hashLen + len(crlf) {
		var err error
		header, err = r.Peek(i + 1)
		if err != nil {
			if errors.IsIoEof(err) {
				return false, nil
			}
			return false, errors.WithStack(err)
		}

		if i <= hashLen {
			if wasCR {
				// Read one line so our server behaves like a normal HTTP
				// server.  If we encounter CRLF before reading enough bytes
				// for the password hash, the request doesn't match the Trojan
				// protocol format.
				if header[i] == crlf[1] {
					return false, nil
				}
			}
			wasCR = header[i] == crlf[0]
		}
		// i == hashLen + 1 actually when the loop reaches the last element.
		if wasCR && header[i] == crlf[1] {
			return subtle.ConstantTimeCompare(header[:hashLen], s.passwordHash[:]) == 1, nil
		}
	}
	return false, nil
}

// ServeAuthenticated serves the Trojan request on conn after HasPasswordHash
// has found the password token at the start of r, which reads from conn.
func (s *Server) ServeAuthenticated(ctx context.Context, r *bufio.Reader, conn net.Conn) error {
	_, err := r.Discard(len(s.passwordHash) + len(crlf))
	if err != nil {
		return errors.WithStack(err)
	}

	commandType, err := ioutil.Read1(r)
	if err != nil {
		return err
	}
	if commandType != socks.ConnectionCommandConnect {
		return errors.Newf("unsupported command type %v", commandType)
	}
	accessAddr, err := socks.ReadSOCKS5Address(r)
	if err != nil {
		return err
	}
	crlfBs := make([]byte, 2)
	_, err = ioutil.ReadFull(r, crlfBs)
	if err != nil {
		return errors.WithStack(err)
	}

	unreadLen := r.Buffered()
	unreadBs, err := r.Peek(unreadLen)
	if err != nil {
		return errors.WithStack(err)
	}
	return transport.ForwardTCP(ctx, accessAddr, ioutil.NewBytesReadPreloadConn(unreadBs, conn), s.targetClient)
}
