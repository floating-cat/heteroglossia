package sq_carrier

import (
	"context"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/quic-go/quic-go"
)

type server struct {
	host           string
	port           uint16
	tlsCertKeyPair *conf.TLSCertKeyPair
	authHash       [64]byte
	targetClient   transport.Client
}

var _ transport.Server = (*server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	return &server{host: hg.Host, port: hg.QUICPort, tlsCertKeyPair: hg.TLSCertKeyPair,
		authHash: toSunnyQUICAuthHash(hg.Password.String), targetClient: targetClient}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	tlsConfig, err := netutil.TLSServerConfig(s.host, s.tlsCertKeyPair, true)
	if err != nil {
		return err
	}

	hostWithPort := netutil.JoinHostPort(s.host, s.port)
	return netutil.ListenQUICAndServe(ctx, hostWithPort, tlsConfig, func(quicConn *quic.Conn) {
		connCtx := contextutil.WithSourceAndInboundValues(ctx, quicConn.RemoteAddr().String(), "SunnyQUIC carrier")
		s.Serve(connCtx, quicConn)
	})

}

func (s *server) Serve(ctx context.Context, conn *quic.Conn) {
	//goland:noinspection GoResourceLeak
	serverConn := newServerQUICConn(ctx, s, conn)
	go serverConn.handleUniStreams(conn)
	go serverConn.handleAuthTimeout()
	serverConn.handleStreams(conn)
}
