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
	listenHostWithPort string
	host               string
	tlsCertKeyPair     *conf.TLSCertKeyPair
	authHash           [64]byte
	statelessResetKey  *quic.StatelessResetKey

	targetClient transport.Client
}

var _ transport.Server = (*server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	return &server{
		netutil.JoinHostPort(hg.ListenHost, hg.QUICPort),
		hg.Host,
		hg.TLSCertKeyPair,
		toSunnyQUICAuthHash(hg.Password),
		toStatelessResetKey(hg.Password),
		targetClient,
	}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	tlsConfig, err := netutil.TLSServerConfig(s.host, s.tlsCertKeyPair, true)
	if err != nil {
		return err
	}

	return netutil.ListenQUICEarlyAndServe(ctx, s.listenHostWithPort, tlsConfig, s.statelessResetKey, func(quicConn *quic.Conn) {
		connCtx := contextutil.WithSourceAndInboundValues(ctx, quicConn.RemoteAddr().String(), "SunnyQUIC carrier")
		s.serve(connCtx, quicConn)
	})

}

func (s *server) serve(ctx context.Context, conn *quic.Conn) {
	serverConn := newServerQUICConn(ctx, s, conn)
	go serverConn.handleAuthTimeout()
	serverConn.handleStreams(conn)
}
