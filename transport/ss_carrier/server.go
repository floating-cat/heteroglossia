package ss_carrier

import (
	"context"
	"net"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type server struct {
	hostWithPort string
	preSharedKey []byte
	aeadOverhead int
	// we can use '[16]byte' here actually, but we still use string here
	// because we may support "2022-blake3-aes-256-gcm" later which uses '[32]byte'
	saltPool     *saltPool[string]
	targetClient transport.Client
}

var _ transport.Server = (*server)(nil)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	hostWithPort := netutil.JoinHostPort(hg.Host, *hg.TCPPort)
	return &server{hostWithPort, hg.Password.Raw[:], gcmTagOverhead, newSaltPool[string](), targetClient}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	return netutil.ListenTCPAndServe(ctx, s.hostWithPort, func(conn *net.TCPConn) {
		connCtx := contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "Shadowsocks carrier")
		err := s.Serve(connCtx, conn)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a connection", err)
		}
	})
}

func (s *server) Serve(ctx context.Context, conn net.Conn) error {
	//goland:noinspection GoResourceLeak
	serverConn := newServerConn(conn.(*net.TCPConn), s.preSharedKey, s.aeadOverhead, s.saltPool)
	// this is needed to get the access address for 'targetClient'
	err := serverConn.readClientFirstPayload()
	if err != nil {
		return err
	}
	return transport.ForwardTCP(ctx, serverConn.accessAddr, serverConn, s.targetClient)
}
