package sq_carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/socks"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/netutil"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/quic-go/quic-go"
)

type client struct {
	serverHostWithPort string
	authHash           [64]byte
	tlsConfig          *tls.Config

	// quicConn caches the shared QUIC connection. SunnyQUIC multiplexes every TCP
	// proxy request as a separate stream over a single authenticated
	// connection, so it is dialed lazily and reused.
	quicConn      *quic.Conn
	quicConnMutex sync.Mutex
}

var _ transport.Client = (*client)(nil)

func NewClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	tlsConfig, err := netutil.TLSClientConfig(proxyNode.Host, proxyNode.TLSCustomCertFile, tlsKeyLog, true)
	if err != nil {
		return nil, err
	}

	serverHostWithPort := netutil.JoinHostPort(proxyNode.Host, proxyNode.QUICPort)
	return &client{
		serverHostWithPort: serverHostWithPort,
		tlsConfig:          tlsConfig,
		authHash:           toSunnyQUICAuthHash(proxyNode.Password.String),
	}, nil
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	conn, err := c.getQUICConn(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStream()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = c.sendTCPConnectCommand(stream, addr)
	if err != nil {
		_ = stream.Close()
		return nil, errors.WithStack(err)
	}
	return newStreamConn(stream, conn), nil
}

// getQUICConn returns a live authenticated QUIC connection, dialing a new one if
// none exists yet or the previous one has been closed.
func (c *client) getQUICConn(ctx context.Context) (*quic.Conn, error) {
	c.quicConnMutex.Lock()
	defer c.quicConnMutex.Unlock()
	if c.quicConn != nil && c.quicConn.Context().Err() == nil {
		return c.quicConn, nil
	}

	conn, err := netutil.DialQUIC(ctx, c.serverHostWithPort, c.tlsConfig)
	if err != nil {
		return nil, errors.Newf("fail to connect to the QUIC server %v: %.0w", c.serverHostWithPort, err)
	}
	go func() {
		err := c.sendAuthenticationCommand(conn)
		if err != nil {
			c.quicConnMutex.Lock()
			if c.quicConn == conn {
				c.quicConn = nil
			}
			c.quicConnMutex.Unlock()
			_ = conn.CloseWithError(connCloseErrCode, connCloseErrDesc)
		}
	}()
	c.quicConn = conn
	return conn, nil
}

func (c *client) sendAuthenticationCommand(conn *quic.Conn) error {
	stream, err := conn.OpenUniStream()
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(stream *quic.SendStream) {
		_ = stream.Close()
	}(stream)

	authCmdBs := pool.Get(1 + len(c.authHash))
	defer pool.Put(authCmdBs)
	authCmdBuf := bytes.NewBuffer(authCmdBs[:0])
	authCmdBuf.WriteByte(authCommand)
	authCmdBuf.Write(c.authHash[:])
	_, err = authCmdBuf.WriteTo(stream)
	return errors.WithStack(err)
}

func (c *client) sendTCPConnectCommand(stream *quic.Stream, addr *transport.SocketAddress) error {
	tcpConnectCmdBs := pool.Get(1 + 1 + socks.SOCKSLikeAddrSizeInBytes(addr))
	defer pool.Put(tcpConnectCmdBs)
	tcpConnectCmdBuf := bytes.NewBuffer(tcpConnectCmdBs[:0])
	tcpConnectCmdBuf.WriteByte(tcpConnectCommand)
	socks.WriteSOCKSLikeAddr(tcpConnectCmdBuf, addr)
	_, err := tcpConnectCmdBuf.WriteTo(stream)
	return errors.WithStack(err)
}
