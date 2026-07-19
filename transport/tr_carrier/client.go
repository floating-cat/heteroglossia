package tr_carrier

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type client struct {
	serverHostWithPort string
	passwordHash       [56]byte
	tlsConfig          *tls.Config
}

var _ transport.Client = (*client)(nil)

func NewClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	clientHandler := &client{serverHostWithPort: netutil.JoinHostPort(proxyNode.Host, proxyNode.TLSPort)}
	clientHandler.passwordHash = toTrojanPasswordHash(proxyNode.Password.String)
	tlsConfig, err := netutil.TLSClientConfig(proxyNode.Host, proxyNode.TLSCustomCertFile, tlsKeyLog, false)
	if err != nil {
		return nil, err
	}
	clientHandler.tlsConfig = tlsConfig
	return clientHandler, nil
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	tlsConn, err := netutil.DialTLS(ctx, c.serverHostWithPort, c.tlsConfig)
	if err != nil {
		return nil, errors.Newf("fail to connect to the TLS server %v: %.0w", c.serverHostWithPort, err)
	}
	return newClientConn(tlsConn, addr, c.passwordHash), nil
}
