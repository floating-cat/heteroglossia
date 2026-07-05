package tr_carrier

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/netutil"
	"github.com/floating-cat/heteroglossia/util/strutil"
)

type client struct {
	proxyNode           *conf.ProxyNode
	tlsConfig           *tls.Config
	passwordWithoutCRLF [16]byte
}

var _ transport.Client = new(client)

func NewClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	clientHandler := &client{proxyNode: proxyNode}
	tlsConfig, err := netutil.TLSClientConfig(proxyNode, tlsKeyLog)
	if err != nil {
		return nil, err
	}
	clientHandler.tlsConfig = tlsConfig
	clientHandler.passwordWithoutCRLF = replaceCRLF(proxyNode.Password.Raw)
	return clientHandler, nil
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	targetHostWithPort := c.proxyNode.Host + ":" + strutil.ToA(c.proxyNode.TLSPort)
	tlsConn, err := netutil.DialTLS(ctx, targetHostWithPort, c.tlsConfig)
	if err != nil {
		return nil, errors.Newf("fail to connect to the TLS server %v: %.0w", targetHostWithPort, err)
	}
	return newClientConn(tlsConn, addr, c.passwordWithoutCRLF), nil
}
