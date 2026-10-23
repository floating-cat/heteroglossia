package ss_carrier

import (
	"context"
	"math/rand/v2"
	"net"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/netutil"
)

type client struct {
	serverHostWithPort string
	preSharedKey       []byte
	aeadOverhead       int
	// A function to randomly pick Ex2 and 5 mentioned here
	// https://gfw.report/publications/usenixsecurity23/en/.
	exPicker func() int
}

var _ transport.Client = (*client)(nil)

func NewClient(proxyNode *conf.ProxyNode) transport.Client {
	return &client{
		netutil.JoinHostPort(proxyNode.Host, *proxyNode.TCPPort),
		toShadowsocksSharedKey(proxyNode.Password),
		gcmTagOverhead,
		weightedIntN(2),
	}
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	clientSalt := generateSalt(c.preSharedKey)
	c.customFirstReqPrefixes(clientSalt)

	targetConn, err := netutil.DialTCP(ctx, c.serverHostWithPort)
	if err != nil {
		return nil, errors.Newf("fail to connect to the server %v: %.0w", c.serverHostWithPort, err)
	}
	return newClientConn(targetConn, addr, c.preSharedKey, clientSalt, c.aeadOverhead), nil
}

func (c *client) customFirstReqPrefixes(bs []byte) {
	switch c.exPicker() {
	case 0:
		// Ex2 exemption
		for i := range 6 {
			bs[i] = byte(rand.N(0x7e-0x20+1) + 0x20)
		}
	case 1:
		// Ex5 exemption
		pattern := [6]string{"GET ", "HEAD ", "POST ", "PUT ", "\x16\x03\x02", "\x16\x03\x03"}
		copy(bs, pattern[rand.N(6)])
	default:
		panic("unreachable code line")
	}
}
