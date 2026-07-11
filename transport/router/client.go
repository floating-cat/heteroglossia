package router

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/floating-cat/heteroglossia/conf"
	"github.com/floating-cat/heteroglossia/transport"
	"github.com/floating-cat/heteroglossia/transport/direct"
	"github.com/floating-cat/heteroglossia/transport/reject"
	"github.com/floating-cat/heteroglossia/transport/ss_carrier"
	"github.com/floating-cat/heteroglossia/transport/tr_carrier"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/updater"
)

type client struct {
	routing        *conf.Routing
	routingRWMutex *sync.RWMutex
	outbounds      map[string]*conf.ProxyNode
	ruleDBFilePath string
	tlsKeyLog      bool

	httpClient *http.Client
}

var _ transport.Client = (*client)(nil)

func NewClient(routing *conf.Routing, outbounds map[string]*conf.ProxyNode,
	ruleDBFilePath string, autoUpdateRuleFiles bool, tlsKeyLog bool) transport.Client {
	router := &client{routing, new(sync.RWMutex), outbounds, ruleDBFilePath, tlsKeyLog, nil}
	router.httpClient = transport.HTTPClientThroughRouter(router)
	if autoUpdateRuleFiles {
		go updater.StartUpdateCron(func() {
			router.updateRouting()
		})
	}
	return router
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	var policy string
	if c.routing != nil {
		c.routingRWMutex.RLock()
	matchAgain:
		switch addr.AddrType {
		case transport.IPv4, transport.IPv6:
			for _, rule := range c.routing.Rules {
				if rule.Matcher.MatchIP(addr.IP) {
					policy = rule.Policy
					break
				}
			}
		default:
			for _, rule := range c.routing.Rules {
				if rule.Matcher.MatchDomain(addr.Domain) {
					policy = rule.Policy
					break matchAgain
				}
			}
			// some clients (e.g., Chrome SmartProxy extension) send IP addresses within domain types in the SOCKS protocol
			ip, err := netip.ParseAddr(addr.Domain)
			if err == nil {
				addr = transport.NewSocketAddressByIP(&ip, addr.Port)
				goto matchAgain
			}
		}
		c.routingRWMutex.RUnlock()

		if policy == "final" || policy == "" {
			policy = c.routing.Final
		}
	} else {
		// default to direct if no routing is configured
		policy = "direct"
	}

	var nextClient transport.Client
	switch policy {
	case "direct":
		nextClient = direct.NewClient()
	case "reject":
		nextClient = reject.NewClient()
	default:
		proxyNode := c.outbounds[policy]
		var err error
		nextClient, err = newCarrierClient(c.routing.Transport.TCP, proxyNode, c.tlsKeyLog)
		if err != nil {
			return nil, err
		}
	}
	log.Info("routing", contextutil.SourceTag, ctx.Value(contextutil.SourceTag),
		contextutil.InboundTag, ctx.Value(contextutil.InboundTag), "access", addr.ToHostStr(), "policy", policy)
	return nextClient.DialTCP(ctx, addr)
}

func newCarrierClient(t conf.TCPTransport, proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	switch t {
	case conf.TrojanTransport, conf.TrojanTransportAlias:
		return tr_carrier.NewClient(proxyNode, tlsKeyLog)
	case conf.ShadowsocksTransport, conf.ShadowsocksTransportAlias:
		return ss_carrier.NewClient(proxyNode), nil
	default:
		return nil, errors.Newf("unsupported transport type: %v", t)
	}
}

func (c *client) updateRouting() {
	success, err := updater.UpdateRuleDBFile(c.ruleDBFilePath, c.httpClient)
	if err != nil {
		log.WarnWithError("fail to update rules' files", err)
		return
	}
	if !success {
		return
	}

	c.routingRWMutex.RLock()
	newRules, err := c.routing.Rules.CopyWithNewRulesData(c.ruleDBFilePath)
	if err != nil {
		c.routingRWMutex.RUnlock()
		log.WarnWithError("fail to update rules' 'matcher'", err)
		return
	}
	c.routingRWMutex.RUnlock()

	c.routingRWMutex.Lock()
	c.routing.Rules = newRules
	c.routingRWMutex.Unlock()
	log.Info("update rules' files successfully")
}
