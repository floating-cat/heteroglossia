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
	"github.com/floating-cat/heteroglossia/transport/sq_carrier"
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

	// carrierClients caches one carrier client per outbound so that stateful
	// transports (e.g. SunnyQUIC, which multiplexes every request over a single
	// reused QUIC connection) are built once instead of on every DialTCP call.
	carrierClients      map[string]transport.Client
	carrierClientsMutex sync.Mutex

	httpClient *http.Client
}

var _ transport.Client = (*client)(nil)

func NewClient(routing *conf.Routing, outbounds map[string]*conf.ProxyNode,
	ruleDBFilePath string, autoUpdateRuleFiles bool, tlsKeyLog bool) transport.Client {
	router := &client{
		routing:        routing,
		routingRWMutex: new(sync.RWMutex),
		outbounds:      outbounds,
		ruleDBFilePath: ruleDBFilePath,
		tlsKeyLog:      tlsKeyLog,
		carrierClients: make(map[string]transport.Client),
	}
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
		nextClient = direct.Client
	case "reject":
		nextClient = reject.Client
	default:
		var err error
		nextClient, err = c.getCarrierClient(policy)
		if err != nil {
			return nil, err
		}
	}
	log.Info("routing", contextutil.SourceTag, ctx.Value(contextutil.SourceTag),
		contextutil.InboundTag, ctx.Value(contextutil.InboundTag), "access", addr.ToHostStr(), "policy", policy)
	return nextClient.DialTCP(ctx, addr)
}

// getCarrierClient returns the cached carrier client for the given outbound,
// building and caching it on first use. The global TCP transport type is
// immutable after configuration, so a cached client stays valid for the
// router's lifetime.
func (c *client) getCarrierClient(outboundName string) (transport.Client, error) {
	c.carrierClientsMutex.Lock()
	defer c.carrierClientsMutex.Unlock()
	carrierClient, ok := c.carrierClients[outboundName]
	if ok {
		return carrierClient, nil
	}
	proxyNode := c.outbounds[outboundName]
	carrierClient, err := newCarrierClient(c.routing.Transport.TCP, proxyNode, c.tlsKeyLog)
	if err != nil {
		return nil, err
	}
	c.carrierClients[outboundName] = carrierClient
	return carrierClient, nil
}

func newCarrierClient(transport conf.TCPTransport, proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	switch transport {
	case conf.ShadowsocksTransport, conf.ShadowsocksTransportAlias:
		return ss_carrier.NewClient(proxyNode), nil
	case conf.TrojanTransport, conf.TrojanTransportAlias:
		return tr_carrier.NewClient(proxyNode, tlsKeyLog)
	case conf.SunnyQUICTransport, conf.SunnyQUICTransportAlias:
		return sq_carrier.NewClient(proxyNode, tlsKeyLog)
	default:
		return nil, errors.Newf("unsupported transport type: %v", transport)
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
