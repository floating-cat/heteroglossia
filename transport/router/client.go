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
	"github.com/floating-cat/heteroglossia/transport/tr_carrier"
	"github.com/floating-cat/heteroglossia/util/contextutil"
	"github.com/floating-cat/heteroglossia/util/log"
	"github.com/floating-cat/heteroglossia/util/updater"
)

type client struct {
	route        *conf.Route
	routeRWMutex *sync.RWMutex
	outbounds    map[string]*conf.ProxyNode
	tlsKeyLog    bool

	httpClient *http.Client
}

var _ transport.Client = new(client)

func NewClient(route *conf.Route, autoUpdateRuleFiles bool, outbounds map[string]*conf.ProxyNode, tlsKeyLog bool) transport.Client {
	router := &client{route, new(sync.RWMutex), outbounds, tlsKeyLog, nil}
	router.httpClient = transport.HTTPClientThroughRouter(router)
	if autoUpdateRuleFiles {
		go updater.StartUpdateCron(func() {
			router.updateRoute()
		})
	}
	return router
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	c.routeRWMutex.RLock()
	var policy string

matchAgain:
	switch addr.AddrType {
	case transport.IPv4, transport.IPv6:
		for _, rule := range c.route.Rules {
			if rule.Matcher.MatchIP(addr.IP) {
				policy = rule.Policy
				break
			}
		}
	default:
		for _, rule := range c.route.Rules {
			if rule.Matcher.MatchDomain(addr.Domain) {
				policy = rule.Policy
				break
			}
		}
		// some clients (e.g., Chrome SmartProxy extension) send IP addresses within domain types in the SOCKS protocol
		ip, err := netip.ParseAddr(addr.Domain)
		if err == nil {
			addr = transport.NewSocketAddressByIP(&ip, addr.Port)
			goto matchAgain
		}
	}
	c.routeRWMutex.RUnlock()
	if policy == "final" || policy == "" {
		policy = c.route.Final
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
		nextClient, err = tr_carrier.NewClient(proxyNode, c.tlsKeyLog)
		if err != nil {
			return nil, err
		}
	}
	log.Info("route", contextutil.SourceTag, ctx.Value(contextutil.SourceTag),
		contextutil.InboundTag, ctx.Value(contextutil.InboundTag), "access", addr.ToHostStr(), "policy", policy)
	return nextClient.DialTCP(ctx, addr)
}

func (c *client) updateRoute() {
	success, err := updater.UpdateRuleFile(c.httpClient)
	if err != nil {
		log.WarnWithError("fail to update rules' files", err)
		return
	}
	if !success {
		return
	}

	c.routeRWMutex.RLock()
	newRules, err := c.route.Rules.CopyWithNewRulesData()
	if err != nil {
		c.routeRWMutex.RUnlock()
		log.WarnWithError("fail to update rules' 'matcher'", err)
		return
	}
	c.routeRWMutex.RUnlock()

	c.routeRWMutex.Lock()
	c.route.Rules = newRules
	c.routeRWMutex.Unlock()
	log.Info("update rules' files successfully")
}
