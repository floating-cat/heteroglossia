package conf

import (
	"encoding/json/v2"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	libRule "github.com/floating-cat/heteroglossia/conf/rule"
	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/nobl9/govy/pkg/govy"
	"github.com/nobl9/govy/pkg/rules"
)

func Parse(configFilePath string, ruleDBFilePath string) (*Config, error) {
	bs, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = json.Unmarshal(bs, config)
	if err != nil {
		return nil, errors.Newf("fail to pase %v: %w", configFilePath, err)
	}

	if config.Routing != nil {
		err = config.Routing.Rules.setupRulesData(ruleDBFilePath)
	}
	if err != nil {
		err = errors.Newf("'routing': %v", err.Error())
	} else {
		err = validate(config)
	}
	if err != nil {
		return nil, errors.Newf("fail to parse the config file %v: %.0w", configFilePath, err)
	}

	resolveAllFilePathsToConfigFolder(config, filepath.Dir(configFilePath))
	return config, nil
}

func validate(config *Config) error {
	var hostRule = govy.NewRule(func(host string) error {
		if isIPOrHostname(host) {
			return nil
		}
		return govy.NewRuleError("must be a valid IP address or a hostname that follows RFC 1123", "host")
	})
	var portRules = govy.NewRuleSet(rules.GTE[uint16](1), rules.LTE[uint16](65535))
	var hexPasswordValidator = govy.New(
		govy.For(func(p HexPassword) string { return p.String }).
			WithName("password").
			HideValue().
			Required(),
	)

	var httpSOCKSValidator = govy.New(
		govy.For(func(h HTTPSOCKS) string { return h.Host }).
			WithName("host").
			Required().
			Rules(hostRule),
		govy.For(func(h HTTPSOCKS) uint16 { return h.Port }).
			WithName("port").
			Rules(portRules),
	)

	var hgValidator = govy.New(
		govy.For(func(h Hg) string { return h.Host }).
			WithName("host").
			Required().
			Rules(hostRule),
		govy.For(func(h Hg) HexPassword { return h.Password }).
			WithName("password").
			Include(hexPasswordValidator),
		govy.ForPointer(func(h Hg) *uint16 { return h.TCPPort }).
			WithName("tcp-port").
			Rules(portRules),
		govy.For(func(h Hg) uint16 { return h.TLSPort }).
			WithName("tls-port").
			Rules(portRules),
		govy.For(func(h Hg) uint16 { return h.QUICPort }).
			WithName("quic-port").
			Rules(portRules),
	)

	var inboundsValidator = govy.New(
		govy.For(func(i Inbounds) Inbounds { return i }).
			Rules(govy.NewRule(func(i Inbounds) error {
				if i.HTTPSOCKS == nil && i.Hg == nil {
					return govy.NewRuleError(
						"at least one of \"http-socks\" or \"hg\" must be configured", "inbound_required")
				}
				return nil
			})),
		govy.ForPointer(func(i Inbounds) *HTTPSOCKS { return i.HTTPSOCKS }).
			WithName("http-socks").
			Include(httpSOCKSValidator),
		govy.ForPointer(func(i Inbounds) *Hg { return i.Hg }).
			WithName("hg").
			Include(hgValidator),
	)

	var proxyNodeValidator = govy.New(
		govy.For(func(n *ProxyNode) string { return n.Host }).
			WithName("host").
			Required().
			Rules(hostRule),
		govy.For(func(n *ProxyNode) HexPassword { return n.Password }).
			WithName("password").
			Include(hexPasswordValidator),
		govy.ForPointer(func(n *ProxyNode) *uint16 { return n.TCPPort }).
			WithName("tcp-port").
			Rules(portRules),
		govy.For(func(n *ProxyNode) uint16 { return n.TLSPort }).
			WithName("tls-port").
			Rules(portRules),
		govy.For(func(n *ProxyNode) uint16 { return n.QUICPort }).
			WithName("quic-port").
			Rules(portRules),
	).When(func(t *ProxyNode) bool {
		return t != nil
	})

	var transportValidator = govy.New(
		govy.For(func(t Transport) TCPTransport { return t.TCP }).
			WithName("tcp").
			Required().
			Rules(
				rules.OneOf(
					ShadowsocksTransport, ShadowsocksTransportAlias,
					TrojanTransport, TrojanTransportAlias,
					SunnyQUICTransport, SunnyQUICTransportAlias,
				),
				govy.NewRule(func(tcp TCPTransport) error {
					switch tcp {
					// no need to check TLSPort and QUICPort for other protocols because they have default values.
					case ShadowsocksTransport, ShadowsocksTransportAlias:
						for name, proxyNode := range config.Outbounds {
							if proxyNode == nil {
								// null value is already reported by nonNullValueOutboundsRules
								continue
							}
							if proxyNode.TCPPort == nil {
								return govy.NewRuleError(fmt.Sprintf(
									"requires each outbound to define a \"tcp-port\" for %q protocol, "+
										"but 'outbounds.%v' doesn't have one", tcp, name),
									"outbound_tcp_port_required")
							}
						}
					}
					return nil
				}),
			),
	)

	quotedOutboundNames := make([]string, 0, len(config.Outbounds))
	for name := range config.Outbounds {
		quotedOutboundNames = append(quotedOutboundNames, strconv.Quote(name))
	}
	outboundNames := strings.Join(quotedOutboundNames, " ")
	var ruleValidator = govy.New(
		govy.For(func(r Rule) *libRule.Matcher { return r.Matcher }).
			WithName("match").
			Required(),
		govy.For(func(r Rule) string { return r.Policy }).
			WithName("policy").
			Required().
			Rules(govy.NewRule(func(policy string) error {
				if policy == "direct" || policy == "reject" || policy == "final" {
					return nil
				}
				if _, ok := config.Outbounds[policy]; !ok {
					return govy.NewRuleError(fmt.Sprintf(
						"must be \"direct\", \"reject\", \"final\" or an outbound name (%v)", outboundNames),
						"rule_policy_invalid")
				}
				return nil
			})),
	)

	var routingValidator = govy.New(
		govy.For(func(r Routing) Transport { return r.Transport }).
			WithName("transport").
			Include(transportValidator),
		govy.ForSlice(func(r Routing) Rules { return r.Rules }).
			WithName("rules").
			IncludeForEach(ruleValidator),
		govy.For(func(r Routing) string { return r.Final }).
			WithName("final").
			Rules(govy.NewRule(func(final string) error {
				if final == "direct" || final == "reject" {
					return nil
				}
				if _, ok := config.Outbounds[final]; !ok {
					return govy.NewRuleError(fmt.Sprintf(
						"must be \"direct\", \"reject\", or an outbound name (%v)", outboundNames),
						"final_invalid")
				}
				return nil
			})),
	)

	var miscValidator = govy.New(
		govy.For(func(m Misc) uint16 { return m.ProfilingPort }).
			WithName("profiling-port").
			// profiling-port only needs to be valid when profiling is enabled
			When(func(m Misc) bool { return m.Profiling }).
			Rules(portRules),
	)

	var nonNullValueOutboundsRules = govy.For(func(c *Config) *Config { return c }).
		When(func(c *Config) bool { return c.Outbounds != nil }).
		Rules(govy.NewRule(func(c *Config) error {
			for name := range c.Outbounds {
				if c.Outbounds[name] == nil {
					return govy.NewRuleError(fmt.Sprintf("'outbounds.%v' must not be null", name),
						"outbound_non_null_value")
				}
			}
			return nil
		}))

	var configValidator = govy.New(
		govy.For(func(c *Config) Inbounds { return c.Inbounds }).
			WithName("inbounds").
			Include(inboundsValidator),
		govy.ForMap(func(c *Config) map[string]*ProxyNode { return c.Outbounds }).
			WithName("outbounds").
			IncludeForValues(proxyNodeValidator),
		govy.ForPointer(func(c *Config) *Routing { return c.Routing }).
			WithName("routing").
			Include(routingValidator),
		govy.For(func(c *Config) Misc { return c.Misc }).
			WithName("misc").
			Include(miscValidator),
		nonNullValueOutboundsRules,
	)

	err := configValidator.Validate(config)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func resolveAllFilePathsToConfigFolder(config *Config, configFileFolder string) {
	hg := config.Inbounds.Hg
	if hg != nil {
		tlsCertKeyPair := config.Inbounds.Hg.TLSCertKeyPair
		if tlsCertKeyPair != nil {
			tlsCertKeyPair.CertFile = joinIfRelative(configFileFolder, tlsCertKeyPair.CertFile)
			tlsCertKeyPair.KeyFile = joinIfRelative(configFileFolder, tlsCertKeyPair.KeyFile)
		}
		if hg.TLSBadAuthFallbackSiteDir != "" {
			hg.TLSBadAuthFallbackSiteDir = joinIfRelative(configFileFolder, hg.TLSBadAuthFallbackSiteDir)
		}
	}
	for _, v := range config.Outbounds {
		if v.TLSCustomCertFile != "" {
			v.TLSCustomCertFile = joinIfRelative(configFileFolder, v.TLSCustomCertFile)
		}
	}
}

func joinIfRelative(basePath string, relativePath string) string {
	if filepath.IsAbs(relativePath) {
		return relativePath
	}
	return filepath.Join(basePath, relativePath)
}

// forked from https://github.com/go-playground/validator/pull/1562
var hostnameRFC1123Regex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

func isIPOrHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	} else if isDottedDecimalIPv4(host) {
		return false
	}
	return hostnameRFC1123Regex.MatchString(host)
}

func isDottedDecimalIPv4(s string) bool {
	labels := 1
	labelLen := 0

	for _, c := range s {
		switch {
		case c == '.':
			if labelLen == 0 {
				return false
			}
			labels++
			labelLen = 0
		case c >= '0' && c <= '9':
			labelLen++
		default:
			return false
		}
	}

	return labels == 4 && labelLen > 0
}
