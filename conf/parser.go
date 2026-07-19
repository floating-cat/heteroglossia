package conf

import (
	"encoding/json/v2"
	"net"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/twharmon/govalid"
	"golang.org/x/exp/maps"
)

func init() {
	govalid.Rule("host", func(v any) error {
		switch tv := v.(type) {
		case string:
			if isIPOrHostname(tv) {
				return nil
			}
			return govalid.NewValidationError("must be a valid IP address or a hostname that follows RFC 1123")
		default:
			return errors.New("host constraint must be applied to string only")
		}
	})
}

func Parse(configFilePath string, ruleDBFilePath string) (*Config, error) {
	bs, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = json.Unmarshal(bs, config)
	if err != nil {
		return nil, errors.Newf("fail to pase %v: %.0w", configFilePath, err)
	}

	if config.Routing != nil {
		err = config.Routing.Rules.setupRulesData(ruleDBFilePath)
	}
	if err != nil {
		err = errors.Newf("field Routing: field Rules: %.0w", err)
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
	err := govalid.Validate(config)
	if err != nil {
		return errors.WithStack(err)
	}

	// govalid cannot dive into map values, so validate them manually
	for proxyNodeName, proxyNode := range config.Outbounds {
		err := govalid.Validate(proxyNode)
		if err != nil {
			return errors.Newf("field Outbounds: field %v: %.0w", proxyNodeName, err)
		}
	}

	err = validateRouting(config)
	if err != nil {
		return err
	}
	return nil
}

func validateRouting(config *Config) error {
	routing := config.Routing
	if routing == nil {
		return nil
	}

	switch routing.Transport.TCP {
	// no need to check TLSPort for the Trojan protocol because it defaults to 443
	case ShadowsocksTransport, ShadowsocksTransportAlias:
		for name, node := range config.Outbounds {
			if node.TCPPort == nil {
				return errors.Newf("field Routing: field Transport: field TCP is \"%v\", "+
					"but outbound %v has no \"tcp-port\" defined", routing.Transport.TCP, name)
			}
		}
	}

	outboundNames := strings.Join(maps.Keys(config.Outbounds), " ")

	for i, rule := range routing.Rules {
		policy := rule.Policy
		if policy == "direct" || policy == "reject" || policy == "final" {
			continue
		}
		_, ok := config.Outbounds[policy]
		if !ok {
			return errors.Newf("field Routing: field Rules: rule [%v]: "+
				"field Policy %v must be \"direct\", \"reject\", \"final\" or an outbound proxy name (%v)",
				i+1, policy, outboundNames)
		}
	}

	final := routing.Final
	if final == "direct" || final == "reject" {
		return nil
	}
	_, ok := config.Outbounds[final]
	if !ok {
		return errors.Newf("field Routing: "+
			"field Final %v must be \"direct\", \"reject\", or an outbound proxy name (%v)",
			final, outboundNames)
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
