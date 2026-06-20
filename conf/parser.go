package conf

import (
	"encoding/json/v2"
	"net"
	"path/filepath"
	"regexp"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/floating-cat/heteroglossia/util/ioutil"
	"github.com/twharmon/govalid"
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

func Parse(configFilePath string) (*Config, error) {
	bs, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = json.Unmarshal(bs, config)
	if err != nil {
		return nil, errors.Newf("fail to pase %v: %.0w", configFilePath, err)
	}

	err = config.Route.Rules.setupRulesData()
	if err != nil {
		return nil, err
	}

	err = validate(config)
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
	return nil
}

func resolveAllFilePathsToConfigFolder(config *Config, configFileFolder string) {
	hg := config.Inbounds.Hg
	if hg != nil {
		tlsCertKeyPair := config.Inbounds.Hg.TLSCertKeyPair
		if tlsCertKeyPair != nil {
			tlsCertKeyPair.CertFile = resolveTo(tlsCertKeyPair.CertFile, configFileFolder)
			tlsCertKeyPair.KeyFile = resolveTo(tlsCertKeyPair.KeyFile, configFileFolder)
		}
		if hg.TLSBadAuthFallbackSiteDir != "" {
			hg.TLSBadAuthFallbackSiteDir = resolveTo(hg.TLSBadAuthFallbackSiteDir, configFileFolder)
		}
	}
	for _, v := range config.Outbounds {
		if v.TLSCustomCertFile != "" {
			v.TLSCustomCertFile = resolveTo(v.TLSCustomCertFile, configFileFolder)
		}
	}
}

func resolveTo(relativePath string, basePath string) string {
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
