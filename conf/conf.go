package conf

import (
	"encoding/hex"
	"encoding/json/v2"
	"strings"

	libRule "github.com/floating-cat/heteroglossia/conf/rule"
	"github.com/floating-cat/heteroglossia/util/errors"
)

type Config struct {
	Inbounds  Inbounds              `json:"inbounds" valid:"dive"`
	Outbounds map[string]*ProxyNode `json:"outbounds"`
	Route     Route                 `json:"route" valid:"dive"`
	Misc      Misc                  `json:"misc" valid:"dive"`
}

type Inbounds struct {
	HTTPSOCKS *HTTPSOCKS `json:"http-socks" valid:"dive"`
	Hg        *Hg        `json:"hg" valid:"dive"`
}

type HTTPSOCKS struct {
	Host        string `json:"host" valid:"req|host"`
	Port        uint16 `json:"port" valid:"min:1|max:65535"`
	Username    string `json:"username"`
	Password    string `json:"password,secure"`
	SystemProxy bool   `json:"system-proxy"`
}

func (httpSOCKS *HTTPSOCKS) UnmarshalJSON(data []byte) error {
	type HTTPSOCKSAlias HTTPSOCKS
	httpSOCKSAlias := (*HTTPSOCKSAlias)(httpSOCKS)
	httpSOCKSAlias.Port = defaultHTTPSOCKSPort
	return json.Unmarshal(data, httpSOCKSAlias)
}

func (httpSOCKS *HTTPSOCKS) ToHTTPSOCKSAuthInfo() *HTTPSOCKSAuthInfo {
	return &HTTPSOCKSAuthInfo{Username: httpSOCKS.Username, Password: httpSOCKS.Password}
}

type Hg struct {
	Host                      string          `json:"host" valid:"req|host"`
	Password                  HexPassword     `json:"password,secure" valid:"dive"`
	TCPPort                   int             `json:"tcp-port" valid:"min:1|max:65535"`
	TLSPort                   int             `json:"tls-port" valid:"min:1|max:65535"`
	TLSCertKeyPair            *TLSCertKeyPair `json:"tls-cert-key-pair"`
	TLSBadAuthFallbackSiteDir string          `json:"tls-bad-auth-fallback-site-dir"`
	QUICPort                  int             `json:"quic-port" valid:"min:1|max:65535"`
}

func (hg *Hg) UnmarshalJSON(data []byte) error {
	type HgAlias Hg
	hgAlias := (*HgAlias)(hg)
	hgAlias.TLSPort = defaultTLSPort
	hgAlias.QUICPort = defaultQUICPort
	return json.Unmarshal(data, hgAlias)
}

type ProxyNode struct {
	Host              string      `json:"host" valid:"req|host"`
	Password          HexPassword `json:"password,secure" valid:"dive"`
	TCPPort           int         `json:"tcp-port" valid:"min:1|max:65535"`
	TLSPort           int         `json:"tls-port" valid:"min:1|max:65535"`
	TLSCustomCertFile string      `json:"tls-cert"`
	QUICPort          int         `json:"quic-port" valid:"min:1|max:65535"`
}

type HexPassword struct {
	Raw    [16]byte
	String string `valid:"req"`
}

func (pw *HexPassword) UnmarshalJSON(data []byte) error {
	var pwStr string
	err := json.Unmarshal(data, &pwStr)
	if err != nil {
		return errors.New("fail to parse the \"password\" field", err)
	}

	bs, err := hex.DecodeString(pwStr)
	if err != nil || len(bs) != 16 {
		return errors.New("the password must be 32 hex characters in length")
	}
	pw.Raw = [16]byte(bs)
	pw.String = pwStr
	return nil
}

func (node *ProxyNode) UnmarshalJSON(data []byte) error {
	type ProxyNodeAlias ProxyNode
	proxyNodeAlias := (*ProxyNodeAlias)(node)
	proxyNodeAlias.TLSPort = defaultTLSPort
	proxyNodeAlias.QUICPort = defaultQUICPort
	return json.Unmarshal(data, proxyNodeAlias)
}

type Route struct {
	Rules Rules  `json:"rules" valid:"dive"`
	Final string `json:"final"`
}

type Rules []Rule

type Rule struct {
	Matcher *libRule.Matcher `json:"match" valid:"req"`
	Policy  string           `json:"policy" valid:"req"`
}

type Misc struct {
	HgBinaryAutoUpdate  bool `json:"hg-binary-auto-update"`
	RulesFileAutoUpdate bool `json:"rules-file-auto-update"`
	TLSKeyLog           bool `json:"tls-key-log"`
	VerboseLog          bool `json:"verbose-log"`
	Profiling           bool `json:"profiling"`
	ProfilingPort       int  `json:"profiling-port" valid:"min:1|max:65535"`
}

func (misc *Misc) UnmarshalJSON(data []byte) error {
	// https://stackoverflow.com/a/41102996
	type MiscAlias Misc
	miscAlias := (*MiscAlias)(misc)
	miscAlias.ProfilingPort = defaultProfilingPort
	return json.Unmarshal(data, miscAlias)
}

type TLSCertKeyPair struct {
	CertFile string
	KeyFile  string
}

func (pair *TLSCertKeyPair) UnmarshalJSON(data []byte) error {
	var certKeyStr string
	err := json.Unmarshal(data, &certKeyStr)
	if err != nil {
		return errors.New("fail to parse the \"tls-cert-key-pair\" field", err)
	}

	certKeyPairs := strings.Split(certKeyStr, " ")
	if len(certKeyPairs) != 2 {
		return errors.New("the certificate and key file's paths must be separated by whitespace, e.g. \"tls-cert-key-pair\" = \"tls_cert.pem tls_key.pem\"")
	}
	pair.CertFile = certKeyPairs[0]
	pair.KeyFile = certKeyPairs[1]
	return nil
}

func (rules Rules) setupRulesData() error {
	store, err := libRule.NewDomainIPSetRulesQueryStore()
	if err != nil {
		return err
	}
	defer store.Close()

	for i, rule := range rules {
		err := rule.Matcher.SetupRulesData(store)
		if err != nil {
			return errors.Newf("rule [%v]: %.0w", i+1, err)
		}
	}
	return nil
}

func (rules Rules) CopyWithNewRulesData() (Rules, error) {
	newRules := make([]Rule, 0, len(rules))
	for _, oldRule := range rules {
		var newRule Rule
		matcher := oldRule.Matcher.CopyWithBakedRulesOnly()
		newRule.Matcher = matcher
		newRule.Policy = oldRule.Policy
		newRules = append(newRules, newRule)
	}

	err := Rules(newRules).setupRulesData()
	if err != nil {
		return nil, err
	}
	return newRules, nil
}

const (
	defaultHTTPSOCKSPort = 1080
	defaultTLSPort       = 443
	defaultQUICPort      = 443
	defaultProfilingPort = 6060
)
