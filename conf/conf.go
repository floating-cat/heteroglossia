package conf

import (
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"

	libRule "github.com/floating-cat/heteroglossia/conf/rule"
	"github.com/floating-cat/heteroglossia/util/errors"
)

type Config struct {
	Inbounds  Inbounds              `json:"inbounds"`
	Outbounds map[string]*ProxyNode `json:"outbounds"`
	Routing   *Routing              `json:"routing"`
	Misc      Misc                  `json:"misc"`
}

type Inbounds struct {
	HTTPSOCKS *HTTPSOCKS `json:"http-socks"`
	Hg        *Hg        `json:"hg"`
}

type HTTPSOCKS struct {
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SystemProxy bool   `json:"system-proxy"`
}

func (httpSOCKS *HTTPSOCKS) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	// https://stackoverflow.com/a/41102996
	type HTTPSOCKSAlias HTTPSOCKS
	httpSOCKSAlias := (*HTTPSOCKSAlias)(httpSOCKS)
	httpSOCKSAlias.Port = defaultHTTPSOCKSPort
	return json.UnmarshalDecode(dec, httpSOCKSAlias)
}

func (httpSOCKS *HTTPSOCKS) ToHTTPSOCKSAuthInfo() *HTTPSOCKSAuthInfo {
	return &HTTPSOCKSAuthInfo{Username: httpSOCKS.Username, Password: httpSOCKS.Password}
}

type Hg struct {
	Host                      string          `json:"host"`
	Password                  *Password       `json:"password"`
	TCPPort                   *uint16         `json:"tcp-port"`
	TLSPort                   uint16          `json:"tls-port"`
	TLSCertKeyPair            *TLSCertKeyPair `json:"tls-cert-key-pair"`
	TLSBadAuthFallbackSiteDir string          `json:"tls-bad-auth-fallback-site-dir"`
	QUICPort                  uint16          `json:"quic-port"`
}

func (hg *Hg) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	type HgAlias Hg
	hgAlias := (*HgAlias)(hg)
	hgAlias.TLSPort = defaultTLSPort
	hgAlias.QUICPort = defaultQUICPort
	return json.UnmarshalDecode(dec, hgAlias)
}

type ProxyNode struct {
	Host              string    `json:"host"`
	Password          *Password `json:"password"`
	TCPPort           *uint16   `json:"tcp-port"`
	TLSPort           uint16    `json:"tls-port"`
	TLSCustomCertFile string    `json:"tls-cert"`
	QUICPort          uint16    `json:"quic-port"`
}

type Password [16]byte

func (pw *Password) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var pwStr string
	err := json.UnmarshalDecode(dec, &pwStr)
	if err != nil {
		return errors.New(`fail to parse the "password" field`, err)
	}

	bs, err := hex.DecodeString(pwStr)
	if err != nil || len(bs) != 16 {
		return errors.New("the password must be 32 hex characters in length", err)
	}
	*pw = [16]byte(bs)

	return nil
}

func (node *ProxyNode) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	type ProxyNodeAlias ProxyNode
	proxyNodeAlias := (*ProxyNodeAlias)(node)
	proxyNodeAlias.TLSPort = defaultTLSPort
	proxyNodeAlias.QUICPort = defaultQUICPort
	return json.UnmarshalDecode(dec, proxyNodeAlias)
}

type Routing struct {
	Transport Transport `json:"transport"`
	Rules     Rules     `json:"rules"`
	Final     string    `json:"final"`
}

type Transport struct {
	TCP TCPTransport `json:"tcp"`
	// UDP is not used yet; it will be supported later.
	UDP string `json:"udp"`
}

type TCPTransport string

type Rules []Rule

type Rule struct {
	Matcher *libRule.Matcher `json:"match"`
	Policy  string           `json:"policy"`
}

type Misc struct {
	HgBinaryAutoUpdate  bool   `json:"hg-binary-auto-update"`
	RulesFileAutoUpdate bool   `json:"rules-file-auto-update"`
	TLSKeyLog           bool   `json:"tls-key-log"`
	VerboseLog          bool   `json:"verbose-log"`
	Profiling           bool   `json:"profiling"`
	ProfilingPort       uint16 `json:"profiling-port"`
}

func (misc *Misc) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	type MiscAlias Misc
	miscAlias := (*MiscAlias)(misc)
	miscAlias.ProfilingPort = defaultProfilingPort
	return json.UnmarshalDecode(dec, miscAlias)
}

type TLSCertKeyPair struct {
	CertFile string
	KeyFile  string
}

func (pair *TLSCertKeyPair) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var certKeyStr string
	err := json.UnmarshalDecode(dec, &certKeyStr)
	if err != nil {
		return errors.New(`fail to parse the "tls-cert-key-pair" field`, err)
	}

	certKeyPairs := strings.Split(certKeyStr, " ")
	if len(certKeyPairs) != 2 {
		return errors.New("the certificate and key file's paths must be separated by whitespace, " +
			`e.g., "tls-cert-key-pair" = "tls_cert.pem tls_key.pem"`)
	}
	pair.CertFile = certKeyPairs[0]
	pair.KeyFile = certKeyPairs[1]
	return nil
}

func (rules Rules) setupRulesData(ruleDBFilePath string) error {
	store, err := libRule.NewDomainIPSetRulesQueryStore(ruleDBFilePath)
	if err != nil {
		return err
	}
	defer store.Close()

	for i, rule := range rules {
		err := rule.Matcher.SetupRulesData(store)
		if err != nil {
			return errors.Newf("'rules.[%v]': %v", i+1, err.Error())
		}
	}
	return nil
}

func (rules Rules) CopyWithNewRulesData(ruleDBFilePath string) (Rules, error) {
	newRules := make([]Rule, 0, len(rules))
	for _, oldRule := range rules {
		var newRule Rule
		matcher := oldRule.Matcher.CopyWithBakedRulesOnly()
		newRule.Matcher = matcher
		newRule.Policy = oldRule.Policy
		newRules = append(newRules, newRule)
	}

	err := Rules(newRules).setupRulesData(ruleDBFilePath)
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

	ShadowsocksTransport      TCPTransport = "shadowsocks"
	ShadowsocksTransportAlias TCPTransport = "ss"
	TrojanTransport           TCPTransport = "trojan"
	TrojanTransportAlias      TCPTransport = "tr"
	NaiveProxyTransport       TCPTransport = "naiveproxy"
	NaiveProxyTransportAlias  TCPTransport = "np"
	SunnyQUICTransport        TCPTransport = "sunnyquic"
	SunnyQUICTransportAlias   TCPTransport = "sq"

	DirectPolicy = "direct"
	FinalPolicy  = "final"
	RejectPolicy = "reject"
)
