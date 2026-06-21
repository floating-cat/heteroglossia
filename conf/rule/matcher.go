package rule

import (
	"encoding/json/v2"
	"net/netip"
	"regexp"
	"strings"

	"github.com/floating-cat/heteroglossia/util/errors"
	"github.com/gaissmai/bart"
)

type Matcher struct {
	domainFullAndSuffixMatcher domainFullAndSuffixMatcher
	domainRegexMatcher         []regexp.Regexp
	ipCidrMatcher              *bart.Fast[any]
	bakedMatchRules            []string
}

const (
	domainFullPrefix   = "domain-full/"
	domainSuffixPrefix = "domain-suffix/"
	domainRegexPrefix  = "domain-regex/"
	ipPrefix           = "ip/"
	cidrPrefix         = "cidr/"
	domainTagPrefix    = "domain-tag/"
	ipSetTagPrefix     = "ip-set-tag/"
)

func newMatcher(matchRules []string) *Matcher {
	return &Matcher{domainFullAndSuffixMatcher: newDomainFullAndSuffixMatcher(), bakedMatchRules: matchRules}
}

func (matcher *Matcher) CopyWithBakedRulesOnly() *Matcher {
	return newMatcher(matcher.bakedMatchRules)
}

func (matcher *Matcher) SetupRulesData(rulesQueryStore *DomainIPSetRulesQueryStore) error {
	var domainRegexMatcher []regexp.Regexp
	ipPrefixSet := new(bart.Fast[any])

	var err error
	var regex *regexp.Regexp
	for i, rule := range matcher.bakedMatchRules {
		switch {
		case strings.HasPrefix(rule, domainFullPrefix):
			domain := strings.TrimPrefix(rule, domainFullPrefix)
			matcher.domainFullAndSuffixMatcher.addDomainFullRule(domain)

		case strings.HasPrefix(rule, domainSuffixPrefix):
			domain := strings.TrimPrefix(rule, domainSuffixPrefix)
			matcher.domainFullAndSuffixMatcher.addDomainSuffixRule(domain)

		case strings.HasPrefix(rule, domainRegexPrefix):
			domainRegex := strings.TrimPrefix(rule, domainRegexPrefix)
			regex, err = regexp.Compile(domainRegex)
			if err != nil {
				break
			}
			domainRegexMatcher = append(domainRegexMatcher, *regex)

		case strings.HasPrefix(rule, ipPrefix):
			ip := strings.TrimPrefix(rule, ipPrefix)
			addr := netip.MustParseAddr(ip)
			var prefix netip.Prefix
			prefix, err = toPrefixUnmapped(addr, addr.BitLen())
			if err != nil {
				break
			}
			ipPrefixSet.Insert(prefix, nil)

		case strings.HasPrefix(rule, cidrPrefix):
			cidr := strings.TrimPrefix(rule, cidrPrefix)
			prefix := netip.MustParsePrefix(cidr)
			prefix, err = toPrefixUnmapped(prefix.Addr(), prefix.Bits())
			if err != nil {
				break
			}
			ipPrefixSet.Insert(prefix, nil)

		case strings.HasPrefix(rule, domainTagPrefix):
			domainTag := strings.TrimPrefix(rule, domainTagPrefix)
			err = rulesQueryStore.queryDomainRulesByTag(domainTag, func(domainType domainType, domain string) {
				switch domainType {
				case domainFull:
					matcher.domainFullAndSuffixMatcher.addDomainFullRule(domain)
				case domainSuffix:
					matcher.domainFullAndSuffixMatcher.addDomainSuffixRule(domain)
				case domainKeyword:
					regex, err = errors.WithStack2(regexp.Compile("^.*" + regexp.QuoteMeta(domain) + ".*$"))
					if err != nil {
						break
					}
					domainRegexMatcher = append(domainRegexMatcher, *regex)
				case domainRegex:
					regex, err = regexp.Compile(domain)
					if err != nil {
						break
					}
					domainRegexMatcher = append(domainRegexMatcher, *regex)
				}
			})

		case strings.HasPrefix(rule, ipSetTagPrefix):
			ipSetTag := strings.TrimPrefix(rule, ipSetTagPrefix)
			err = rulesQueryStore.queryIPSetRulesByTag(ipSetTag, func(ip netip.Addr, bits int) error {
				prefix, err := toPrefixUnmapped(ip, ip.BitLen())
				if err != nil {
					return err
				}
				ipPrefixSet.Insert(prefix, nil)
				return nil
			})
		default:
			return errors.Newf("fail to parse match [%v] \"%v\"", i+1, rule)
		}
		if err != nil {
			return errors.Newf("fail to parse match [%v] \"%v\": %.0w", i+1, rule, err)
		}
	}

	matcher.domainRegexMatcher = domainRegexMatcher
	matcher.ipCidrMatcher = ipPrefixSet
	return nil
}

func (matcher *Matcher) MatchDomain(domain string) bool {
	if matcher.domainFullAndSuffixMatcher.match(domain) {
		return true
	}
	for _, regex := range matcher.domainRegexMatcher {
		if regex.MatchString(domain) {
			return true
		}
	}
	return false
}

func (matcher *Matcher) MatchIP(ip *netip.Addr) bool {
	return matcher.ipCidrMatcher.Contains(ip.Unmap())
}

func (matcher *Matcher) UnmarshalJSON(data []byte) error {
	var matchRules []string
	err := json.Unmarshal(data, &matchRules)
	if err != nil {
		return errors.New("fail to parse 'match' rules", err)
	}

	createdMatcher := newMatcher(matchRules)
	*matcher = *createdMatcher
	return nil
}

// bart.Fast doesn't support IPv4-in-IPv6 addresses, so unmap them
func toPrefixUnmapped(ip netip.Addr, bits int) (netip.Prefix, error) {
	if ip.Is4In6() {
		return errors.WithStack2(ip.Unmap().Prefix(bits - 96))
	}
	return errors.WithStack2(ip.Prefix(bits))
}
