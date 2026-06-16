package rule

import (
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/shoenig/test/must"
)

func TestIPRulesWithIP(t *testing.T) {
	tests := []struct {
		rule     string
		input    string
		expected bool
	}{
		{"192.0.2.1", "192.0.2.1", true},
		{"192.0.2.1", "192.0.2.2", false},
		{"::1", "::1", true},
		{"::1", "::2", false},
		{"::ffff:192.0.2.128", "192.0.2.128", true},
		{"192.0.2.128", "::ffff:192.0.2.128", true},
	}
	for _, tt := range tests {
		ip := netip.MustParseAddr(tt.rule)
		matcher := newIPCidrMatcher(t, ip, ip.BitLen())
		must.Eq(t, tt.expected, matcher.MatchIP(new(netip.MustParseAddr(tt.input))), must.Sprintf("no match: %v", tt))
	}
}

func TestCidrRulesWithIP(t *testing.T) {
	tests := []struct {
		rule     string
		input    string
		expected bool
	}{
		{"192.0.2.1/32", "192.0.2.1", true},
		{"192.0.2.1/32", "192.0.2.2", false},
		{"192.0.2.1/24", "192.0.2.2", true},
		{"192.0.2.1/24", "192.0.1.1", false},
		{"::ffff:192.0.2.128/120", "::ffff:192.0.2.128", true},
		{"::ffff:192.0.2.128/120", "::ffff:192.0.2.1", true},
		{"::ffff:192.0.2.128/120", "::ffff:192.0.1.1", false},
	}
	for _, tt := range tests {
		prefix := netip.MustParsePrefix(tt.rule)
		matcher := newIPCidrMatcher(t, prefix.Addr(), prefix.Bits())
		must.Eq(t, tt.expected, matcher.MatchIP(new(netip.MustParseAddr(tt.input))), must.Sprintf("no match: %v", tt))
	}
}

func newIPCidrMatcher(t *testing.T, ip netip.Addr, bits int) *Matcher {
	ipPrefixSet := new(bart.Fast[any])
	prefix, err := toPrefixUnmapped(ip, bits)
	must.NoError(t, err)
	ipPrefixSet.Insert(prefix, nil)

	matcher := new(Matcher)
	matcher.ipCidrMatcher = ipPrefixSet
	return matcher
}
