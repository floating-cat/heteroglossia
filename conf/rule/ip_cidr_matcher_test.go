package rule

import (
	"net/netip"
	"testing"

	"github.com/shoenig/test/must"
	"go4.org/netipx"
)

func TestIpMatchWithIp(t *testing.T) {
	tests := []struct {
		rule     string
		input    string
		expected bool
	}{
		{"192.0.2.1", "192.0.2.1", true},
		{"192.0.2.1", "192.0.2.2", false},
		{"::1", "::1", true},
		{"::1", "::2", false},
		{"::ffff:192.0.2.128", "192.0.2.128", false},
		{"192.0.2.128", "::ffff:192.0.2.128", false},
	}
	for _, tt := range tests {
		var ipSetBuilder netipx.IPSetBuilder
		ipSetBuilder.Add(netip.MustParseAddr(tt.rule))
		ipset, _ := ipSetBuilder.IPSet()
		must.Eq(t, tt.expected, ipset.Contains(netip.MustParseAddr(tt.input)), must.Sprintf("no match: %v", tt))
	}
}

func TestIpMatchWithCidr(t *testing.T) {
	tests := []struct {
		rule     string
		input    string
		expected bool
	}{
		{"192.0.2.1", "192.0.2.1/32", true},
		{"192.0.2.1", "192.0.2.1/31", false},
	}
	for _, tt := range tests {
		var ipSetBuilder netipx.IPSetBuilder
		ipSetBuilder.Add(netip.MustParseAddr(tt.rule))
		ipset, _ := ipSetBuilder.IPSet()
		must.Eq(t, tt.expected, ipset.ContainsPrefix(netip.MustParsePrefix(tt.input)), must.Sprintf("no match: %v", tt))
	}
}

func TestCidrMatchWithIp(t *testing.T) {
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
		var ipSetBuilder netipx.IPSetBuilder
		ipSetBuilder.AddPrefix(netip.MustParsePrefix(tt.rule))
		ipset, _ := ipSetBuilder.IPSet()
		must.Eq(t, tt.expected, ipset.Contains(netip.MustParseAddr(tt.input)), must.Sprintf("no match: %v", tt))
	}
}
