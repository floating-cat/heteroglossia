package rule

import (
	"net/netip"
	"testing"

	"github.com/shoenig/test/must"
)

func TestPrivateIPMatch(t *testing.T) {
	matcher := newMatcher([]string{"ip-set-tag/private"})
	store, err := NewDomainIPSetRulesQueryStore("../../domain-ip-set-rules-sample.db")
	must.NoError(t, err)
	err = matcher.SetupRulesData(store)
	must.NoError(t, err)

	must.True(t, matcher.MatchIP(new(netip.MustParseAddr("127.0.0.1"))))
}

func TestDomainWithTrailingDotMatch(t *testing.T) {
	matcher := newMatcher([]string{
		"domain-full/example.com",
		"domain-suffix/example.org.",
		`domain-regex/^www\.example\.net$`,
	})
	//goland:noinspection GoMaybeNil
	err := matcher.SetupRulesData(nil)
	must.NoError(t, err)

	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", true},
		{"example.com.", true},
		{"www.example.org", true},
		{"www.example.org.", true},
		{"www.example.net.", true},
		{"example.com..", false},
		{".", false},
	}
	for _, tt := range tests {
		must.Eq(t, tt.expected, matcher.MatchDomain(tt.input), must.Sprintf("no match: %v", tt))
	}
}

func TestInvalidIPCIDRRules(t *testing.T) {
	for _, rule := range []string{"ip/foo", "cidr/foo/42"} {
		matcher := newMatcher([]string{rule})
		//goland:noinspection GoMaybeNil
		err := matcher.SetupRulesData(nil)
		must.Error(t, err)
	}
}
