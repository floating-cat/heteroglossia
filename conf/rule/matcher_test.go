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
