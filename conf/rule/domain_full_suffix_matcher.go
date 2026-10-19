package rule

import (
	"slices"
	"strings"
)

type domainFullAndSuffixMatcher map[string]*domainSegments

type domainSegments struct {
	match         match
	domainMatcher domainFullAndSuffixMatcher
}

type match byte

const (
	none   match = 0
	full   match = 1
	suffix match = 2
)

func newDomainFullAndSuffixMatcher() domainFullAndSuffixMatcher {
	return make(map[string]*domainSegments)
}

func (matcher domainFullAndSuffixMatcher) addDomainFullRule(domain string) {
	matcher.addDomainFullOrSuffixRule(domain, full)
}

func (matcher domainFullAndSuffixMatcher) addDomainSuffixRule(domain string) {
	matcher.addDomainFullOrSuffixRule(domain, suffix)
}

func (matcher domainFullAndSuffixMatcher) addDomainFullOrSuffixRule(domain string, matchType match) {
	// domain URLs are case-insensitive
	segments := strings.Split(strings.ToLower(trimDomainRootDot(domain)), ".")
	loopedDomainMatcher := matcher
	for i := len(segments) - 1; i >= 1; i-- {
		segment := segments[i]
		nextSegment, ok := loopedDomainMatcher[segment]
		if !ok {
			nextSegment = new(domainSegments)
			nextSegment.match = none
			nextSegment.domainMatcher = domainFullAndSuffixMatcher{}
			loopedDomainMatcher[segment] = nextSegment
		} else {
			if nextSegment.match == suffix {
				return
			}
		}

		if nextSegment.domainMatcher == nil {
			nextSegment.domainMatcher = domainFullAndSuffixMatcher{}
		}
		loopedDomainMatcher = nextSegment.domainMatcher
	}

	last := segments[0]
	nextSegment, ok := loopedDomainMatcher[last]
	if !ok {
		nextSegment = new(domainSegments)
		nextSegment.match = matchType
		loopedDomainMatcher[last] = nextSegment
	} else {
		if nextSegment.match != suffix {
			nextSegment.match = matchType
		}
	}
}

func (matcher domainFullAndSuffixMatcher) match(domain string) bool {
	segments := strings.Split(strings.ToLower(domain), ".")
	loopedDomainMatcher := matcher
	var loopedSegment *domainSegments
	for _, segment := range slices.Backward(segments) {
		nextSegment, ok := loopedDomainMatcher[segment]
		if !ok {
			return false
		}

		if nextSegment.match == suffix {
			return true
		}
		loopedDomainMatcher = nextSegment.domainMatcher
		loopedSegment = nextSegment
	}
	if loopedSegment == nil {
		panic("domain can't be empty")
	}
	return loopedSegment.match == full
}

// A fully qualified domain name may end with a dot for the DNS root (e.g.,
// "example.com."), which should be treated the same as "example.com"
func trimDomainRootDot(domain string) string {
	return strings.TrimSuffix(domain, ".")
}
