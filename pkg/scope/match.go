package scope

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Decision records the outcome of a single scope check: whether the
// target is allowed, which rule (if any) decided that, and why. It is
// also the unit that pkg/audit logs — see audit.Log.
type Decision struct {
	// Allowed is the scope outcome: true if Target is in scope and the
	// engagement window is currently open.
	Allowed bool `json:"allowed"`
	// Mode is copied from the Scope that produced this Decision. It
	// does not affect Allowed — it's metadata telling the consumer
	// how to react (block, warn-and-pass, or take no real action).
	Mode Mode `json:"mode"`
	// Target is the IP or hostname that was checked, as passed to
	// Check or CheckHost (or its net.IP.String() form).
	Target string `json:"target"`
	// MatchedRule is the raw include/exclude entry that decided this
	// outcome, or empty if nothing matched (an implicit deny).
	MatchedRule string `json:"matched_rule,omitempty"`
	// Reason is a human-readable explanation, suitable for printing
	// directly in a CLI violation message or audit export.
	Reason string `json:"reason"`
}

// Check reports whether ip is in scope right now: denied if it falls
// in an exclude CIDR, allowed if it falls in an include CIDR, denied
// otherwise. Used directly for a literal-IP target; a hostname target
// uses CheckHost instead, which re-validates its resolved address
// with CheckResolvedIP rather than this method — see CheckResolvedIP
// for why.
func (s *Scope) Check(ip net.IP) Decision {
	if ip == nil {
		return s.decide(false, "no IP address provided", "", "")
	}
	target := ip.String()

	if r, ok := s.matchedExclude(ip); ok {
		return s.decide(false, fmt.Sprintf("matched exclude %s", r.raw), r.raw, target)
	}
	for _, r := range s.includeCIDRs {
		if r.ipnet.Contains(ip) {
			return s.decide(true, fmt.Sprintf("matched include %s", r.raw), r.raw, target)
		}
	}
	return s.decide(false, "no include rule matched", "", target)
}

// CheckHost reports whether host is in scope right now. Domain rules
// (including wildcard subdomains) are matched here; a literal IP
// string is delegated to Check so both entry points share one
// matching outcome for the same address.
func (s *Scope) CheckHost(host string) Decision {
	h := normalizeHost(host)
	if h == "" {
		return s.decide(false, "empty target", "", host)
	}

	if ip := net.ParseIP(h); ip != nil {
		return s.Check(ip)
	}

	for _, r := range s.excludeDomains {
		if r.matches(h) {
			return s.decide(false, fmt.Sprintf("matched exclude %s", r.raw), r.raw, h)
		}
	}
	for _, r := range s.includeDomains {
		if r.matches(h) {
			return s.decide(true, fmt.Sprintf("matched include %s", r.raw), r.raw, h)
		}
	}
	return s.decide(false, "no include rule matched", "", h)
}

// CheckResolvedIP re-validates ip — the address a hostname that
// already passed CheckHost resolved to — against only the exclude
// rules. This is the DNS-rebinding close described in
// THREAT_MODEL.md: a hostname check and the IP it eventually resolves
// to are not guaranteed to agree, so the resolved address gets a
// second look before anything connects to it.
//
// Deliberately exclude-only, not a full Check: the hostname's
// inclusion already came from its own domain rule, so this doesn't
// re-demand the resolved address independently match some CIDR
// include rule too — most real scope files describe a target by
// domain alone with no corresponding CIDR at all (a third-party
// site's IP ranges are rarely stable or enumerable), and requiring
// one would make domain-only include rules unusable in practice. What
// this does catch is the one failure mode that actually matters here:
// a nominally in-scope hostname resolving into a range the scope file
// explicitly excludes.
func (s *Scope) CheckResolvedIP(ip net.IP) Decision {
	if ip == nil {
		return s.decide(false, "no IP address provided", "", "")
	}
	target := ip.String()

	if r, ok := s.matchedExclude(ip); ok {
		return s.decide(false, fmt.Sprintf("matched exclude %s", r.raw), r.raw, target)
	}
	return s.decide(true, "resolved address is not in any excluded range", "", target)
}

// matchedExclude reports the first exclude CIDR containing ip, if
// any — the one check Check and CheckResolvedIP both need before
// diverging on what happens if nothing matches.
func (s *Scope) matchedExclude(ip net.IP) (cidrRule, bool) {
	for _, r := range s.excludeCIDRs {
		if r.ipnet.Contains(ip) {
			return r, true
		}
	}
	return cidrRule{}, false
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// decide applies the engagement-window check on top of a raw
// rule-matching result. An expired or not-yet-started window denies
// regardless of what the CIDR/domain rules said — fail-closed applies
// to time the same way it applies to address space.
func (s *Scope) decide(allowed bool, reason, rule, target string) Decision {
	now := time.Now().UTC()
	if now.Before(s.Start) {
		return Decision{
			Allowed: false,
			Mode:    s.Mode,
			Target:  target,
			Reason:  fmt.Sprintf("engagement window has not started yet (begins %s)", s.Start.Format(time.RFC3339)),
		}
	}
	if s.End != nil && now.After(*s.End) {
		return Decision{
			Allowed: false,
			Mode:    s.Mode,
			Target:  target,
			Reason:  fmt.Sprintf("engagement window ended %s", s.End.Format(time.RFC3339)),
		}
	}
	return Decision{
		Allowed:     allowed,
		Mode:        s.Mode,
		Target:      target,
		MatchedRule: rule,
		Reason:      reason,
	}
}
