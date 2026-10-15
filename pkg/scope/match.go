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

// Check reports whether ip is in scope right now. This is the
// re-check that must be performed against a resolved address at
// connection time, independent of any earlier hostname-based
// decision, to close the DNS-rebinding gap described in
// THREAT_MODEL.md — a hostname check and the IP it eventually
// resolves to are not guaranteed to agree.
func (s *Scope) Check(ip net.IP) Decision {
	if ip == nil {
		return s.decide(false, "no IP address provided", "", "")
	}
	target := ip.String()

	for _, r := range s.excludeCIDRs {
		if r.ipnet.Contains(ip) {
			return s.decide(false, fmt.Sprintf("matched exclude %s", r.raw), r.raw, target)
		}
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
	if now.After(s.End) {
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
