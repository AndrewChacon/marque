package scope

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type cidrRule struct {
	raw   string
	ipnet *net.IPNet
}

type domainRule struct {
	raw      string
	wildcard bool
	base     string // "acme.com" for both "acme.com" and "*.acme.com"
}

// matches reports whether host falls under this domain rule. A
// wildcard rule ("*.acme.com") matches any subdomain at any depth
// (foo.acme.com, deep.sub.acme.com) but not the apex domain itself —
// list the apex separately if it should also be in scope. This is
// intentionally broader than TLS SAN wildcard semantics (which match
// only one label deep), since ROEs generally mean "this domain and
// everything under it," not "exactly one level down."
func (d domainRule) matches(host string) bool {
	if !d.wildcard {
		return host == d.base
	}
	return strings.HasSuffix(host, "."+d.base)
}

func looksLikeCIDROrIP(s string) bool {
	if strings.Contains(s, "/") {
		return true
	}
	return net.ParseIP(s) != nil
}

func parseCIDROrIP(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, cidrError(s, err)
		}
		return ipnet, nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%q is not a valid IP address or CIDR", s)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits))
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid IP address: %w", s, err)
	}
	return ipnet, nil
}

// cidrError turns the stdlib's generic "invalid CIDR address" error
// into an actionable one when the problem is specifically an
// out-of-range prefix length, per the fail-loud/actionable-errors
// principle in docs/UX_FLOW.md.
func cidrError(raw string, err error) error {
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) == 2 {
		maxBits := 32
		if strings.Contains(parts[0], ":") {
			maxBits = 128
		}
		if n, perr := strconv.Atoi(parts[1]); perr == nil && (n < 0 || n > maxBits) {
			return fmt.Errorf("CIDR %q is invalid: prefix must be 0-%d", raw, maxBits)
		}
	}
	return fmt.Errorf("CIDR %q is invalid: %w", raw, err)
}

// domainLabel matches a single DNS label: alphanumeric, internal
// hyphens allowed, no leading/trailing hyphen. Lowercase only — its
// one caller always lowercases first.
var domainLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func parseDomainRule(raw string) (domainRule, error) {
	s := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))

	wildcard := false
	base := s
	if strings.HasPrefix(s, "*.") {
		wildcard = true
		base = s[2:]
	}

	if base == "" || strings.Contains(base, "*") {
		return domainRule{}, fmt.Errorf("invalid domain pattern %q: wildcard must be a single leading \"*.\"", raw)
	}
	if !validHostname(base) {
		return domainRule{}, fmt.Errorf("invalid domain pattern %q: not a valid hostname", raw)
	}

	return domainRule{raw: raw, wildcard: wildcard, base: base}, nil
}

func validHostname(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !domainLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}
