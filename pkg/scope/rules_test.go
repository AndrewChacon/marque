package scope

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCIDROrIP_BareIPv6Literal covers the one shape no existing
// test exercised: a bare IPv6 host address with no "/" prefix at all
// (as opposed to an IPv6 CIDR like "2001:db8::/32", which every
// existing IPv6 test uses). This is what decides the /128 default
// prefix branch (ip.To4() == nil) rather than the /32 one bare IPv4
// addresses take.
func TestParseCIDROrIP_BareIPv6Literal(t *testing.T) {
	ipnet, err := parseCIDROrIP("2001:db8::1")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1/128", ipnet.String())
}

func TestParseCIDROrIP_BareIPv4Literal(t *testing.T) {
	ipnet, err := parseCIDROrIP("10.0.0.5")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5/32", ipnet.String())
}

// TestParseCIDROrIP_NotAnIPOrCIDR exercises parseCIDROrIP directly
// with input that's neither — unreachable through the normal
// addRule -> looksLikeCIDROrIP -> parseCIDROrIP call chain (anything
// looksLikeCIDROrIP rejects never reaches parseCIDROrIP at all), but
// calling it directly proves the function itself still fails closed
// if that calling convention ever changes.
func TestParseCIDROrIP_NotAnIPOrCIDR(t *testing.T) {
	_, err := parseCIDROrIP("not-an-ip-or-cidr")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid IP address or CIDR")
}

// TestCidrError_MalformedAddressWithValidLookingPrefix covers
// cidrError's fallback branch: a CIDR string whose prefix number
// parses fine and is in range, so the "prefix must be 0-N" special
// case doesn't apply, but the address portion itself is garbage —
// every existing malformed-CIDR test uses an out-of-range prefix
// instead, which takes the other branch.
func TestCidrError_MalformedAddressWithValidLookingPrefix(t *testing.T) {
	_, err := parseCIDROrIP("300.1.1.1/24")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `CIDR "300.1.1.1/24" is invalid`)
	assert.NotContains(t, err.Error(), "prefix must be")
}

// TestParseDomainRule_InvalidWildcardPattern covers the
// wildcard-specific validation error (base == "" or contains another
// "*"), distinct from validHostname's plain "not a valid hostname"
// error every existing invalid-domain test triggers instead.
func TestParseDomainRule_InvalidWildcardPattern(t *testing.T) {
	cases := []string{"*.", "a*.acme.com", "*.*.acme.com"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			_, err := parseDomainRule(raw)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "wildcard must be a single leading")
		})
	}
}

func TestValidHostname_SingleLabelAndFQDN(t *testing.T) {
	assert.True(t, validHostname("webserver01"))
	assert.True(t, validHostname("foo.acme.com"))
	assert.False(t, validHostname("-leadinghyphen.com"))
	assert.False(t, validHostname("trailinghyphen-.com"))
}
