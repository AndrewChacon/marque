package scope

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustScope builds a Scope from a scope.yaml body (everything under
// and including the top-level "scope:" and "mode:" keys), wrapping it
// with a fixed engagement window that's safely active (started an
// hour ago, ends in an hour) so window logic doesn't interfere with
// matcher-focused tests.
func mustScope(t *testing.T, scopeYAML string) *Scope {
	t.Helper()
	return mustScopeMode(t, "enforce", scopeYAML)
}

func mustScopeMode(t *testing.T, mode, scopeYAML string) *Scope {
	t.Helper()
	doc := fmt.Sprintf(`
engagement:
  name: test
  start: %s
  end: %s
mode: %s
%s
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339), mode, scopeYAML)
	s, err := Parse([]byte(doc))
	require.NoError(t, err)
	return s
}

func TestCheck_IncludeExclude(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/16
  exclude:
    - 10.0.5.0/24
`)

	cases := []struct {
		name        string
		ip          string
		wantAllowed bool
	}{
		{"in broad include", "10.0.1.5", true},
		{"inside excluded subrange", "10.0.5.10", false},
		{"outside include entirely", "192.168.1.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := s.Check(net.ParseIP(tc.ip))
			assert.Equal(t, tc.wantAllowed, d.Allowed, d.Reason)
		})
	}
}

// TestCheck_ExcludeAlwaysWinsRegardlessOfSpecificity locks in the
// confirmed design decision in ARCHITECTURE.md: exclude wins on list
// membership alone, not on which rule is more specific. A broad
// exclude swallows a narrower include sitting inside it.
func TestCheck_ExcludeAlwaysWinsRegardlessOfSpecificity(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.5.0/24
  exclude:
    - 10.0.0.0/8
`)
	d := s.Check(net.ParseIP("10.0.5.10"))
	assert.False(t, d.Allowed, "broad exclude must win even though include is narrower")
}

func TestCheck_IPv6(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - "2001:db8::/32"
  exclude:
    - "2001:db8:1::/48"
`)

	cases := []struct {
		name        string
		ip          string
		wantAllowed bool
	}{
		{"in broad include", "2001:db8:2::1", true},
		{"inside excluded subrange", "2001:db8:1::1", false},
		{"outside include entirely", "2001:db9::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := s.Check(net.ParseIP(tc.ip))
			assert.Equal(t, tc.wantAllowed, d.Allowed, d.Reason)
		})
	}
}

func TestCheck_BareIPTreatedAsHostRoute(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.5
`)
	assert.True(t, s.Check(net.ParseIP("10.0.0.5")).Allowed)
	assert.False(t, s.Check(net.ParseIP("10.0.0.6")).Allowed)
}

func TestCheckHost_WildcardSubdomain(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - "*.acme.com"
  exclude:
    - "db.internal.acme.com"
`)

	cases := []struct {
		name        string
		host        string
		wantAllowed bool
	}{
		{"direct subdomain", "foo.acme.com", true},
		{"nested subdomain", "deep.sub.acme.com", true},
		{"apex not matched by wildcard", "acme.com", false},
		{"excluded subdomain wins", "db.internal.acme.com", false},
		{"unrelated domain", "evil.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := s.CheckHost(tc.host)
			assert.Equal(t, tc.wantAllowed, d.Allowed, d.Reason)
		})
	}
}

func TestCheckHost_ExactAndNormalization(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - "Target.Acme.com"
`)
	assert.True(t, s.CheckHost("target.acme.com").Allowed)
	assert.True(t, s.CheckHost("TARGET.ACME.COM.").Allowed, "case and trailing dot must normalize")
	assert.False(t, s.CheckHost("other.acme.com").Allowed)
}

func TestCheckHost_LiteralIPDelegatesToCheck(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/16
`)
	assert.True(t, s.CheckHost("10.0.1.1").Allowed)
	assert.False(t, s.CheckHost("192.168.1.1").Allowed)
}

func TestCheckHost_Empty(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/16
`)
	d := s.CheckHost("")
	assert.False(t, d.Allowed)
	assert.Equal(t, "empty target", d.Reason)
}

func TestCheck_NilIP(t *testing.T) {
	s := mustScope(t, `
scope:
  include:
    - 10.0.0.0/16
`)
	d := s.Check(nil)
	assert.False(t, d.Allowed)
}

func TestCheck_ModeCarriesThroughRegardlessOfOutcome(t *testing.T) {
	s := mustScopeMode(t, "warn", `
scope:
  include:
    - 10.0.0.0/16
`)
	allowed := s.Check(net.ParseIP("10.0.1.1"))
	denied := s.Check(net.ParseIP("192.168.1.1"))
	assert.Equal(t, ModeWarn, allowed.Mode)
	assert.Equal(t, ModeWarn, denied.Mode)
	assert.True(t, allowed.Allowed)
	assert.False(t, denied.Allowed)
}

func TestCheck_EngagementWindow(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		doc := fmt.Sprintf(`
engagement:
  name: test
  start: %s
  end: %s
mode: enforce
scope:
  include:
    - 10.0.0.0/8
`, time.Now().Add(-48*time.Hour).Format(time.RFC3339), time.Now().Add(-24*time.Hour).Format(time.RFC3339))
		s, err := Parse([]byte(doc))
		require.NoError(t, err)
		d := s.Check(net.ParseIP("10.0.0.1"))
		assert.False(t, d.Allowed)
		assert.Contains(t, d.Reason, "ended")
	})

	t.Run("not yet started", func(t *testing.T) {
		doc := fmt.Sprintf(`
engagement:
  name: test
  start: %s
  end: %s
mode: enforce
scope:
  include:
    - 10.0.0.0/8
`, time.Now().Add(24*time.Hour).Format(time.RFC3339), time.Now().Add(48*time.Hour).Format(time.RFC3339))
		s, err := Parse([]byte(doc))
		require.NoError(t, err)
		d := s.Check(net.ParseIP("10.0.0.1"))
		assert.False(t, d.Allowed)
		assert.Contains(t, d.Reason, "not started")
	})
}

func TestParse_MalformedInputs(t *testing.T) {
	cases := []struct {
		name            string
		doc             string
		wantErrContains string
	}{
		{
			name:            "not yaml",
			doc:             "not: [valid",
			wantErrContains: "parsing scope file",
		},
		{
			name: "missing name",
			doc: `
engagement:
  start: 2026-01-01T00:00:00Z
  end: 2026-01-02T00:00:00Z
scope:
  include: ["10.0.0.0/8"]
`,
			wantErrContains: "engagement.name",
		},
		{
			name: "bad start",
			doc: `
engagement:
  name: x
  start: not-a-date
  end: 2026-01-02T00:00:00Z
scope:
  include: ["10.0.0.0/8"]
`,
			wantErrContains: "engagement.start",
		},
		{
			name: "end before start",
			doc: `
engagement:
  name: x
  start: 2026-01-02T00:00:00Z
  end: 2026-01-01T00:00:00Z
scope:
  include: ["10.0.0.0/8"]
`,
			wantErrContains: "must be after",
		},
		{
			name: "invalid cidr prefix",
			doc: `
engagement:
  name: x
  start: 2026-01-01T00:00:00Z
  end: 2026-01-02T00:00:00Z
scope:
  include: ["10.0.0.0/33"]
`,
			wantErrContains: "prefix must be 0-32",
		},
		{
			name: "invalid ipv6 cidr prefix",
			doc: `
engagement:
  name: x
  start: 2026-01-01T00:00:00Z
  end: 2026-01-02T00:00:00Z
scope:
  include: ["2001:db8::/129"]
`,
			wantErrContains: "prefix must be 0-128",
		},
		{
			name: "invalid domain",
			doc: `
engagement:
  name: x
  start: 2026-01-01T00:00:00Z
  end: 2026-01-02T00:00:00Z
scope:
  include: ["not a domain!!"]
`,
			wantErrContains: "not a valid hostname",
		},
		{
			name: "invalid mode",
			doc: `
engagement:
  name: x
  start: 2026-01-01T00:00:00Z
  end: 2026-01-02T00:00:00Z
scope:
  include: ["10.0.0.0/8"]
mode: yolo
`,
			wantErrContains: "mode",
		},
		{
			name: "no include rules",
			doc: `
engagement:
  name: x
  start: 2026-01-01T00:00:00Z
  end: 2026-01-02T00:00:00Z
scope:
  include: []
`,
			wantErrContains: "at least one",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrContains)
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/scope.yaml")
	require.Error(t, err)
}

func TestLoad_RealFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/scope.yaml"
	doc := fmt.Sprintf(`
engagement:
  name: test
  start: %s
  end: %s
mode: enforce
scope:
  include:
    - 10.0.0.0/8
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339))
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o644))

	s, err := Load(path)
	require.NoError(t, err)
	assert.True(t, s.Check(net.ParseIP("10.0.0.1")).Allowed)
}
