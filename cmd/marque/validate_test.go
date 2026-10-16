package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndrewChacon/marque/internal/engagement"
	"github.com/AndrewChacon/marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testScope(t *testing.T, start, end time.Time, scopeYAML string) *scope.Scope {
	t.Helper()
	doc := fmt.Sprintf(`
engagement:
  name: test-engagement
  start: %s
  end: %s
mode: enforce
%s
`, start.Format(time.RFC3339), end.Format(time.RFC3339), scopeYAML)
	s, err := scope.Parse([]byte(doc))
	require.NoError(t, err)
	return s
}

func testScopeOpenEnded(t *testing.T, start time.Time, scopeYAML string) *scope.Scope {
	t.Helper()
	doc := fmt.Sprintf(`
engagement:
  name: test-engagement
  start: %s
mode: enforce
%s
`, start.Format(time.RFC3339), scopeYAML)
	s, err := scope.Parse([]byte(doc))
	require.NoError(t, err)
	return s
}

func TestPrintValidationTable_OpenEnded(t *testing.T) {
	s := testScopeOpenEnded(t, time.Now().Add(-time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var buf bytes.Buffer
	printValidationTable(&buf, s)
	out := buf.String()
	assert.Contains(t, out, "ongoing")
	assert.NotContains(t, out, "engagement window has ended")
}

func TestPrintValidationJSON_OpenEndedOmitsEnd(t *testing.T) {
	s := testScopeOpenEnded(t, time.Now().Add(-time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var buf bytes.Buffer
	require.NoError(t, printValidationJSON(&buf, s))
	out := buf.String()
	assert.Contains(t, out, `"status": "active"`)
	assert.NotContains(t, out, `"end"`)
}

func TestWindowStatus_OpenEndedIsNeverExpired(t *testing.T) {
	now := time.Now()
	active := testScopeOpenEnded(t, now.Add(-time.Hour), "scope:\n  include:\n    - 10.0.0.0/16\n")
	assert.Equal(t, "active", windowStatus(active, now))

	upcoming := testScopeOpenEnded(t, now.Add(time.Hour), "scope:\n  include:\n    - 10.0.0.0/16\n")
	assert.Equal(t, "upcoming", windowStatus(upcoming, now))
}

func TestWindowSummary_OpenEndedSaysOngoing(t *testing.T) {
	now := time.Now()
	s := testScopeOpenEnded(t, now.Add(-time.Hour), "scope:\n  include:\n    - 10.0.0.0/16\n")
	assert.Equal(t, "ongoing — no end date", windowSummary(s, now))
}

func TestWindowDateRange_OpenEndedShowsOngoing(t *testing.T) {
	now := time.Now()
	s := testScopeOpenEnded(t, now.Add(-time.Hour), "scope:\n  include:\n    - 10.0.0.0/16\n")
	assert.Contains(t, windowDateRange(s), "→ ongoing")
}

func TestPrintValidationTable_Active(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(80*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
  exclude:
    - 10.0.5.0/24
`)
	var buf bytes.Buffer
	printValidationTable(&buf, s)
	out := buf.String()

	assert.Contains(t, out, "test-engagement")
	assert.Contains(t, out, "10.0.0.0/16")
	assert.Contains(t, out, "10.0.5.0/24")
	assert.Contains(t, out, "3 days remaining") // floor(80h/24h); comfortably clear of the exact-72h boundary
	assert.NotContains(t, out, "engagement window has ended")
}

func TestPrintValidationTable_Expired(t *testing.T) {
	s := testScope(t, time.Now().Add(-96*time.Hour), time.Now().Add(-48*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	t.Setenv("NO_COLOR", "1")

	var buf bytes.Buffer
	printValidationTable(&buf, s)
	out := buf.String()

	assert.Contains(t, out, "expired 2 days ago")
	assert.Contains(t, out, "engagement window has ended")
}

func TestPrintValidationTable_Upcoming(t *testing.T) {
	s := testScope(t, time.Now().Add(80*time.Hour), time.Now().Add(200*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var buf bytes.Buffer
	printValidationTable(&buf, s)
	assert.Contains(t, buf.String(), "starts in 3 days")
}

func TestPrintValidationTable_UpcomingShowsLoudWarning(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	s := testScope(t, time.Now().Add(80*time.Hour), time.Now().Add(200*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var buf bytes.Buffer
	printValidationTable(&buf, s)
	assert.Contains(t, buf.String(), "engagement window has not started yet")
}

func TestPrintValidationTable_NoExcludeSectionWhenEmpty(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var buf bytes.Buffer
	printValidationTable(&buf, s)
	assert.NotContains(t, buf.String(), "EXCLUDED")
}

func TestPrintValidationJSON(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
  exclude:
    - 10.0.5.0/24
`)
	var buf bytes.Buffer
	require.NoError(t, printValidationJSON(&buf, s))

	out := buf.String()
	assert.Contains(t, out, `"status": "active"`)
	assert.Contains(t, out, `"mode": "enforce"`)
	assert.Contains(t, out, "10.0.0.0/16")
	assert.Contains(t, out, "10.0.5.0/24")
}

func TestWindowStatus(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		start, end time.Time
		want       string
	}{
		{"active", now.Add(-time.Hour), now.Add(time.Hour), "active"},
		{"expired", now.Add(-48 * time.Hour), now.Add(-time.Hour), "expired"},
		{"upcoming", now.Add(time.Hour), now.Add(48 * time.Hour), "upcoming"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testScope(t, tc.start, tc.end, "scope:\n  include:\n    - 10.0.0.0/16\n")
			assert.Equal(t, tc.want, windowStatus(s, now))
		})
	}
}

func TestEngagementLabel(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	assert.Equal(t, "test-engagement", engagementLabel(s))

	s.Client = "Acme Corp"
	assert.Equal(t, "test-engagement (Acme Corp)", engagementLabel(s))
}

func TestPluralDays(t *testing.T) {
	assert.Equal(t, "1 day", pluralDays(1))
	assert.Equal(t, "0 days", pluralDays(0))
	assert.Equal(t, "5 days", pluralDays(5))
}

func writeTempScope(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestValidateCmd_ValidScope(t *testing.T) {
	path := writeTempScope(t, fmt.Sprintf(`
engagement:
  name: acme
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
mode: enforce
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339)))

	var out bytes.Buffer
	cmd := newValidateCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", path})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "acme")
}

func TestValidateCmd_ExpiredScopeWarnsButDoesNotError(t *testing.T) {
	path := writeTempScope(t, fmt.Sprintf(`
engagement:
  name: acme
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
mode: enforce
`, time.Now().Add(-96*time.Hour).Format(time.RFC3339), time.Now().Add(-48*time.Hour).Format(time.RFC3339)))

	var out bytes.Buffer
	cmd := newValidateCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", path})

	require.NoError(t, cmd.Execute(), "validate is a preflight check — it warns on an expired window, it doesn't fail")
	assert.Contains(t, out.String(), "engagement window has ended")
}

func TestValidateCmd_MalformedScope(t *testing.T) {
	path := writeTempScope(t, `
engagement:
  name: bad
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/33
`)

	cmd := newValidateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--scope", path})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prefix must be 0-32")
}

func TestValidateCmd_MissingFile(t *testing.T) {
	cmd := newValidateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--scope", filepath.Join(t.TempDir(), "nope.yaml")})

	err := cmd.Execute()
	require.Error(t, err)
}

func TestValidateCmd_MissingScopeFlagNoActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}

	cmd := newValidateCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope")
	assert.Contains(t, err.Error(), "engagement use")
}

func TestValidateCmd_FallsBackToActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	doc := fmt.Sprintf(`
engagement:
  name: acme-2026q4
  client: Acme Corp
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339))
	require.NoError(t, store.Add("acme-2026q4", []byte(doc)))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newValidateCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{}) // no --scope at all

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "acme-2026q4 (Acme Corp)")
}

func TestValidateCmd_ExplicitScopeStillOverridesActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	activeDoc := fmt.Sprintf(`
engagement:
  name: wrong-one
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339))
	require.NoError(t, store.Add("wrong-one", []byte(activeDoc)))
	require.NoError(t, store.SetActive("wrong-one"))

	overridePath := writeTempScope(t, fmt.Sprintf(`
engagement:
  name: the-right-one
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339)))

	cmd := newValidateCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--scope", overridePath})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "the-right-one")
	assert.NotContains(t, out.String(), "wrong-one")
}

func TestValidateCmd_JSONFlag(t *testing.T) {
	path := writeTempScope(t, fmt.Sprintf(`
engagement:
  name: acme
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
mode: enforce
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339)))

	var out bytes.Buffer
	cmd := newValidateCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", path, "--json"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"status": "active"`)
}

func TestValidateCmd_JSONFlag_OpenEndedOmitsEnd(t *testing.T) {
	path := writeTempScope(t, fmt.Sprintf(`
engagement:
  name: bugbounty
  start: %s
scope:
  include:
    - 10.0.0.0/16
mode: enforce
`, time.Now().Add(-time.Hour).Format(time.RFC3339)))

	var out bytes.Buffer
	cmd := newValidateCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--scope", path, "--json"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"status": "active"`)
	assert.NotContains(t, out.String(), `"end"`)
}
