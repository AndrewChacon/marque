package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/pkg/scope"
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

func TestValidateCmd_MissingScopeFlag(t *testing.T) {
	cmd := newValidateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope")
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
