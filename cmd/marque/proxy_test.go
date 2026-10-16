package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkProxyPreflight and the pure formatting functions are tested
// directly here rather than through a full cmd.Execute() + Serve()
// lifecycle: the real substance (scope checks, dialing, relay,
// DNS-rebinding defense) is already proven end to end in
// internal/proxy's integration tests against a real listener. What's
// specific to this CLI layer — the --force gate, and how a Decision
// renders — doesn't need a live network to verify, and the full
// start/Ctrl-C lifecycle is covered by manual smoke testing.

func TestCheckProxyPreflight_ActiveWindow(t *testing.T) {
	now := time.Now()
	s := testScope(t, now.Add(-time.Hour), now.Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	assert.NoError(t, checkProxyPreflight(s, false, now))
	assert.NoError(t, checkProxyPreflight(s, true, now), "force is a no-op on an active window")
}

func TestCheckProxyPreflight_ExpiredWithoutForce(t *testing.T) {
	now := time.Now()
	s := testScope(t, now.Add(-48*time.Hour), now.Add(-time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	err := checkProxyPreflight(s, false, now)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")
}

func TestCheckProxyPreflight_ExpiredWithForce(t *testing.T) {
	now := time.Now()
	s := testScope(t, now.Add(-48*time.Hour), now.Add(-time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	assert.NoError(t, checkProxyPreflight(s, true, now))
}

func TestPrintProxyBanner(t *testing.T) {
	now := time.Now()
	s := testScope(t, now.Add(-time.Hour), now.Add(80*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	s.Client = "Acme Corp"

	var buf bytes.Buffer
	printProxyBanner(&buf, s, "127.0.0.1:1080")
	out := buf.String()

	assert.Contains(t, out, "test-engagement (Acme Corp)")
	assert.Contains(t, out, "3 days remaining")
	assert.Contains(t, out, "enforce")
	assert.Contains(t, out, "127.0.0.1:1080")
}

func TestCheckProxyPreflight_OpenEndedNeverRefuses(t *testing.T) {
	now := time.Now()
	s := testScopeOpenEnded(t, now.Add(-time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	assert.NoError(t, checkProxyPreflight(s, false, now))
}

func TestPrintProxyBanner_OpenEnded(t *testing.T) {
	now := time.Now()
	s := testScopeOpenEnded(t, now.Add(-time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)

	var buf bytes.Buffer
	printProxyBanner(&buf, s, "127.0.0.1:1080")
	assert.Contains(t, buf.String(), "ongoing")
}

func TestPrintDecision_Text(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var buf bytes.Buffer
	printDecision(&buf, scope.Decision{Allowed: true, Target: "10.0.0.1", Reason: "matched include 10.0.0.0/16"}, false)
	assert.Contains(t, buf.String(), "ALLOW")
	assert.Contains(t, buf.String(), "10.0.0.1")

	buf.Reset()
	printDecision(&buf, scope.Decision{Allowed: false, Target: "192.168.1.1", Reason: "no include rule matched"}, false)
	assert.Contains(t, buf.String(), "BLOCK")
}

func TestPrintDecision_JSON(t *testing.T) {
	var buf bytes.Buffer
	printDecision(&buf, scope.Decision{Allowed: true, Target: "10.0.0.1", Reason: "matched include 10.0.0.0/16"}, true)

	var d scope.Decision
	require.NoError(t, json.Unmarshal(buf.Bytes(), &d))
	assert.True(t, d.Allowed)
	assert.Equal(t, "10.0.0.1", d.Target)
}

// TestRunProxy_NoScopeNoActiveEngagementReturnsEarly proves the
// engagement-context retrofit: with neither --scope nor an active
// engagement, runProxy must fail via path resolution before ever
// touching a real listener or audit log — the same pure, fast
// early-return path.Execute() tests already rely on for validate.
func TestRunProxy_NoScopeNoActiveEngagementReturnsEarly(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	cmd := newProxyCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope")
	assert.Contains(t, err.Error(), "engagement use")
}
