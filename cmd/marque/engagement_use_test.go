package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addTestEngagement(t *testing.T, store *engagement.Store, name string, start, end time.Time) {
	t.Helper()
	doc := fmt.Sprintf(`
engagement:
  name: %s
  client: Acme Corp
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
`, name, start.Format(time.RFC3339), end.Format(time.RFC3339))
	require.NoError(t, store.Add(name, []byte(doc)))
}

func addTestEngagementOpenEnded(t *testing.T, store *engagement.Store, name string, start time.Time) {
	t.Helper()
	doc := fmt.Sprintf(`
engagement:
  name: %s
  client: Acme Corp
  start: %s
scope:
  include:
    - 10.0.0.0/16
`, name, start.Format(time.RFC3339))
	require.NoError(t, store.Add(name, []byte(doc)))
}

func TestPrintSwitchConfirmation_OpenEndedNeverWarns(t *testing.T) {
	now := time.Now()
	s := testScopeOpenEnded(t, now.Add(-time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var out bytes.Buffer
	printSwitchConfirmation(&out, "test-engagement", s, now)
	assert.NotContains(t, out.String(), "WARNING")
}

func TestPrintSwitchConfirmation_Active(t *testing.T) {
	now := time.Now()
	s := testScope(t, now.Add(-time.Hour), now.Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var out bytes.Buffer
	printSwitchConfirmation(&out, "test-engagement", s, now)
	assert.Contains(t, out.String(), "switched to")
	assert.NotContains(t, out.String(), "WARNING")
}

func TestPrintSwitchConfirmation_Expired(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	now := time.Now()
	s := testScope(t, now.Add(-96*time.Hour), now.Add(-48*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var out bytes.Buffer
	printSwitchConfirmation(&out, "test-engagement", s, now)
	assert.Contains(t, out.String(), "WARNING: this engagement expired 2 days ago")
}

func TestPrintSwitchConfirmation_UpcomingShowsWarning(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	now := time.Now()
	s := testScope(t, now.Add(time.Hour), now.Add(48*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var out bytes.Buffer
	printSwitchConfirmation(&out, "test-engagement", s, now)
	assert.Contains(t, out.String(), "WARNING")
	assert.Contains(t, out.String(), "starts in")
}

func TestPrintSwitchConfirmation_UsesStoreKeyNotScopeFilesSelfReportedName(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`) // s.Name == "test-engagement"
	var out bytes.Buffer
	printSwitchConfirmation(&out, "the-storage-key", s, time.Now())
	assert.Contains(t, out.String(), "the-storage-key")
	assert.NotContains(t, out.String(), "test-engagement")
}

func TestEngagementUseCmd_SwitchesActive(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme-2026q4", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	cmd := newEngagementUseCmdWithStore(store)
	cmd.SetArgs([]string{"acme-2026q4"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	active, err := store.Active()
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", active)
	assert.Contains(t, out.String(), "Acme Corp")
}

func TestEngagementUseCmd_UnknownNameIsActionable(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}

	cmd := newEngagementUseCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"nope"})
	cmd.SetOut(&bytes.Buffer{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "engagement add")
}

func TestEngagementUseCmd_InvalidScopeFileIsActionable(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, store.Add("broken", []byte("not valid yaml: [")))

	cmd := newEngagementUseCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"broken"})
	cmd.SetOut(&bytes.Buffer{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")

	active, activeErr := store.Active()
	require.NoError(t, activeErr)
	assert.Empty(t, active, "an invalid engagement must never become active")
}
