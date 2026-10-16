package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngagementCurrentCmd_NoActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	cmd := newEngagementCurrentCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "no active engagement")
	assert.Contains(t, out.String(), "engagement use")
}

func TestEngagementCurrentCmd_DefaultLine(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme-2026q4", time.Now().Add(-time.Hour), time.Now().Add(13*24*time.Hour))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newEngagementCurrentCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "acme-2026q4 (Acme Corp)")
	assert.Contains(t, out.String(), "active")
	assert.Contains(t, out.String(), "remaining")
}

func TestEngagementCurrentCmd_Short_PrintsBareName(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme-2026q4", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SetArgs([]string{"--short"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Equal(t, "acme-2026q4\n", out.String())
}

func TestEngagementCurrentCmd_DefaultLine_UsesStoreKeyNotScopeFilesSelfReportedName(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	doc := `
engagement:
  name: whatever-the-file-says
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`
	require.NoError(t, store.Add("acme-2026q4", []byte(doc)))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newEngagementCurrentCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "acme-2026q4")
	assert.NotContains(t, out.String(), "whatever-the-file-says")
}

func TestEngagementCurrentCmd_Short_UsesStoreKeyNotScopeFilesSelfReportedName(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	// Added under "acme-2026q4" but the file's own engagement.name differs —
	// same mismatch TestEngagementAddCmd_NonInteractiveImport exercises for add.
	doc := `
engagement:
  name: whatever-the-file-says
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`
	require.NoError(t, store.Add("acme-2026q4", []byte(doc)))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SetArgs([]string{"--short"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Equal(t, "acme-2026q4\n", out.String(), "--short must print the round-trippable store key, not the scope file's self-reported name")
}

func TestEngagementCurrentCmd_Short_NoActiveEngagementPrintsNothingAndSucceeds(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SetArgs([]string{"--short"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Empty(t, out.String())
}

func TestEngagementCurrentCmd_Short_BrokenScopeFileStillHardErrors(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, store.Add("broken", []byte("not valid yaml: [")))
	require.NoError(t, store.SetActive("broken"))

	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--short"})
	cmd.SetOut(&bytes.Buffer{})

	err := cmd.Execute()
	require.Error(t, err, "--short must not silently swallow a broken active engagement the way it does a merely-unset one")
	assert.Contains(t, err.Error(), "broken")
}

func TestEngagementCurrentCmd_JSON_NoActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	var got map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, false, got["active"])
	_, hasName := got["name"]
	assert.False(t, hasName, "name should be omitted entirely when nothing is active")
}

func TestEngagementCurrentCmd_JSON_ActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme-2026q4", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	var got currentJSON
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.True(t, got.Active)
	assert.Equal(t, "acme-2026q4", got.Name)
	assert.Equal(t, "Acme Corp", got.Client)
	assert.Equal(t, "active", got.Status)
}

func TestEngagementCurrentCmd_JSON_UsesStoreKeyNotScopeFilesSelfReportedName(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	doc := `
engagement:
  name: whatever-the-file-says
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`
	require.NoError(t, store.Add("acme-2026q4", []byte(doc)))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	var got currentJSON
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.Equal(t, "acme-2026q4", got.Name)
}

func TestEngagementCurrentCmd_OpenEndedEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagementOpenEnded(t, store, "bugbounty", time.Now().Add(-time.Hour))
	require.NoError(t, store.SetActive("bugbounty"))

	cmd := newEngagementCurrentCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "ongoing")
}

func TestEngagementCurrentCmd_BrokenScopeFileIsActionableInDefaultMode(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, store.Add("broken", []byte("not valid yaml: [")))
	require.NoError(t, store.SetActive("broken"))

	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetOut(&bytes.Buffer{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")
}

func TestEngagementCurrentCmd_JSONAndShortAreMutuallyExclusive(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	cmd := newEngagementCurrentCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--json", "--short"})
	cmd.SetOut(&bytes.Buffer{})

	err := cmd.Execute()
	require.Error(t, err)
}

func TestEngagementCurrentCmd_ExpiredEngagementStatus(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "globex-oct", time.Now().Add(-96*time.Hour), time.Now().Add(-48*time.Hour))
	require.NoError(t, store.SetActive("globex-oct"))

	cmd := newEngagementCurrentCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "expired")
}
