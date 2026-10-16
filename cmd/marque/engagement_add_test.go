package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWizardDate(t *testing.T) {
	got, err := parseWizardDate("2026-10-14")
	require.NoError(t, err)
	assert.True(t, got.Equal(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)))

	_, err = parseWizardDate("Oct 14 2026")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "YYYY-MM-DD")
}

func TestRunWizard_BuildsParseableScopeFile(t *testing.T) {
	input := "Acme Corp\n2026-10-01\n2026-10-28\n10.0.0.0/16, *.acme.com\n\n10.0.5.0/24\n\n"
	var out bytes.Buffer

	doc, err := runWizard(strings.NewReader(input), &out, "acme-2026q4")
	require.NoError(t, err)

	s, err := scope.Parse(doc)
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", s.Name)
	assert.Equal(t, "Acme Corp", s.Client)
	assert.Equal(t, []string{"10.0.0.0/16", "*.acme.com"}, s.IncludeRules)
	assert.Equal(t, []string{"10.0.5.0/24"}, s.ExcludeRules)
}

func TestRunWizard_NoExclusionsIsFine(t *testing.T) {
	input := "Acme Corp\n2026-10-01\n2026-10-28\n10.0.0.0/16\n\n\n"
	doc, err := runWizard(strings.NewReader(input), &bytes.Buffer{}, "acme-2026q4")
	require.NoError(t, err)

	s, err := scope.Parse(doc)
	require.NoError(t, err)
	assert.Empty(t, s.ExcludeRules)
}

func TestRunWizard_PromptsArePrintedToW(t *testing.T) {
	input := "Acme Corp\n2026-10-01\n2026-10-28\n10.0.0.0/16\n\n\n"
	var out bytes.Buffer

	_, err := runWizard(strings.NewReader(input), &out, "acme-2026q4")
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Client name")
	assert.Contains(t, out.String(), "in-scope CIDRs/domains")
	assert.Contains(t, out.String(), "Any exclusions")
}

func TestRunWizard_UnexpectedEOFMidPrompt(t *testing.T) {
	// Input runs out before the end date is given.
	input := "Acme Corp\n2026-10-01\n"
	_, err := runWizard(strings.NewReader(input), &bytes.Buffer{}, "acme-2026q4")
	require.Error(t, err)
}

func TestRunWizard_InvalidDateIsActionable(t *testing.T) {
	input := "Acme Corp\nnot-a-date\n"
	_, err := runWizard(strings.NewReader(input), &bytes.Buffer{}, "acme-2026q4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "YYYY-MM-DD")
}

func TestBuildScopeYAML_RoundTrips(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)

	doc, err := buildScopeYAML("acme-2026q4", "Acme Corp", start, &end,
		[]string{"10.0.0.0/16"}, nil)
	require.NoError(t, err)

	s, err := scope.Parse(doc)
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", s.Name)
	assert.True(t, s.Start.Equal(start))
	require.NotNil(t, s.End)
	assert.True(t, s.End.Equal(end))
}

func TestBuildScopeYAML_NilEndOmitsEndKey(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	doc, err := buildScopeYAML("bugbounty", "Acme Corp", start, nil,
		[]string{"10.0.0.0/16"}, nil)
	require.NoError(t, err)
	assert.NotContains(t, string(doc), "end:")

	s, err := scope.Parse(doc)
	require.NoError(t, err)
	assert.Nil(t, s.End)
}

func TestRunWizard_BlankEndIsOpenEnded(t *testing.T) {
	input := "Acme Corp\n2026-10-01\n\n10.0.0.0/16\n\n\n"
	doc, err := runWizard(strings.NewReader(input), &bytes.Buffer{}, "bugbounty")
	require.NoError(t, err)

	s, err := scope.Parse(doc)
	require.NoError(t, err)
	assert.Nil(t, s.End)
}

func TestRunWizard_EndPromptMentionsOngoing(t *testing.T) {
	input := "Acme Corp\n2026-10-01\n\n10.0.0.0/16\n\n\n"
	var out bytes.Buffer
	_, err := runWizard(strings.NewReader(input), &out, "bugbounty")
	require.NoError(t, err)
	assert.Contains(t, out.String(), "leave blank if ongoing")
}

func TestEngagementAddCmd_NonInteractiveImport(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	scopeFile := t.TempDir() + "/scope.yaml"
	require.NoError(t, os.WriteFile(scopeFile, []byte(`
engagement:
  name: whatever-the-file-says
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`), 0o600))

	cmd := newEngagementAddCmdWithStore(store)
	cmd.SetArgs([]string{"acme-2026q4", "--scope", scopeFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.True(t, store.Exists("acme-2026q4"), "the positional name is the storage key, independent of the file's own engagement.name")

	active, err := store.Active()
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", active, "the first-ever add should auto-activate using the storage key")
}

func TestEngagementAddCmd_RejectsInvalidImport(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	scopeFile := t.TempDir() + "/scope.yaml"
	require.NoError(t, os.WriteFile(scopeFile, []byte("not: yaml: at: all: ["), 0o600)) // malformed

	cmd := newEngagementAddCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"acme-2026q4", "--scope", scopeFile})
	cmd.SetOut(&bytes.Buffer{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.False(t, store.Exists("acme-2026q4"), "an invalid import must not be saved")

	active, activeErr := store.Active()
	require.NoError(t, activeErr)
	assert.Empty(t, active, "a rejected import must never become active")
}

func TestPrintAutoActivateNotice_UpcomingShowsWarning(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	now := time.Now()
	s := testScope(t, now.Add(time.Hour), now.Add(48*time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	var out bytes.Buffer
	printAutoActivateNotice(&out, "test-engagement", s, now)
	assert.Contains(t, out.String(), "WARNING")
	assert.Contains(t, out.String(), "starts in")
}

func TestPrintAutoActivateNotice_UsesStoreKeyNotScopeFilesSelfReportedName(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`) // s.Name == "test-engagement"
	var out bytes.Buffer
	printAutoActivateNotice(&out, "the-storage-key", s, time.Now())
	assert.Contains(t, out.String(), "the-storage-key")
	assert.NotContains(t, out.String(), "test-engagement")
}

func TestEngagementAddCmd_RefusesToOverwriteExistingEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme-2026q4", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	originalDoc, err := os.ReadFile(store.ScopePath("acme-2026q4"))
	require.NoError(t, err)

	scopeFile := t.TempDir() + "/scope.yaml"
	require.NoError(t, os.WriteFile(scopeFile, []byte(`
engagement:
  name: different-engagement
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`), 0o600))

	cmd := newEngagementAddCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"acme-2026q4", "--scope", scopeFile})
	cmd.SetOut(&bytes.Buffer{})

	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	unchanged, err := os.ReadFile(store.ScopePath("acme-2026q4"))
	require.NoError(t, err)
	assert.Equal(t, originalDoc, unchanged, "a refused add must never touch the existing scope file")
}

func TestEngagementAddCmd_AutoActivatesWhenNothingActive(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	scopeFile := t.TempDir() + "/scope.yaml"
	require.NoError(t, os.WriteFile(scopeFile, []byte(`
engagement:
  name: acme-2026q4
  client: Acme Corp
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`), 0o600))

	cmd := newEngagementAddCmdWithStore(store)
	cmd.SetArgs([]string{"acme-2026q4", "--scope", scopeFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	active, err := store.Active()
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", active)
	assert.Contains(t, out.String(), "automatically activated")
}

func TestEngagementAddCmd_NeverOverridesAnExistingActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "globex-oct", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("globex-oct"))

	scopeFile := t.TempDir() + "/scope.yaml"
	require.NoError(t, os.WriteFile(scopeFile, []byte(`
engagement:
  name: acme-2026q4
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`), 0o600))

	cmd := newEngagementAddCmdWithStore(store)
	cmd.SetArgs([]string{"acme-2026q4", "--scope", scopeFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())

	active, err := store.Active()
	require.NoError(t, err)
	assert.Equal(t, "globex-oct", active, "an already-active engagement must never be overridden by add")
	assert.NotContains(t, out.String(), "automatically activated")
}

func TestEngagementAddCmd_SecondAddInABulkImportDoesNotStompTheFirst(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}

	for _, name := range []string{"acme-2026q4", "globex-oct"} {
		scopeFile := t.TempDir() + "/scope.yaml"
		require.NoError(t, os.WriteFile(scopeFile, []byte(fmt.Sprintf(`
engagement:
  name: %s
  start: 2026-10-01T00:00:00Z
  end: 2026-10-28T00:00:00Z
scope:
  include:
    - 10.0.0.0/16
`, name)), 0o600))

		cmd := newEngagementAddCmdWithStore(store)
		cmd.SetArgs([]string{name, "--scope", scopeFile})
		cmd.SetOut(&bytes.Buffer{})
		require.NoError(t, cmd.Execute())
	}

	active, err := store.Active()
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", active, "only the first add in the loop should have auto-activated")
}

func TestEngagementAddCmd_AutoActivateWarnsOnAlreadyExpiredWindow(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	t.Setenv("NO_COLOR", "1")
	scopeFile := t.TempDir() + "/scope.yaml"
	require.NoError(t, os.WriteFile(scopeFile, []byte(fmt.Sprintf(`
engagement:
  name: globex-oct
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
`, time.Now().Add(-96*time.Hour).Format(time.RFC3339), time.Now().Add(-48*time.Hour).Format(time.RFC3339))), 0o600))

	cmd := newEngagementAddCmdWithStore(store)
	cmd.SetArgs([]string{"globex-oct", "--scope", scopeFile})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "WARNING: this engagement expired")
}
