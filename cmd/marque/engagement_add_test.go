package main

import (
	"bytes"
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

	doc, err := buildScopeYAML("acme-2026q4", "Acme Corp", start, end,
		[]string{"10.0.0.0/16"}, nil)
	require.NoError(t, err)

	s, err := scope.Parse(doc)
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", s.Name)
	assert.True(t, s.Start.Equal(start))
	assert.True(t, s.End.Equal(end))
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
}
