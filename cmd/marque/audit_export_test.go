package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadAuditEntries_SkipsBlankAndCorruptLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	good := mustMarshalEntry(t, scope.Decision{Allowed: true, Target: "10.0.0.1", Reason: "ok"})
	content := string(good) + "\n\nnot-json\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	entries, err := readAuditEntries(path)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "10.0.0.1", entries[0].Decision.Target)
}

func TestSummarizeEntries_CountsAllowedAndBlocked(t *testing.T) {
	entries := []audit.Entry{
		{Decision: scope.Decision{Allowed: true}},
		{Decision: scope.Decision{Allowed: false}},
		{Decision: scope.Decision{Allowed: true}},
	}
	sum := summarizeEntries(entries)
	assert.Equal(t, 3, sum.Total)
	assert.Equal(t, 2, sum.Allowed)
	assert.Equal(t, 1, sum.Blocked)
}

func TestExportJSON_IncludesVerifyErrorWhenTampered(t *testing.T) {
	var out bytes.Buffer
	s := &scope.Scope{Name: "acme", Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	require.NoError(t, exportJSON(&out, s, nil, assert.AnError))

	var doc exportDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))
	assert.False(t, doc.Verified)
	assert.Contains(t, doc.VerifyError, assert.AnError.Error())
}

func TestExportJSON_VerifiedWhenNoError(t *testing.T) {
	var out bytes.Buffer
	s := &scope.Scope{Name: "acme", Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	require.NoError(t, exportJSON(&out, s, nil, nil))

	var doc exportDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))
	assert.True(t, doc.Verified)
	assert.Empty(t, doc.VerifyError)
}

func TestExportMarkdown_BannersTamperFailure(t *testing.T) {
	var out bytes.Buffer
	s := &scope.Scope{Name: "acme", Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	require.NoError(t, exportMarkdown(&out, s, nil, assert.AnError))

	assert.Contains(t, out.String(), "WARNING")
	assert.Contains(t, out.String(), assert.AnError.Error())
}

func TestExportMarkdown_NoBannerWhenVerified(t *testing.T) {
	var out bytes.Buffer
	s := &scope.Scope{Name: "acme", Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	require.NoError(t, exportMarkdown(&out, s, nil, nil))

	assert.NotContains(t, out.String(), "WARNING")
}

func TestExportMarkdown_TableHasOneRowPerEntry(t *testing.T) {
	var out bytes.Buffer
	s := &scope.Scope{Name: "acme", Start: time.Now().Add(-time.Hour), End: time.Now().Add(time.Hour)}
	entries := []audit.Entry{
		{Timestamp: time.Now(), Decision: scope.Decision{Allowed: true, Target: "10.0.0.1", Reason: "in scope"}},
		{Timestamp: time.Now(), Decision: scope.Decision{Allowed: false, Target: "evil.example", Reason: "excluded"}},
	}
	require.NoError(t, exportMarkdown(&out, s, entries, nil))

	output := out.String()
	assert.Contains(t, output, "10.0.0.1")
	assert.Contains(t, output, "ALLOW")
	assert.Contains(t, output, "evil.example")
	assert.Contains(t, output, "BLOCK")
	assert.Equal(t, 2, strings.Count(output, "|---|"))
}

func TestAuditExportCmd_InvalidFormatIsActionable(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newAuditCmdWithStore(store)
	cmd.SetArgs([]string{"export", "--format", "xml"})
	cmd.SilenceErrors = true

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--format")
}

func TestAuditExportCmd_EndToEndJSON(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	log, err := audit.Open(store.AuditPath("acme"))
	require.NoError(t, err)
	require.NoError(t, log.Log(scope.Decision{Allowed: true, Target: "10.0.0.1", Reason: "in scope"}))
	require.NoError(t, log.Close())

	cmd := newAuditCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"export"})

	require.NoError(t, cmd.Execute())

	var doc exportDoc
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))
	assert.True(t, doc.Verified)
	assert.Equal(t, 1, doc.Summary.Total)
	require.Len(t, doc.Entries, 1)
	assert.Equal(t, "10.0.0.1", doc.Entries[0].Decision.Target)
}

func TestAuditExportCmd_EndToEndMarkdown(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	log, err := audit.Open(store.AuditPath("acme"))
	require.NoError(t, err)
	require.NoError(t, log.Log(scope.Decision{Allowed: false, Target: "evil.example", Reason: "excluded"}))
	require.NoError(t, log.Close())

	cmd := newAuditCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"export", "--format", "markdown"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "evil.example")
	assert.Contains(t, out.String(), "BLOCK")
}
