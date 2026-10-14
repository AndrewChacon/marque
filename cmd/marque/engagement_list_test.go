package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintEngagementList_Empty(t *testing.T) {
	var out bytes.Buffer
	printEngagementList(&out, &engagement.Store{Root: t.TempDir()}, nil, "", time.Now())
	assert.Contains(t, out.String(), "engagement add")
}

func TestPrintEngagementList_MarksActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	now := time.Now()
	addTestEngagement(t, store, "acme-2026q4", now.Add(-time.Hour), now.Add(time.Hour))
	addTestEngagement(t, store, "globex-oct", now.Add(-96*time.Hour), now.Add(-48*time.Hour))

	var out bytes.Buffer
	printEngagementList(&out, store, []string{"acme-2026q4", "globex-oct"}, "globex-oct", now)
	output := out.String()

	assert.Contains(t, output, "active")
	assert.Contains(t, output, "expired")
	assert.Contains(t, output, "Acme Corp")

	var globexLine, acmeLine string
	for _, l := range strings.Split(output, "\n") {
		if strings.Contains(l, "globex-oct") {
			globexLine = l
		}
		if strings.Contains(l, "acme-2026q4") {
			acmeLine = l
		}
	}
	require.NotEmpty(t, globexLine)
	require.NotEmpty(t, acmeLine)
	assert.Contains(t, globexLine, "→", "the active engagement's row must be marked")
	assert.NotContains(t, acmeLine, "→", "only the active engagement gets the marker")
}

func TestPrintEngagementList_ParseErrorDoesNotCrashTheWholeList(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	now := time.Now()
	addTestEngagement(t, store, "good", now.Add(-time.Hour), now.Add(time.Hour))
	require.NoError(t, store.Add("broken", []byte("not valid yaml: [")))

	var out bytes.Buffer
	printEngagementList(&out, store, []string{"broken", "good"}, "", now)
	output := out.String()

	assert.Contains(t, output, "good")
	assert.Contains(t, output, "broken")
	assert.Contains(t, output, "parse error")
}

func TestEngagementListCmd_RunsEndToEnd(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme-2026q4", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme-2026q4"))

	cmd := newEngagementListCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "acme-2026q4")
	assert.Contains(t, out.String(), "→")
}
