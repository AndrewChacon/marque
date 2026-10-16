package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTargets_WholeTokenIP(t *testing.T) {
	assert.Equal(t, []string{"10.0.0.5"}, extractTargets([]string{"nmap", "-sV", "10.0.0.5"}))
}

func TestExtractTargets_WholeTokenIPv6(t *testing.T) {
	assert.Equal(t, []string{"::1"}, extractTargets([]string{"ping", "::1"}))
}

func TestExtractTargets_WholeTokenHostname(t *testing.T) {
	assert.Equal(t, []string{"example.com"}, extractTargets([]string{"curl", "example.com"}))
}

func TestExtractTargets_URLEmbeddedHost(t *testing.T) {
	assert.Equal(t, []string{"example.com"}, extractTargets([]string{"curl", "https://example.com/path?x=1"}))
}

func TestExtractTargets_IPv4SubstringInFlag(t *testing.T) {
	assert.Equal(t, []string{"10.0.0.5"}, extractTargets([]string{"nmap", "--target=10.0.0.5"}))
}

func TestExtractTargets_IgnoresPlainFlagsAndNumbers(t *testing.T) {
	assert.Empty(t, extractTargets([]string{"nmap", "-sV", "-p", "1-1000", "--max-retries=3"}))
}

func TestExtractTargets_NoDuplicates(t *testing.T) {
	assert.Equal(t, []string{"10.0.0.5"}, extractTargets([]string{"nmap", "10.0.0.5", "10.0.0.5"}))
}

func TestExtractTargets_MultipleDistinctTargets(t *testing.T) {
	got := extractTargets([]string{"curl", "https://example.com", "10.0.0.5"})
	assert.Equal(t, []string{"example.com", "10.0.0.5"}, got)
}

func TestExtractTargets_NoTargetsIsEmptyNotError(t *testing.T) {
	assert.Empty(t, extractTargets([]string{"ls", "-la"}))
}

func TestExtractTargets_IgnoresCommonFilenames(t *testing.T) {
	for _, f := range []string{"scan.xml", "wordlist.txt", "exploit.py", "app.sh", "results.gnmap"} {
		assert.Empty(t, extractTargets([]string{"nmap", "-oX", f}), "filename %q must not be extracted as a target", f)
	}
}

func TestExtractTargets_RealisticNmapInvocationOnlyExtractsTheRealTarget(t *testing.T) {
	got := extractTargets([]string{"nmap", "-sV", "-oX", "scan.xml", "target.com"})
	assert.Equal(t, []string{"target.com"}, got)
}

type fakeAuditLogger struct {
	entries []scope.Decision
	failErr error
}

func (f *fakeAuditLogger) Log(d scope.Decision) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.entries = append(f.entries, d)
	return nil
}

func TestCheckRunTargets_AllowsInScope(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	log := &fakeAuditLogger{}
	var out bytes.Buffer

	err := checkRunTargets(&out, s, log, []string{"nmap", "10.0.1.5"})
	require.NoError(t, err)
	assert.Len(t, log.entries, 1)
	assert.True(t, log.entries[0].Allowed)
}

func TestCheckRunTargets_RefusesOnAnyDeniedTarget(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	log := &fakeAuditLogger{}
	var out bytes.Buffer

	err := checkRunTargets(&out, s, log, []string{"nmap", "10.0.1.5", "192.168.1.1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 target(s) out of scope")
	assert.Contains(t, out.String(), "BLOCKED")
	assert.Contains(t, out.String(), "192.168.1.1")
	assert.Len(t, log.entries, 2, "both the allowed and the denied target must still be logged")
}

func TestCheckRunTargets_NoTargetsFoundProceedsWithoutError(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	log := &fakeAuditLogger{}
	err := checkRunTargets(&bytes.Buffer{}, s, log, []string{"ls", "-la"})
	require.NoError(t, err)
	assert.Empty(t, log.entries)
}

func TestCheckRunTargets_AuditFailureRefusesRegardlessOfDecision(t *testing.T) {
	s := testScope(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), `
scope:
  include:
    - 10.0.0.0/16
`)
	log := &fakeAuditLogger{failErr: fmt.Errorf("disk full")}

	err := checkRunTargets(&bytes.Buffer{}, s, log, []string{"nmap", "10.0.1.5"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit log write failed")
}

func TestExecCommand_UnknownCommandIsActionable(t *testing.T) {
	err := execCommand([]string{"this-command-does-not-exist-anywhere"})
	require.Error(t, err)
}

func TestRunCmd_RefusesOnExpiredWindowEvenWithNoExtractableTarget(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-96*time.Hour), time.Now().Add(-48*time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newRunCmdWithStore(store)
	cmd.SilenceErrors = true
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--", "whoami"}) // argv has no hostname/IP-shaped token at all

	err := cmd.Execute()
	require.Error(t, err, "an expired window must refuse even when nothing was extracted to check")
	assert.Contains(t, err.Error(), "window ended")
}

func TestRunCmd_PrintsEngagementHeader(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newRunCmdWithStore(store)
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	// Out of scope, same as TestRunCmd_RefusesOutOfScopeBeforeExec — refuses
	// before ever exec'ing, so this never risks execCommand's syscall.Exec
	// actually replacing the test binary's process image.
	cmd.SetArgs([]string{"--", "echo", "192.168.1.1"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, out.String(), "RedMarque — engagement: acme")
}

func TestRunCmd_RefusesOutOfScopeBeforeExec(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	doc := fmt.Sprintf(`
engagement:
  name: acme
  start: %s
  end: %s
scope:
  include:
    - 10.0.0.0/16
`, time.Now().Add(-time.Hour).Format(time.RFC3339), time.Now().Add(time.Hour).Format(time.RFC3339))
	require.NoError(t, store.Add("acme", []byte(doc)))
	require.NoError(t, store.SetActive("acme"))

	cmd := newRunCmdWithStore(store)
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--", "echo", "192.168.1.1"})

	err := cmd.Execute()
	require.Error(t, err, "an out-of-scope target in argv must refuse before ever exec'ing")
	assert.Contains(t, out.String(), "BLOCKED")
}
