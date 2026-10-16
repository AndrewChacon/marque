package main

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunDoctorChecks_NoActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	checks := runDoctorChecks(store)

	require.NotEmpty(t, checks)
	assert.Equal(t, "FAIL", checks[0].status)
	assert.Contains(t, checks[0].detail, "engagement use")

	// The port check is independent and must still run.
	names := checkNames(checks)
	assert.Contains(t, names, "proxy port "+defaultProxyAddr)
}

func TestRunDoctorChecks_ActiveButScopeFileBroken(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, store.Add("broken", []byte("not valid yaml: [")))
	require.NoError(t, store.SetActive("broken"))

	checks := runDoctorChecks(store)
	byName := checksByName(checks)

	assert.Equal(t, "PASS", byName["active engagement"].status)
	assert.Equal(t, "FAIL", byName["scope file"].status)
	_, hasWindowCheck := byName["engagement window"]
	assert.False(t, hasWindowCheck, "window can't be checked without a parseable scope file")
}

func TestRunDoctorChecks_AllGood(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	checks := runDoctorChecks(store)
	byName := checksByName(checks)

	assert.Equal(t, "PASS", byName["active engagement"].status)
	assert.Equal(t, "PASS", byName["scope file"].status)
	assert.Equal(t, "PASS", byName["engagement window"].status)
}

func TestRunDoctorChecks_ExpiredWindowFails(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-96*time.Hour), time.Now().Add(-48*time.Hour))
	require.NoError(t, store.SetActive("acme"))

	checks := runDoctorChecks(store)
	assert.Equal(t, "FAIL", checksByName(checks)["engagement window"].status)
}

func TestRunDoctorChecks_UpcomingWindowWarns(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(48*time.Hour), time.Now().Add(96*time.Hour))
	require.NoError(t, store.SetActive("acme"))

	checks := runDoctorChecks(store)
	assert.Equal(t, "WARN", checksByName(checks)["engagement window"].status)
}

func TestRunDoctorChecks_OpenEndedWindowPasses(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagementOpenEnded(t, store, "acme", time.Now().Add(-time.Hour))
	require.NoError(t, store.SetActive("acme"))

	checks := runDoctorChecks(store)
	byName := checksByName(checks)
	assert.Equal(t, "PASS", byName["engagement window"].status)
	assert.Contains(t, byName["engagement window"].detail, "ongoing")
}

func TestPortFreeCheck_FreePasses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	store := &engagement.Store{Root: t.TempDir()}
	c := portFreeCheck(addr, store)
	assert.Equal(t, "PASS", c.status)
}

func TestPortFreeCheck_InUseByUnrelatedProcessFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	store := &engagement.Store{Root: t.TempDir()} // no proxy.pid at all
	c := portFreeCheck(ln.Addr().String(), store)
	assert.Equal(t, "FAIL", c.status)
	assert.Contains(t, c.detail, "not a marque-managed proxy")
}

func TestPortFreeCheck_InUseByOwnDaemonWarns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	addr := ln.Addr().String()

	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{
		PID:        os.Getpid(), // our own test process — guaranteed alive
		ListenAddr: addr,
		StartedAt:  time.Now(),
	}))

	c := portFreeCheck(addr, store)
	assert.Equal(t, "WARN", c.status)
	assert.Contains(t, c.detail, "marque proxy stop")
}

func TestPrintDoctorReport_AllPassing(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var out bytes.Buffer
	printDoctorReport(&out, []doctorCheck{
		{"active engagement", "PASS", "acme"},
	})
	assert.Contains(t, out.String(), "Everything looks ready.")
}

func TestPrintDoctorReport_AnyFailureChangesSummary(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var out bytes.Buffer
	printDoctorReport(&out, []doctorCheck{
		{"active engagement", "PASS", "acme"},
		{"scope file", "FAIL", "boom"},
	})
	assert.Contains(t, out.String(), "Some checks failed")
}

func TestDoctorCmd_ExitsNonZeroOnFailure(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	cmd := newDoctorCmdWithStore(store)
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, out.String(), "FAIL")
}

func TestDoctorCmd_SucceedsWhenEverythingIsGood(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newDoctorCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "Everything looks ready.")
}

func checkNames(checks []doctorCheck) []string {
	names := make([]string, len(checks))
	for i, c := range checks {
		names[i] = c.name
	}
	return names
}

func checksByName(checks []doctorCheck) map[string]doctorCheck {
	m := make(map[string]doctorCheck, len(checks))
	for _, c := range checks {
		m[c.name] = c
	}
	return m
}
