package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- processAlive --------------------------------------------------

func TestProcessAlive_TrueForOwnProcess(t *testing.T) {
	assert.True(t, processAlive(os.Getpid()))
}

func TestProcessAlive_FalseForDeadProcess(t *testing.T) {
	pid := spawnAndWaitForExit(t)
	assert.False(t, processAlive(pid))
}

func TestProcessAlive_FalseForZeroOrNegative(t *testing.T) {
	assert.False(t, processAlive(0))
	assert.False(t, processAlive(-1))
}

// --- PID file lifecycle ---------------------------------------------

func TestProxyPID_WriteReadRoundTrip(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	want := proxyDaemonInfo{
		PID:        os.Getpid(), // our own test process — guaranteed alive
		ListenAddr: "127.0.0.1:1080",
		StartedAt:  time.Now().UTC().Truncate(time.Second),
		Engagement: "acme",
	}
	require.NoError(t, writeProxyPID(store, want))

	got, alive, err := readProxyPID(store)
	require.NoError(t, err)
	require.True(t, alive)
	assert.Equal(t, want.PID, got.PID)
	assert.Equal(t, want.ListenAddr, got.ListenAddr)
	assert.Equal(t, want.Engagement, got.Engagement)
	assert.True(t, want.StartedAt.Equal(got.StartedAt))
}

func TestProxyPID_RemoveThenReadIsNotRunning(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{PID: os.Getpid()}))
	require.NoError(t, removeProxyPID(store))

	got, alive, err := readProxyPID(store)
	require.NoError(t, err)
	assert.False(t, alive)
	assert.Nil(t, got)
}

func TestProxyPID_RemoveWhenNoFileIsNotAnError(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	assert.NoError(t, removeProxyPID(store))
}

func TestReadProxyPID_NoFile(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	info, alive, err := readProxyPID(store)
	require.NoError(t, err)
	assert.False(t, alive)
	assert.Nil(t, info)
}

func TestReadProxyPID_StaleFileIsCleanedUp(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	deadPID := spawnAndWaitForExit(t)
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{PID: deadPID}))

	info, alive, err := readProxyPID(store)
	require.NoError(t, err)
	assert.False(t, alive)
	// Non-nil on purpose: stop/status/doctor need the stale PID itself
	// to report a useful message ("removed a stale pid file for pid N"),
	// not just a bare "nothing running."
	require.NotNil(t, info)
	assert.Equal(t, deadPID, info.PID)
	_, statErr := os.Stat(store.ProxyPIDPath())
	assert.True(t, os.IsNotExist(statErr), "stale pid file should have been removed")
}

func TestReadProxyPID_CorruptFileIsCleanedUp(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, os.MkdirAll(store.Root, 0o700))
	require.NoError(t, os.WriteFile(store.ProxyPIDPath(), []byte("not json"), 0o600))

	info, alive, err := readProxyPID(store)
	require.NoError(t, err)
	assert.False(t, alive)
	assert.Nil(t, info)
}

// spawnAndWaitForExit starts a trivial subprocess and waits for it to
// exit, returning its now-guaranteed-dead PID — a real dead PID
// rather than a guessed "probably unused" number, to avoid flakiness.
func spawnAndWaitForExit(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	require.NoError(t, cmd.Wait())
	return pid
}

// --- daemonArgs -------------------------------------------------------

func TestDaemonArgs_MinimalOnlyListen(t *testing.T) {
	args := daemonArgs(proxyOptions{listenAddr: "127.0.0.1:1080"})
	assert.Equal(t, []string{"proxy", "--listen", "127.0.0.1:1080"}, args)
}

func TestDaemonArgs_IncludesSetFlagsOnly(t *testing.T) {
	args := daemonArgs(proxyOptions{
		listenAddr:   "127.0.0.1:1080",
		scopeFlag:    "scope.yaml",
		auditLogFlag: "audit.jsonl",
		force:        true,
		foreground:   true, // must never leak into the child's argv
	})
	assert.Equal(t, []string{
		"proxy", "--listen", "127.0.0.1:1080",
		"--scope", "scope.yaml",
		"--audit-log", "audit.jsonl",
		"--force",
	}, args)
	assert.NotContains(t, args, "--foreground")
}

// --- daemonizeProxy -----------------------------------------------------

func withFakeStartDaemonChild(t *testing.T, fn func(args []string, logPath string) (daemonHandshake, error)) {
	t.Helper()
	orig := startDaemonChild
	startDaemonChild = fn
	t.Cleanup(func() { startDaemonChild = orig })
}

func TestDaemonizeProxy_PreflightFailureNeverSpawnsChild(t *testing.T) {
	spawned := false
	withFakeStartDaemonChild(t, func(args []string, logPath string) (daemonHandshake, error) {
		spawned = true
		return daemonHandshake{OK: true}, nil
	})

	store := &engagement.Store{Root: t.TempDir()}
	cmd := newProxyCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope")
	assert.False(t, spawned, "a validation failure must never spawn a child")
}

func TestDaemonizeProxy_AlreadyRunningRefusesWithoutSpawning(t *testing.T) {
	spawned := false
	withFakeStartDaemonChild(t, func(args []string, logPath string) (daemonHandshake, error) {
		spawned = true
		return daemonHandshake{OK: true}, nil
	})

	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{
		PID:        os.Getpid(),
		ListenAddr: defaultProxyAddr,
		StartedAt:  time.Now(),
	}))

	err := daemonizeProxy(newProxyCmdWithStore(store), store, proxyOptions{listenAddr: defaultProxyAddr})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
	assert.Contains(t, err.Error(), "marque proxy stop")
	assert.False(t, spawned)
}

func TestDaemonizeProxy_SpawnErrorPropagates(t *testing.T) {
	withFakeStartDaemonChild(t, func(args []string, logPath string) (daemonHandshake, error) {
		return daemonHandshake{}, fmt.Errorf("starting proxy daemon: exec permission denied")
	})

	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	err := daemonizeProxy(newProxyCmdWithStore(store), store, proxyOptions{listenAddr: defaultProxyAddr})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exec permission denied")
}

func TestDaemonizeProxy_ChildReportedFailurePropagates(t *testing.T) {
	withFakeStartDaemonChild(t, func(args []string, logPath string) (daemonHandshake, error) {
		return daemonHandshake{OK: false, Error: "listening on 127.0.0.1:1080: bind: address already in use"}, nil
	})

	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	err := daemonizeProxy(newProxyCmdWithStore(store), store, proxyOptions{listenAddr: defaultProxyAddr})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "address already in use")
}

func TestDaemonizeProxy_SuccessPrintsBannerAndHints(t *testing.T) {
	withFakeStartDaemonChild(t, func(args []string, logPath string) (daemonHandshake, error) {
		return daemonHandshake{
			OK:         true,
			PID:        54321,
			ListenAddr: "127.0.0.1:1080",
			Banner:     "RedMarque — engagement: acme (Acme Corp)\nmode: enforce · listening on 127.0.0.1:1080\n\n",
		}, nil
	})

	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newProxyCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})

	require.NoError(t, cmd.Execute())
	output := out.String()
	assert.Contains(t, output, "RedMarque — engagement: acme")
	assert.Contains(t, output, "backgrounded — pid 54321")
	assert.Contains(t, output, "marque proxy status")
	assert.Contains(t, output, "marque audit --tail")
	assert.Contains(t, output, "marque proxy stop")
}

// --- runProxyChild's early-failure paths -------------------------------

func withFakeWriteDaemonHandshake(t *testing.T) *[]daemonHandshake {
	t.Helper()
	var sent []daemonHandshake
	orig := writeDaemonHandshake
	writeDaemonHandshake = func(hs daemonHandshake) {
		sent = append(sent, hs)
	}
	t.Cleanup(func() { writeDaemonHandshake = orig })
	return &sent
}

func TestRunProxyChild_PreflightFailureReportsOverHandshake(t *testing.T) {
	sent := withFakeWriteDaemonHandshake(t)

	store := &engagement.Store{Root: t.TempDir()}
	cmd := newProxyCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := runProxyChild(cmd, store, proxyOptions{listenAddr: defaultProxyAddr})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope")

	require.Len(t, *sent, 1)
	assert.False(t, (*sent)[0].OK)
	assert.Contains(t, (*sent)[0].Error, "--scope")
}

func TestRunProxyChild_ExpiredWindowWithoutForceReportsFailure(t *testing.T) {
	sent := withFakeWriteDaemonHandshake(t)

	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newProxyCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := runProxyChild(cmd, store, proxyOptions{listenAddr: defaultProxyAddr})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")

	require.Len(t, *sent, 1)
	assert.False(t, (*sent)[0].OK)
	assert.Contains(t, (*sent)[0].Error, "--force")
}
