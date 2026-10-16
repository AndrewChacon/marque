package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/audit"
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

func TestWriteProxyPID_RefusesSecondClaimWhileFirstExists(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{PID: 111, ListenAddr: "127.0.0.1:1080"}))

	err := writeProxyPID(store, proxyDaemonInfo{PID: 222, ListenAddr: "127.0.0.1:1081"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "claimed the pid file first")

	info, _, err := readProxyPID(store)
	require.NoError(t, err)
	assert.Equal(t, 111, info.PID, "the first writer's claim must survive a second writer's failed attempt")
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
	assert.Contains(t, err.Error(), "a *different* engagement", "--foreground must not read as a safe way to duplicate the same audit log")
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

// TestRunProxyChild_AuditLogLockedReportsOverHandshake exercises the
// exact scenario the whole proxy-backgrounding feature is designed
// around: something else — realistically another marque proxy
// already backgrounded against this engagement — already has the
// audit log open. runProxyChild must report a clear, fail-closed
// failure over the handshake rather than corrupting anything.
func TestRunProxyChild_AuditLogLockedReportsOverHandshake(t *testing.T) {
	sent := withFakeWriteDaemonHandshake(t)

	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	held, err := audit.Open(store.AuditPath("acme"))
	require.NoError(t, err)
	defer held.Close()

	cmd := newProxyCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	err = runProxyChild(cmd, store, proxyOptions{listenAddr: defaultProxyAddr})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already open for writing")
	assert.Contains(t, err.Error(), "marque proxy")

	require.Len(t, *sent, 1)
	assert.False(t, (*sent)[0].OK)
	assert.Contains(t, (*sent)[0].Error, "already open for writing")
}

// TestRunProxyChild_HappyPathServesUntilSignaled exercises the one
// large piece of runProxyChild no existing test reached: the full
// success path past net.Listen — PID file written, handshake sent
// with OK:true, the real proxy.Serve loop running — and its graceful
// shutdown via the same SIGTERM the real detached child listens for.
// Previously this was only ever verified manually against a real
// build; this covers it at the `go test` level too. Sends SIGTERM to
// this test process's own PID, which is safe here specifically
// because runProxyChild's signal.NotifyContext is registered (and,
// via its deferred stop(), unregistered) for the exact duration of
// this one call.
func TestRunProxyChild_HappyPathServesUntilSignaled(t *testing.T) {
	// A channel, not withFakeWriteDaemonHandshake's plain slice: the
	// handshake is written from runProxyChild's own goroutine and read
	// from the test's main goroutine, and a bare slice shared across
	// goroutines with no synchronization is a real data race under
	// -race — confirmed by hitting it the first time this test was
	// written with require.Eventually polling the slice directly.
	hsCh := make(chan daemonHandshake, 1)
	origHandshake := writeDaemonHandshake
	writeDaemonHandshake = func(hs daemonHandshake) { hsCh <- hs }
	t.Cleanup(func() { writeDaemonHandshake = origHandshake })

	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newProxyCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)

	done := make(chan error, 1)
	go func() {
		done <- runProxyChild(cmd, store, proxyOptions{listenAddr: "127.0.0.1:0"})
	}()

	var hs daemonHandshake
	select {
	case hs = <-hsCh:
	case <-time.After(2 * time.Second):
		t.Fatal("handshake was never sent")
	}
	require.True(t, hs.OK)
	assert.NotEmpty(t, hs.ListenAddr)
	assert.Contains(t, hs.Banner, "acme")

	info, alive, err := readProxyPID(store)
	require.NoError(t, err)
	require.True(t, alive)
	assert.Equal(t, os.Getpid(), info.PID)
	assert.Equal(t, "acme", info.Engagement)

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	select {
	case err := <-done:
		require.NoError(t, err, "a graceful shutdown via SIGTERM must return nil, not surface net.ErrClosed as a failure")
	case <-time.After(2 * time.Second):
		t.Fatal("runProxyChild did not return after SIGTERM")
	}

	_, alive, err = readProxyPID(store)
	require.NoError(t, err)
	assert.False(t, alive, "the PID file must be cleaned up after shutdown")
}
