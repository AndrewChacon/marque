package main

import (
	"bytes"
	"os/exec"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunProxyStop_NoPIDFile(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	var out bytes.Buffer
	cmd := newProxyStopCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStop(cmd, store))
	assert.Contains(t, out.String(), "no backgrounded proxy is running")
}

func TestRunProxyStop_StalePIDFileCleanedUp(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	deadPID := spawnAndWaitForExit(t)
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{PID: deadPID}))

	var out bytes.Buffer
	cmd := newProxyStopCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStop(cmd, store))
	assert.Contains(t, out.String(), "no backgrounded proxy is running")
	assert.Contains(t, out.String(), "stale")
}

func TestRunProxyStop_LiveProcessGracefulStop(t *testing.T) {
	restoreGrace := setShortProxyStopGrace(t)
	defer restoreGrace()

	store := &engagement.Store{Root: t.TempDir()}
	sleeper := exec.Command("sleep", "30")
	require.NoError(t, sleeper.Start())
	t.Cleanup(func() { _ = sleeper.Process.Kill() })
	go func() { _ = sleeper.Wait() }() // reap it once killed — otherwise it zombies and processAlive never sees it as dead
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{PID: sleeper.Process.Pid, ListenAddr: "127.0.0.1:1080"}))

	var out bytes.Buffer
	cmd := newProxyStopCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStop(cmd, store))
	assert.Contains(t, out.String(), "stopped proxy")
	assert.False(t, processAlive(sleeper.Process.Pid))

	_, alive, err := readProxyPID(store)
	require.NoError(t, err)
	assert.False(t, alive)
}

func TestRunProxyStop_EscalatesToSIGKILLWhenUnresponsive(t *testing.T) {
	restoreGrace := setShortProxyStopGrace(t)
	defer restoreGrace()

	store := &engagement.Store{Root: t.TempDir()}
	// Ignores SIGTERM deliberately, forcing the SIGKILL escalation path.
	stubborn := exec.Command("sh", "-c", `trap "" TERM; sleep 30`)
	require.NoError(t, stubborn.Start())
	t.Cleanup(func() { _ = stubborn.Process.Kill() })
	go func() { _ = stubborn.Wait() }() // reap it once killed — otherwise it zombies and processAlive never sees it as dead
	time.Sleep(100 * time.Millisecond)  // give the shell time to actually execute `trap` before SIGTERM arrives
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{PID: stubborn.Process.Pid, ListenAddr: "127.0.0.1:1080"}))

	var out bytes.Buffer
	cmd := newProxyStopCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStop(cmd, store))
	assert.Contains(t, out.String(), "SIGKILL")

	// Give the kernel a moment to actually reap/report the kill.
	require.Eventually(t, func() bool {
		return !processAlive(stubborn.Process.Pid)
	}, 2*time.Second, 50*time.Millisecond)

	_, alive, err := readProxyPID(store)
	require.NoError(t, err)
	assert.False(t, alive)
}

// setShortProxyStopGrace shrinks the stop grace period for the
// duration of a test, so exercising the escalation path doesn't
// actually wait out the real 5s default.
func setShortProxyStopGrace(t *testing.T) func() {
	t.Helper()
	orig := proxyStopGracePeriod
	proxyStopGracePeriod = 300 * time.Millisecond
	return func() { proxyStopGracePeriod = orig }
}
