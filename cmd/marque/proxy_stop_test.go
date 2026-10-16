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

// TestWaitForExit_CatchesDeathDuringTheFinalSleep is the regression
// test for the original bug, exercised deterministically rather than
// by racing a real process against the wall clock: aliveFn reports
// alive for the two checks that happen inside the loop (at the start
// and after the first 100ms sleep), then dead — simulating a process
// that exits during the loop's last, deadline-overshooting sleep.
// Without the trailing check after the loop, that death would never
// be observed and waitForExit would wrongly report "still alive."
func TestWaitForExit_CatchesDeathDuringTheFinalSleep(t *testing.T) {
	calls := 0
	aliveFn := func() bool {
		calls++
		return calls <= 2
	}
	deadline := time.Now().Add(150 * time.Millisecond)

	assert.True(t, waitForExit(aliveFn, deadline, 100*time.Millisecond))
	assert.Equal(t, 3, calls, "must check once more after the loop's deadline-overshooting sleep exits it")
}

func TestWaitForExit_StillAliveAtDeadlineReturnsFalse(t *testing.T) {
	aliveFn := func() bool { return true }
	deadline := time.Now().Add(50 * time.Millisecond)

	assert.False(t, waitForExit(aliveFn, deadline, 10*time.Millisecond))
}

func TestWaitForExit_AlreadyDeadBeforeTheFirstCheckReturnsImmediately(t *testing.T) {
	aliveFn := func() bool { return false }
	deadline := time.Now().Add(time.Second)

	start := time.Now()
	assert.True(t, waitForExit(aliveFn, deadline, 100*time.Millisecond))
	assert.Less(t, time.Since(start), 50*time.Millisecond, "must not sleep at all once already dead")
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
