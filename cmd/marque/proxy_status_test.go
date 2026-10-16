package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunProxyStatus_NotRunning(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	var out bytes.Buffer
	cmd := newProxyStatusCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStatus(cmd, store, false))
	assert.Contains(t, out.String(), "no backgrounded proxy is running")
}

func TestRunProxyStatus_Running(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{
		PID:        os.Getpid(), // our own test process — guaranteed alive
		ListenAddr: "127.0.0.1:1080",
		StartedAt:  time.Now().Add(-90 * time.Second),
		Engagement: "acme",
	}))

	var out bytes.Buffer
	cmd := newProxyStatusCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStatus(cmd, store, false))
	output := out.String()
	assert.Contains(t, output, "proxy running")
	assert.Contains(t, output, "127.0.0.1:1080")
	assert.Contains(t, output, "engagement: acme")
	assert.Contains(t, output, "marque audit --tail")
	assert.Contains(t, output, "marque proxy stop")
}

func TestRunProxyStatus_RunningWithoutEngagementOmitsEngagementLine(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{
		PID:        os.Getpid(),
		ListenAddr: "127.0.0.1:1080",
		StartedAt:  time.Now(),
		// Engagement left empty — started via explicit --scope, no active engagement.
	}))

	var out bytes.Buffer
	cmd := newProxyStatusCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStatus(cmd, store, false))
	assert.NotContains(t, out.String(), "engagement:")
}

func TestRunProxyStatus_JSON_NotRunning(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	var out bytes.Buffer
	cmd := newProxyStatusCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStatus(cmd, store, true))

	var got proxyStatusJSON
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.False(t, got.Running)
}

func TestRunProxyStatus_JSON_Running(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, writeProxyPID(store, proxyDaemonInfo{
		PID:        os.Getpid(),
		ListenAddr: "127.0.0.1:1080",
		StartedAt:  time.Now().Add(-90 * time.Second),
		Engagement: "acme",
	}))

	var out bytes.Buffer
	cmd := newProxyStatusCmd(store)
	cmd.SetOut(&out)

	require.NoError(t, runProxyStatus(cmd, store, true))

	var got proxyStatusJSON
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	assert.True(t, got.Running)
	assert.Equal(t, os.Getpid(), got.PID)
	assert.Equal(t, "127.0.0.1:1080", got.ListenAddr)
	assert.Equal(t, "acme", got.Engagement)
	assert.GreaterOrEqual(t, got.UptimeSecs, 90.0)
}
