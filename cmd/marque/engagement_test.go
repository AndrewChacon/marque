package main

import (
	"path/filepath"
	"testing"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePaths_ExplicitScopeWins(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, store.SetActive("some-other-engagement"))

	paths, err := resolvePaths("/custom/scope.yaml", "", store)
	require.NoError(t, err)
	assert.Equal(t, "/custom/scope.yaml", paths.scopePath)
	assert.Equal(t, filepath.Join("/custom", "audit.jsonl"), paths.auditLogPath)
	assert.Empty(t, paths.engagement, "an explicit --scope isn't resolved via an engagement")
}

func TestResolvePaths_ExplicitScopeAndAuditLogBothWin(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}

	paths, err := resolvePaths("/custom/scope.yaml", "/elsewhere/audit.jsonl", store)
	require.NoError(t, err)
	assert.Equal(t, "/custom/scope.yaml", paths.scopePath)
	assert.Equal(t, "/elsewhere/audit.jsonl", paths.auditLogPath)
}

func TestResolvePaths_FallsBackToActiveEngagement(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	require.NoError(t, store.Add("acme-2026q4", []byte("doc")))
	require.NoError(t, store.SetActive("acme-2026q4"))

	paths, err := resolvePaths("", "", store)
	require.NoError(t, err)
	assert.Equal(t, store.ScopePath("acme-2026q4"), paths.scopePath)
	assert.Equal(t, store.AuditPath("acme-2026q4"), paths.auditLogPath)
	assert.Equal(t, "acme-2026q4", paths.engagement)
}

func TestResolvePaths_NoScopeNoActiveEngagementIsAnActionableError(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}

	_, err := resolvePaths("", "", store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope")
	assert.Contains(t, err.Error(), "engagement use")
}

func TestStoreOrDefault(t *testing.T) {
	injected := &engagement.Store{Root: "/custom/root"}
	got, err := storeOrDefault(injected)
	require.NoError(t, err)
	assert.Same(t, injected, got)

	t.Setenv("HOME", t.TempDir())
	got, err = storeOrDefault(nil)
	require.NoError(t, err)
	assert.Contains(t, got.Root, ".marque")
}

func TestResolveScopePath_DelegatesToResolvePaths(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}

	path, err := resolveScopePath("/custom/scope.yaml", store)
	require.NoError(t, err)
	assert.Equal(t, "/custom/scope.yaml", path)

	_, err = resolveScopePath("", store)
	require.Error(t, err)
}
