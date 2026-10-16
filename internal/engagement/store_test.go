package engagement

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore_RootsAtHomeDotMarque(t *testing.T) {
	t.Setenv("HOME", "/home/fake-user")
	s, err := NewStore()
	require.NoError(t, err)
	assert.Equal(t, "/home/fake-user/.marque", s.Root)
}

func TestStore_ActiveIsEmptyBeforeAnythingSet(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	active, err := s.Active()
	require.NoError(t, err)
	assert.Empty(t, active, "no active engagement is an unset default, not an error")
}

func TestStore_SetActiveAndActiveRoundTrip(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	require.NoError(t, s.SetActive("acme-2026q4"))

	active, err := s.Active()
	require.NoError(t, err)
	assert.Equal(t, "acme-2026q4", active)
}

func TestStore_SetActiveOverwrites(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	require.NoError(t, s.SetActive("first"))
	require.NoError(t, s.SetActive("second"))

	active, err := s.Active()
	require.NoError(t, err)
	assert.Equal(t, "second", active)
}

func TestStore_ExistsBeforeAndAfterAdd(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	assert.False(t, s.Exists("acme-2026q4"))

	require.NoError(t, s.Add("acme-2026q4", []byte("placeholder")))
	assert.True(t, s.Exists("acme-2026q4"))
}

func TestStore_AddWritesReadableScopeFile(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	doc := []byte("engagement:\n  name: acme-2026q4\n")
	require.NoError(t, s.Add("acme-2026q4", doc))

	got, err := os.ReadFile(s.ScopePath("acme-2026q4"))
	require.NoError(t, err)
	assert.Equal(t, doc, got)
}

func TestStore_ScopePathAndAuditPathLayout(t *testing.T) {
	s := &Store{Root: "/home/u/.marque"}
	assert.Equal(t, filepath.Join("/home/u/.marque", "engagements", "acme", "scope.yaml"), s.ScopePath("acme"))
	assert.Equal(t, filepath.Join("/home/u/.marque", "engagements", "acme", "audit.jsonl"), s.AuditPath("acme"))
}

func TestStore_ProxyPIDAndLogPathLayout(t *testing.T) {
	s := &Store{Root: "/home/u/.marque"}
	assert.Equal(t, filepath.Join("/home/u/.marque", "proxy.pid"), s.ProxyPIDPath())
	assert.Equal(t, filepath.Join("/home/u/.marque", "proxy.log"), s.ProxyLogPath())
}

func TestStore_ListIsEmptyThenSorted(t *testing.T) {
	s := &Store{Root: t.TempDir()}

	names, err := s.List()
	require.NoError(t, err)
	assert.Empty(t, names)

	require.NoError(t, s.Add("zebra", []byte("z")))
	require.NoError(t, s.Add("acme", []byte("a")))
	require.NoError(t, s.Add("midco", []byte("m")))

	names, err = s.List()
	require.NoError(t, err)
	assert.Equal(t, []string{"acme", "midco", "zebra"}, names)
}

// TestStore_List_ExcludesDirectoriesWithoutAScopeFile covers the gap
// between List (originally just "is a directory under engagements/")
// and Exists (always "has a scope.yaml") — reachable if Add's
// MkdirAll-then-WriteFile is ever interrupted between the two steps,
// leaving a stray directory with no scope file inside.
func TestStore_List_ExcludesDirectoriesWithoutAScopeFile(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	require.NoError(t, s.Add("real", []byte("doc")))
	require.NoError(t, os.MkdirAll(filepath.Join(s.Root, "engagements", "half-created"), 0o700))

	names, err := s.List()
	require.NoError(t, err)
	assert.Equal(t, []string{"real"}, names)
}

func TestNewStore_ErrorsWithNoHome(t *testing.T) {
	t.Setenv("HOME", "")
	_, err := NewStore()
	require.Error(t, err)
}

func TestStore_Active_ErrorsOnReadFailure(t *testing.T) {
	root := t.TempDir()
	// "active" as a directory, not a file — ReadFile fails with
	// "is a directory," a real error distinct from NotExist.
	require.NoError(t, os.Mkdir(filepath.Join(root, "active"), 0o700))

	s := &Store{Root: root}
	_, err := s.Active()
	require.Error(t, err)
}

func TestStore_SetActive_ErrorsWhenRootIsAFile(t *testing.T) {
	parent := t.TempDir()
	rootAsFile := filepath.Join(parent, "marque-root")
	require.NoError(t, os.WriteFile(rootAsFile, []byte("not a directory"), 0o600))

	s := &Store{Root: rootAsFile}
	err := s.SetActive("acme-2026q4")
	require.Error(t, err)
}

func TestStore_Add_ErrorsWhenEngagementsPathIsAFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "engagements"), []byte("x"), 0o600))

	s := &Store{Root: root}
	err := s.Add("acme-2026q4", []byte("doc"))
	require.Error(t, err)
}

// TestStore_SetActive_ErrorsWhenWriteFails covers SetActive's second
// failure point — MkdirAll on Root succeeds, but the write to the
// active file itself fails — distinct from
// TestStore_SetActive_ErrorsWhenRootIsAFile above, which only
// exercises the earlier MkdirAll failure. Making the active file's
// own path already exist as a directory is what forces WriteFile
// specifically to fail.
func TestStore_SetActive_ErrorsWhenWriteFails(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "active"), 0o700))

	s := &Store{Root: root}
	err := s.SetActive("acme-2026q4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "setting active engagement")
}

// TestStore_Add_ErrorsWhenWriteFails is Add's equivalent of the test
// above: the engagement directory itself is created successfully, but
// scope.yaml's own path already exists as a directory, so the final
// WriteFile fails distinctly from the earlier MkdirAll failure
// TestStore_Add_ErrorsWhenEngagementsPathIsAFile covers.
func TestStore_Add_ErrorsWhenWriteFails(t *testing.T) {
	root := t.TempDir()
	s := &Store{Root: root}
	require.NoError(t, os.MkdirAll(s.ScopePath("acme-2026q4"), 0o700))

	err := s.Add("acme-2026q4", []byte("doc"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "writing scope file")
}

func TestStore_List_ErrorsWhenEngagementsPathIsAFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "engagements"), []byte("x"), 0o600))

	s := &Store{Root: root}
	_, err := s.List()
	require.Error(t, err)
}
