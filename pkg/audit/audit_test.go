package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decision(allowed bool, target string) scope.Decision {
	reason := "no include rule matched"
	rule := ""
	if allowed {
		reason = "matched include 10.0.0.0/8"
		rule = "10.0.0.0/8"
	}
	return scope.Decision{
		Allowed:     allowed,
		Mode:        scope.ModeEnforce,
		Target:      target,
		MatchedRule: rule,
		Reason:      reason,
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func TestLog_WritesChainedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)

	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Log(decision(false, "192.168.1.1")))
	require.NoError(t, l.Log(decision(true, "10.0.0.2")))
	require.NoError(t, l.Close())

	lines := readLines(t, path)
	require.Len(t, lines, 3)

	var entries []Entry
	for _, line := range lines {
		var e Entry
		require.NoError(t, json.Unmarshal([]byte(line), &e))
		entries = append(entries, e)
	}

	assert.Equal(t, "", entries[0].PrevHash, "genesis entry has no predecessor")
	assert.Equal(t, entries[0].Hash, entries[1].PrevHash)
	assert.Equal(t, entries[1].Hash, entries[2].PrevHash)
	assert.NotEqual(t, entries[0].Hash, entries[1].Hash)

	assert.NoError(t, Verify(path))
}

func TestLog_EntryFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Close())

	lines := readLines(t, path)
	require.Len(t, lines, 1)

	var raw map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &raw))

	assert.Contains(t, raw, "timestamp")
	assert.Contains(t, raw, "prev_hash")
	assert.Contains(t, raw, "hash")
	require.Contains(t, raw, "decision")

	d := raw["decision"].(map[string]any)
	assert.Equal(t, true, d["allowed"])
	assert.Equal(t, "enforce", d["mode"], "Mode must render as its string name, not a bare int")
	assert.Equal(t, "10.0.0.1", d["target"])
}

func TestLog_ResumesChainAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	l1, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l1.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l1.Close())

	l2, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l2.Log(decision(false, "8.8.8.8")))
	require.NoError(t, l2.Close())

	lines := readLines(t, path)
	require.Len(t, lines, 2)

	var first, second Entry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))

	assert.Equal(t, first.Hash, second.PrevHash, "entry written after reopen must chain onto the prior process's last entry")
	assert.NoError(t, Verify(path))
}

func TestVerify_EmptyLogIsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Close())

	assert.NoError(t, Verify(path))
}

// TestVerify_DetectsTampering is the test the project brief calls out
// explicitly: the hash chain must detectably break when a line is
// altered after the fact. This is what "tamper-evident, not
// tamper-proof" means in practice.
func TestVerify_DetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Log(decision(false, "192.168.1.1")))
	require.NoError(t, l.Log(decision(true, "10.0.0.2")))
	require.NoError(t, l.Close())

	require.NoError(t, Verify(path), "untampered log must verify cleanly first")

	lines := readLines(t, path)
	var tampered Entry
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &tampered))
	tampered.Decision.Allowed = true // flip a denial into an allow after the fact
	rewritten, err := json.Marshal(tampered)
	require.NoError(t, err)
	lines[1] = string(rewritten)

	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	err = Verify(path)
	require.Error(t, err, "tampering with a middle entry must be detected")
	assert.Contains(t, err.Error(), "line 2")
}

func TestOpen_RejectsCorruptExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	require.NoError(t, os.WriteFile(path, []byte("not json\n"), 0o600))

	_, err := Open(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "corrupt")
}

func TestOpen_InvalidPath(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl"))
	require.Error(t, err)
}

func TestOpen_RejectsOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	huge := strings.Repeat("a", 2*1024*1024)
	require.NoError(t, os.WriteFile(path, []byte(huge+"\n"), 0o600))

	_, err := Open(path)
	require.Error(t, err, "a line past the scan buffer limit must surface as an error, not silently truncate")
}

func TestVerify_RejectsOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	huge := strings.Repeat("a", 2*1024*1024)
	require.NoError(t, os.WriteFile(path, []byte(huge+"\n"), 0o600))

	err := Verify(path)
	require.Error(t, err)
}

func TestVerify_MissingFile(t *testing.T) {
	err := Verify(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	require.Error(t, err)
}

func TestVerify_CorruptLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Close())

	require.NoError(t, os.WriteFile(path, []byte("not json at all\n"), 0o600))

	err = Verify(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 1")
}

// TestLog_ReturnsErrorWhenUnderlyingFileIsClosed exercises the write
// failure path directly (via the unexported field, same package) —
// a write failure must surface as an error, never a silent allow that
// the caller mistakes for "logged."
func TestLog_ReturnsErrorWhenUnderlyingFileIsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.f.Close())

	err = l.Log(decision(true, "10.0.0.1"))
	require.Error(t, err)
}

func TestVerify_DetectsReordering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Log(decision(false, "192.168.1.1")))
	require.NoError(t, l.Close())

	lines := readLines(t, path)
	require.Len(t, lines, 2)
	lines[0], lines[1] = lines[1], lines[0]
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	err = Verify(path)
	require.Error(t, err, "reordered entries must break the prev_hash chain")
}
