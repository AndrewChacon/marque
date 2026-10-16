package audit

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AndrewChacon/marque/pkg/scope"
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

// TestOpen_RecognizesLikelyTruncatedWrite covers the case the project
// brief flagged explicitly: a crash mid-write (laptop dies, OOM-kill,
// power loss) leaves the log's last line as a half-written fragment.
// Open still fails closed — it must not silently resume logging onto
// an unverified file — but the error has to say "this looks like an
// incomplete write," not the scarier, wrong "corrupt"/"tampered"
// wording, since a human reading it needs to know this isn't evidence
// someone altered their audit trail.
func TestOpen_RecognizesLikelyTruncatedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	require.NoError(t, os.WriteFile(path, []byte("not json\n"), 0o600))

	_, err := Open(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete write")
	assert.NotContains(t, err.Error(), "compromised")
}

// TestOpen_RecognizesTruncatedTailAfterGoodEntries is the more
// realistic version of the above: a chain with real history behind
// it, then a crash mid-write of the next entry. The good entries
// before the break must still verify cleanly, and the diagnosis has
// to be the same "incomplete write" wording, not "compromised."
func TestOpen_RecognizesTruncatedTailAfterGoodEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Log(decision(false, "192.168.1.1")))
	require.NoError(t, l.Close())

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString(`{"timestamp":"2026-10-14T12:00:00Z","decision":{"allowed":true,"mode":"enf`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = Open(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete write")
	assert.NotContains(t, err.Error(), "compromised")
}

// TestOpen_DetectsTamperingBeforeTheLastEntry is the test that proves
// the actual gap: before this, Open only ever recovered the hash of
// the last entry — it never verified anything before it, so tampering
// earlier in the file would go completely unnoticed until something
// explicitly called Verify (which nothing does yet). Open must now
// catch this itself, at resume time, with wording that makes clear
// this is NOT the benign "incomplete write" case.
func TestOpen_DetectsTamperingBeforeTheLastEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Log(decision(false, "192.168.1.1")))
	require.NoError(t, l.Close())

	lines := readLines(t, path)
	require.Len(t, lines, 2)

	var tampered Entry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &tampered))
	tampered.Decision.Allowed = !tampered.Decision.Allowed // flip the first entry's decision, leaving its stored hash stale
	rewritten, err := json.Marshal(tampered)
	require.NoError(t, err)
	lines[0] = string(rewritten)
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	_, err = Open(path)
	require.Error(t, err, "tampering before the last entry must be caught on Open, not just on an explicit Verify call")
	assert.Contains(t, err.Error(), "compromised")
	assert.NotContains(t, err.Error(), "incomplete write")
}

// TestOpen_DetectsTamperingOnTheLastEntry is the regression test for
// the original gap: a hash mismatch (structurally valid JSON, wrong
// hash) on the very last line used to be indistinguishable from a
// crash mid-write, because the old logic only asked "is this the
// last line," never "did this line even fail to parse." Tampering
// with the last line's content now correctly says "compromised," the
// same as tampering anywhere else.
func TestOpen_DetectsTamperingOnTheLastEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.Log(decision(false, "192.168.1.1")))
	require.NoError(t, l.Close())

	lines := readLines(t, path)
	require.Len(t, lines, 2)

	var tampered Entry
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &tampered))
	tampered.Decision.Allowed = !tampered.Decision.Allowed // flip the LAST entry's decision, leaving its stored hash stale
	rewritten, err := json.Marshal(tampered)
	require.NoError(t, err)
	lines[1] = string(rewritten)
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600))

	_, err = Open(path)
	require.Error(t, err, "tampering with the last entry must be caught, not mistaken for an incomplete write")
	assert.Contains(t, err.Error(), "compromised")
	assert.NotContains(t, err.Error(), "incomplete write")
}

// TestLog_ReturnsErrorWhenSeekFails is what the old
// "TestLog_RollsBackOnWriteFailure" actually exercised, discovered
// while chasing pkg/audit's coverage gaps during the extensive-
// testing pass: closing l.f makes the *next* Seek call fail too
// (Seek on a closed file errors identically to Write), so that test
// never reached the Write call it claimed to be testing at all. Kept
// as its own real, correctly-named test for the Seek-failure branch;
// see TestLog_RollsBackOnWriteFailure below for the branch it was
// supposed to cover.
func TestLog_ReturnsErrorWhenSeekFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))
	require.NoError(t, l.f.Close())

	err = l.Log(decision(true, "10.0.0.2"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "seeking audit log")
}

// TestLog_RollsBackOnWriteFailure is the regression test for a write
// that fails partway through: without a rollback, the file's physical
// tail and the in-memory l.last can disagree, and the next successful
// Log() call forks the chain onto a stale hash. Swapping l.f for a
// read-only handle on the same path lets Seek succeed (no write
// permission needed) while Write fails with EBADF — the Write-failure
// branch specifically, not Seek's (closing the fd outright, as an
// earlier version of this test did, fails at Seek instead and never
// reaches Write at all).
//
// The Sync-only-fails branch takes the identical rollback code path
// (same Truncate(offset) call) but isn't given its own repro: reliably
// forcing fsync() to fail while a preceding write() to the same fd
// just succeeded needs OS-level fault injection (a failing block
// device, a restricted filesystem) that isn't practical to simulate
// portably in a unit test. Introducing a Sync-able interface seam
// purely to make this one branch mockable was considered and rejected
// — this codebase deliberately favors concrete types over interfaces
// added for testability alone (see pkg/scope and pkg/audit's existing
// design), and the risk here is adequately covered by this test
// exercising the same rollback logic from the Write side.
func TestLog_RollsBackOnWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l.Log(decision(true, "10.0.0.1")))

	sizeBefore, err := l.f.Seek(0, io.SeekEnd)
	require.NoError(t, err)

	require.NoError(t, l.f.Close())
	roFile, err := os.OpenFile(path, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer roFile.Close()
	l.f = roFile

	err = l.Log(decision(true, "10.0.0.2"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "writing audit entry", "must fail at the Write call specifically, not an earlier Seek")

	sizeAfter, err := roFile.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, sizeBefore, sizeAfter, "a failed write must never leave extra bytes behind")
}

func TestOpen_InvalidPath(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl"))
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrLocked), "a missing-directory failure must not be mistaken for lock contention")
}

func TestOpen_RefusesSecondOpenWhileFirstIsOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l1, err := Open(path)
	require.NoError(t, err)
	defer l1.Close()

	_, err = Open(path)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLocked)
}

func TestOpen_SucceedsOnceFirstLogCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l1, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l1.Close())

	l2, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, l2.Close())
}

// TestOpen_ConcurrentAttemptsOnlyOneWriterWins is the direct
// regression test for the original bug: two (or more) processes
// opening the same audit log concurrently used to interleave raw
// writes (no O_APPEND) and each track a stale, process-local "last
// hash" (no cross-process coordination), corrupting the chain. Now
// exactly one Open() wins the lock; everyone else fails immediately
// with ErrLocked instead of writing anything, so there's no second
// writer left to corrupt the file. In-process goroutines rather than
// real subprocesses — flock contends on the open file description,
// not process identity, so this exercises the identical kernel code
// path the original two-process repro hit, without subprocess
// flakiness.
func TestOpen_ConcurrentAttemptsOnlyOneWriterWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	const attempts = 20
	var wg sync.WaitGroup
	winners := make(chan *Log, attempts)
	losers := make(chan error, attempts)

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := Open(path)
			if err != nil {
				losers <- err
				return
			}
			winners <- l
		}()
	}
	wg.Wait()
	close(winners)
	close(losers)

	var opened []*Log
	for l := range winners {
		opened = append(opened, l)
	}
	require.Len(t, opened, 1, "exactly one concurrent Open() must win the exclusive lock")

	for i := 0; i < 50; i++ {
		require.NoError(t, opened[0].Log(decision(true, "10.0.0.1")))
	}
	require.NoError(t, opened[0].Close())

	for err := range losers {
		assert.ErrorIs(t, err, ErrLocked)
	}

	assert.NoError(t, Verify(path))
	assert.Len(t, readLines(t, path), 50)
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
