// Package audit provides a tamper-evident log of scope decisions.
//
// Tamper-evident, not tamper-proof: the hash chain makes a retroactive
// edit to any line detectable on Verify, because it breaks that
// line's hash and every hash after it. It does not stop someone with
// write access to the log file from regenerating a self-consistent
// chain from scratch — that would require external append-only
// storage or remote signing, which is out of scope here. See
// docs/THREAT_MODEL.md.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/AndrewChacon/marque/pkg/scope"
)

// entryBody is the portion of an Entry that gets hashed. Keeping it as
// its own type (rather than hashing a partially-built Entry) guarantees
// Log and Verify serialize the exact same bytes for the exact same
// logical entry.
type entryBody struct {
	Timestamp time.Time      `json:"timestamp"`
	Decision  scope.Decision `json:"decision"`
	PrevHash  string         `json:"prev_hash"`
}

// Entry is one line of the audit log.
type Entry struct {
	// Timestamp is when the decision was logged, in UTC.
	Timestamp time.Time `json:"timestamp"`
	// Decision is the scope outcome this entry records.
	Decision scope.Decision `json:"decision"`
	// PrevHash is the Hash of the entry immediately before this one,
	// or "" for the first entry in the log.
	PrevHash string `json:"prev_hash"`
	// Hash is sha256(PrevHash + the JSON-encoded Timestamp/Decision/PrevHash),
	// forming the chain Verify walks.
	Hash string `json:"hash"`
}

func computeHash(prevHash string, ts time.Time, d scope.Decision) (string, error) {
	body, err := json.Marshal(entryBody{Timestamp: ts, Decision: d, PrevHash: prevHash})
	if err != nil {
		return "", fmt.Errorf("encoding audit entry: %w", err)
	}
	sum := sha256.Sum256(append([]byte(prevHash), body...))
	return hex.EncodeToString(sum[:]), nil
}

// Log is an append-only, hash-chained decision log backed by a file.
type Log struct {
	mu   sync.Mutex
	f    *os.File
	last string
}

// ErrLocked indicates the audit log at a given path is already open
// for writing — by this process or (far more commonly) a separate one
// entirely. Exactly one writer may hold a given audit log open at a
// time; this is what enforces that, instead of leaving two writers to
// race and silently interleave raw writes or each track an
// independent, stale view of the chain's last hash onto a file
// neither has exclusive visibility into.
var ErrLocked = errors.New("audit log is already open for writing by another process")

// Open opens (creating if necessary) the audit log at path, taking an
// exclusive, non-blocking lock on it for as long as the returned *Log
// stays open: at most one writer may hold a given audit log open at a
// time. A second Open while the first is still open fails immediately
// with an error wrapping ErrLocked — refuse fast, never wait your
// turn or, worse, let two writers interleave onto a file neither has
// exclusive visibility into. The lock releases automatically when
// Close is called, or when the holding process exits for any reason
// including a crash (flock(2) semantics) — nothing else needs to
// clean it up.
//
// If the file already has entries, Open verifies the entire existing
// chain (the same check Verify performs) before trusting it —
// tampering anywhere in the file is caught here, at resume time,
// rather than only when something later calls Verify explicitly. An
// unreadable final entry with nothing valid after it is reported
// distinctly from tampering (it's consistent with a crash mid-write),
// but Open still fails closed either way: it never resumes logging
// onto a chain it hasn't fully verified.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("opening audit log %s: %w", path, ErrLocked)
		}
		return nil, fmt.Errorf("locking audit log: %w", err)
	}

	last, err := lastHash(f)
	if err != nil {
		f.Close() // also releases the flock acquired above
		return nil, err
	}
	return &Log{f: f, last: last}, nil
}

// chainBreak records where an audit log's hash chain first stopped
// verifying, and whether any further line follows it. That second
// detail is what lets a caller tell "the last entry looks like an
// incomplete write" (nothing follows it — plausibly just a crash)
// apart from "something is wrong and more data follows it anyway"
// (not a shape a crash produces — treat it as compromised).
type chainBreak struct {
	lineNo      int
	reason      error
	moreFollows bool
	// unreadable is true only when the line failed to unmarshal as an
	// Entry at all — the one break shape a crash mid-write actually
	// produces. A line that unmarshals cleanly but whose prev_hash or
	// hash doesn't check out is never a truncation artifact, no matter
	// its position in the file, and must not be reported as one.
	unreadable bool
}

// walkChain scans every line of an audit log, verifying the hash
// chain: each entry's prev_hash must match the previous entry's hash,
// and its own hash must match what computeHash produces. It keeps
// scanning past the first break — without further verifying anything,
// since the chain is already broken — purely to learn whether brk
// was at the end of the file.
func walkChain(r io.Reader) (lastGoodHash string, brk *chainBreak, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	prev := ""
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		if brk != nil {
			brk.moreFollows = true
			continue
		}

		var e Entry
		if uerr := json.Unmarshal(line, &e); uerr != nil {
			brk = &chainBreak{lineNo: lineNo, reason: uerr, unreadable: true}
			continue
		}
		if e.PrevHash != prev {
			brk = &chainBreak{lineNo: lineNo, reason: fmt.Errorf("prev_hash %q does not match preceding entry's hash %q — chain broken", e.PrevHash, prev)}
			continue
		}
		want, herr := computeHash(e.PrevHash, e.Timestamp, e.Decision)
		if herr != nil {
			brk = &chainBreak{lineNo: lineNo, reason: herr}
			continue
		}
		if want != e.Hash {
			brk = &chainBreak{lineNo: lineNo, reason: errors.New("hash mismatch — entry has been tampered with")}
			continue
		}

		prev = e.Hash
		lastGoodHash = e.Hash
	}
	if serr := scanner.Err(); serr != nil {
		return lastGoodHash, brk, fmt.Errorf("reading audit log: %w", serr)
	}
	return lastGoodHash, brk, nil
}

// lastHash verifies the entire existing chain (not just its last
// entry) and returns the hash to resume logging from. A break with
// nothing valid following it — consistent with a crash mid-write —
// and a break with good-looking data after it — which a crash
// wouldn't produce — are reported with different, honest wording.
// Either way this fails closed: it never returns a usable hash
// alongside an error, and callers (Open) must not resume logging on
// an unverified file.
func lastHash(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("seeking audit log: %w", err)
	}

	last, brk, err := walkChain(f)
	if err != nil {
		return "", err
	}
	if brk == nil {
		return last, nil
	}
	if brk.unreadable && !brk.moreFollows {
		return "", fmt.Errorf("existing audit log: entry at line %d is unreadable, but the chain before it verifies cleanly — this looks like an incomplete write (e.g. a crash), not tampering. To resume, remove that incomplete last line and try again: %w", brk.lineNo, brk.reason)
	}
	return "", fmt.Errorf("existing audit log failed verification at line %d: %w — a crash wouldn't produce this; treat this log as compromised", brk.lineNo, brk.reason)
}

// Log appends a decision to the log, chained onto the previous entry.
// An error here means the entry was not durably recorded — callers
// that treat "allowed" as meaning "allowed and audited" must deny the
// underlying action when Log returns an error, per the fail-closed
// principle in docs/THREAT_MODEL.md: an unaudited allow is indistinguishable
// from no safety net at all.
func (l *Log) Log(d scope.Decision) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC()
	hash, err := computeHash(l.last, ts, d)
	if err != nil {
		return err
	}
	entry := Entry{Timestamp: ts, Decision: d, PrevHash: l.last, Hash: hash}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding audit entry: %w", err)
	}
	line = append(line, '\n')

	offset, err := l.f.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seeking audit log: %w", err)
	}

	if _, err := l.f.Write(line); err != nil {
		_ = l.f.Truncate(offset) // roll back a partial write — never leave bytes the chain doesn't account for
		return fmt.Errorf("writing audit entry: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		_ = l.f.Truncate(offset) // bytes landed but aren't durable and l.last won't advance — don't leave them for the next Log() call to silently fork onto
		return fmt.Errorf("syncing audit entry: %w", err)
	}

	l.last = hash
	return nil
}

// Close closes the underlying file, which also releases the exclusive
// lock Open took out — flock(2) releases a lock once every file
// descriptor referring to the locked open file description is closed,
// which happens implicitly on process exit (including a crash), so an
// abnormal exit never leaves the log stuck "locked."
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// Verify walks the hash chain in the log at path and returns the
// first detected break, or nil if the chain is intact end to end.
func Verify(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	_, brk, err := walkChain(f)
	if err != nil {
		return err
	}
	if brk != nil {
		return fmt.Errorf("line %d: %w", brk.lineNo, brk.reason)
	}
	return nil
}
