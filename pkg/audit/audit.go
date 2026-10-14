// Package audit provides a tamper-evident log of scope decisions.
//
// Tamper-evident, not tamper-proof: the hash chain makes a retroactive
// edit to any line detectable on Verify, because it breaks that
// line's hash and every hash after it. It does not stop someone with
// write access to the log file from regenerating a self-consistent
// chain from scratch — that would require external append-only
// storage or remote signing, which is out of scope here. See
// THREAT_MODEL.md.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/AndrewChacon/red-marque/pkg/scope"
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

// Open opens (creating if necessary) the audit log at path and
// recovers the hash of its last entry so new entries chain onto it
// correctly across process restarts.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	last, err := lastHash(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, fmt.Errorf("seeking audit log: %w", err)
	}
	return &Log{f: f, last: last}, nil
}

func lastHash(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("seeking audit log: %w", err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	last := ""
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return "", fmt.Errorf("existing audit log is corrupt: %w", err)
		}
		last = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading audit log: %w", err)
	}
	return last, nil
}

// Log appends a decision to the log, chained onto the previous entry.
// An error here means the entry was not durably recorded — callers
// that treat "allowed" as meaning "allowed and audited" must deny the
// underlying action when Log returns an error, per the fail-closed
// principle in THREAT_MODEL.md: an unaudited allow is indistinguishable
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

	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("syncing audit entry: %w", err)
	}

	l.last = hash
	return nil
}

// Close closes the underlying file.
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

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	prev := ""
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("line %d: prev_hash %q does not match preceding entry's hash %q — chain broken", lineNo, e.PrevHash, prev)
		}
		want, err := computeHash(e.PrevHash, e.Timestamp, e.Decision)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if want != e.Hash {
			return fmt.Errorf("line %d: hash mismatch — entry has been tampered with", lineNo)
		}
		prev = e.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading audit log: %w", err)
	}
	return nil
}
