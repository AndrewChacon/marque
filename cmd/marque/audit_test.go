package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer guards a bytes.Buffer with a mutex so tailAuditLog
// (writing from a background goroutine) and the test's own
// require.Eventually polling (reading from the test goroutine) can
// safely race against each other.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func TestPrintCompleteLines_SplitsCompleteFromPending(t *testing.T) {
	var out bytes.Buffer
	e := mustMarshalEntry(t, scope.Decision{Allowed: true, Target: "10.0.0.1", Reason: "in scope"})

	remainder := printCompleteLines(&out, append(e, []byte("\npartial-no-newline-yet")...), false)

	assert.Contains(t, out.String(), "10.0.0.1")
	assert.Equal(t, "partial-no-newline-yet", string(remainder))
}

func TestPrintCompleteLines_SkipsUnparseableLines(t *testing.T) {
	var out bytes.Buffer
	remainder := printCompleteLines(&out, []byte("not json at all\n"), false)

	assert.Empty(t, out.String())
	assert.Empty(t, remainder)
}

func TestPrintCompleteLines_SkipsBlankLines(t *testing.T) {
	var out bytes.Buffer
	remainder := printCompleteLines(&out, []byte("\n\n"), false)

	assert.Empty(t, out.String())
	assert.Empty(t, remainder)
}

func TestPrintCompleteLines_JSONMode(t *testing.T) {
	var out bytes.Buffer
	e := mustMarshalEntry(t, scope.Decision{Allowed: false, Target: "evil.example", Reason: "excluded"})

	printCompleteLines(&out, append(e, '\n'), true)

	var d scope.Decision
	require.NoError(t, json.Unmarshal(out.Bytes(), &d))
	assert.Equal(t, "evil.example", d.Target)
	assert.False(t, d.Allowed)
}

func TestTailAuditLog_PicksUpAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	require.NoError(t, err)

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Seek(0, io.SeekEnd)
	require.NoError(t, err)

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- tailAuditLog(ctx, out, f, false, 5*time.Millisecond)
	}()

	require.NoError(t, log.Log(scope.Decision{Allowed: true, Target: "10.0.0.5", Reason: "in scope"}))

	require.Eventually(t, func() bool {
		return bytes.Contains(out.Bytes(), []byte("10.0.0.5"))
	}, time.Second, 5*time.Millisecond)

	cancel()
	require.NoError(t, <-done)
	require.NoError(t, log.Close())
}

func TestAuditCmd_NoTailFlagIsActionable(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	cmd := newAuditCmdWithStore(store)
	cmd.SetArgs([]string{})
	cmd.SilenceErrors = true

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit export")
}

func TestAuditCmd_Tail_MissingLogIsActionable(t *testing.T) {
	store := &engagement.Store{Root: t.TempDir()}
	addTestEngagement(t, store, "acme", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	require.NoError(t, store.SetActive("acme"))

	cmd := newAuditCmdWithStore(store)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--tail"})
	cmd.SilenceErrors = true

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marque proxy")
	assert.Contains(t, out.String(), "RedMarque — engagement: acme", "the header must print even though tailing itself never starts")
}

func mustMarshalEntry(t *testing.T, d scope.Decision) []byte {
	t.Helper()
	b, err := json.Marshal(audit.Entry{Timestamp: time.Now().UTC(), Decision: d})
	require.NoError(t, err)
	return b
}
