package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/AndrewChacon/red-marque/internal/engagement"
	"github.com/AndrewChacon/red-marque/internal/proxy"
	"github.com/AndrewChacon/red-marque/pkg/audit"
	"github.com/AndrewChacon/red-marque/pkg/scope"
	"github.com/spf13/cobra"
)

// daemonChildEnv, set to "1" in the re-exec'd child's environment, is
// how runProxy tells the daemon child apart from a normal invocation.
const daemonChildEnv = "MARQUE_PROXY_DAEMON_CHILD"

// daemonReadyFD is the child's end of the readiness pipe — the first
// (and only) entry of exec.Cmd.ExtraFiles always lands at fd 3.
const daemonReadyFD = 3

// daemonHandshakeTimeout bounds how long the parent waits for the
// child to report readiness before giving up on a direct answer (the
// child isn't killed — it may just be slow to bind or resolve).
const daemonHandshakeTimeout = 10 * time.Second

// daemonHandshake is the one JSON line the child writes to fd 3
// before closing it, reporting the outcome the parent otherwise has
// no way to observe (nothing in the child's address space survives
// the exec boundary).
type daemonHandshake struct {
	OK         bool   `json:"ok"`
	PID        int    `json:"pid,omitempty"`
	ListenAddr string `json:"listen_addr,omitempty"`
	Banner     string `json:"banner,omitempty"`
	Error      string `json:"error,omitempty"`
}

// proxyDaemonInfo is the content of Store.ProxyPIDPath() — enough for
// `marque proxy status`/`stop`/doctor to report something useful
// without re-parsing the scope file.
type proxyDaemonInfo struct {
	PID        int       `json:"pid"`
	ListenAddr string    `json:"listen_addr"`
	StartedAt  time.Time `json:"started_at"`
	Engagement string    `json:"engagement,omitempty"` // "" when started via explicit --scope with no active engagement
}

// startDaemonChild spawns the real background proxy process and
// blocks until it reports readiness (or failure) over the handshake
// pipe. Replaced in tests: self-re-exec can't run for real under `go
// test`, since os.Executable() there resolves to the compiled test
// binary, not the real `marque` binary.
var startDaemonChild = defaultStartDaemonChild

func defaultStartDaemonChild(args []string, logPath string) (daemonHandshake, error) {
	exe, err := os.Executable()
	if err != nil {
		return daemonHandshake{}, fmt.Errorf("finding marque's own executable path: %w", err)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return daemonHandshake{}, fmt.Errorf("opening %s: %w", logPath, err)
	}
	defer logFile.Close()

	readyR, readyW, err := os.Pipe()
	if err != nil {
		return daemonHandshake{}, fmt.Errorf("creating readiness pipe: %w", err)
	}
	defer readyR.Close()

	cmd := exec.Command(exe, args...) //nolint:gosec // G204: re-execs marque's own trusted binary (os.Executable()) with an argv we built ourselves in daemonArgs, not user-supplied input
	cmd.Env = append(os.Environ(), daemonChildEnv+"=1")
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{readyW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		readyW.Close()
		return daemonHandshake{}, fmt.Errorf("starting proxy daemon: %w", err)
	}
	// Our own copy of the write end must close now, or our read below
	// never sees EOF — the child's inherited copy is what keeps the
	// pipe open until it's actually done with it.
	readyW.Close()
	_ = cmd.Process.Release()

	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(readyR)
		done <- result{data, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return daemonHandshake{}, fmt.Errorf("reading readiness handshake: %w", r.err)
		}
		var hs daemonHandshake
		if err := json.Unmarshal(r.data, &hs); err != nil {
			return daemonHandshake{}, fmt.Errorf("proxy exited before reporting it was ready — see %s", logPath)
		}
		return hs, nil
	case <-time.After(daemonHandshakeTimeout):
		return daemonHandshake{}, fmt.Errorf("timed out waiting for the proxy to report readiness — it may still start; check `marque proxy status` or %s", logPath)
	}
}

// daemonArgs reconstructs argv for the re-exec'd child from the
// already-parsed options rather than reusing os.Args — avoids any
// ambiguity about flag order/quoting, and guarantees --foreground
// (which only makes sense for the parent's own dispatch) can never
// leak into the child's argv.
func daemonArgs(opts proxyOptions) []string {
	args := []string{"proxy", "--listen", opts.listenAddr}
	if opts.scopeFlag != "" {
		args = append(args, "--scope", opts.scopeFlag)
	}
	if opts.auditLogFlag != "" {
		args = append(args, "--audit-log", opts.auditLogFlag)
	}
	if opts.force {
		args = append(args, "--force")
	}
	return args
}

// daemonizeProxy is the new default `marque proxy` entry point: it
// runs the same cheap validation the foreground path always has
// (resolvePaths/scope.Load/checkProxyPreflight) itself, synchronously,
// before ever spawning anything — a typo'd --scope fails immediately,
// no subprocess involved. Only once that passes does it hand off to
// startDaemonChild, which does the stateful part (opening the audit
// log, binding the listener) in a detached child and reports back
// whether that succeeded.
func daemonizeProxy(cmd *cobra.Command, store *engagement.Store, opts proxyOptions) error {
	paths, err := resolvePaths(opts.scopeFlag, opts.auditLogFlag, store)
	if err != nil {
		return err
	}
	s, err := scope.Load(paths.scopePath)
	if err != nil {
		return err
	}
	if err := checkProxyPreflight(s, opts.force, time.Now()); err != nil {
		return err
	}

	info, alive, err := readProxyPID(store)
	if err != nil {
		return err
	}
	if alive {
		return fmt.Errorf(
			"a marque proxy is already running (pid %d, listening on %s, started %s) — `marque proxy stop` to stop it, or `--foreground` to run a second instance anyway",
			info.PID, info.ListenAddr, info.StartedAt.Format(time.RFC3339),
		)
	}

	hs, err := startDaemonChild(daemonArgs(opts), store.ProxyLogPath())
	if err != nil {
		return err
	}
	if !hs.OK {
		return errors.New(hs.Error)
	}

	out := cmd.OutOrStdout()
	fmt.Fprint(out, hs.Banner)
	fmt.Fprintf(out, "backgrounded — pid %d\n", hs.PID)
	fmt.Fprintln(out, "  marque proxy status      check it's still running")
	printProxyNextSteps(out)
	return nil
}

// printProxyNextSteps writes the "what to do next" lines shared by
// the backgrounded-start banner and `marque proxy status` — "check
// status" itself isn't included here, since status's own output
// suggesting you check status again would be silly; daemonizeProxy
// prints that one line itself, above this.
func printProxyNextSteps(w io.Writer) {
	fmt.Fprintln(w, "  marque audit --tail      watch decisions live")
	fmt.Fprintln(w, "  marque proxy stop        stop it")
}

// runProxyChild is what actually runs inside the re-exec'd, detached
// process: the same validation+setup runProxyForeground does (nothing
// from the parent's own run survives the exec boundary, so this can't
// avoid redoing the cheap checks), then — unlike the foreground
// path — reports its outcome over the readiness pipe instead of
// printing straight to a terminal, since by the time anything here
// runs there may no longer be one attached.
func runProxyChild(cmd *cobra.Command, store *engagement.Store, opts proxyOptions) error {
	paths, err := resolvePaths(opts.scopeFlag, opts.auditLogFlag, store)
	if err != nil {
		return reportDaemonFailure(err)
	}
	s, err := scope.Load(paths.scopePath)
	if err != nil {
		return reportDaemonFailure(err)
	}
	if err := checkProxyPreflight(s, opts.force, time.Now()); err != nil {
		return reportDaemonFailure(err)
	}

	log, err := audit.Open(paths.auditLogPath)
	if err != nil {
		return reportDaemonFailure(err)
	}
	defer log.Close()

	ln, err := net.Listen("tcp", opts.listenAddr)
	if err != nil {
		return reportDaemonFailure(fmt.Errorf("listening on %s: %w", opts.listenAddr, err))
	}

	var bannerBuf bytes.Buffer
	printProxyBanner(&bannerBuf, s, ln.Addr().String())

	if err := writeProxyPID(store, proxyDaemonInfo{
		PID:        os.Getpid(),
		ListenAddr: ln.Addr().String(),
		StartedAt:  time.Now().UTC(),
		Engagement: paths.engagement,
	}); err != nil {
		ln.Close()
		return reportDaemonFailure(err)
	}
	defer func() { _ = removeProxyPID(store) }()

	// A timestamped start record in the crash/panic log, for whoever
	// goes looking — separate from the structured decision log
	// (pkg/audit), which is unaffected by any of this.
	fmt.Fprint(cmd.OutOrStdout(), bannerBuf.String())

	writeDaemonHandshake(daemonHandshake{
		OK:         true,
		PID:        os.Getpid(),
		ListenAddr: ln.Addr().String(),
		Banner:     bannerBuf.String(),
	})

	p := &proxy.Proxy{
		Scope: s,
		Audit: log,
		// No OnDecision: there's no attached terminal to print an
		// ALLOW/BLOCK feed to once backgrounded. Every decision is
		// still fully captured in the audit log regardless — `marque
		// audit --tail`/`audit export` are how to see them live or
		// after the fact.
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	err = p.Serve(ln)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func reportDaemonFailure(err error) error {
	writeDaemonHandshake(daemonHandshake{OK: false, Error: err.Error()})
	return err
}

// writeDaemonHandshake is the child's only channel back to the parent
// — a var, not a plain func, so tests exercising runProxyChild's
// early-failure paths can capture what would have been sent instead
// of writing to whatever fd 3 happens to be in a `go test` process
// (which is not the readiness pipe outside of a real re-exec).
var writeDaemonHandshake = defaultWriteDaemonHandshake

func defaultWriteDaemonHandshake(hs daemonHandshake) {
	data, err := json.Marshal(hs)
	if err != nil {
		return // nothing more we can do — this is the child's only channel back
	}
	f := os.NewFile(uintptr(daemonReadyFD), "ready")
	if f == nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(data) // this is the child's only channel back to the parent — nothing to do if it fails
}

// writeProxyPID records info as the backgrounded proxy's PID file.
func writeProxyPID(store *engagement.Store, info proxyDaemonInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("encoding proxy pid info: %w", err)
	}
	if err := os.WriteFile(store.ProxyPIDPath(), data, 0o600); err != nil {
		return fmt.Errorf("writing proxy pid file: %w", err)
	}
	return nil
}

// readProxyPID reads the PID file, if any, and reports whether the
// process it names is actually still alive. A stale file (process no
// longer running, or unreadable content) is removed automatically
// rather than trusted — callers never need to separately check
// staleness themselves.
func readProxyPID(store *engagement.Store) (info *proxyDaemonInfo, alive bool, err error) {
	data, err := os.ReadFile(store.ProxyPIDPath())
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading proxy pid file: %w", err)
	}

	var parsed proxyDaemonInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		_ = removeProxyPID(store)
		return nil, false, nil
	}

	if !processAlive(parsed.PID) {
		_ = removeProxyPID(store)
		return &parsed, false, nil
	}
	return &parsed, true, nil
}

func removeProxyPID(store *engagement.Store) error {
	err := os.Remove(store.ProxyPIDPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing proxy pid file: %w", err)
	}
	return nil
}

// processAlive reports whether pid names a live process, using the
// standard signal-0 idiom: sending signal 0 does no actual signaling,
// only existence/permission checks.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	// EPERM means the process exists but belongs to someone else —
	// still alive, just not ours to signal freely.
	return errors.Is(err, syscall.EPERM)
}
