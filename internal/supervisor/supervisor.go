// Package supervisor runs the child command as a supervised process: it can
// be PID 1 of a container, reaps zombies, forwards signals to the child's
// process group, restarts the child in place on SIGHUP or when the secrets
// change, and exits with the child's exit code.
//
// Everything runs in one goroutine (the loop in Run), so the child pid, the
// restart state and the reaping never race.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// Exit codes of the supervisor itself (the child's own code is passed through).
const (
	ExitCannotExecute = 126
	ExitNotFound      = 127
)

// Reloader fetches a fresh child environment and its fingerprint. The
// environment holds secret values: it is only passed to the child.
type Reloader func(ctx context.Context) (env []string, hash string, err error)

// Config configures Run.
type Config struct {
	// Argv is the child command (Argv[0] is resolved through PATH).
	Argv []string
	// Env and Hash are the first child environment and its fingerprint.
	Env  []string
	Hash string
	// Reload is called on SIGHUP and on every Refresh tick. Nil restarts the
	// child with the current environment on SIGHUP and disables Refresh.
	Reload Reloader
	// Refresh is the period of change checks (0 = off). A changed
	// fingerprint restarts the child; a failed check keeps it running.
	Refresh time.Duration
	// ReloadTimeout bounds one Reload call (default 60 s).
	ReloadTimeout time.Duration
	// Grace is the wait between SIGTERM and SIGKILL on a restart (default 10 s).
	Grace time.Duration
	// ForwardHUP forwards SIGHUP to the child instead of restarting it.
	ForwardHUP bool
	// StateFile receives a JSON status after every start/exit ("" = none).
	StateFile string
	// Version is written to the state file.
	Version string
	// Logger receives supervisor events (never values).
	Logger *slog.Logger
	// Stdin, Stdout and Stderr of the child (default: the supervisor's).
	Stdin, Stdout, Stderr *os.File
}

// State is the content of Config.StateFile.
type State struct {
	Version       string    `json:"version"`
	SupervisorPID int       `json:"supervisorPid"`
	ChildPID      int       `json:"childPid"`
	StartedAt     time.Time `json:"startedAt"`
	Restarts      int       `json:"restarts"`
	LastExitCode  *int      `json:"lastExitCode,omitempty"`
	SecretsHash   string    `json:"secretsHash,omitempty"`
	Running       bool      `json:"running"`
}

type reloadResult struct {
	env    []string
	hash   string
	err    error
	force  bool
	reason string
}

type runner struct {
	cfg      Config
	log      *slog.Logger
	useGroup bool

	pid       int
	env       []string
	hash      string
	state     State
	restart   *reloadResult // pending restart (child is being stopped)
	stopping  bool          // a stop signal arrived: no more restarts
	reloading bool
	reloadCh  chan reloadResult
	grace     *time.Timer
	stateErr  bool
}

// forwarded are the signals passed to the child; SIGCHLD is handled here.
var forwarded = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP,
	syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH, syscall.SIGCHLD,
}

// Run starts the child and supervises it until it exits on its own or after
// a stop signal (SIGTERM, SIGINT, SIGQUIT, or ctx being cancelled, which acts
// like SIGTERM). It returns the exit code for the supervisor process.
func Run(ctx context.Context, cfg Config) int {
	if cfg.Grace <= 0 {
		cfg.Grace = 10 * time.Second
	}
	if cfg.ReloadTimeout <= 0 {
		cfg.ReloadTimeout = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Stdin == nil {
		cfg.Stdin = os.Stdin
	}
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	r := &runner{
		cfg: cfg, log: cfg.Logger, env: cfg.Env, hash: cfg.Hash,
		// A child in its own process group cannot read an interactive
		// terminal, so keep the group only when stdin is not a TTY.
		useGroup: !isTerminal(cfg.Stdin),
		reloadCh: make(chan reloadResult, 1),
	}
	r.state = State{Version: cfg.Version, SupervisorPID: os.Getpid()}

	sigCh := make(chan os.Signal, 64)
	signal.Notify(sigCh, forwarded...)
	defer signal.Stop(sigCh)
	if err := setSubreaper(); err != nil {
		r.log.Debug("child subreaper not available", "error", err.Error())
	}

	if code, err := r.start(); err != nil {
		return code
	}
	reapTick := time.NewTicker(2 * time.Second)
	defer reapTick.Stop()
	var refreshC <-chan time.Time
	if cfg.Refresh > 0 && cfg.Reload != nil {
		t := time.NewTicker(cfg.Refresh)
		defer t.Stop()
		refreshC = t.C
	}
	done := ctx.Done()
	for {
		var graceC <-chan time.Time
		if r.grace != nil {
			graceC = r.grace.C
		}
		select {
		case <-done:
			done = nil
			r.stop(syscall.SIGTERM)
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGCHLD:
			case syscall.SIGHUP:
				if cfg.ForwardHUP {
					r.signal(sig)
				} else {
					r.triggerReload(ctx, true, "sighup")
				}
			case syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT:
				r.stop(sig.(syscall.Signal))
			default:
				r.signal(sig)
			}
		case <-reapTick.C:
		case <-refreshC:
			r.triggerReload(ctx, false, "refresh")
		case res := <-r.reloadCh:
			r.reloading = false
			r.handleReload(res)
			continue
		case <-graceC:
			r.grace = nil
			r.log.Warn("child did not stop within the grace period, killing it", "grace", cfg.Grace.String())
			r.signal(syscall.SIGKILL)
		}
		if code, exited := r.reap(); exited {
			return code
		}
	}
}

// start launches the child with r.env.
func (r *runner) start() (int, error) {
	path, err := exec.LookPath(r.cfg.Argv[0])
	if err != nil {
		code := ExitNotFound
		if errors.Is(err, os.ErrPermission) {
			code = ExitCannotExecute
		}
		r.log.Error("cannot start the command", "command", r.cfg.Argv[0], "error", err.Error())
		return code, err
	}
	proc, err := os.StartProcess(path, r.cfg.Argv, &os.ProcAttr{
		Env:   r.env,
		Files: []*os.File{r.cfg.Stdin, r.cfg.Stdout, r.cfg.Stderr},
		Sys:   &syscall.SysProcAttr{Setpgid: r.useGroup},
	})
	if err != nil {
		r.log.Error("cannot start the command", "command", r.cfg.Argv[0], "error", err.Error())
		return ExitCannotExecute, err
	}
	r.pid = proc.Pid
	// The loop reaps with wait4(-1); release the os.Process handle.
	_ = proc.Release()
	r.state.ChildPID = r.pid
	r.state.StartedAt = time.Now().UTC()
	r.state.SecretsHash = r.hash
	r.state.Running = true
	r.writeState()
	r.log.Info("child started", "pid", r.pid, "restarts", r.state.Restarts)
	return 0, nil
}

// reap collects every exited child. It returns the supervisor exit code when
// the main child exited and no restart follows.
func (r *runner) reap() (int, bool) {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil || pid <= 0 {
			return 0, false
		}
		if pid != r.pid {
			continue // an orphan we adopted as PID 1 / subreaper
		}
		code := exitCode(ws)
		oldGroup := r.pid
		r.pid = 0
		r.state.Running = false
		r.state.LastExitCode = &code
		if r.grace != nil {
			r.grace.Stop()
			r.grace = nil
		}
		if r.restart == nil || r.stopping {
			r.writeState()
			r.log.Info("child exited", "code", code)
			return code, true
		}
		// In-place restart: clear what is left of the old group, start again.
		if r.useGroup {
			_ = syscall.Kill(-oldGroup, syscall.SIGKILL)
		}
		next := r.restart
		r.restart = nil
		r.env, r.hash = next.env, next.hash
		r.state.Restarts++
		r.log.Info("restarting child", "reason", next.reason, "previousExitCode", code)
		if c, err := r.start(); err != nil {
			return c, true
		}
	}
}

// triggerReload starts one Reload in the background (at most one at a time).
func (r *runner) triggerReload(ctx context.Context, force bool, reason string) {
	if r.stopping {
		return
	}
	if r.cfg.Reload == nil {
		r.handleReload(reloadResult{env: r.env, hash: r.hash, force: force, reason: reason})
		return
	}
	if r.reloading {
		return
	}
	r.reloading = true
	go func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.cfg.ReloadTimeout)
		defer cancel()
		env, hash, err := r.cfg.Reload(rctx)
		r.reloadCh <- reloadResult{env: env, hash: hash, err: err, force: force, reason: reason}
	}()
}

// handleReload restarts the child when forced or when the fingerprint changed.
func (r *runner) handleReload(res reloadResult) {
	if r.stopping || r.pid == 0 {
		return
	}
	if res.err != nil {
		if !res.force {
			r.log.Warn("secrets refresh failed, the child keeps its current values", "error", res.err.Error())
			return
		}
		r.log.Warn("secrets reload failed, restarting with the current values", "error", res.err.Error())
		res.env, res.hash = r.env, r.hash
	}
	if !res.force && res.hash == r.hash {
		return
	}
	if !res.force {
		res.reason = "secrets changed"
	}
	r.restart = &res
	r.signal(syscall.SIGTERM)
	if r.grace == nil {
		r.grace = time.NewTimer(r.cfg.Grace)
	}
}

// stop forwards a stop signal; no restart happens afterwards.
func (r *runner) stop(sig syscall.Signal) {
	r.stopping = true
	r.restart = nil
	r.signal(sig)
}

// signal sends sig to the child's process group (or the child alone).
func (r *runner) signal(sig os.Signal) {
	if r.pid == 0 {
		return
	}
	s, ok := sig.(syscall.Signal)
	if !ok {
		return
	}
	target := r.pid
	if r.useGroup {
		target = -r.pid
	}
	if err := syscall.Kill(target, s); err != nil && r.useGroup {
		_ = syscall.Kill(r.pid, s)
	}
}

// writeState writes the status file atomically (best effort).
func (r *runner) writeState() {
	if r.cfg.StateFile == "" {
		return
	}
	err := func() error {
		if err := os.MkdirAll(filepath.Dir(r.cfg.StateFile), 0o755); err != nil {
			return err
		}
		b, err := json.Marshal(r.state)
		if err != nil {
			return err
		}
		tmp := r.cfg.StateFile + ".tmp"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, r.cfg.StateFile)
	}()
	if err != nil && !r.stateErr {
		r.stateErr = true
		r.log.Warn("cannot write the state file", "path", r.cfg.StateFile, "error", err.Error())
	}
}

// ReadState reads a state file written by a supervisor.
func ReadState(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

// exitCode maps a wait status to a shell-style exit code (128+n for signal n).
func exitCode(ws syscall.WaitStatus) int {
	switch {
	case ws.Exited():
		return ws.ExitStatus()
	case ws.Signaled():
		return 128 + int(ws.Signal())
	}
	return 1
}
