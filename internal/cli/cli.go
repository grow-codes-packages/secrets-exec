// Package cli implements the grow-secrets-exec command line.
//
//	grow-secrets-exec [flags] -- <command> [args...]   supervise (default) or --exec
//	grow-secrets-exec names                            print the key names it would export
//	grow-secrets-exec status                           print the supervisor state file
//	grow-secrets-exec restart                          SIGHUP the running supervisor
//	grow-secrets-exec version
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/grow-codes-packages/secrets-exec/internal/bootstrap"
	"github.com/grow-codes-packages/secrets-exec/internal/envx"
	"github.com/grow-codes-packages/secrets-exec/internal/secrets"
	"github.com/grow-codes-packages/secrets-exec/internal/supervisor"
)

// Exit codes of the wrapper itself (sysexits.h), chosen so they never look
// like a clean exit and are easy to tell apart from the app's own codes in
// `kubectl describe` / the platform diagnostics.
const (
	ExitOK          = 0
	ExitUsage       = 64 // bad flags or no command
	ExitUnavailable = 69 // secrets service unreachable/sealed until --wait elapsed
	ExitSoftware    = 70 // internal error
	ExitNoPerm      = 77 // login rejected or permission denied
	ExitConfig      = 78 // bootstrap incomplete, unsupported provider, missing required keys
)

// DefaultStateFile is where the supervisor writes its status.
const DefaultStateFile = "/tmp/grow-secrets-exec/state.json"

// Env names of the options (flags win).
const (
	EnvRequired = "GROW_SECRETS_REQUIRED"
	EnvRefresh  = "GROW_SECRETS_REFRESH"
)

// Options are the parsed flags.
type Options struct {
	Exec             bool
	Required         []string
	Refresh          time.Duration
	Wait             time.Duration
	Grace            time.Duration
	Optional         bool
	RequireBootstrap bool
	StripBootstrap   bool
	KeepExisting     bool
	ForwardHUP       bool
	StateFile        string
	Command          []string
}

// IO bundles what Main needs from the process (replaceable in tests).
type IO struct {
	Args    []string
	Getenv  func(string) string
	Environ func() []string
	Stdout  io.Writer
	Stderr  io.Writer
}

// Main runs the command line and returns the process exit code.
func Main(ctx context.Context, version string, pio IO) int {
	log := slog.New(slog.NewJSONHandler(pio.Stderr, nil)).With("logger", "grow-secrets-exec")
	args := pio.Args
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version":
			fmt.Fprintln(pio.Stdout, "grow-secrets-exec", version)
			return ExitOK
		case "names":
			return runNames(ctx, version, pio, log)
		case "status":
			return runStatus(pio, args[1:])
		case "restart":
			return runRestart(pio, log, args[1:])
		}
	}
	opts, err := ParseFlags(args, pio.Getenv, pio.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		fmt.Fprintln(pio.Stderr, "grow-secrets-exec:", err)
		return ExitUsage
	}
	env, hash, loader, code := initialEnv(ctx, version, opts, pio, log)
	if code != ExitOK {
		return code
	}
	if opts.Exec {
		if loader != nil {
			loader.Close(ctx)
		}
		return execCommand(opts.Command, env, log)
	}
	var reload supervisor.Reloader
	if loader != nil {
		if opts.Refresh <= 0 {
			// No periodic refresh: do not keep a token alive between restarts.
			loader.Close(ctx)
			loader = nil
		}
		reload = func(rctx context.Context) ([]string, string, error) {
			l := loader
			if l == nil {
				b, err := bootstrap.FromEnv(pio.Getenv)
				if err != nil {
					return nil, "", err
				}
				if l, err = secrets.New(b, secrets.Options{UserAgent: "grow-secrets-exec/" + version}); err != nil {
					return nil, "", err
				}
				defer l.Close(rctx)
			}
			res, err := l.Load(rctx)
			if err != nil {
				return nil, "", err
			}
			merged, err := buildEnv(pio.Environ(), res, opts)
			if err != nil {
				return nil, "", err
			}
			logLoaded(log, "secrets reloaded", res, 0)
			return merged, envx.Hash(res.Values), nil
		}
	}
	code = supervisor.Run(ctx, supervisor.Config{
		Argv: opts.Command, Env: env, Hash: hash, Reload: reload,
		Refresh: opts.Refresh, Grace: opts.Grace, ForwardHUP: opts.ForwardHUP,
		StateFile: opts.StateFile, Version: version, Logger: log,
	})
	if loader != nil {
		loader.Close(context.WithoutCancel(ctx))
	}
	return code
}

// ParseFlags parses args (flags, then "--", then the command).
func ParseFlags(args []string, getenv func(string) string, stderr io.Writer) (Options, error) {
	fs := flag.NewFlagSet("grow-secrets-exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o Options
	var required string
	refreshDefault := time.Duration(0)
	if v := strings.TrimSpace(getenv(EnvRefresh)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return o, fmt.Errorf("%s: %v", EnvRefresh, err)
		}
		refreshDefault = d
	}
	fs.BoolVar(&o.Exec, "exec", false, "plain mode: load the secrets, then replace this process with the command (no supervisor)")
	fs.StringVar(&required, "required", getenv(EnvRequired), "comma-separated names that must be set (secrets or environment); exit 78 naming the missing ones")
	fs.DurationVar(&o.Refresh, "refresh", refreshDefault, "re-read the secrets this often and restart the child when they changed (0 = off)")
	fs.DurationVar(&o.Wait, "wait", 120*time.Second, "keep retrying an unreachable or sealed secrets service this long at start")
	fs.DurationVar(&o.Grace, "grace", 10*time.Second, "wait between SIGTERM and SIGKILL when restarting the child")
	fs.BoolVar(&o.Optional, "optional", false, "start the command without secrets when loading fails (logged as an error)")
	fs.BoolVar(&o.RequireBootstrap, "require-bootstrap", false, "exit 78 when no GROW_SECRETS_* bootstrap is present (default: run the command unchanged)")
	fs.BoolVar(&o.StripBootstrap, "strip-bootstrap", false, "remove GROW_SECRETS_ROLE_ID/SECRET_ID/TOKEN from the child environment")
	fs.BoolVar(&o.KeepExisting, "keep-existing", false, "keep variables already set in the environment instead of overriding them with secrets")
	fs.BoolVar(&o.ForwardHUP, "forward-hup", false, "forward SIGHUP to the child instead of restarting it")
	fs.StringVar(&o.StateFile, "state-file", DefaultStateFile, "supervisor status file (\"\" = none)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: grow-secrets-exec [flags] -- <command> [args...]")
		fmt.Fprintln(stderr, "       grow-secrets-exec names | status | restart | version")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.Required = envx.SplitList(required)
	o.Command = fs.Args()
	if len(o.Command) == 0 {
		return o, errors.New("no command given (usage: grow-secrets-exec [flags] -- <command> [args...])")
	}
	if o.Refresh < 0 || o.Wait < 0 || o.Grace < 0 {
		return o, errors.New("durations must not be negative")
	}
	return o, nil
}

// initialEnv loads the secrets once (with retries) and builds the first child
// environment. loader is nil when there is no bootstrap or with --optional
// after a failure.
func initialEnv(ctx context.Context, version string, opts Options, pio IO, log *slog.Logger) ([]string, string, *secrets.Loader, int) {
	base := pio.Environ()
	if !bootstrap.Present(pio.Getenv) {
		if opts.RequireBootstrap {
			log.Error("no secrets bootstrap (GROW_SECRETS_*) in the environment")
			return nil, "", nil, ExitConfig
		}
		log.Warn("no secrets bootstrap (GROW_SECRETS_*) in the environment, starting the command without secrets")
		return checkRequired(base, "", nil, opts, log)
	}
	b, err := bootstrap.FromEnv(pio.Getenv)
	if err != nil {
		log.Error("invalid secrets bootstrap", "error", err.Error())
		return nil, "", nil, ExitConfig
	}
	loader, err := secrets.New(b, secrets.Options{UserAgent: "grow-secrets-exec/" + version})
	if err != nil {
		log.Error("invalid secrets bootstrap", "error", err.Error())
		return nil, "", nil, ExitConfig
	}
	started := time.Now()
	res, err := loadWithRetry(ctx, loader, opts.Wait, log)
	if err != nil {
		loader.Close(ctx)
		code := ExitSoftware
		switch secrets.Kind(err) {
		case "auth":
			code = ExitNoPerm
		case "unavailable":
			code = ExitUnavailable
		}
		if opts.Optional {
			log.Error("loading secrets failed, starting the command without secrets (--optional)",
				"path", b.Path, "provider", b.Provider, "error", err.Error())
			return checkRequired(base, "", nil, opts, log)
		}
		log.Error("loading secrets failed", "path", b.Path, "provider", b.Provider, "error", err.Error(), "exitCode", code)
		return nil, "", nil, code
	}
	logLoaded(log.With("path", b.Path, "provider", b.Provider), "secrets loaded", res, time.Since(started))
	env, err := buildEnv(base, res, opts)
	if err != nil {
		loader.Close(ctx)
		log.Error(err.Error())
		return nil, "", nil, ExitConfig
	}
	return env, envx.Hash(res.Values), loader, ExitOK
}

// checkRequired verifies the required names on an environment without secrets.
func checkRequired(env []string, hash string, loader *secrets.Loader, opts Options, log *slog.Logger) ([]string, string, *secrets.Loader, int) {
	if missing := envx.Missing(env, opts.Required); len(missing) > 0 {
		log.Error("required keys are missing", "missing", missing)
		return nil, "", nil, ExitConfig
	}
	return env, hash, loader, ExitOK
}

// buildEnv merges the secrets into base and checks the required names.
func buildEnv(base []string, res secrets.Result, opts Options) ([]string, error) {
	env := envx.Merge(base, res.Values, envx.MergeOptions{KeepExisting: opts.KeepExisting, StripBootstrap: opts.StripBootstrap})
	if missing := envx.Missing(env, opts.Required); len(missing) > 0 {
		return nil, fmt.Errorf("required keys are missing (not in the secrets path nor the environment): %s", strings.Join(missing, ", "))
	}
	return env, nil
}

// loadWithRetry retries retryable failures with backoff until wait elapsed.
func loadWithRetry(ctx context.Context, l *secrets.Loader, wait time.Duration, log *slog.Logger) (secrets.Result, error) {
	deadline := time.Now().Add(wait)
	backoff := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		res, err := l.Load(ctx)
		if err == nil || !secrets.Retryable(err) || time.Now().Add(backoff).After(deadline) {
			return res, err
		}
		log.Warn("secrets service not ready, retrying", "attempt", attempt, "in", backoff.String(), "error", err.Error())
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 10*time.Second {
			backoff = 10 * time.Second
		}
	}
}

// logLoaded logs names-free statistics of one load (never values).
func logLoaded(log *slog.Logger, msg string, res secrets.Result, took time.Duration) {
	attrs := []any{"count", len(res.Values), "hash", envx.Hash(res.Values)}
	if took > 0 {
		attrs = append(attrs, "ms", took.Milliseconds())
	}
	if len(res.Skipped) > 0 {
		attrs = append(attrs, "skipped", res.Skipped)
	}
	log.Info(msg, attrs...)
}

// execCommand replaces the process with the command (plain --exec mode).
func execCommand(argv []string, env []string, log *slog.Logger) int {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		log.Error("cannot start the command", "command", argv[0], "error", err.Error())
		if errors.Is(err, os.ErrPermission) {
			return supervisor.ExitCannotExecute
		}
		return supervisor.ExitNotFound
	}
	err = syscall.Exec(path, argv, env)
	log.Error("cannot start the command", "command", argv[0], "error", err.Error())
	return supervisor.ExitCannotExecute
}

// runNames prints the names that would be exported, one per line.
func runNames(ctx context.Context, version string, pio IO, log *slog.Logger) int {
	if !bootstrap.Present(pio.Getenv) {
		log.Error("no secrets bootstrap (GROW_SECRETS_*) in the environment")
		return ExitConfig
	}
	b, err := bootstrap.FromEnv(pio.Getenv)
	if err != nil {
		log.Error("invalid secrets bootstrap", "error", err.Error())
		return ExitConfig
	}
	l, err := secrets.New(b, secrets.Options{UserAgent: "grow-secrets-exec/" + version})
	if err != nil {
		log.Error("invalid secrets bootstrap", "error", err.Error())
		return ExitConfig
	}
	defer l.Close(ctx)
	res, err := l.Load(ctx)
	if err != nil {
		log.Error("loading secrets failed", "error", err.Error())
		if secrets.Kind(err) == "auth" {
			return ExitNoPerm
		}
		return ExitUnavailable
	}
	for _, n := range envx.Names(res.Values) {
		fmt.Fprintln(pio.Stdout, n)
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(pio.Stderr, "skipped %s: %s\n", s.Name, s.Reason)
	}
	return ExitOK
}

// runStatus prints the state file.
func runStatus(pio IO, args []string) int {
	path := DefaultStateFile
	if len(args) > 0 {
		path = args[0]
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(pio.Stderr, "grow-secrets-exec: no supervisor state:", err)
		return ExitUnavailable
	}
	fmt.Fprintln(pio.Stdout, strings.TrimSpace(string(b)))
	return ExitOK
}

// runRestart sends SIGHUP to the supervisor named in the state file.
func runRestart(pio IO, log *slog.Logger, args []string) int {
	path := DefaultStateFile
	if len(args) > 0 {
		path = args[0]
	}
	st, err := supervisor.ReadState(path)
	if err != nil || st.SupervisorPID <= 0 {
		fmt.Fprintln(pio.Stderr, "grow-secrets-exec: no supervisor state at", path)
		return ExitUnavailable
	}
	if err := syscall.Kill(st.SupervisorPID, syscall.SIGHUP); err != nil {
		fmt.Fprintln(pio.Stderr, "grow-secrets-exec: cannot signal the supervisor:", err)
		return ExitUnavailable
	}
	fmt.Fprintf(pio.Stdout, "restart requested (supervisor pid %d, restarts so far %d)\n", st.SupervisorPID, st.Restarts)
	return ExitOK
}
