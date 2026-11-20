package main

// End-to-end tests: build the real binary once, run it against the fake
// Vault and drive it with real signals.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/grow-codes-packages/secrets-exec/internal/fakevault"
	"github.com/grow-codes-packages/secrets-exec/internal/supervisor"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "grow-secrets-exec-test")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "grow-secrets-exec")
	out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput()
	if err != nil {
		fmt.Fprintln(os.Stderr, string(out))
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

const secretValue = "postgres://user:Sup3rS3cret@db/app"

func newVault(t *testing.T) *fakevault.Server {
	t.Helper()
	fv := fakevault.New()
	t.Cleanup(fv.Close)
	fv.Set("services/api", "DATABASE_URL", secretValue)
	fv.Set("services/api", "LOG_LEVEL", "debug")
	return fv
}

func bootstrapEnv(fv *fakevault.Server) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"GROW_SECRETS_PROVIDER=hashicorp-vault",
		"GROW_SECRETS_ADDR=" + fv.URL,
		"GROW_SECRETS_KV_MOUNT=secret",
		"GROW_SECRETS_PATH=services/api",
		"GROW_SECRETS_AUTH=approle",
		"GROW_SECRETS_ROLE_ID=role-1",
		"GROW_SECRETS_SECRET_ID=secret-1",
		"LOG_LEVEL=info",
	}
}

type run struct {
	cmd            *exec.Cmd
	stdout, stderr *bytes.Buffer
}

func start(t *testing.T, env []string, args ...string) *run {
	t.Helper()
	r := &run{cmd: exec.Command(binary, args...), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	r.cmd.Env = env
	r.cmd.Stdout, r.cmd.Stderr = r.stdout, r.stderr
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.cmd.Process.Kill(); _ = r.cmd.Wait() })
	return r
}

func (r *run) wait(t *testing.T) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("timeout; stderr:\n%s", r.stderr)
	}
	return r.cmd.ProcessState.ExitCode()
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func readFile(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{secretValue, "Sup3rS3cret", "secret-1"} {
		if strings.Contains(out, s) {
			t.Fatalf("output leaks %q:\n%s", s, out)
		}
	}
}

func TestSuperviseInjectsSecretsAndPassesExitCode(t *testing.T) {
	fv := newVault(t)
	r := start(t, bootstrapEnv(fv), "--state-file", "", "--",
		"sh", "-c", `[ "$DATABASE_URL" = "`+secretValue+`" ] && [ "$LOG_LEVEL" = debug ] && echo injected; exit 7`)
	if code := r.wait(t); code != 7 {
		t.Fatalf("exit %d, stderr:\n%s", code, r.stderr)
	}
	if strings.TrimSpace(r.stdout.String()) != "injected" {
		t.Fatalf("stdout %q", r.stdout)
	}
	if !strings.Contains(r.stderr.String(), `"msg":"secrets loaded"`) || !strings.Contains(r.stderr.String(), `"count":2`) {
		t.Fatalf("stderr %s", r.stderr)
	}
	assertNoLeak(t, r.stderr.String())
	if fv.Revokes.Load() != 1 {
		t.Fatalf("token not revoked (refresh off): %d", fv.Revokes.Load())
	}
}

func TestKeepExistingAndStripBootstrap(t *testing.T) {
	fv := newVault(t)
	r := start(t, bootstrapEnv(fv), "--keep-existing", "--strip-bootstrap", "--state-file", "", "--",
		"sh", "-c", `[ "$LOG_LEVEL" = info ] && [ -z "$GROW_SECRETS_SECRET_ID" ] && [ -n "$GROW_SECRETS_PATH" ]`)
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, r.stderr)
	}
}

func TestRequiredMissingFailsFastNamingKeys(t *testing.T) {
	fv := newVault(t)
	r := start(t, bootstrapEnv(fv), "--required", "DATABASE_URL,JWT_SECRET,REDIS_URL", "--", "true")
	if code := r.wait(t); code != 78 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(r.stderr.String(), "JWT_SECRET, REDIS_URL") {
		t.Fatalf("stderr %s", r.stderr)
	}
	assertNoLeak(t, r.stderr.String())
}

func TestRequiredFromEnvVariable(t *testing.T) {
	fv := newVault(t)
	env := append(bootstrapEnv(fv), "GROW_SECRETS_REQUIRED=DATABASE_URL LOG_LEVEL")
	if code := start(t, env, "--state-file", "", "--", "true").wait(t); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestBadSecretIDExits77(t *testing.T) {
	fv := newVault(t)
	fv.SetSecretID("other")
	r := start(t, bootstrapEnv(fv), "--", "true")
	if code := r.wait(t); code != 77 {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
	assertNoLeak(t, r.stderr.String())
}

func TestSealedExits69AfterWait(t *testing.T) {
	fv := newVault(t)
	fv.Seal()
	r := start(t, bootstrapEnv(fv), "--wait", "1s", "--", "true")
	if code := r.wait(t); code != 69 {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
}

func TestSealedThenUnsealedStarts(t *testing.T) {
	fv := newVault(t)
	fv.Seal()
	r := start(t, bootstrapEnv(fv), "--wait", "20s", "--state-file", "", "--", "sh", "-c", `[ -n "$DATABASE_URL" ]`)
	time.Sleep(700 * time.Millisecond)
	fv.Unseal()
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
}

func TestOptionalStartsWithoutSecrets(t *testing.T) {
	fv := newVault(t)
	fv.SetSecretID("other")
	r := start(t, bootstrapEnv(fv), "--optional", "--state-file", "", "--", "sh", "-c", `[ -z "$DATABASE_URL" ]`)
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
}

func TestNoBootstrapPassesThroughOrFails(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH")}
	if code := start(t, env, "--state-file", "", "--", "sh", "-c", "exit 5").wait(t); code != 5 {
		t.Fatalf("pass-through exit %d", code)
	}
	if code := start(t, env, "--require-bootstrap", "--", "true").wait(t); code != 78 {
		t.Fatalf("--require-bootstrap exit %d", code)
	}
}

func TestInvalidBootstrapExits78(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH"), "GROW_SECRETS_ADDR=http://v:8200", "GROW_SECRETS_PROVIDER=infisical"}
	r := start(t, env, "--", "true")
	if code := r.wait(t); code != 78 || !strings.Contains(r.stderr.String(), "GROW_SECRETS_PROVIDER") {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
}

func TestUsageAndNotFound(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH")}
	if code := start(t, env).wait(t); code != 64 {
		t.Fatalf("no command: exit %d", code)
	}
	if code := start(t, env, "--state-file", "", "--", "does-not-exist-xyz").wait(t); code != 127 {
		t.Fatalf("not found: exit %d", code)
	}
}

func TestExecModeReplacesProcess(t *testing.T) {
	fv := newVault(t)
	r := start(t, bootstrapEnv(fv), "--exec", "--", "sh", "-c", `[ -n "$DATABASE_URL" ] && echo $$`)
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
	if got := strings.TrimSpace(r.stdout.String()); got != strconv.Itoa(r.cmd.Process.Pid) {
		t.Fatalf("exec pid %s, wrapper pid %d", got, r.cmd.Process.Pid)
	}
	if fv.Revokes.Load() != 1 {
		t.Fatal("token not revoked before exec")
	}
}

func TestNamesPrintsNamesOnly(t *testing.T) {
	fv := newVault(t)
	r := start(t, bootstrapEnv(fv), "names")
	if code := r.wait(t); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if r.stdout.String() != "DATABASE_URL\nLOG_LEVEL\n" {
		t.Fatalf("stdout %q", r.stdout)
	}
	assertNoLeak(t, r.stdout.String()+r.stderr.String())
}

// childScript records "<pid> <DATABASE_URL>" and waits for TERM (exit 42).
const childScript = `echo "$$ $DATABASE_URL" > "$OUT"; trap 'exit 42' TERM; while :; do sleep 0.05; done`

func TestTermIsForwardedAndCodePassedThrough(t *testing.T) {
	fv := newVault(t)
	out := filepath.Join(t.TempDir(), "child")
	r := start(t, append(bootstrapEnv(fv), "OUT="+out), "--state-file", "", "--", "sh", "-c", childScript)
	eventually(t, "child start", func() bool { return readFile(out) != "" })
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	if code := r.wait(t); code != 42 {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
}

func TestHupRestartsChildWithFreshSecrets(t *testing.T) {
	fv := newVault(t)
	dir := t.TempDir()
	out, state := filepath.Join(dir, "child"), filepath.Join(dir, "state.json")
	r := start(t, append(bootstrapEnv(fv), "OUT="+out), "--state-file", state, "--grace", "5s", "--", "sh", "-c", childScript)
	eventually(t, "child start", func() bool { return readFile(out) != "" })
	first := readFile(out)
	fv.Set("services/api", "DATABASE_URL", "postgres://rotated")
	_ = r.cmd.Process.Signal(syscall.SIGHUP)
	eventually(t, "restart", func() bool { got := readFile(out); return got != first && strings.HasSuffix(got, "postgres://rotated") })
	eventually(t, "state", func() bool {
		st, err := supervisor.ReadState(state)
		return err == nil && st.Restarts == 1 && st.Running && st.SupervisorPID == r.cmd.Process.Pid
	})
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	if code := r.wait(t); code != 42 {
		t.Fatalf("exit %d, stderr %s", code, r.stderr)
	}
	assertNoLeak(t, r.stderr.String())
}

func TestRestartSubcommandSignalsSupervisor(t *testing.T) {
	dir := t.TempDir()
	out, state := filepath.Join(dir, "child"), filepath.Join(dir, "state.json")
	env := []string{"PATH=" + os.Getenv("PATH"), "OUT=" + out}
	r := start(t, env, "--state-file", state, "--", "sh", "-c", childScript)
	eventually(t, "child start", func() bool { return readFile(out) != "" })
	first := readFile(out)
	ctl := start(t, env, "restart", state)
	if code := ctl.wait(t); code != 0 {
		t.Fatalf("restart exit %d: %s", code, ctl.stderr)
	}
	eventually(t, "restart", func() bool { return readFile(out) != first })
	st := start(t, env, "status", state)
	if code := st.wait(t); code != 0 || !strings.Contains(st.stdout.String(), `"restarts":1`) {
		t.Fatalf("status %d %s", code, st.stdout)
	}
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	r.wait(t)
}

func TestRefreshRestartsOnlyOnChange(t *testing.T) {
	fv := newVault(t)
	dir := t.TempDir()
	out, state := filepath.Join(dir, "child"), filepath.Join(dir, "state.json")
	r := start(t, append(bootstrapEnv(fv), "OUT="+out), "--refresh", "150ms", "--state-file", state, "--", "sh", "-c", childScript)
	eventually(t, "child start", func() bool { return readFile(out) != "" })
	first := readFile(out)
	time.Sleep(600 * time.Millisecond) // several unchanged refreshes
	if st, _ := supervisor.ReadState(state); st.Restarts != 0 || readFile(out) != first {
		t.Fatalf("restarted without a change: %+v", st)
	}
	logins := fv.Logins.Load()
	fv.Set("services/api", "NEW_KEY", "x")
	eventually(t, "restart on change", func() bool { return readFile(out) != first })
	if fv.Logins.Load() != logins {
		t.Fatal("refresh logged in again although the token is valid")
	}
	fv.Seal() // failing refreshes keep the child running
	time.Sleep(500 * time.Millisecond)
	if st, _ := supervisor.ReadState(state); st.Restarts != 1 || !st.Running {
		t.Fatalf("state after failing refresh %+v", st)
	}
	fv.Unseal()
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	if code := r.wait(t); code != 42 {
		t.Fatalf("exit %d", code)
	}
}

func TestGraceKillsStubbornChildOnRestart(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "child")
	env := []string{"PATH=" + os.Getenv("PATH"), "OUT=" + out}
	script := `echo $$ > "$OUT"; trap '' TERM; while :; do sleep 0.05; done`
	r := start(t, env, "--grace", "300ms", "--state-file", "", "--", "sh", "-c", script)
	eventually(t, "child start", func() bool { return readFile(out) != "" })
	first := readFile(out)
	_ = r.cmd.Process.Signal(syscall.SIGHUP)
	eventually(t, "restart after kill", func() bool { return readFile(out) != "" && readFile(out) != first })
	// The stubborn group would outlive a killed wrapper (not PID 1 here).
	if pid, err := strconv.Atoi(readFile(out)); err == nil {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
	_ = r.cmd.Process.Signal(syscall.SIGKILL)
	r.wait(t)
}
