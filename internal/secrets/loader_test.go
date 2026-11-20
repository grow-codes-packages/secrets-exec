package secrets

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/grow-codes-packages/secrets-exec/internal/bootstrap"
	"github.com/grow-codes-packages/secrets-exec/internal/fakevault"
)

func setup(t *testing.T) (*fakevault.Server, *Loader) {
	t.Helper()
	fv := fakevault.New()
	t.Cleanup(fv.Close)
	l, err := New(bootstrap.Bootstrap{
		Provider: bootstrap.ProviderHashiCorpVault, Addr: fv.URL, KVMount: "secret",
		Path: "services/api", Auth: bootstrap.AuthAppRole, RoleID: "role-1", SecretID: "secret-1",
	}, Options{RequestTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(context.Background()) })
	return fv, l
}

func TestLoadReadsEveryKey(t *testing.T) {
	fv, l := setup(t)
	fv.Set("services/api", "DATABASE_URL", "postgres://db")
	fv.Set("services/api", "PORT", 8080.0)
	fv.Set("services/api", "DEBUG", true)
	fv.Set("services/api", "FEATURES", map[string]any{"a": 1.0})
	fv.Set("services/api/nested", "X", "skip-me")
	fv.SetRaw("services/api", "NO_VALUE")
	fv.Set("services/api", "bad-name", "x")
	fv.Set("services/other", "OTHER", "not mine")
	res, err := l.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"DATABASE_URL": "postgres://db", "PORT": "8080", "DEBUG": "true", "FEATURES": `{"a":1}`}
	if len(res.Values) != len(want) {
		t.Fatalf("values %v", res.Values)
	}
	for k, v := range want {
		if res.Values[k] != v {
			t.Errorf("%s = %q, want %q", k, res.Values[k], v)
		}
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Name] = s.Reason
	}
	if reasons["nested"] != "sub-folder" || reasons["NO_VALUE"] == "" || reasons["bad-name"] == "" || len(reasons) != 3 {
		t.Fatalf("skipped %+v", res.Skipped)
	}
}

func TestLoadEmptyPath(t *testing.T) {
	_, l := setup(t)
	res, err := l.Load(t.Context())
	if err != nil || len(res.Values) != 0 {
		t.Fatalf("got %v %v", res.Values, err)
	}
}

func TestLoadKeepsTokenAndReloginsAfterRevoke(t *testing.T) {
	fv, l := setup(t)
	fv.Set("services/api", "A", "1")
	for range 3 {
		if _, err := l.Load(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if n := fv.Logins.Load(); n != 1 {
		t.Fatalf("logins = %d, want 1 (token reused)", n)
	}
	fv.RevokeAll()
	res, err := l.Load(t.Context())
	if err != nil || res.Values["A"] != "1" {
		t.Fatalf("relogin load: %v %v", res.Values, err)
	}
	if n := fv.Logins.Load(); n != 2 {
		t.Fatalf("logins = %d, want 2", n)
	}
}

func TestLoginAgainAfterHalfTTL(t *testing.T) {
	fv, l := setup(t)
	fv.SetTokenTTL(10)
	now := time.Now()
	l.opts.Now = func() time.Time { return now }
	if _, err := l.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	if _, err := l.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := fv.Logins.Load(); n != 2 {
		t.Fatalf("logins = %d, want 2", n)
	}
}

func TestBadSecretIDIsAuthAndDoesNotLeak(t *testing.T) {
	fv, _ := setup(t)
	l, err := New(bootstrap.Bootstrap{Addr: fv.URL, KVMount: "secret", Path: "p", Auth: bootstrap.AuthAppRole,
		RoleID: "role-1", SecretID: "wrong-secret-id-value"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close(t.Context())
	_, err = l.Load(t.Context())
	if err == nil || Kind(err) != "auth" || Retryable(err) {
		t.Fatalf("got %v kind=%s", err, Kind(err))
	}
	if strings.Contains(err.Error(), "wrong-secret-id-value") {
		t.Fatal("error leaks the secret id")
	}
}

func TestSealedIsRetryable(t *testing.T) {
	fv, l := setup(t)
	fv.Seal()
	_, err := l.Load(t.Context())
	if err == nil || !Retryable(err) || Kind(err) != "unavailable" {
		t.Fatalf("got %v", err)
	}
}

func TestCloseRevokesAppRoleToken(t *testing.T) {
	fv, l := setup(t)
	if _, err := l.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	l.Close(t.Context())
	if fv.Revokes.Load() != 1 {
		t.Fatalf("revokes = %d", fv.Revokes.Load())
	}
}

func TestManyKeysInParallel(t *testing.T) {
	fv, l := setup(t)
	for i := range 50 {
		fv.Set("services/api", "K"+strings.Repeat("X", i%5)+string(rune('A'+i%26))+string(rune('A'+i/26)), "v")
	}
	res, err := l.Load(t.Context())
	if err != nil || len(res.Values) != 50 || fv.Reads.Load() != 50 {
		t.Fatalf("values=%d reads=%d err=%v", len(res.Values), fv.Reads.Load(), err)
	}
}
