// Package secrets logs in to HashiCorp Vault or OpenBao and reads every key
// under the service's secrets path.
//
// Layout (Grow foundation): one KV v2 secret per key, the value in the field
// "value", under <mount>/<path>/<KEY>. Sub-folders are skipped.
//
// It uses the Grow Codes Go SDK (github.com/grow-codes-packages/hashicorp-vault/go),
// which redacts credentials from its errors. Values are returned in memory only.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	vault "github.com/grow-codes-packages/hashicorp-vault/go"

	"github.com/grow-codes-packages/secrets-exec/internal/bootstrap"
	"github.com/grow-codes-packages/secrets-exec/internal/envx"
)

// ValueField is the KV data field that holds a key's value.
const ValueField = "value"

// DefaultConcurrency is the number of parallel key reads.
const DefaultConcurrency = 8

// Result is one load: the values plus the keys that were not exported.
type Result struct {
	Values  map[string]string
	Skipped []envx.Skip
}

// Options configure a Loader.
type Options struct {
	// Concurrency of key reads (default DefaultConcurrency).
	Concurrency int
	// RequestTimeout bounds one HTTP attempt (default 10 s).
	RequestTimeout time.Duration
	// UserAgent is appended to the SDK user agent.
	UserAgent string
	// Now replaces time.Now in tests.
	Now func() time.Time
}

// Loader reads the secrets of one service. It keeps its token between loads
// and logs in again when the token is about to expire or was rejected.
type Loader struct {
	b    Bootstrap
	opts Options

	client   *vault.Client
	kv       *vault.KVv2
	mu       sync.Mutex
	loggedIn bool
	expires  time.Time // zero = no expiry
}

// Bootstrap is an alias kept for readability of the constructor.
type Bootstrap = bootstrap.Bootstrap

// New builds a Loader. It does not contact the server.
func New(b Bootstrap, opts Options) (*Loader, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 10 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	cfg := vault.Config{}
	cfg.URL = b.Addr
	cfg.KVMount = b.KVMount
	cfg.KVVersion = 2
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RequestTimeout = opts.RequestTimeout
	cfg.TotalTimeout = 3 * opts.RequestTimeout
	cfg.UserAgentSuffix = opts.UserAgent
	cfg.TLS.CACertPath = b.CACert
	if b.Auth == bootstrap.AuthToken {
		cfg.Token = vault.NewSecret(b.Token)
	}
	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Loader{b: b, opts: opts, client: client, kv: client.KVv2(b.KVMount)}, nil
}

// Load lists and reads every key under the secrets path.
func (l *Loader) Load(ctx context.Context) (Result, error) {
	res, err := l.loadOnce(ctx)
	if err != nil && errors.Is(err, vault.ErrAuthentication) && l.b.Auth == bootstrap.AuthAppRole {
		// The token expired or was revoked: log in again once.
		l.mu.Lock()
		l.loggedIn = false
		l.mu.Unlock()
		res, err = l.loadOnce(ctx)
	}
	return res, err
}

// loadOnce lists the path and reads every key (8 in parallel) with the current token.
func (l *Loader) loadOnce(ctx context.Context) (Result, error) {
	if err := l.ensureLogin(ctx); err != nil {
		return Result{}, err
	}
	keys, err := l.kv.List(ctx, l.b.Path)
	if err != nil {
		return Result{}, err
	}
	var (
		mu      sync.Mutex
		raw     = map[string]string{}
		skipped []envx.Skip
		firstEr error
		wg      sync.WaitGroup
		sem     = make(chan struct{}, l.opts.Concurrency)
	)
	for _, key := range keys {
		if strings.HasSuffix(key, "/") {
			mu.Lock()
			skipped = append(skipped, envx.Skip{Name: strings.TrimSuffix(key, "/"), Reason: "sub-folder"})
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(key string) {
			defer wg.Done()
			defer func() { <-sem }()
			value, skip, err := l.readKey(ctx, key)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				if firstEr == nil {
					firstEr = err
				}
			case skip != "":
				skipped = append(skipped, envx.Skip{Name: key, Reason: skip})
			default:
				raw[key] = value
			}
		}(key)
	}
	wg.Wait()
	if firstEr != nil {
		return Result{}, firstEr
	}
	values, invalid := envx.Clean(raw)
	return Result{Values: values, Skipped: append(skipped, invalid...)}, nil
}

// readKey returns the value of one key, or a skip reason.
func (l *Loader) readKey(ctx context.Context, key string) (string, string, error) {
	secret, err := l.kv.Read(ctx, joinPath(l.b.Path, key), nil)
	if errors.Is(err, vault.ErrNotFound) {
		return "", "deleted or destroyed", nil
	}
	if err != nil {
		return "", "", err
	}
	v, ok := secret.Data[ValueField]
	if !ok || v == nil {
		return "", "no \"value\" field", nil
	}
	s, err := stringify(v)
	if err != nil {
		return "", "value is not representable as text", nil
	}
	return s, "", nil
}

// ensureLogin logs in with AppRole when there is no valid token.
func (l *Loader) ensureLogin(ctx context.Context) error {
	if l.b.Auth != bootstrap.AuthAppRole {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.opts.Now()
	if l.loggedIn && (l.expires.IsZero() || now.Before(l.expires)) {
		return nil
	}
	auth := vault.NewAppRoleAuth(l.b.RoleID, l.b.SecretID)
	auth.Mount = l.b.AuthMount
	info, err := l.client.Auth().Login(ctx, auth)
	if err != nil {
		return err
	}
	l.loggedIn = true
	l.expires = time.Time{}
	if info.LeaseDuration > 0 {
		// Log in again after half the TTL, so a refresh never uses a token
		// that expires mid-load.
		l.expires = now.Add(info.LeaseDuration / 2)
	}
	return nil
}

// Close revokes the AppRole token (best effort) and releases the client.
// Token auth keeps its token: it belongs to the caller.
func (l *Loader) Close(ctx context.Context) {
	l.mu.Lock()
	loggedIn := l.loggedIn
	l.loggedIn = false
	l.mu.Unlock()
	if loggedIn && l.b.Auth == bootstrap.AuthAppRole {
		_ = l.client.Auth().RevokeSelf(ctx)
	}
	_ = l.client.Close()
}

// Retryable reports whether err may go away by itself (server sealed,
// starting, unreachable, rate limited or timed out).
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	var e *vault.Error
	if errors.As(err, &e) {
		return e.Retryable || e.Code.Retryable()
	}
	return false
}

// Kind classifies err for exit codes: "auth", "unavailable" or "other".
func Kind(err error) string {
	switch {
	case errors.Is(err, vault.ErrAuthentication), errors.Is(err, vault.ErrPermissionDenied):
		return "auth"
	case Retryable(err):
		return "unavailable"
	}
	return "other"
}

// stringify turns a KV value into environment text (JSON for objects).
func stringify(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case json.Number:
		return t.String(), nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", fmt.Errorf("encode value: %w", err)
		}
		return string(b), nil
	}
}

// joinPath joins non-empty path segments with "/".
func joinPath(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.Trim(p, "/"); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}
