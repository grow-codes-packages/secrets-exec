// Package fakevault is an in-memory HashiCorp Vault / OpenBao for tests: the
// AppRole login, KV v2 list/read and token revoke-self endpoints, with the
// same status codes and error bodies as the real server.
package fakevault

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Server is a fake Vault. Use New, then Set/Delete keys while tests run.
type Server struct {
	*httptest.Server

	// Mount is the KV v2 mount (fixed at "secret").
	Mount string

	roleID, secretID string
	tokenTTL         int // lease_duration (seconds) of logins

	mu      sync.Mutex
	data    map[string]any // full path under the mount -> value field
	tokens  map[string]bool
	sealed  bool
	counter atomic.Int64

	Logins  atomic.Int64
	Revokes atomic.Int64
	Reads   atomic.Int64
}

// New starts a fake Vault with one AppRole (role-1 / secret-1) and mount "secret".
func New() *Server {
	s := &Server{roleID: "role-1", secretID: "secret-1", Mount: "secret", tokenTTL: 3600,
		data: map[string]any{}, tokens: map[string]bool{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Set stores key = value (any JSON value) at path/key.
func (s *Server) Set(path, key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[strings.Trim(path, "/")+"/"+key] = value
}

// SetRaw stores a secret without a "value" field (data = nil marker).
func (s *Server) SetRaw(path, key string) { s.Set(path, key, rawMarker{}) }

// Delete removes path/key.
func (s *Server) Delete(path, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, strings.Trim(path, "/")+"/"+key)
}

// SetSecretID changes the accepted AppRole secret id.
func (s *Server) SetSecretID(id string) { s.mu.Lock(); s.secretID = id; s.mu.Unlock() }

// SetTokenTTL changes the lease_duration (seconds) of later logins.
func (s *Server) SetTokenTTL(ttl int) { s.mu.Lock(); s.tokenTTL = ttl; s.mu.Unlock() }

// Seal makes every request answer 503 (sealed) until Unseal.
func (s *Server) Seal() { s.mu.Lock(); s.sealed = true; s.mu.Unlock() }

// Unseal ends Seal.
func (s *Server) Unseal() { s.mu.Lock(); s.sealed = false; s.mu.Unlock() }

// RevokeAll invalidates every issued token (simulates expiry).
func (s *Server) RevokeAll() { s.mu.Lock(); s.tokens = map[string]bool{}; s.mu.Unlock() }

type rawMarker struct{}

// handle routes one request like the Vault HTTP API.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	sealed := s.sealed
	s.mu.Unlock()
	if sealed {
		writeErr(w, http.StatusServiceUnavailable, "Vault is sealed")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case r.Method == http.MethodPost && p == "auth/approle/login":
		s.login(w, r)
	case r.Method == http.MethodPost && p == "auth/token/revoke-self":
		if !s.authorized(r) {
			writeErr(w, http.StatusForbidden, "permission denied")
			return
		}
		s.mu.Lock()
		delete(s.tokens, r.Header.Get("X-Vault-Token"))
		s.mu.Unlock()
		s.Revokes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(p, s.Mount+"/metadata/") && (r.Method == "LIST" || r.URL.Query().Get("list") == "true"):
		if !s.authorized(r) {
			writeErr(w, http.StatusForbidden, "permission denied")
			return
		}
		s.list(w, strings.Trim(strings.TrimPrefix(p, s.Mount+"/metadata/"), "/"))
	case r.Method == http.MethodGet && strings.HasPrefix(p, s.Mount+"/data/"):
		if !s.authorized(r) {
			writeErr(w, http.StatusForbidden, "permission denied")
			return
		}
		s.read(w, strings.Trim(strings.TrimPrefix(p, s.Mount+"/data/"), "/"))
	default:
		writeErr(w, http.StatusNotFound, "")
	}
}

// login implements POST auth/approle/login.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	ok, ttl := body.RoleID == s.roleID && body.SecretID == s.secretID, s.tokenTTL
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid role or secret ID")
		return
	}
	token := fmt.Sprintf("hvs.fake-%d", s.counter.Add(1))
	s.mu.Lock()
	s.tokens[token] = true
	s.mu.Unlock()
	s.Logins.Add(1)
	writeJSON(w, map[string]any{"auth": map[string]any{
		"client_token": token, "accessor": "acc-" + token, "policies": []string{"default"},
		"lease_duration": ttl, "renewable": true,
	}})
}

// authorized reports whether the request carries a live token.
func (s *Server) authorized(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[r.Header.Get("X-Vault-Token")]
}

// list implements LIST <mount>/metadata/<folder>.
func (s *Server) list(w http.ResponseWriter, folder string) {
	s.mu.Lock()
	seen := map[string]bool{}
	for full := range s.data {
		rest, ok := strings.CutPrefix(full, folder+"/")
		if !ok {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i+1]
		}
		seen[rest] = true
	}
	s.mu.Unlock()
	if len(seen) == 0 {
		writeErr(w, http.StatusNotFound, "")
		return
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeJSON(w, map[string]any{"data": map[string]any{"keys": keys}})
}

// read implements GET <mount>/data/<path>.
func (s *Server) read(w http.ResponseWriter, full string) {
	s.Reads.Add(1)
	s.mu.Lock()
	v, ok := s.data[full]
	s.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "")
		return
	}
	data := map[string]any{"value": v}
	if _, raw := v.(rawMarker); raw {
		data = map[string]any{"other": "x"}
	}
	writeJSON(w, map[string]any{"data": map[string]any{
		"data":     data,
		"metadata": map[string]any{"version": 1, "created_time": "2026-11-20T00:00:00Z", "destroyed": false, "deletion_time": ""},
	}})
}

// writeJSON writes v as a JSON 200 response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes a Vault-style {"errors": [...]} response.
func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	errs := []string{}
	if msg != "" {
		errs = append(errs, msg)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
}
