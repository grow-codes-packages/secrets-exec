// Package envx validates secret names and builds the child environment.
//
// Values only ever live in memory: nothing in this package writes, prints or
// logs a value. Skip reasons and errors carry names only.
package envx

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// MaxValueBytes is the largest value exported into the environment.
const MaxValueBytes = 64 * 1024

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// protectedNames are never overwritten by a secret.
var protectedNames = map[string]bool{
	"PATH": true, "HOME": true, "PWD": true, "OLDPWD": true, "SHELL": true,
	"HOSTNAME": true, "USER": true, "TERM": true,
}

// protectedPrefixes are never overwritten by a secret.
var protectedPrefixes = []string{"LD_", "GROW_SECRETS_"}

// BootstrapCredentialNames are removed from the child by MergeOptions.StripBootstrap.
var BootstrapCredentialNames = []string{"GROW_SECRETS_ROLE_ID", "GROW_SECRETS_SECRET_ID", "GROW_SECRETS_TOKEN"}

// Skip records a key that was not exported and why (name + reason, no value).
type Skip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// ValidName reports whether name can be an environment variable name.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// Protected reports whether name is reserved for the platform or the system.
func Protected(name string) bool {
	if protectedNames[name] {
		return true
	}
	for _, p := range protectedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// Clean drops keys that cannot or must not be exported: invalid names,
// protected names, values over MaxValueBytes and values with a NUL byte.
// It returns the exportable values and the skipped names with reasons.
func Clean(values map[string]string) (map[string]string, []Skip) {
	out := make(map[string]string, len(values))
	var skipped []Skip
	for _, name := range sortedKeys(values) {
		v := values[name]
		switch {
		case !ValidName(name):
			skipped = append(skipped, Skip{Name: truncate(name, 64), Reason: "not a valid environment variable name"})
		case Protected(name):
			skipped = append(skipped, Skip{Name: name, Reason: "protected name"})
		case len(v) > MaxValueBytes:
			skipped = append(skipped, Skip{Name: name, Reason: "value larger than 64 KiB"})
		case strings.IndexByte(v, 0) >= 0:
			skipped = append(skipped, Skip{Name: name, Reason: "value contains a NUL byte"})
		default:
			out[name] = v
		}
	}
	return out, skipped
}

// MergeOptions control Merge.
type MergeOptions struct {
	// KeepExisting keeps a variable already present in base instead of
	// replacing it with the secret (default: the secret wins, because the
	// secrets service is the source of truth).
	KeepExisting bool
	// StripBootstrap removes BootstrapCredentialNames from the child.
	StripBootstrap bool
}

// Merge returns base ("NAME=value" entries, as os.Environ) with secrets added.
// The order is stable: base order first, then new names sorted.
func Merge(base []string, secrets map[string]string, opts MergeOptions) []string {
	strip := map[string]bool{}
	if opts.StripBootstrap {
		for _, n := range BootstrapCredentialNames {
			strip[n] = true
		}
	}
	out := make([]string, 0, len(base)+len(secrets))
	seen := map[string]bool{}
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if strip[name] || seen[name] {
			continue
		}
		seen[name] = true
		if v, ok := secrets[name]; ok && !opts.KeepExisting {
			out = append(out, name+"="+v)
			continue
		}
		out = append(out, kv)
	}
	for _, name := range sortedKeys(secrets) {
		if !seen[name] && !strip[name] {
			out = append(out, name+"="+secrets[name])
		}
	}
	return out
}

// Missing returns the required names that are absent or empty in env.
func Missing(env []string, required []string) []string {
	have := map[string]bool{}
	for _, kv := range env {
		name, v, _ := strings.Cut(kv, "=")
		if v != "" {
			have[name] = true
		}
	}
	var missing []string
	for _, r := range required {
		if r = strings.TrimSpace(r); r != "" && !have[r] {
			missing = append(missing, r)
		}
	}
	return missing
}

// SplitList parses a comma or whitespace separated list of names.
func SplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}

// Hash is a short fingerprint of a values map (sorted names and values). It
// changes when any value changes and reveals nothing usable about a value.
func Hash(values map[string]string) string {
	h := sha256.New()
	for _, name := range sortedKeys(values) {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write([]byte(values[name]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Names returns the sorted names of values.
func Names(values map[string]string) []string { return sortedKeys(values) }

// sortedKeys returns the keys of m in ascending order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// truncate shortens s to n bytes (for names in skip reports).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
