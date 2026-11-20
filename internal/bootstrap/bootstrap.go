// Package bootstrap reads the secrets-service bootstrap identity that the Grow
// platform injects into a service pod (the GROW_SECRETS_* variables).
//
// The variables are the contract of the Grow foundation (GRO-1390):
//
//	GROW_SECRETS_PROVIDER   hashicorp-vault | openbao
//	GROW_SECRETS_ADDR       base URL of the secrets service (in-cluster)
//	GROW_SECRETS_KV_MOUNT   KV v2 mount (default "secret")
//	GROW_SECRETS_PATH       folder of the service's keys, e.g. services/api
//	GROW_SECRETS_AUTH       approle (default when a role id is set) | token
//	GROW_SECRETS_ROLE_ID    AppRole role id
//	GROW_SECRETS_SECRET_ID  AppRole secret id
//
// Optional: GROW_SECRETS_AUTH_MOUNT (AppRole mount, default "approle"),
// GROW_SECRETS_TOKEN (token auth; VAULT_TOKEN / BAO_TOKEN as fallbacks) and
// GROW_SECRETS_CA_CERT (CA bundle; VAULT_CACERT / BAO_CACERT as fallbacks).
package bootstrap

import (
	"fmt"
	"net/url"
	"strings"
)

// Supported providers. OpenBao keeps the HashiCorp Vault HTTP API, so both use
// the same client.
const (
	ProviderHashiCorpVault = "hashicorp-vault"
	ProviderOpenBao        = "openbao"
)

// Auth methods.
const (
	AuthAppRole = "approle"
	AuthToken   = "token"
)

// DefaultKVMount is used when GROW_SECRETS_KV_MOUNT is empty.
const DefaultKVMount = "secret"

// Bootstrap is the parsed bootstrap identity. RoleID, SecretID and Token are
// credentials: never log or print them.
type Bootstrap struct {
	Provider  string
	Addr      string
	KVMount   string
	Path      string
	Auth      string
	AuthMount string
	RoleID    string
	SecretID  string
	Token     string
	CACert    string
}

// Present reports whether the environment carries any bootstrap variable.
// It is false for a pod that the platform did not give an identity.
func Present(getenv func(string) string) bool {
	return strings.TrimSpace(getenv("GROW_SECRETS_ADDR")) != "" ||
		strings.TrimSpace(getenv("GROW_SECRETS_PROVIDER")) != "" ||
		strings.TrimSpace(getenv("GROW_SECRETS_PATH")) != ""
}

// FromEnv parses and validates the bootstrap variables.
//
// getenv is os.Getenv in production; tests pass a map lookup. The error names
// the missing or invalid variable, never a value.
func FromEnv(getenv func(string) string) (Bootstrap, error) {
	get := func(names ...string) string {
		for _, n := range names {
			if v := strings.TrimSpace(getenv(n)); v != "" {
				return v
			}
		}
		return ""
	}
	b := Bootstrap{
		Provider:  strings.ToLower(get("GROW_SECRETS_PROVIDER")),
		Addr:      strings.TrimRight(get("GROW_SECRETS_ADDR"), "/"),
		KVMount:   strings.Trim(get("GROW_SECRETS_KV_MOUNT"), "/"),
		Path:      strings.Trim(get("GROW_SECRETS_PATH"), "/"),
		Auth:      strings.ToLower(get("GROW_SECRETS_AUTH")),
		AuthMount: strings.Trim(get("GROW_SECRETS_AUTH_MOUNT"), "/"),
		RoleID:    get("GROW_SECRETS_ROLE_ID"),
		SecretID:  get("GROW_SECRETS_SECRET_ID"),
		Token:     get("GROW_SECRETS_TOKEN", "VAULT_TOKEN", "BAO_TOKEN"),
		CACert:    get("GROW_SECRETS_CA_CERT", "VAULT_CACERT", "BAO_CACERT"),
	}
	if b.Provider == "" {
		b.Provider = ProviderHashiCorpVault
	}
	if b.KVMount == "" {
		b.KVMount = DefaultKVMount
	}
	if b.Auth == "" {
		if b.RoleID != "" {
			b.Auth = AuthAppRole
		} else {
			b.Auth = AuthToken
		}
	}
	return b, b.Validate()
}

// Validate checks that the bootstrap is complete and supported.
func (b Bootstrap) Validate() error {
	switch b.Provider {
	case ProviderHashiCorpVault, ProviderOpenBao:
	default:
		return fmt.Errorf("GROW_SECRETS_PROVIDER %q is not supported (supported: %s, %s)",
			b.Provider, ProviderHashiCorpVault, ProviderOpenBao)
	}
	if b.Addr == "" {
		return fmt.Errorf("GROW_SECRETS_ADDR is not set")
	}
	u, err := url.Parse(b.Addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("GROW_SECRETS_ADDR must be an absolute http or https URL")
	}
	if b.Path == "" {
		return fmt.Errorf("GROW_SECRETS_PATH is not set")
	}
	switch b.Auth {
	case AuthAppRole:
		var missing []string
		if b.RoleID == "" {
			missing = append(missing, "GROW_SECRETS_ROLE_ID")
		}
		if b.SecretID == "" {
			missing = append(missing, "GROW_SECRETS_SECRET_ID")
		}
		if len(missing) > 0 {
			return fmt.Errorf("GROW_SECRETS_AUTH=approle needs %s", strings.Join(missing, " and "))
		}
	case AuthToken:
		if b.Token == "" {
			return fmt.Errorf("GROW_SECRETS_AUTH=token needs GROW_SECRETS_TOKEN (or VAULT_TOKEN / BAO_TOKEN)")
		}
	default:
		return fmt.Errorf("GROW_SECRETS_AUTH %q is not supported (supported: approle, token)", b.Auth)
	}
	return nil
}
