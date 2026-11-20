package bootstrap

import (
	"strings"
	"testing"
)

func lookup(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func full() map[string]string {
	return map[string]string{
		"GROW_SECRETS_PROVIDER":  "hashicorp-vault",
		"GROW_SECRETS_ADDR":      "http://vault:8200/",
		"GROW_SECRETS_KV_MOUNT":  "/secret/",
		"GROW_SECRETS_PATH":      "/services/api/",
		"GROW_SECRETS_AUTH":      "approle",
		"GROW_SECRETS_ROLE_ID":   "r",
		"GROW_SECRETS_SECRET_ID": "s",
	}
}

func TestFromEnvNormalises(t *testing.T) {
	b, err := FromEnv(lookup(full()))
	if err != nil {
		t.Fatal(err)
	}
	if b.Addr != "http://vault:8200" || b.KVMount != "secret" || b.Path != "services/api" || b.Auth != AuthAppRole {
		t.Fatalf("unexpected %+v", b)
	}
}

func TestFromEnvDefaults(t *testing.T) {
	env := full()
	delete(env, "GROW_SECRETS_PROVIDER")
	delete(env, "GROW_SECRETS_KV_MOUNT")
	delete(env, "GROW_SECRETS_AUTH")
	b, err := FromEnv(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	if b.Provider != ProviderHashiCorpVault || b.KVMount != DefaultKVMount || b.Auth != AuthAppRole {
		t.Fatalf("defaults not applied: %+v", b)
	}
}

func TestFromEnvErrorsNameTheVariableNotTheValue(t *testing.T) {
	cases := map[string]func(map[string]string){
		"GROW_SECRETS_PROVIDER":  func(m map[string]string) { m["GROW_SECRETS_PROVIDER"] = "infisical" },
		"GROW_SECRETS_ADDR":      func(m map[string]string) { m["GROW_SECRETS_ADDR"] = "vault:8200" },
		"GROW_SECRETS_PATH":      func(m map[string]string) { delete(m, "GROW_SECRETS_PATH") },
		"GROW_SECRETS_SECRET_ID": func(m map[string]string) { delete(m, "GROW_SECRETS_SECRET_ID") },
		"GROW_SECRETS_TOKEN":     func(m map[string]string) { m["GROW_SECRETS_AUTH"] = "token" },
		"GROW_SECRETS_AUTH":      func(m map[string]string) { m["GROW_SECRETS_AUTH"] = "kubernetes" },
	}
	for name, mutate := range cases {
		env := full()
		env["GROW_SECRETS_SECRET_ID"] = "very-secret-value"
		mutate(env)
		_, err := FromEnv(lookup(env))
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: got %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "very-secret-value") {
			t.Errorf("%s: error leaks the secret id", name)
		}
	}
}

func TestPresent(t *testing.T) {
	if Present(lookup(map[string]string{})) {
		t.Fatal("empty env is not a bootstrap")
	}
	if !Present(lookup(map[string]string{"GROW_SECRETS_ADDR": "http://v"})) {
		t.Fatal("addr alone marks a bootstrap")
	}
}

func TestTokenAuthFallbacks(t *testing.T) {
	b, err := FromEnv(lookup(map[string]string{
		"GROW_SECRETS_ADDR": "https://bao:8200", "GROW_SECRETS_PATH": "p",
		"GROW_SECRETS_PROVIDER": "openbao", "BAO_TOKEN": "t",
	}))
	if err != nil || b.Auth != AuthToken || b.Token != "t" || b.Provider != ProviderOpenBao {
		t.Fatalf("got %+v %v", b, err)
	}
}
