# AGENTS.md — grow-secrets-exec

Instructions for AI coding agents and humans working in this repository (`CLAUDE.md` is a symlink).

## What this is

A static Go binary that loads a service's configuration from HashiCorp Vault / OpenBao (AppRole
bootstrap from `GROW_SECRETS_*`) into a command's environment, in memory only, and supervises the
command (PID 1, signal forwarding, `SIGHUP` in-place restart, optional refresh). The Grow platform
runs it in every managed-stack code service that has a secrets bootstrap (init container download,
version + SHA-256 pinned in `stacks-service/src/modules/stacks/managed-stack-secrets-exec.ts` of
grow-codes/platform). The user-facing contract is `README.md`.

## Layout

| Path | What |
| - | - |
| `cmd/grow-secrets-exec/` | `main.go` + end-to-end tests (build the binary, fake Vault, real signals) |
| `internal/cli/` | flags, subcommands (`names`, `status`, `restart`, `version`), exit codes, initial load with retry |
| `internal/bootstrap/` | `GROW_SECRETS_*` parsing and validation |
| `internal/secrets/` | login + list + parallel read through the Grow Codes Go SDK `github.com/grow-codes-packages/hashicorp-vault/go` |
| `internal/envx/` | name validation, protected names, merge, required check, fingerprint |
| `internal/supervisor/` | single-goroutine supervisor loop (start, reap, signals, restart, state file) |
| `internal/fakevault/` | in-memory Vault for tests (AppRole login, KV v2 list/read, revoke-self, seal) |
| `.goreleaser.yaml`, `.github/workflows/` | CI and the tag-driven release (binaries + `checksums.txt`) |

## Rules

- **Never** print, log or write a secret value, token, role id or secret id — not in errors, not in
  debug output, not in tests' failure messages. Log names, counts and the `envx.Hash` fingerprint
  only. The e2e tests assert this (`assertNoLeak`); add the check to every new e2e test.
- No new dependencies beyond the standard library and the Grow Codes SDK. Keep `CGO_ENABLED=0`.
- Exit codes are a contract (README table; platform diagnostics rely on them). Do not renumber.
- Flags and the state-file JSON are a contract with the platform (`managed-stack-secrets-exec.ts`
  renders the flags; restart tooling reads the state file). Add, never rename.
- The supervisor loop is single-goroutine on purpose (pid, restart state and reaping never race).
  Background work (reloads) reports back through a channel.
- Builds must stay reproducible: `-trimpath -buildvcs=false`, `-buildid=`, Go version pinned in
  `release.yml`. After changing Go code, a new release is needed and every consumer pin (version +
  SHA-256) must be updated from the release's `checksums.txt`.
- Go doc comments on every function and type; files under 1000 lines.

## Checks

```sh
gofmt -l .            # must print nothing
go vet ./...
go test -p 2 -race -count=1 ./...
make build-all
```

## Release

1. Merge to `main` with green CI.
2. Tag `vX.Y.Z` and push the tag → GoReleaser uploads `grow-secrets-exec_linux_amd64`,
   `grow-secrets-exec_linux_arm64`, `checksums.txt`.
3. Compare `checksums.txt` with `make checksums VERSION=X.Y.Z` (same Go version) and update the
   platform pin (`SECRETS_EXEC_VERSION`, `SECRETS_EXEC_SHA256`).
