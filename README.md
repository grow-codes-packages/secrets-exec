# grow-secrets-exec

Load a service's configuration from **HashiCorp Vault** or **OpenBao** into the environment of its
process — in memory only — and supervise it. One static binary (Go, no CGO, ~7 MB, linux
amd64/arm64), no code change in the service.

```sh
grow-secrets-exec -- node dist/main.js
```

It reads the AppRole bootstrap the Grow platform puts into the pod (`GROW_SECRETS_*`), logs in,
lists every key under `GROW_SECRETS_PATH` (KV v2, one secret per key, field `value`), starts the
command with those keys added to its environment, forwards signals, restarts the command in place on
`SIGHUP`, and can restart it when the secrets change. Values are never written to disk, printed or
logged.

## Bootstrap (environment)

| Variable | Meaning |
| - | - |
| `GROW_SECRETS_PROVIDER` | `hashicorp-vault` (default) or `openbao` |
| `GROW_SECRETS_ADDR` | base URL of the secrets service, e.g. `http://vault:8200` |
| `GROW_SECRETS_KV_MOUNT` | KV v2 mount (default `secret`) |
| `GROW_SECRETS_PATH` | folder of the service's keys, e.g. `services/api` |
| `GROW_SECRETS_AUTH` | `approle` (default when a role id is set) or `token` |
| `GROW_SECRETS_ROLE_ID`, `GROW_SECRETS_SECRET_ID` | AppRole credential |
| `GROW_SECRETS_AUTH_MOUNT` | AppRole mount (default `approle`) |
| `GROW_SECRETS_TOKEN` | token auth (`VAULT_TOKEN` / `BAO_TOKEN` as fallbacks) |
| `GROW_SECRETS_CA_CERT` | CA bundle for https (`VAULT_CACERT` / `BAO_CACERT` as fallbacks) |
| `GROW_SECRETS_REQUIRED` | default of `--required` |
| `GROW_SECRETS_REFRESH` | default of `--refresh` (Go duration, e.g. `30s`) |

Without any `GROW_SECRETS_*` variable the command runs unchanged (one warning line), unless
`--require-bootstrap` is given.

Key layout: `<mount>/data/<path>/<KEY>` → `{"value": "..."}`. A key becomes the variable `KEY`.
Numbers and booleans are written as text, objects as JSON. Skipped (with a warning naming the key):
sub-folders, secrets without a `value` field, names that are not `[A-Za-z_][A-Za-z0-9_]*`, values over
64 KiB or with a NUL byte, and protected names (`PATH HOME PWD OLDPWD SHELL HOSTNAME USER TERM`,
`LD_*`, `GROW_SECRETS_*`). A secret **overrides** a variable that is already set (the secrets service
is the source of truth); `--keep-existing` turns that around.

## Usage

```text
grow-secrets-exec [flags] -- <command> [args...]
grow-secrets-exec names                 print the key names it would export (never values)
grow-secrets-exec status [state-file]   print the supervisor state (JSON)
grow-secrets-exec restart [state-file]  SIGHUP the running supervisor (in-place restart)
grow-secrets-exec version
```

| Flag | Default | Meaning |
| - | - | - |
| `--exec` | off | plain mode: load, then `exec` the command (no supervisor, secrets fixed for the process life) |
| `--required A,B` | `$GROW_SECRETS_REQUIRED` | names that must be non-empty (secrets or environment); exit 78 naming the missing ones |
| `--refresh 30s` | `$GROW_SECRETS_REFRESH` or off | re-read the secrets; restart the command only when they changed |
| `--wait 120s` | 120 s | keep retrying an unreachable or sealed server at start |
| `--grace 10s` | 10 s | SIGTERM → SIGKILL wait when restarting the command |
| `--optional` | off | start without secrets when loading fails (logged as an error) |
| `--require-bootstrap` | off | exit 78 when no bootstrap is present |
| `--strip-bootstrap` | off | remove `GROW_SECRETS_ROLE_ID/SECRET_ID/TOKEN` from the command's environment |
| `--keep-existing` | off | keep variables already set instead of overriding them |
| `--forward-hup` | off | forward SIGHUP to the command instead of restarting it |
| `--state-file PATH` | `/tmp/grow-secrets-exec/state.json` | supervisor state (`""` = none) |

## Supervisor mode (default)

- Works as **PID 1** of a container: reaps zombies (and is a child subreaper when it is not PID 1).
- Starts the command in its own process group and forwards `SIGTERM SIGINT SIGQUIT SIGUSR1 SIGUSR2
  SIGWINCH` to the whole group, so `bash → bun → go run → binary` chains all receive them. After a
  stop signal it waits for the command and exits with the command's exit code (`128+n` when the
  command died from signal `n`).
- **`SIGHUP` = in-place restart**: re-reads the secrets (a failed read keeps the last values),
  sends `SIGTERM` to the group, `SIGKILL` after `--grace`, kills what is left of the old group, and
  starts the command again — no container restart, no lost `/tmp`, no CrashLoop back-off.
  `grow-secrets-exec restart` sends that signal for you.
- `--refresh`: re-reads the secrets periodically with the same token (logs in again after half the
  token TTL or when the token is rejected) and restarts the command only when a value changed. A
  failed refresh keeps the command running on the last values (logged as a warning).
- When the command exits on its own, the supervisor exits with its code (Kubernetes restarts the
  container as usual).
- The state file (`supervisorPid`, `childPid`, `startedAt`, `restarts`, `lastExitCode`,
  `secretsHash`, `running`) lets tools verify that a restart really happened.
- Without `--refresh` the AppRole token is revoked right after the load; a `SIGHUP` logs in again.

## Exit codes

| Code | When |
| - | - |
| child's code | the command exited (`128+n` for signal `n`) |
| 64 | bad flags or no command |
| 69 | secrets service unreachable or sealed until `--wait` elapsed |
| 70 | internal error |
| 77 | login rejected or permission denied (wrong role/secret id, policy) |
| 78 | bootstrap incomplete or unsupported provider, required keys missing, `--require-bootstrap` without bootstrap |
| 126 / 127 | the command cannot be executed / was not found |

The wrapper never exits 0 on its own failure. Every failure is one JSON line on stderr naming the
cause (`"msg":"loading secrets failed", "error":"auth.login approle/login: invalid role or secret ID
(HTTP 400)", "exitCode":77`), which is what `kubectl logs --previous` and pod diagnostics show.

## Logging

JSON lines on **stderr** (`"logger":"grow-secrets-exec"`): `secrets loaded` (`count`, `hash`, `ms`,
`skipped` names with reasons, `path`, `provider`), `child started`, `restarting child`, `child
exited`, warnings. Never values, tokens or secret ids. `hash` is a 16-hex fingerprint of all values
together, for change detection only.

## Install

Download a release asset and check it against `checksums.txt` (always pin version **and** SHA-256):

```sh
V=0.1.0; A=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
wget -qO grow-secrets-exec "https://github.com/grow-codes-packages/secrets-exec/releases/download/v$V/grow-secrets-exec_linux_$A"
echo "<sha256>  grow-secrets-exec" | sha256sum -c - && chmod +x grow-secrets-exec
```

Dockerfile: `ENTRYPOINT ["/usr/local/bin/grow-secrets-exec", "--exec", "--"]` + your `CMD`.

Kubernetes (what the Grow platform renders for managed stacks): an init container (busybox pinned by
digest) downloads the pinned asset into an `emptyDir` mounted at `/grow/bin`, verifies the SHA-256,
and the app container command becomes `/grow/bin/grow-secrets-exec -- <original command>`.

## Build and test

```sh
make test                          # go test -race (fake Vault + real signals)
make build-all                     # dist/grow-secrets-exec_linux_{amd64,arm64}
make checksums VERSION=0.1.0       # reproducible: same SHA-256 as the release with the same Go version
```

Release: push tag `vX.Y.Z` → `.github/workflows/release.yml` (GoReleaser) uploads the two binaries and
`checksums.txt`. The Go version is pinned there so local and CI builds are byte-identical.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
