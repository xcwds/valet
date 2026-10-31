# Agent guide

How AI coding agents (Claude Code and others) should work in this repo. The files below are the
source of truth. This page points to them and adds the gotchas that don't fit anywhere else. If
this page and a repo file disagree, the repo file wins. Fix this page when you notice a mismatch.

## Read these first

| File                                                 | What it covers                                                                               |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [`CLAUDE.md`](CLAUDE.md)                             | The agent rules: pre-push checks, PR and merge flow, security limits                         |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                 | Setup and the commands you run                                                               |
| [`docs/rfc/0001-design.md`](docs/rfc/0001-design.md) | The design and its numbered decisions. Change the RFC in the same PR when a decision changes |
| [`.github/labels.md`](.github/labels.md)             | Issue labels                                                                                 |

## The plan

- Issue #1 is the owner's design doc; the RFC is its copy of record.
- Epic #2 tracks the work. Its sub-issues are listed in build order, grouped by milestone (M0–M5).
  Each says what it depends on; don't start one before its dependencies have merged.
- Work an issue at a time, one PR per issue unless the issue says otherwise.

## What's where

- `cmd/valet`: the one binary. `internal/cli` dispatches it: `valet …` is the CLI; run as `valetd`
  (a symlink or copy with that name) or `valet daemon`, it is the daemon (RFC decision 14).
- `internal/config`: strict YAML config plus `VALET_*` overrides; `valet.example.yaml` documents it
  and a test keeps it loadable. Add a setting in all three places: the struct, `envOverrides` and
  the example.
- `internal/daemon`: valetd's three listeners (admin, agent, egress), each its own `http.Server`.
  Agent and egress refuse every request (403) until their components land.
- `internal/store`: the SQLite database (`modernc.org/sqlite`, no cgo) in `data_dir/valet.db`.
  `Store.Write(ctx, fn)` runs `fn` in a `BEGIN IMMEDIATE` transaction on the single writer
  connection; `Store.Read()` is a read-only pool. Migrations are embedded from
  `internal/store/migrations/NNNN_name.sql`, numbered without gaps, each applied in its own
  transaction and recorded with a SHA-256 in `schema_migrations`. The data directory must be 0700
  and the database 0600; valetd refuses looser modes rather than fixing them silently.
  `Open` also takes an exclusive `flock` on `data_dir/valetd.lock`, so a second valetd on the
  same data directory exits with an error.
- `internal/secrets`: Hekate. Envelope encryption (per-secret AES-256-GCM data key, wrapped by the
  master key, secret name bound into both as additional data). `master_keys` holds a canary per key,
  so valetd refuses a different key at start. Values come back as `secrets.Secret`, which prints
  and encodes as `[redacted]` in every form; call `Reveal()` only where the value is used.
- `internal/logging`: `slog` JSON or text; `logging.For(log, logging.Themis)` adds the component,
  shown as a `[themis]` prefix in text mode.
- `internal/version`: the build's version, set with
  `-ldflags "-X github.com/xcwds/valet/internal/version.Version=…"`.
- `internal/` (planned): one package per component, named for what it does (`config`, `store`,
  `secrets`, `audit`, `jobs`, `policy`, `connector`, `connector/github`, `mcp`, `gitproxy`,
  `egress`, `approval`, …).
- `deploy/`: Dockerfile, `compose.yaml` and the example agent devcontainer.
- `e2e/`: the demo scenarios from the RFC, run against a fake upstream.
- `docs/`: the RFC and operator guides.

## Tooling

- Go and golangci-lint versions are pinned in `go.mod` (`toolchain`), `mise.toml` and
  `.github/workflows/ci.yml`; govulncheck in `ci.yml` and `.devcontainer/devcontainer.json`.
  Renovate updates Go modules, `mise.toml` and action digests, but not the `version:` input of the
  golangci-lint action or the `govulncheck@` version, so bump those by hand alongside `mise.toml`.
- Lint config is `.golangci.yml` (golangci-lint v2). `golangci-lint fmt` applies gofumpt and
  goimports.

## Cloud containers

- The preinstalled `golangci-lint` is built with an older Go and refuses this module. Install the
  pinned one into the scratchpad and put it first on `PATH`:
  ```sh
  GOBIN="<scratchpad>/bin" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
  ```
  (`go` downloads the toolchain from `go.mod` by itself.)
- `govulncheck` can't reach `vuln.go.dev` through the proxy; rely on CI's run.

## Hard rules

- **No secrets in the repo.** Not keys, tokens, `.pem` files or real-looking fixtures. Generate
  them in tests.
- **Fail closed.** Every error path in policy, approvals, proxies and token checks denies and
  audits.
- **Credentials stay inside.** Nothing a connector mints may reach the agent, a log line or an
  audit row.
- **Core is upstream-agnostic.** Adding a connector must not touch core code; that is what M4
  proves.
- **Never skip, disable or quarantine a test** to get CI green.

## Workflow

1. Branch from `main` as `claude/<topic>`.
2. Make the change, with tests. Security-relevant code (policy, token checks, ref parsing,
   redaction) gets negative tests: show that the bad case is denied, not just that the good case
   works.
3. Run the pre-push checks from `CLAUDE.md`.
4. Open a PR against `main` with `Closes #n` for each issue it closes.
5. Review it adversarially (what's broken, unsafe or missing, not just style) and post that review
   on GitHub. Fix, push, and review again, for at most 3 rounds.
6. Squash-merge once CI is green and the review is clean, unless the owner says not to.

## Issues and labels

- Label new issues with one type and one priority from `.github/labels.md`. Never invent labels.
- `needs decision` issues wait for the owner; `tracking` issues are worked through their
  sub-issues.
