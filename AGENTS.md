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
- `internal/audit`: Clio. `Log.Append` records an event in its own transaction; `AppendTx` +
  `Emit` record it inside a caller's `store.Write`, so it commits with the change it describes.
  Rows are hash-chained (each hash covers the row's canonical JSON, including `seq` and
  `prev_hash`); `Verify` reports the first edited, deleted or reordered row, and valetd refuses to
  start on a broken chain. Params are canonical JSON with sensitive keys redacted and strings over
  1 KiB replaced by length and SHA-256. Each event is also emitted on stdout at `LevelAudit`, which
  no log level hides. A chain can't reveal that the newest rows were cut off; the stdout copy
  shipped off the host is the check for that. `valet audit tail|verify --data-dir` read the
  database directly, read-only and without the lock.
- `internal/tokens`: `vlt_sess_`, `vlt_admin_`, `vlt_enroll_` tokens (256 random bits, lowercase
  base32), stored only as SHA-256. `Parse` checks the kind, so one kind never passes for another.
- `internal/jobs`: jobs and their session (create, get, list, revoke, all audited). Enrollment
  (`enroll.go`, #19): `CreateForEnrollment` stores a job with a one-time code instead of a session;
  `Enroll` (`POST /enroll` on the agent port, outside `RequireSession`) creates the one session on
  first use, and within the repeat window answers retries with the exact same bytes from memory
  (never stored; filled before commit so a racing retry finds it); everything else is a generic
  `ErrEnrollRefused`, audited and alerted. `Reenroll` revokes the session for a new code.
  `RequireSession` wraps the agent port (Bearer, or the basic-auth password git sends) and puts a
  `Principal` in the request context. Expiry is derived from `expires_at` on every request. A
  request with no `Authorization` at all is only challenged (401, not audited or throttled): git
  asks anonymously before every credential-helper run.
- `internal/throttle`: failed authentications per source IP. The first 10 a minute are audited one
  by one, the crossing once as `throttled`, later ones get 429 with no write, so a flooding agent
  can't fill the disk or stall audit writes. Valid tokens are never throttled.
- `internal/operator`: admin tokens. valetd writes the first one to `data_dir/admin.token` (0600);
  `valet admin reset-token` (valetd stopped) replaces a lost one.
- `internal/adminapi`: the admin API at `/api/` (jobs, secrets, audit), Bearer admin token only,
  no cookies. It refuses non-canonical paths so IDs and secret names mean exactly what was sent.
  The CLI reads the token from `--token-file`, `$VALET_ADMIN_TOKEN` or `$VALET_DATA_DIR/admin.token`,
  never from a flag value.
- `internal/connector`: Hephaestus. The `Connector` interface (`Name`, `Actions`, `Mint`, `Execute`;
  optional `Classifier` and `Revoker`), `ActionSpec` with a JSON Schema built by `connector.Object`
  (closed: `additionalProperties: false` is required), the `Registry` that checks catalogs at start
  and validates params, and the per-job credential `Cache`. In-tree connectors go in
  `internal/connector/<name>/` and are listed in `internal/connector/builtin`; a test fails if any
  other non-test code imports a specific connector. `internal/connector/fake` is for tests.
- `internal/connector/github`: the GitHub App connector. `Mint` signs an App JWT (RS256, stdlib),
  checks every job repo belongs to the installation's account, requests a token narrowed to the
  job's repos and role permissions, and revokes and refuses one that comes back broader. Backoff per
  job and on rate limits. The v1 actions (`actions.go`) are plain REST calls that return curated
  fields only; `repo` params must be canonical lowercase `owner/name` (schema pattern, rechecked in
  `Execute`), file paths are escaped per segment with `.`/`..` refused. Schemas must be trees:
  build each from a constructor, never share one `*jsonschema.Schema`. It is also a
  `connector.GitRemote` (`git.go`): repos lowercased, `git_url` (default https://github.com) plus
  `/{owner}/{name}.git`, token as the `x-access-token` password. Operator setup:
  `docs/github-app.md`.
- `internal/pipeline`: the one path every agent request takes: resolve and validate → policy →
  audit the decision → mint (cached) → execute → audit the result. `Authorize` is the first half,
  for interfaces that stream (git): it returns `*Allowed`, whose `Credential` mints and `Done`
  records the result. An action whose spec lists `Interfaces` is unknown on any other interface. Anything but an allow returns
  `*pipeline.Denied` before minting; `require_approval` fails closed until #23. Until #11 valetd
  uses `pipeline.DenyAll`.
- `internal/mcp`: Iris, MCP at `/mcp` on the agent port (`modelcontextprotocol/go-sdk`, stateless
  streamable HTTP, behind `jobs.RequireSession`). Each POST builds a server for that request's
  session; tools are actions with `.` → `_`, offered when the role's policy could allow them
  (`policy.MayAllow`); every `tools/call` (offered or not) goes through the pipeline via receiving
  middleware. Denials name the rule; other failures return only the upstream status. See
  `docs/mcp.md`.
- `internal/gitproxy`: Ariadne, git smart HTTP at `/git/{provider}/{owner}/{repo}.git` on the agent
  port (`docs/git.md`). Only the three smart-HTTP endpoints; each request is `git.fetch` or
  `git.push` through `pipeline.Authorize`, then `httputil.ReverseProxy` with only git's headers and
  the provider's credential (`connector.GitRemote`). Pushes: `ParseCommands` reads the pkt-lines
  before the flush (capped), policy decides on every ref, and the read bytes plus the untouched rest
  go upstream; a denial answers with report-status `ng` lines. The git actions live here
  (`gitproxy.Actions`, registered by valetd) with `Interfaces: [git]`, so MCP never offers them.
  Tests run real `git` against `git http-backend` through `net/http/cgi`.
- `internal/egress`: Charon, HTTPS `CONNECT` tunnels on the egress port (`docs/egress.md`). Session
  token from `Proxy-Authorization` (Basic password or Bearer; none is a 407 challenge, not
  audited), then port, then the `egress.allow` list, then Valet resolves the name and refuses any
  non-public address (`public` in `addr.go`) and dials the vetted IP. Audited directly as
  `egress.connect` (decision, then bytes); denials go to the alerter. Not via Themis: host-only, the
  RFC's one exception. Tunnels end at job expiry; `CloseJob` (on revoke) closes them. Tests use a
  fake resolver and dialer.
- `internal/policy`: Themis. Roles from YAML (`policies/roles.yaml` is built in), CEL conditions
  compiled and type-checked at load (`cel.dev/cel-go`; `job` and `action` are typed, `params` is
  dynamic), first match wins, no match or any evaluation error denies, cost limit and timeout per
  condition. Implements `pipeline.Policy`; `jobs.Service.RequireRoles` refuses undefined roles.
- `internal/alert`: denials and `alert: true` rules reach the operator (ntfy, or a JSON webhook),
  configured under `alerts:`. The pipeline calls `Send` after the decision is audited; `Send`
  never blocks (a bounded queue drops and counts when full), a worker retries with backoff, and
  each job gets at most `PerJob` alerts a window, then one summary. Alerts carry the audit
  record's already-redacted params, never the request's. Delivery drains for a few seconds at
  shutdown.
- `internal/logging`: `slog` JSON or text; `logging.For(log, logging.Themis)` adds the component,
  shown as a `[themis]` prefix in text mode.
- `internal/version`: the build's version, set with
  `-ldflags "-X github.com/xcwds/valet/internal/version.Version=…"`.
- `internal/` (planned): one package per component, named for what it does (`approval`, …).
- `deploy/` (`docs/deploy.md`): `Dockerfile` (static build on distroless, non-root, `/data`),
  `compose.yaml` (`agentnet` internal; valetd binds admin to its fixed `egress` address and the
  agent ports to its `agentnet` address; runs as the host uid from `init.sh`'s `.env`, because
  compose file secrets keep the host file's owner and mode), `valet.yaml`, `connectors.yaml`, and
  `devcontainer/` (agent image with the `valet` CLI, `valet-setup` at start, `new-job.sh` on the
  host). `deploy/smoke.sh` checks it end to end and runs in CI; CI pushes
  `ghcr.io/xcwds/valet:dev` from `main`. In a cloud container, start `dockerd` yourself; containers
  there have no internet, so build from a context with `go mod vendor` and run
  `SMOKE_OFFLINE=1 deploy/smoke.sh`.
- `deploy/github/`: the second wall's rulesets as JSON (protected branches, `agent/**`, tags) with
  `apply.sh` and `check.sh`, run with the operator's `gh` (`docs/github-rulesets.md`); never give the
  App Administration to do it. `e2e/rulesets_test.go` runs both scripts against a fake `gh`.
- `e2e/`: the RFC's demo scenarios against a real valetd (in-process, temp data dir, generated
  keys), a fake GitHub that records every call and enforces each token's grant like GitHub does,
  an ntfy sink, and an MCP client holding only a session token. `Start(t)` wires it all; helpers
  create jobs, call tools, read the audit trail and wait for alerts. Part of `go test ./...`; no
  network. Add a milestone's scenario here as `<role>_test.go`. `e2e/live/` holds manual scripts
  against a real App and sandbox repo (see its README); never run them in CI.
- `docs/`: the RFC and operator guides.
- `site/`: valet.xcwds.com (GitHub Pages, `.github/workflows/site.yml` after CI passes on `main`):
  plain HTML and CSS, no build step, no scripts or third-party requests (`e2e/site_test.go`
  checks that and every local link). `site/github-app/` is the GitHub App's homepage; keep its
  permissions table in step with `docs/github-app.md`.

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
