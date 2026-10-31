# Agent notes

Valet is a self-hosted credential broker for AI coding agents: agents hold only a per-job session
token and act through Valet, which mints narrow upstream credentials, checks every action against
policy and audits every decision. Plan: epic #2 with one milestone per phase (M0–M5). Design:
`docs/rfc/0001-design.md` (from the design doc in #1); follow its numbered decisions, and change
the RFC in the same PR when a decision changes.

Go, one module (`github.com/xcwds/valet`), one static binary built from `cmd/valet`: it is the
`valet` CLI, and the daemon when run as `valetd` or `valet daemon`. SQLite by default.

- [AGENTS.md](AGENTS.md) collects the conventions and gotchas for agents working here; keep it in
  step with this file.
- Before pushing: `go mod tidy -diff && go build ./... && go vet ./... && golangci-lint run && go test -race ./...`.
  CI also runs `govulncheck ./...` and a `CGO_ENABLED=0` static build.
- In Claude Code cloud containers the preinstalled `golangci-lint` is too old for this module and
  `vuln.go.dev` is blocked; see AGENTS.md (Cloud containers).
- Never commit a secret, key or token, not even a test one that looks real. Tests generate keys at
  run time.
- Core code (`internal/` outside `internal/connector/<name>`) never imports a specific connector or
  knows about GitHub (RFC decision 7). Route through the connector interface.
- Deny by default (RFC decision 5): a missing rule, an unknown action, a parse error or a timeout
  denies, and the denial is audited (decision 6). Never fail open.
- Upstream credentials never leave Valet (decision 1): not in responses, errors, logs or audit
  params. Carry them as `secrets.Secret` (prints as `[redacted]`) and call `Reveal()` only at the
  point of use.
- Code paths stay descriptive (`internal/policy`); the Greek names (Themis, Ariadne, …) appear in
  docs, UI and log prefixes only (decision 15).
- Schema changes are new numbered files in `internal/store/migrations/`, forward-only. Never edit
  an applied migration: valetd refuses to start when one changed.
- Never phone home: no telemetry and no network calls except to upstreams a connector or the
  operator's config declares.
- Always open a PR against `main` linking the issues it closes (write "Closes #n" for each one).
  Review it adversarially, post the review on GitHub, fix and re-review (at most 3 rounds), then
  squash-merge once CI is green, unless the user says not to.
- Issue labels follow `.github/labels.md`. Label new issues you open with a type and a priority
  from it.
