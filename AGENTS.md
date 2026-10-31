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

## What's where (planned)

- `cmd/valetd`, `cmd/valet`: the daemon and the CLI (the same binary is fine if the setup issue
  chooses so).
- `internal/`: one package per component, named for what it does (`policy`, `audit`, `secrets`,
  `jobs`, `mcp`, `gitproxy`, `egress`, `approval`, `connector`, `connector/github`, …).
- `deploy/`: Dockerfile, `compose.yaml` and the example agent devcontainer.
- `e2e/`: the demo scenarios from the RFC, run against a fake upstream.
- `docs/`: the RFC and operator guides.

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
