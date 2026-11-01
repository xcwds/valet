# Live end-to-end checks

The scenarios in `e2e/` run against a fake GitHub in CI. The scripts here run the same steps
against a real GitHub App and a sandbox repository. **Run them by hand, never in CI**: they talk to
github.com and post real comments.

## Setup

1. A sandbox repository you don't mind commenting on, with one open pull request. Protect its
   default branch (so even a mistake can't merge).
2. A GitHub App set up as in [docs/github-app.md](../../docs/github-app.md) and installed on that
   repository only.
3. A `valet` binary: `go build -o /tmp/valet ./cmd/valet`.

## Run

```sh
export VALET_BIN=/tmp/valet
export VALET_LIVE_APP_ID=123456
export VALET_LIVE_INSTALLATION_ID=7890123
export VALET_LIVE_KEY_FILE=~/keys/valet-sandbox.private-key.pem
export VALET_LIVE_REPO=you/valet-sandbox
export VALET_LIVE_PR=1
e2e/live/reviewer.sh
```

The script starts a throwaway valetd (temporary data directory and master key, ports 14500/14501;
override with `VALET_LIVE_ADMIN_PORT` / `VALET_LIVE_AGENT_PORT`), stores the App key through
`valet secrets set` (read from the file, never a flag), creates a reviewer job and, over MCP:

| Step                                 | Expected                                   |
| ------------------------------------ | ------------------------------------------ |
| `github_pr_comment` on the PR        | a comment appears on GitHub                |
| `github_pr_review_submit` `APPROVE`  | denied by `reviewer/never-approve`         |
| `github_pr_merge`                    | denied by `reviewer/never-merge`           |
| `valet audit verify`                 | the chain verifies                         |

For GitHub Enterprise Server, also set `VALET_LIVE_API_URL`.

It prints the audit trail and exits non-zero if a step didn't go as expected. At the end it revokes
the job, which revokes the installation token on GitHub; on exit it stops valetd and deletes
everything it created locally.
