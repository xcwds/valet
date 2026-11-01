# GitHub rulesets: the second wall

Valet's policy is the first wall; GitHub is the second (RFC decision 4). If a policy bug ever let an
agent's request through, these rulesets still refuse a push to `main`, a merge without your review,
a rewritten or deleted agent branch, or a new tag. Valet's App is never on a bypass list.

## The rulesets

`deploy/github/` has them as JSON, importable in **Settings → Rules → Rulesets → New ruleset →
Import a ruleset**, or applied with `gh`.

| File                      | Applies to                                    | Rules                                                                                     | Bypass                  |
| ------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------- |
| `protected-branches.json` | default branch, `main`, `release/**`          | pull request with 1 approval from a **code owner**, last pusher can't approve, stale approvals dismissed; no force push; no deletion | **nobody**              |
| `agent-branches.json`     | `agent/**`                                    | no force push; no deletion                                                                | repository admins (you) |
| `tags.json`               | every tag                                     | no creation, update or deletion                                                           | repository admins (you) |

Admins may bypass the agent-branch and tag rules so you can clean up branches and cut releases; the
App is not an admin and has no Administration permission, so it can't.

## Apply them

With your own `gh` login (repository admin), never the App's:

```sh
deploy/github/apply.sh owner/name    # creates, or updates by name
```

Then add a `CODEOWNERS` file that names **people only** (never the App or a team it belongs to):

```
# .github/CODEOWNERS
* @your-username
```

## Check them

```sh
deploy/github/check.sh owner/name --app-id 123456
```

It reads the rules GitHub actually applies to the default branch and to an `agent/` branch
(including organization rulesets and however they were created), checks `CODEOWNERS` exists, and
reads every active ruleset's bypass list. It fails if:

- the default branch doesn't require a pull request approved by a code owner, or allows force
  push or deletion;
- `agent/**` allows force push or deletion;
- there's no `CODEOWNERS`;
- Valet's App (`--app-id`) is on any bypass list.

It warns when the last pusher may approve, a GitHub App or deploy key can bypass a ruleset (without
`--app-id` it can't tell whether that's Valet's), there's no tag ruleset, or a bypass list isn't
visible to you. Exit status 1 on any failure.

We chose this over a `valet doctor github` command: reading rulesets needs the Administration
permission, and Valet's App deliberately never has it (see [github-app.md](github-app.md)).

## Why a bot approval never satisfies a merge

Even if a policy bug let a reviewer agent approve (Valet denies `github.pr.review.submit` with
`APPROVE` for every default role):

- **Code owner review is required**, and `CODEOWNERS` names only you. An approval from the App
  isn't a code owner's approval, so it never counts toward the requirement.
- **The last pusher can't approve.** An implementer agent pushes the branch; nothing it does can
  approve its own last push.
- **Stale approvals are dismissed** when new commits arrive, so an approval can't be collected
  early and carried over a later push.
- **Nobody bypasses** the protected-branch ruleset, including the App, which has no Administration
  permission to change it either.

So a merge to a protected branch always needs your review, whatever Valet decides. Valet's own
policy keeps merges behind `require_approval` (#23) as well: two walls, each enough on its own.

## The demo repository

The M2 demo (#22) applies these to its sandbox repository and shows a push to `main` refused twice:
by Valet (`implementer/push-elsewhere`), and by GitHub when the policy is deliberately bypassed.
