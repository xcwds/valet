# Valet

A self-hosted credential broker for AI coding agents. Agents never hold upstream credentials: they
act through Valet, which mints narrow, short-lived credentials per job, checks every action against
policy, and logs every decision, including denied attempts.

Named after the valet key, which starts the car but won't open the trunk or glovebox.

> **Status:** proof of concept, early development: M0 is complete: `valet job create` issues a job and its session token, every action is audited, and agents' tokens are checked on the agent port, which has no endpoints yet. M1 is under way: the connector pipeline and the policy engine are in. The plan is the
> [epic](https://github.com/xcwds/valet/issues/2); the design is
> [RFC 0001](docs/rfc/0001-design.md).

## How it works

An agent's container sits on a network whose only exit is Valet. The agent holds one secret, a
session token bound to its job. Everything it does reaches an upstream through one of Valet's
interfaces, is turned into an **action** (`github.pr.review.submit {repo, number, event}`), and is
judged by one policy engine before a connector carries it out with a freshly minted, narrowed
credential.

| Component                      | Name       | Code path (planned)   |
| ------------------------------ | ---------- | --------------------- |
| MCP endpoint                   | Iris       | `internal/mcp`        |
| Git proxy                      | Ariadne    | `internal/gitproxy`   |
| Egress proxy                   | Charon     | `internal/egress`     |
| Policy engine                  | Themis     | `internal/policy`     |
| Approval queue                 | Minos      | `internal/approval`   |
| Secret store and token minting | Hekate     | `internal/secrets`    |
| Audit log                      | Clio       | `internal/audit`      |
| Connector SDK                  | Hephaestus | `internal/connector`  |

The CLI is `valet` and the daemon `valetd`.

## The PoC proves

1. **No secrets in the agent.** A Claude Code devcontainer clones, pushes, opens PRs and comments
   with zero GitHub credentials in its env or filesystem.
2. **Per-job least privilege.** A reviewer can comment but not approve or merge; an implementer can
   push only to its own branch in its own repo.
3. **Visible denials.** Every blocked attempt is audited and alerted.
4. **Extensibility.** A second tool is added without changing Valet's core code.

## Try it

[docs/deploy.md](docs/deploy.md) runs Valet with Docker Compose and an agent devcontainer that has
no route out but through Valet. Operator guides: [GitHub App](docs/github-app.md),
[rulesets](docs/github-rulesets.md), [enrollment](docs/enrollment.md), [MCP](docs/mcp.md),
[git](docs/git.md), [egress](docs/egress.md).

## Milestones

| Milestone | Delivers                                                                   |
| --------- | -------------------------------------------------------------------------- |
| M0        | Skeleton: config, SQLite, secret store, jobs and session tokens, audit, CLI |
| M1        | GitHub over MCP with CEL policy and alerts                                 |
| M2        | Git proxy, egress allowlist and the credential-free devcontainer           |
| M3        | Approvals, auto-revoke and the admin UI                                    |
| M4        | Declarative HTTP connectors and a second real connector                    |
| M5        | Optional egress classifiers (only if M1–M4 show the need)                  |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Agents start at [AGENTS.md](AGENTS.md).

## License

[Apache-2.0](LICENSE).
