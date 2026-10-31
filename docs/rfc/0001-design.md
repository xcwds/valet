# RFC 0001: Valet, an agent credential broker

- Status: accepted for the PoC
- Author: @crisp
- Date: 2026-10-31
- Source: [design doc, issue #1](https://github.com/xcwds/valet/issues/1)

This is the design of record. Follow its [decisions](#decisions), and change this file in the same
PR when a decision changes.

## Summary and goals

Agents never hold upstream credentials. They act through Valet, a self-hosted broker that mints
narrow, short-lived credentials per job, checks every action against policy, and logs every
decision, including denied attempts. GitHub is the first connector; the connector model is built
so any tool can be added.

The PoC is done when it proves four things:

1. **No secrets in the agent.** A Claude Code devcontainer can clone, push, open PRs and comment
   with zero GitHub credentials in its env or filesystem.
2. **Per-job least privilege.** A reviewer job can comment but not approve or merge. An implementer
   job can push only to its own branch in its own repo.
3. **Visible denials.** Every blocked attempt lands in an audit log and triggers an alert.
4. **Extensibility.** A second tool is added without changing Valet's core code.

Non-goals for the PoC: multi-tenant SaaS, HA clustering, a polished UI, brokering the agent's own
LLM credential, and protecting against a compromised Valet host.

## Decisions

The design below in one list, so issues and PRs can cite "RFC decision N".

1. **The agent holds one secret: its session token.** Upstream credentials (GitHub App private key,
   API tokens) live in Valet and never leave it.
2. **Everything is an action.** Each interface turns its traffic into namespaced, typed actions
   before the policy check; policy, audit and approvals share that one vocabulary.
3. **Valet is the agent's only exit.** The agent's network has no other route out.
4. **Enforcement is layered.** Valet's policy is the first wall and the upstream's own controls
   (GitHub rulesets, narrowed token permissions) are the second, so a Valet bug does not grant
   merge rights.
5. **Policy is deny-by-default.** Ordered rules with CEL conditions; first match wins; no match
   denies.
6. **Every decision is audited**, allowed or not, in a hash-chained, append-only log. Registry
   traffic is the one exception to action-level policy: it is checked by hostname only, and logged.
7. **Core never knows about an upstream.** Connectors bring credentials, the action catalog,
   executors and classifiers; adding a tool changes no core code.
8. **No TLS interception in M0 to M4.** The git proxy is a plain reverse proxy that injects auth,
   and the egress proxy is a host allowlist over plain CONNECT. No custom CA in the container.
9. **One GitHub App**, with installation tokens narrowed per job. User auth is supported too, so
   GitHub activity can be attributed to a user account and the App.
10. **Containers register at start-up** to establish their identity with the broker. An agent can't
    establish a new identity.
11. **Session tokens rely on TTL and revocation.** No source-IP binding to start.
12. **The agent's LLM credential stays in the container** for the PoC. Brokering it is a later goal:
    the owner plans to run all agentic development through Valet.
13. **Separate from Agent Vault.** Borrow its ideas; don't fork it or build on it.
14. **Go, one static binary, one image, SQLite by default** (see [Tech stack](#tech-stack)).
15. **Myth names in docs, plain names in code.** Components carry Greek-myth names in docs, UI and
    log prefixes; code paths stay descriptive (see [Naming](#naming)).
16. **Apache-2.0.** Permissive, with an explicit patent grant, as is usual for Go infrastructure
    (Kubernetes, cel-go). Valet's permissively licensed dependencies are compatible with it.

## Naming

The project is **Valet**, after the valet key: it starts the car but won't open the trunk or
glovebox, the way a per-job token allows only the job. Components carry names from Greek mythology
in docs, UI and log prefixes (`[themis] deny: …`); code paths stay descriptive (`internal/policy`,
`internal/gitproxy`) so contributors need no glossary.

| Component                       | Name       | Why                                                                         |
| ------------------------------- | ---------- | --------------------------------------------------------------------------- |
| MCP endpoint                    | Iris       | Messenger between gods and mortals; carries requests without deciding them |
| Git proxy                       | Ariadne    | Gives the thread through the labyrinth: a path, not the map                 |
| Egress proxy                    | Charon     | The ferryman; nothing crosses the boundary except through him               |
| Policy engine                   | Themis     | Goddess of divine law and order                                             |
| Approval queue                  | Minos      | Judge of the dead; human judgment on parked requests                        |
| Secret store and token minting  | Hekate     | The key-bearer; holds the keys, never hands over the master                 |
| Audit log                       | Clio       | Muse of history; records what happened                                      |
| Connector SDK                   | Hephaestus | The forge where new tools are made                                          |

The CLI is `valet` and the daemon `valetd`. Laravel Valet, a macOS PHP dev tool, also ships a
`valet` CLI; if that collision matters, use `vlt` instead.

## Threat model

The adversary is the agent itself, steered by prompt injection from an issue, a README, a web page
or a dependency. Assume it will try anything its environment allows.

| Category      | What the design assumes                                                                                                                                                         |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| In scope      | Exfiltrating credentials; calling actions outside the job (approve, merge, push to main, touch other repos); reaching hosts the job doesn't need; using a leaked Valet session token from elsewhere |
| Out of scope  | Compromised Valet host or Docker daemon; malicious operator; upstream provider compromise; supply-chain attacks on Valet's own dependencies                                      |
| Residual risk | Misuse of allowed actions (e.g. sensitive text in a permitted PR comment); a stolen session token is usable until it expires; data the agent can read is readable               |

Two rules follow from this. First, Valet is the only route out of the agent's network, so there is
no way around it. Second, enforcement is layered: Valet's policy plus the upstream's own controls
(GitHub rulesets), so a Valet bug does not grant merge rights.

## Core concepts

Everything is expressed in terms of **actions**, not raw HTTP. Policy, audit and approvals all speak
the same vocabulary regardless of which tool or interface the request came through.

| Concept       | What it is                                                                                    | Example                                                             |
| ------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Connector     | A plugin for one upstream: credentials, action catalog, executors, request classifiers         | `github`, `forgejo`, `linear`, `http:homeassistant`                 |
| Action        | A namespaced, typed operation with a parameter schema and a risk level                         | `github.pr.review.submit {repo, number, event}`                     |
| Role          | A reusable template of policy rules                                                           | `reviewer`, `implementer`, `triage`                                 |
| Job           | One unit of agent work: a role bound to concrete resources, with a TTL                         | implementer on `cmw/site`, branch `agent/job-42/*`, 2 h             |
| Session token | Opaque bearer token the agent holds, bound to one job; revocable                               | `abk_sess_…`; useless outside the job's scope                       |
| Decision      | allow, deny, or require_approval, plus the rule that produced it                               | `deny: reviewer may not APPROVE`                                    |
| Audit event   | Append-only record of every request: job, action, params, decision, upstream result            | written for denied attempts too                                     |

The only secret an agent ever holds is its session token. Upstream credentials (GitHub App private
key, API tokens) live in Valet and never leave it.

## Architecture

Valet exposes three interfaces to agents and funnels all of them through one policy engine. Each
interface turns its traffic into actions before the policy check, so a push over git and a merge
over MCP are judged by the same rules.

![Valet architecture diagram](https://github.com/user-attachments/assets/0138ef5a-6c0e-4818-9da9-d21db25540ae)

Only connectors touch upstream credentials, and every decision is written to the audit log whether
it was allowed or not. Registry traffic is the one exception to action-level policy: it is checked
by hostname only and logged.

| Interface     | Port                                        | Used for                                                | Credential handling                                                     |
| ------------- | ------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------- |
| MCP endpoint  | 14401 `/mcp`                                | Typed actions (PR comment, review, issue ops)           | Connector executes with a minted token                                  |
| Git proxy     | 14401 `/git/{provider}/{owner}/{repo}.git`  | Clone, fetch, push via `insteadOf`                      | Reverse proxy injects auth; no TLS interception or CA needed            |
| Egress proxy  | 14402                                       | Package registries now; classified API traffic in M5    | Host allowlist; no credentials injected in M0–M4                        |
| Admin API/UI  | 14400                                       | Jobs, policies, approvals, audit                        | Operator auth; bound to the egress network only, never reachable from `agentnet` |

The git proxy is a plain reverse proxy rather than a MITM, which removes the need to install a
custom CA in the container for the core workflow.

## Connector model

A connector is a Go interface with five responsibilities. Core code never knows about GitHub; it
only routes actions to connectors.

```go
type Connector interface {
    // Name is the action namespace, e.g. "github".
    Name() string

    // Actions returns the catalog: names, JSON param schemas, risk levels.
    Actions() []ActionSpec

    // Mint returns the narrowest upstream credential for a job's grants,
    // e.g. a GitHub installation token limited to one repo and two permissions.
    Mint(ctx context.Context, job Job) (Credential, error)

    // Execute performs an allowed action against the upstream.
    Execute(ctx context.Context, cred Credential, a Action) (Result, error)

    // Classify maps a raw proxied request to an action, so proxy traffic
    // is policy-checked in the same terms as MCP calls. Optional.
    Classify(r *http.Request, body []byte) (*Action, error)
}
```

Three ways to add a tool, in order of effort:

1. **Declarative HTTP connector (YAML).** Covers most REST APIs with no code. Each action maps to a
   method, path template and params; auth is one of bearer, header, basic or query. Home Assistant,
   Linear's REST endpoints, ntfy and similar fit here.
2. **In-tree Go connector.** For upstreams that need token minting, GraphQL, or a wire protocol
   (GitHub, Forgejo, git).
3. **Out-of-process plugin (later).** gRPC via `hashicorp/go-plugin` for third-party connectors in
   other languages. Deferred until the interface stabilizes.

Example declarative connector:

```yaml
connector: homeassistant
kind: http
base_url: https://homeassistant.waters.cx/api
auth:
  type: bearer
  secret: ha_long_lived_token
actions:
  - name: state.read
    method: GET
    path: /states/{entity_id}
    risk: low
  - name: service.call
    method: POST
    path: /services/{domain}/{service}
    body: passthrough
    risk: high
```

## Policy engine

Policy is deny-by-default, ordered rules with CEL conditions over the action, its params and the
job. First match wins; no match means deny. CEL (`google/cel-go`) is embeddable, fast, side-effect
free, and readable in YAML; OPA/Rego stays an option if policies outgrow it.

```yaml
role: reviewer
rules:
  - action: github.pr.review.submit
    when: params.event in ['COMMENT', 'REQUEST_CHANGES']
    decision: allow
  - action: github.pr.review.submit
    when: params.event == 'APPROVE'
    decision: deny
    alert: true
  - action: github.{repo,pr,issue}.read*
    when: params.repo in job.repos
    decision: allow
  - action: github.pr.comment
    when: params.repo in job.repos
    decision: allow
---
role: implementer
rules:
  - action: git.push
    when: >
      params.repo in job.repos &&
      params.refs.all(r, r.name.startsWith('refs/heads/agent/' + job.id + '/') && !r.delete)
    decision: allow
  - action: github.pr.create
    when: params.base == 'main' && params.repo in job.repos
    decision: allow
  - action: github.pr.merge
    decision: require_approval
```

**Approvals.** A `require_approval` decision parks the request, returns a pending ID to the agent,
and pushes a notification (ntfy webhook first). The operator approves or rejects with
`valet approve <id>` or in the web UI. The agent's call blocks up to a timeout, then fails closed.

**Alerts.** Any rule can set `alert: true`. Every deny also increments a per-job counter; crossing
a threshold (e.g. 3 denies in 10 minutes) can revoke the job automatically, since repeated probing
is itself a signal of injection.

## GitHub connector

One GitHub App, installed on the repos agents may touch. Hekate, Valet's secret store, holds its
private key and mints an installation token per job, narrowed with the `repositories` and
`permissions` fields of the access-token request. Tokens expire in about an hour; Hekate refreshes
them for long jobs. User auth is supported as well (decision 9), so activity can be attributed to a
user account and the App.

| Role        | Token permissions                                       | Can't do, even if policy is bypassed |
| ----------- | ------------------------------------------------------- | ------------------------------------ |
| reviewer    | contents: read, pull_requests: write, metadata: read    | push, merge                          |
| implementer | contents: write, pull_requests: write, metadata: read   | anything in other repos; admin       |
| triage      | issues: write, metadata: read                           | touch code or PRs                    |

**v1 action catalog:** `repo.read`, `repo.file.get`, `issue.read`, `issue.comment`, `pr.read`,
`pr.diff`, `pr.create`, `pr.comment`, `pr.review.submit`, `pr.merge`, `checks.read`, plus
`git.fetch` and `git.push` from the git proxy.

**Git push ref checks.** Smart-HTTP `git-receive-pack` sends its ref-update commands as pkt-lines
before the packfile: `<old-sha> <new-sha> <refname>`. Ariadne parses only that prefix, evaluates
`git.push` with the list of refs (a new-sha of all zeros is a delete), then streams the rest
through untouched. This gives per-job branch scoping without inspecting objects.

**Defense in depth with rulesets.** Valet's policy is the first wall; GitHub is the second:

- Protected branches (`main`, `release/*`): pull request required, CODEOWNER review from you
  required, force push blocked, App not on the bypass list.
- Agent branches (`agent/**`): force push and deletion blocked.
- A bot approval therefore never satisfies merge requirements, even if a policy bug lets one
  through.

**GraphQL.** The MCP path uses REST or explicit GraphQL inside the connector, so it never needs to
classify GraphQL. If the optional egress proxy lets `gh` through later, its classifier must parse
the GraphQL operation and map known mutations (`mergePullRequest`, `addPullRequestReview`) to
actions; unknown mutations are denied.

## Deployment

Locally, the devcontainer sits on an `internal` Docker network with no route to the internet.
Valet is the only container on both that network and the outside one, so it is the agent's only
exit.

```yaml
# compose.yaml (Valet side)
services:
  valet:
    image: ghcr.io/cmw/valet:dev
    ports: ['127.0.0.1:14400:14400'] # admin UI/API, host only
    volumes: [valet-data:/data]
    secrets: [github_app_key, master_key]
    networks: [agentnet, egress]
networks:
  agentnet: { internal: true } # no default route out
  egress: {}
volumes: { valet-data: {} }
secrets:
  github_app_key: { file: ./secrets/github-app.pem }
  master_key: { file: ./secrets/master.key }
```

```jsonc
// .devcontainer/devcontainer.json
{
  "runArgs": ["--network=agentnet"],
  "containerEnv": {
    "VALET_URL": "http://valet:14401",
    "HTTPS_PROXY": "http://valet:14402",
    "NO_PROXY": "valet"
  },
  "postStartCommand": "valet session login && git config --global url.http://valet:14401/git/github/.insteadOf https://github.com/"
}
```

The `insteadOf` rewrite sends every GitHub clone and push to Ariadne transparently. The session
token is fetched at start (or passed in by whatever launches the job) rather than baked into the
image. Containers register on start-up to establish their identity (decision 10); an agent can't
mint itself a new identity.

**Package registries.** With an internal network, `npm install` and `pip install` fail. Charon,
the egress proxy, runs in host-allowlist mode (plain CONNECT, no TLS interception) for registries
such as npmjs.org, pypi.org and proxy.golang.org. Every CONNECT is logged.

**Homelab.** The same image runs in its own LXC or VM on Proxmox, Postgres optional. Caddy fronts
only the admin port with TLS. The agent VLAN's firewall allows outbound traffic only to Valet's
ports.

## Tech stack

Go, shipped as one static binary and one image, with SQLite by default.

| Area            | Choice                                                     | Why                                                                                                                      |
| --------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Language        | Go                                                         | Strong stdlib for proxies (`httputil.ReverseProxy`, CONNECT); single binary; same choice as Agent Vault, so its code is a useful reference |
| MCP             | `modelcontextprotocol/go-sdk`, streamable HTTP             | Official SDK; one endpoint serves every connector's tools                                                                |
| Policy          | `google/cel-go`                                            | Embedded, sandboxed expressions; rules stay data, not code                                                               |
| GitHub          | `google/go-github` + `bradleyfalzon/ghinstallation`        | App JWT and installation-token minting                                                                                   |
| Storage         | SQLite (`modernc.org/sqlite`, no cgo); Postgres later      | Zero-setup locally; same schema scales up                                                                                |
| Secrets at rest | AES-GCM envelope encryption, key from file or env          | Upstream secrets encrypted in the DB; key never in the image                                                             |
| Audit           | Hash-chained rows in SQLite + JSON lines on stdout         | Tamper-evident locally; Promtail/Loki can ship stdout                                                                    |
| Alerts          | Webhook (ntfy first)                                       | Phone push on deny or pending approval                                                                                   |
| UI              | Server-rendered HTML + htmx                                | Jobs, approvals, audit log; no SPA build for a PoC                                                                       |
| CLI             | Same binary (`valet job create`, `valet approve`)          | Operator workflow from the terminal                                                                                      |

## Milestones and demo scenarios

Six milestones, each ending in something runnable. M2 is the first point where the core idea is
proven end to end. The plan, with one issue per piece of work, is the epic linked from the
[README](../../README.md).

1. **M0 Skeleton.** Go module, config loading, SQLite schema, encrypted secret store, jobs and
   session tokens, hash-chained audit log, CLI. Exit: `valet job create` returns a token and the
   create is audited.
2. **M1 GitHub over MCP.** App token minting with per-job narrowing, the v1 action catalog, CEL
   policy, deny logging, ntfy alert. Exit: Claude Code calls `github.pr.comment` through MCP; an
   attempted approve is denied and alerted.
3. **M2 Git proxy and devcontainer.** Git smart-HTTP reverse proxy with receive-pack ref checks,
   `insteadOf` setup, internal network, registry allowlist. Exit: an implementer agent clones,
   pushes `agent/job-42/fix`, and opens a PR with zero GitHub credentials in the container.
4. **M3 Approvals and UI.** `require_approval` queue, CLI and htmx approve, auto-revoke on repeated
   denies. Exit: a merge request waits for your tap and proceeds.
5. **M4 Extensibility.** Declarative HTTP connector plus one real second connector (Forgejo
   validates that git and PR actions generalize; Home Assistant validates the YAML path). Exit:
   added with no core code changes.
6. **M5 Optional egress classifiers.** TLS-intercepting mode with per-connector classifiers so `gh`
   and other CLIs can run unmodified; GraphQL mutation mapping. Only if M1–M4 show it's needed.

**Demo scenarios** to script as end-to-end tests:

- Reviewer agent comments on a PR; its `APPROVE` attempt is denied, logged and pushed to your phone
- Implementer pushes to its job branch; a push to `main` is denied by Valet, and would be by the
  ruleset too
- `env`, `~/.config` and `git config` inside the container contain no GitHub credential
- A session token used after job expiry or from outside `agentnet` is rejected
- Prompt-injected issue text telling the agent to merge results in a denied, alerted attempt
- A new YAML connector is added and policy-checked without rebuilding Valet

## Open questions

All answered and recorded as decisions above (2026-10-31):

- **Project name:** Valet, with Greek-myth component names (decision 15).
- **Agent LLM credential:** accept in-container auth for now; the owner eventually plans to use
  Valet for all agentic development (decision 12).
- **One GitHub App or one per role:** one GitHub App. User auth should be supported so GitHub
  activity is attributed to a user account and the App (decision 9).
- **Who creates jobs:** ideally, containers register on start-up to establish identity with the
  broker. An agent should not be able to establish a new identity (decision 10).
- **Bind session tokens to source IP:** TTL and revocation are enough to start (decision 11).
- **Build on Agent Vault:** keep it separate, borrow ideas (decision 13).
- **License:** Apache-2.0, chosen over GPL on 2026-10-31 (decision 16, #4).

## Prior art

| Project                                                                                                  | What to borrow                                                                                                    |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| [Infisical Agent Vault](https://github.com/Infisical/agent-vault)                                        | Placeholder-value credential substitution, `agent-vault run` wrapper ergonomics, vault-scoped session tokens      |
| [Pomerium MCP](https://www.pomerium.com/docs/capabilities/mcp)                                           | Per-tool authorization on MCP calls and logging every authorization decision                                      |
| [Honmoon](https://github.com/pleaseai/honmoon)                                                           | CEL over protocol facts with an allow, deny or pause verdict                                                      |
| [agentsh](https://agentsh-website.pages.dev/docs/policy-reference/)                                      | Declaring upstream, path/method rules and credential substitution in one service entry                            |
| [agent-egress-gate](https://github.com/mrd5591/agent-egress-gate)                                        | Strict policy parsing; documenting what a CONNECT tunnel can't enforce                                            |
| [vault-plugin-secrets-github](https://beta.pkg.go.dev/github.com/boh-dan/vault-plugin-secrets-github/v2) | Ephemeral, finely scoped GitHub App installation tokens                                                           |
