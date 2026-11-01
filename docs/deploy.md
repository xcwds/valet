# Deploying Valet

Valet's job is to be the agent's **only exit** (RFC decision 3). Agents run on an internal network
with no route out; Valet is the one container on both that network and an outside one. The admin
port is reachable from your machine only, never from the agents' network.

```
 your machine ──127.0.0.1:14400──▶ ┌────────┐ ──egress──▶ GitHub, registries, api.anthropic.com
                                   │ valetd │
 agent containers ──agentnet──────▶└────────┘
   (no route out)   :14401 MCP, git   :14402 HTTPS proxy (Charon)
```

## Local Docker, end to end

Everything is in `deploy/`.

**1. Prepare** (once):

```sh
deploy/init.sh
```

This creates `deploy/data/` (0700) and a master key at `deploy/secrets/master.key` (0600), both
owned by you, and writes your uid to `deploy/.env`: valetd runs as you, never root, so the key
needn't be readable by anyone else. **Back up the master key**: without it, stored secrets can't be
decrypted. None of these files is ever committed (`deploy/.gitignore`).

**2. Configure.** `deploy/valet.yaml` holds the egress allowlist (npm, PyPI, Go modules, and
`api.anthropic.com` for the agent's own model calls, RFC decision 12) and alert settings.
`deploy/connectors.yaml` holds the GitHub App: set it up as in [github-app.md](github-app.md), then
store its key in Valet's encrypted secret store (it never sits in a file Valet reads):

```sh
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml exec -T valet valet secrets set github/app-key < my-app.private-key.pem
# uncomment the github: section in deploy/connectors.yaml, then
docker compose -f deploy/compose.yaml restart valet
```

The image is `ghcr.io/xcwds/valet:dev`, built and pushed by CI from `main`; `docker compose build`
builds it locally instead.

**3. Use the CLI.** On the host, with the `valet` binary:

```sh
export VALET_ADMIN_URL=http://127.0.0.1:14400 VALET_DATA_DIR=deploy/data
valet status
valet audit tail
```

or inside the container: `docker compose -f deploy/compose.yaml exec valet valet job list`.

**4. Start an agent.** Copy `deploy/devcontainer/` into your project as `.devcontainer/`, then from
the project:

```sh
path/to/valet/deploy/devcontainer/new-job.sh implementer xcwds/site --ttl 4h
```

This creates the job and writes its one-time enrollment code to `.devcontainer/enroll/code` (add
`.devcontainer/enroll/` to the project's `.gitignore`). Then **Reopen in Container** within ten
minutes. At start, `valet-setup`:

- exchanges the code for the job's session token (`~/.valet/token`) and deletes the code
  ([enrollment.md](enrollment.md));
- rewrites `https://github.com/` to Ariadne and sets a credential helper that reads the token
  ([git.md](git.md));
- writes `~/.valet/env` with `HTTPS_PROXY=http://agent:<token>@valet:14402`, loaded by every bash
  ([egress.md](egress.md));
- registers Valet as Claude Code's MCP server ([mcp.md](mcp.md)).

The container has no GitHub credential at any point. Claude Code reaches `api.anthropic.com`
through Charon with its own credential, as the RFC allows for the PoC.

**Check it:** `deploy/smoke.sh` brings the stack up, enrolls a throwaway agent container and checks
there is no direct route out, the admin port is unreachable from agentnet, registries work only
through Charon, MCP answers and git goes to Ariadne. CI runs it on every pull request.

## How the isolation works

- `agentnet` is `internal: true`: Docker gives it no route out. `valet` is on it with a fixed
  address and the alias `valet`.
- The **admin listener binds to Valet's address on `egress`**, so nothing on agentnet can reach it
  (by name or address), and it is published on `127.0.0.1` only. `gw_priority` makes `egress` the
  container's default route, which is also where the published port lands.
- The **agent and egress listeners bind to Valet's agentnet address** and are not published:
  a session token that leaks out of a container has nothing to talk to (decision 11 has no IP
  binding; this is the network's job).
- Subnets and addresses are `172.31.240.0/24` (agentnet) and `172.31.241.0/24` (egress); override
  `VALET_AGENTNET_SUBNET`, `VALET_AGENTNET_IP`, `VALET_EGRESS_SUBNET` and `VALET_EGRESS_IP` in
  `deploy/.env` if they clash with your networks.

## Homelab (Proxmox)

The same image runs in its own LXC or VM; Postgres is optional (SQLite is the default).

- **Two networks.** Give the Valet VM one interface on the agents' VLAN and one on your
  management/LAN side. Bind `listen.agent` and `listen.egress` to the agent-VLAN address and
  `listen.admin` to the management address (or `127.0.0.1` behind Caddy).
- **Firewall the agent VLAN**: from agent hosts, allow only TCP 14401 and 14402 to Valet's
  agent-VLAN address; deny everything else outbound, including DNS to the outside (Charon resolves
  names itself). Deny the agent VLAN to the management network.
- **Caddy fronts only the admin port**, with TLS and your SSO or client certificates in front of
  `/api/` (and the UI, #25). Never proxy 14401 or 14402 to anything but the agent VLAN.
- **Secrets.** The master key in a root-only file (`master_key.file`), backed up offline; the
  GitHub App key only in Valet's secret store. Run valetd as its own user, with the data directory
  0700.
- **Agents** run anywhere on the agent VLAN with `VALET_URL=http://<valet>:14401` and the same
  `valet-setup` steps as the devcontainer.
