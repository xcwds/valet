# Enrolling a container

An agent container gets its identity once, at start-up, by exchanging a one-time **enrollment
code** for its job's session token (RFC decision 10). The code is the only thing the launcher hands
in; the agent can never use it to get a second identity.

## 1. Create the job with a code

On the operator's machine (the admin port):

```sh
valet job create --role implementer --repo xcwds/site --ttl 4h --enroll
```

```
job:     job-k3x9q2ma
role:    implementer
repos:   xcwds/site
branch:  agent/job-k3x9q2ma/*
expires: 2026-11-01T16:00:00Z
code:    vlt_enroll_…
use by:  2026-11-01T12:10:00Z
```

The job has no session yet. The code is good for one first use within `enrollment.code_ttl`
(default 10 minutes). `--json` prints `{job, enrollment: {code, expires_at}}` for scripts.

## 2. Hand the code in as a file

As a Docker secret or a bind-mounted file, **not an environment variable**, which every process in
the container could read for its whole life:

```sh
printf %s "$CODE" > ./valet_enroll
docker run --network agentnet --mount type=bind,src=$PWD/valet_enroll,dst=/run/secrets/valet_enroll …
```

## 3. Log in at start-up

In the container's `postStartCommand` (or entrypoint):

```sh
valet session login
```

It reads the code from `/run/secrets/valet_enroll` (`--code-file`, `$VALET_ENROLL_CODE_FILE`),
posts it to `http://valet:14401/enroll` (`--url`, `$VALET_URL`), writes the session token to
`~/.valet/token` with mode 0600 (`--token-file`, `$VALET_TOKEN_FILE`), and deletes the code file
once Valet has answered. Network errors, 5xx and throttling are retried with the same code for up
to two minutes (`--timeout`); the code is kept until Valet answers.

Then point the tools at the token, e.g. in the shell profile:

```sh
export VALET_TOKEN="$(cat ~/.valet/token)"
export HTTPS_PROXY="http://agent:${VALET_TOKEN}@valet:14402"   # docs/egress.md
```

and git and MCP as in [docs/git.md](git.md) and [docs/mcp.md](mcp.md). The agent may read the
token (RFC decision 17): it only reaches Valet, under the job's policy.

## What Valet does with a code

- **First use** creates the job's one session and answers
  `{"session_token", "job_id", "expires_at"}`, audited as `session.enroll`. It is atomic: if two
  requests race, one creates the session and the other is answered as a replay.
- **Repeat window.** For `enrollment.replay_window` after first use (default 60 s, at most 5 min),
  the same code gets **byte-for-byte the same answer**, up to `enrollment.max_replays` times
  (default 5): no new session, no alert, audited as `session.enroll` with `replay: true`. This is
  for a retry whose first answer was lost in transit. The token is held in memory only for the
  window, then wiped; the database keeps only its hash.
- **Anything else is refused** with one generic 403 (`enrollment refused`), audited with the reason
  and alerted: reuse after the window or the cap, an expired, unknown or malformed code, a code
  superseded by a re-enrollment, or a revoked or expired job (also during the window). Failures
  count toward the same per-source throttle as bad session tokens.
- **A restart** of valetd ends any open window early (nothing is kept on disk), so a retry right
  after a restart is refused and alerted: a rare false positive that fails safe.

## Re-enrolling

A job gets a second session only if the operator asks:

```sh
valet job enroll job-k3x9q2ma
```

This revokes the job's session (and any unused code), closes the egress tunnels it opened, and
prints a new code. The agent port has no route that creates jobs, sessions or codes; only the
admin port does.

## Settings

```yaml
enrollment:
  code_ttl: 10m       # 1m to 24h
  replay_window: 60s  # 0 to 5m; 0 turns retries off
  max_replays: 5      # 0 to 20
```
