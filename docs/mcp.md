# Connecting an agent over MCP

Valet's MCP endpoint (Iris) is at `http://<valet>:14401/mcp` on the agent port. It speaks streamable
HTTP, statelessly: every request carries the job's session token and is authenticated on its own.

## Claude Code

With the session token from `valet job create` (or, once #19 lands, `valet session login`) in
`$VALET_SESSION`:

```sh
claude mcp add --transport http valet http://valet:14401/mcp \
  --header "Authorization: Bearer $VALET_SESSION"
```

The token ends up in Claude Code's config inside the container. That's expected: it only grants
access to Valet under the job's policy (RFC decision 17), and it stops working when the job ends or is
revoked.

## Tools

Each action a connector offers becomes a tool named with underscores for dots
(`github.pr.comment` → `github_pr_comment`), because Anthropic's API only accepts `[a-zA-Z0-9_-]` in
tool names. The input schema is the action's own params schema, so what the agent sees is exactly
what Valet validates.

An agent is offered only the tools its role could ever be allowed (a rule that allows or asks for
approval). Calling any other tool still goes through policy and is denied and audited, since probing
is itself a signal.

## Results

- **Allowed:** the action's curated result as JSON text, and as structured content when it's an
  object.
- **Denied:** an error result naming the rule and its reason, for example
  `denied by rule reviewer/never-approve: a reviewer agent may not approve`.
- **Failed upstream:** an error result with the upstream's HTTP status only. The detail is in the
  audit log, never returned to the agent.
