# Git through Valet

Ariadne, Valet's git proxy, serves git's smart-HTTP protocol at
`http://<valet>:14401/git/{provider}/{owner}/{repo}.git` on the agent port. Agents clone, fetch and
push through it holding only their session token; Valet checks each request against policy,
audits it, and forwards it upstream with the job's minted credential (for GitHub, an installation
token narrowed to the job's repos and role). There is no TLS interception and no CA to install
(RFC decision 8).

## Agent setup

Two pieces of git configuration: rewrite GitHub URLs to Valet, and hand git the session token as
the password through a credential helper. The token comes from `$VALET_TOKEN`, set from the file
`valet session login` writes ([docs/enrollment.md](enrollment.md)); the username is ignored.

```sh
git config --global url."http://valet:14401/git/github/".insteadOf https://github.com/
git config --global credential."http://valet:14401".helper \
  '!f() { test "$1" = get && echo username=valet && echo "password=$VALET_TOKEN"; }; f'
```

Then `git clone https://github.com/xcwds/site` works as usual. The token stays out of URLs, out of
`.git/config` remotes and out of process arguments; git asks the helper when Valet challenges it.
An agent can read its own token (RFC decision 17): it only reaches Valet, under the job's policy.

We chose a credential helper over `http.extraHeader` because a header set that way is sent to every
host git talks to, while a helper scoped to the Valet URL answers only for Valet.

## What is proxied

Only the smart-HTTP endpoints; everything else (dumb HTTP, `HEAD`, `objects/…`, unknown providers,
odd paths) is 404:

| Request                                         | Action      |
| ----------------------------------------------- | ----------- |
| `GET info/refs?service=git-upload-pack`         | `git.fetch` |
| `GET info/refs?service=git-receive-pack`        | `git.fetch` (the ref list before a push) |
| `POST git-upload-pack`                          | `git.fetch` |
| `POST git-receive-pack` with only a flush       | `git.fetch` (git's probe before a large push) |
| `POST git-receive-pack`                         | `git.push`  |

Params, as policy sees them:

- `git.fetch {provider, repo}`
- `git.push {provider, repo, refs: [{name, old, new, delete}]}`: every ref the push updates;
  `delete` is true when `new` is all zeros.

`repo` is canonical (`owner/name`, lowercase for GitHub), as in the GitHub actions. The default
implementer role allows `git.push` only when every ref is `refs/heads/agent/<job-id>/…` and none is
a delete; see `policies/roles.yaml`.

`git.fetch` and `git.push` are only requested by the git proxy: MCP neither offers nor runs them.

## Push checks

Valet reads only the ref-update commands at the start of a push (the pkt-lines before the first
flush, at most 256 KiB and 1000 refs), decides on all of them at once, and on an allow streams
those bytes plus the untouched rest (push options, pack) upstream. A gzip-encoded push is
decompressed and forwarded uncompressed. Malformed, oversized or truncated commands, invalid ref
names (by git's own rules), signed pushes and unknown encodings are denied and audited.

A denied push never reaches upstream. git shows the refusal against every ref, with the rule:

```
remote: valet: denied by rule implementer/push-elsewhere: an implementer may push only to agent/<job>/ branches, and never delete one
 ! [remote rejected] HEAD -> main (denied by rule implementer/push-elsewhere: …)
```

A denied fetch is a 403 whose text git prints. A push is all or nothing: one bad ref denies the
whole push.

## Credentials

- The session token never goes upstream: Valet forwards only the headers git needs
  (`Content-Type`, `Content-Encoding`, `Accept`, `Accept-Encoding`, `Git-Protocol`,
  `User-Agent`) and sets the upstream credential itself.
- The upstream credential never comes back: `Set-Cookie`, `WWW-Authenticate` and `Authorization`
  are stripped from responses. If upstream rejects the credential (401), the agent sees 502 rather
  than a password prompt it can't answer.
- git asks anonymously before running its credential helper, on every command. A request with no
  credentials at all gets the 401 challenge without an audit record or a throttle count; a wrong
  token is audited and throttled as before.

## Timeouts

Transfers stream in both directions without buffering packs, and there is no overall timeout:
large clones and pushes take as long as they take. Connecting upstream times out after 30 s, and a
client that goes away cancels its upstream request.
