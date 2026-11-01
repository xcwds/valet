# Egress through Valet

Agents run on an internal network (`agentnet`) with no route out. Charon, Valet's egress proxy on
port 14402, gives package managers a way to their registries: HTTPS `CONNECT` tunnels to hosts on
an allowlist, attributed to a job, with no TLS interception and no credentials injected (RFC
decision 8). It decides by host name only, the one exception to action-level policy (decision 6).

## Configure

```yaml
egress:
  allow:                       # exact names, or *.suffix for subdomains (not the bare suffix)
    - registry.npmjs.org
    - pypi.org
    - files.pythonhosted.org
    - proxy.golang.org
    - sum.golang.org
  # ports: [443]               # the default
```

`VALET_EGRESS_ALLOW=registry.npmjs.org,pypi.org` overrides the list. With no list, every tunnel is
denied. Entries are lowercase DNS names; IP addresses, ports and a bare `*` are refused at start.

## Agent setup

Every tunnel carries the job's session token as the proxy password, so registry traffic is
attributed to a job and stops when the job does:

```sh
export HTTPS_PROXY="http://agent:${VALET_TOKEN}@valet:14402"
export NO_PROXY=valet
```

npm, pip, Go, curl and most HTTP clients read `HTTPS_PROXY` and send the credentials with the
`CONNECT`. `Proxy-Authorization: Bearer <token>` works too. A client that waits to be asked gets a
`407` challenge first (not audited, like git's anonymous request on the agent port); a wrong,
expired or revoked token is a `407` that is audited and counts toward the per-source throttle.

**No unauthenticated mode.** Image builds that need the registries should run outside `agentnet`
(with the build host's normal network), or with a job of their own. An anonymous mode would let
anything on `agentnet` use the tunnels without a trace of whose they were.

## What is checked

For every `CONNECT host:port`:

1. The token is a live session.
2. The port is allowed (443 unless `egress.ports` says otherwise).
3. The host is on the allowlist (names are lowercased and a trailing dot dropped first).
4. Valet resolves the name itself, and refuses if **any** address is not public: loopback,
   RFC 1918 and unique-local, link-local (including `169.254.169.254`, the cloud metadata
   address), carrier-grade NAT, multicast, reserved and documentation ranges, and IPv6 forms that
   embed an IPv4 address (mapped, NAT64, 6to4, Teredo). An allowed name pointed at Valet's admin
   port or the LAN goes nowhere.
5. It dials the address it checked, never re-resolving, so DNS can't swap in another one.
6. A job may hold at most 64 tunnels at once.

Plain-HTTP forward proxying is off: a non-`CONNECT` request is refused (405) and audited as
`egress.http`.

A tunnel never outlives its job: it closes at the job's expiry, and revoking the job closes every
tunnel it has open.

## Audit and alerts

Each tunnel is two audit records: the decision, `egress.connect {host, port}` with
`allow` and the matching pattern as its rule (`egress:*.pythonhosted.org`) or `deny` with one of
`egress/allowlist`, `egress/port`, `egress/private-address` (with the offending `address`),
`egress/dns`, `egress/limit`, `egress/target`; and, for an opened tunnel, an `info` result with
the address dialed and `bytes_up` / `bytes_down`. Denials are sent to the alerter like any other.

## What a CONNECT tunnel can't enforce

Charon sees a host name and a byte count, nothing inside the TLS session. So it cannot:

- **Restrict paths or packages.** An agent allowed `registry.npmjs.org` can fetch any package on
  it, including ones a prompt injection names.
- **Stop uploads to an allowed host.** `npm publish`, `twine upload` or a `POST` of the
  repository's contents to an allowed registry all look like any other tunnel. Keep publish
  credentials out of agent containers (they need none to install), and prefer registries where an
  upload requires an account the agent doesn't have.
- **Stop data hidden in requests.** Package names, query strings and headers to an allowed host
  can carry data out. The byte counts in the audit log are the signal to watch.
- **Tell hosts apart behind one name.** A CDN name serves whatever it serves; allow names, not
  providers' whole domains (`*.amazonaws.com` lets an agent reach any S3 bucket).
- **Check the server is genuine.** TLS is end to end between the client and the registry, as it
  should be; Charon doesn't terminate it.

Classifying what flows through (paths, methods, API calls) needs TLS interception, which is M5's
question (#30), not M0 to M4's.
