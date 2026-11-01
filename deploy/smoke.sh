#!/usr/bin/env bash
# End-to-end check of deploy/: Valet up, an agent container on agentnet with
# no route out, registries reachable only through Charon, the admin port
# unreachable from agentnet, git routed to Ariadne. Run from the repository
# root after building ghcr.io/xcwds/valet:dev. CI runs it; it needs Docker.
#
# SMOKE_OFFLINE=1 accepts a refused upstream connection for the allowed
# registry (for sandboxes without internet); CI leaves it unset.
set -euo pipefail
cd "$(dirname "$0")"
compose=(docker compose -f compose.yaml)
agent_image=valet-smoke-agent
enroll=$(mktemp -d)
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*" >&2; fail=1; }
cleanup() {
	[ "$fail" = 0 ] || "${compose[@]}" logs valet | tail -40 >&2 || true
	"${compose[@]}" down -v >/dev/null 2>&1 || true
	rm -rf "$enroll" data secrets .env
}
trap cleanup EXIT

./init.sh >/dev/null
"${compose[@]}" up -d --no-build --wait --wait-timeout 60
curl -fsS http://127.0.0.1:14400/healthz >/dev/null && ok "admin port answers on the host's loopback"

docker build -q -t "$agent_image" devcontainer >/dev/null

out=$("${compose[@]}" exec -T valet valet job create --role implementer --repo xcwds/site --enroll --json)
sed -n 's/.*"code": *"\(vlt_enroll_[a-z0-9]*\)".*/\1/p' <<<"$out" >"$enroll/code"
[ -s "$enroll/code" ] || { bad "no enrollment code: $out"; exit 1; }
chmod -R a+rwX "$enroll" # the agent user may differ from ours

docker run --rm --network valet_agentnet -v "$enroll:/run/valet-enroll" \
	-e VALET_URL=http://valet:14401 -e VALET_ENROLL_CODE_FILE=/run/valet-enroll/code \
	-e SMOKE_OFFLINE="${SMOKE_OFFLINE:-}" --user vscode "$agent_image" bash -c '
set -uo pipefail
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*" >&2; fail=1; }

valet-setup >/dev/null && ok "enrolled and configured" || { bad "valet-setup"; exit 1; }
[ ! -e /run/valet-enroll/code ] && ok "the enrollment code was deleted" || bad "the code is still there"
grep -rqs "vlt_sess_" ~/.gitconfig && bad "the session token is in the git config" || ok "no token in the git config"
. ~/.valet/env

# No way out except Valet.
env -u HTTPS_PROXY -u https_proxy curl -sS --max-time 5 -o /dev/null https://github.com 2>/dev/null \
	&& bad "github.com reachable directly" || ok "no direct route to the internet"
curl -sS --max-time 5 -o /dev/null http://valet:14400/healthz 2>/dev/null \
	&& bad "the admin port is reachable from agentnet" || ok "admin port unreachable from agentnet"

# Charon: allowed registries only.
trace=$(curl -sv --max-time 20 -o /dev/null https://registry.npmjs.org/ 2>&1)
code=$(curl -sS --max-time 20 -o /dev/null -w "%{http_code}" https://registry.npmjs.org/ 2>/dev/null)
if ! grep -q "CONNECT tunnel established, response 200" <<<"$trace"; then bad "Charon refused registry.npmjs.org: $(grep "^<" <<<"$trace" | head -3)"
elif [ "$code" = 200 ]; then ok "registry.npmjs.org through Charon"
elif [ -n "$SMOKE_OFFLINE" ]; then ok "Charon opened a tunnel to registry.npmjs.org (offline: TLS inside it not checked)"
else bad "registry.npmjs.org through Charon: HTTP $code"; fi
# (Captured first: grep -q would cut curl off, which pipefail counts.)
trace=$(curl -sv --max-time 10 -o /dev/null https://github.com 2>&1)
grep -q "^< HTTP/1.1 403" <<<"$trace" && ok "github.com refused by Charon" || bad "github.com not refused by Charon"

# Iris answers the session; git is routed to Ariadne.
out=$(curl -fsS -X POST http://valet:14401/mcp -H "Authorization: Bearer $VALET_TOKEN" -H "Content-Type: application/json" \
	-H "Accept: application/json, text/event-stream" -H "Mcp-Protocol-Version: 2025-06-18" \
	--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")
grep -q "\"result\"" <<<"$out" && ok "MCP answers with the session token" || bad "MCP: $out"
out=$(GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/xcwds/site 2>&1)
grep -q "valet:14401/git/github/xcwds/site" <<<"$out" && ok "git goes to Ariadne" || bad "git is not routed to Valet: $out"
exit $fail
' || fail=1

audit=$("${compose[@]}" exec -T valet valet audit tail -n 200)
for action in session.enroll egress.connect; do
	grep -q "\"action\":\"$action\"" <<<"$audit" && ok "audited: $action" || bad "not audited: $action"
done
"${compose[@]}" exec -T valet valet audit verify >/dev/null && ok "audit chain verifies" || bad "audit chain"
exit $fail
