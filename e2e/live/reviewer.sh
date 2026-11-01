#!/usr/bin/env bash
# Manual: the M1 reviewer scenario against a real GitHub App and a sandbox
# repository. Never run in CI. See README.md before running it: it posts a
# real comment on the pull request you name.
set -euo pipefail

: "${VALET_LIVE_APP_ID:?the GitHub App ID}"
: "${VALET_LIVE_INSTALLATION_ID:?the installation ID}"
: "${VALET_LIVE_KEY_FILE:?path to the App private key (.pem)}"
: "${VALET_LIVE_REPO:?sandbox repository, owner/name in lowercase}"
: "${VALET_LIVE_PR:?number of an open pull request in it}"
VALET_BIN=${VALET_BIN:-valet}
ADMIN=127.0.0.1:${VALET_LIVE_ADMIN_PORT:-14500}
AGENT=127.0.0.1:${VALET_LIVE_AGENT_PORT:-14501}

work=$(mktemp -d)
trap 'kill "${pid:-}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$work"' EXIT
export VALET_DATA_DIR=$work/data VALET_ADMIN_URL=http://$ADMIN

"$VALET_BIN" secrets init-key --out "$work/master.key" 2>/dev/null
cat >"$work/connectors.yaml" <<YAML
github:
  app_id: "$VALET_LIVE_APP_ID"
  installation_id: $VALET_LIVE_INSTALLATION_ID
  private_key_secret: github/app-key
${VALET_LIVE_API_URL:+  api_url: $VALET_LIVE_API_URL}
YAML
cat >"$work/valet.yaml" <<YAML
data_dir: $work/data
listen: {admin: '$ADMIN', agent: '$AGENT', egress: '127.0.0.1:0'}
master_key: {file: $work/master.key}
connectors: $work/connectors.yaml
log: {format: text}
YAML

"$VALET_BIN" daemon --config "$work/valet.yaml" >"$work/valetd.log" 2>&1 &
pid=$!
for _ in $(seq 50); do [ -f "$work/data/admin.token" ] && break; sleep 0.1; done
"$VALET_BIN" secrets set github/app-key <"$VALET_LIVE_KEY_FILE"

created=$("$VALET_BIN" job create --role reviewer --repo "$VALET_LIVE_REPO" --json)
token=$(sed -n 's/.*"token": *"\(vlt_sess_[a-z0-9]*\)".*/\1/p' <<<"$created")
job=$(sed -n 's/.*"id": *"\(job-[a-z0-9]*\)".*/\1/p' <<<"$created")
[ -n "$token" ] && [ -n "$job" ] || { echo "job create: $created" >&2; exit 1; }

# call TOOL ARGS_JSON: one stateless MCP tools/call; prints the response.
call() {
	curl -sS "http://$AGENT/mcp" \
		-H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
		-H 'Accept: application/json, text/event-stream' -H 'Mcp-Protocol-Version: 2025-06-18' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"
}
expect() { # expect WHAT PATTERN OUTPUT
	if grep -q -- "$2" <<<"$3"; then echo "ok   $1"; else echo "FAIL $1: $3" >&2; status=1; fi
}
status=0
pr="\"repo\":\"$VALET_LIVE_REPO\",\"number\":$VALET_LIVE_PR"

out=$(call github_pr_comment "{$pr,\"body\":\"Valet live e2e: a reviewer comment ($(date -u +%FT%TZ)).\"}")
if grep -q '"isError":true' <<<"$out"; then out="refused: $out"; fi
expect "comment posted" '"structuredContent":{"id":' "$out"
expect "approve denied" 'never-approve' "$(call github_pr_review_submit "{$pr,\"event\":\"APPROVE\"}")"
expect "merge denied" 'never-merge' "$(call github_pr_merge "{$pr}")"
# Revoking the job revokes its GitHub token now rather than at expiry.
"$VALET_BIN" job revoke "$job" >/dev/null
expect "audit chain verifies" '^ok:' "$("$VALET_BIN" audit verify 2>&1)"

echo "--- audit"
"$VALET_BIN" audit tail -n 20
exit $status
