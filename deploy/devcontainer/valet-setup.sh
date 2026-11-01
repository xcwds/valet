#!/usr/bin/env bash
# Runs at container start (postStartCommand): exchange the enrollment code
# for the job's session token, then route git, HTTPS and MCP through Valet.
# The container holds no GitHub credential at any point.
set -euo pipefail
: "${VALET_URL:=http://valet:14401}"
token_file=${VALET_TOKEN_FILE:-$HOME/.valet/token}
proxy_host=$(sed -E 's#^https?://([^:/]+).*#\1#' <<<"$VALET_URL")

# Skips the exchange if this container already has a session (a restart).
if [ ! -s "$token_file" ]; then
	valet session login --url "$VALET_URL" --token-file "$token_file"
fi

# Git: GitHub URLs go to Ariadne; the helper reads the token at use, never
# storing it in the git config (docs/git.md).
git config --global url."$VALET_URL/git/github/".insteadOf https://github.com/
git config --global credential."$VALET_URL".helper \
	"!f() { test \"\$1\" = get && echo username=valet && echo \"password=\$(cat '$token_file')\"; }; f"

# HTTPS through Charon, with the token as the proxy password (docs/egress.md).
cat >"$HOME/.valet/env" <<ENV
export VALET_TOKEN="\$(cat '$token_file')"
export HTTPS_PROXY="http://agent:\${VALET_TOKEN}@$proxy_host:14402" https_proxy="http://agent:\${VALET_TOKEN}@$proxy_host:14402"
export NO_PROXY="$proxy_host" no_proxy="$proxy_host"
ENV
chmod 0600 "$HOME/.valet/env"
for rc in "$HOME/.bashrc" "$HOME/.profile"; do
	grep -qs '.valet/env' "$rc" || echo '[ -f ~/.valet/env ] && . ~/.valet/env' >>"$rc"
done

# MCP: register Iris with Claude Code, if it's installed.
if command -v claude >/dev/null; then
	claude mcp remove --scope user valet >/dev/null 2>&1 || true
	claude mcp add --scope user --transport http valet "$VALET_URL/mcp" \
		--header "Authorization: Bearer $(cat "$token_file")"
fi
echo "valet-setup: git, HTTPS and MCP go through $VALET_URL"
