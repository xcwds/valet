#!/usr/bin/env bash
# Run inside an agent container: is there a GitHub credential anywhere it
# can see? Exit 0 if none, 1 if any. Prints where each one is, never the
# credential itself. (Valet's own vlt_sess_ token is expected there, RFC
# decision 17, and only reported.)
#
#   e2e/live/no-creds.sh            # scan the usual places
#   NO_CREDS_ROOTS="/workspaces $HOME" e2e/live/no-creds.sh
#   NO_CREDS_PROC=0 ...   # skip other processes' environments
set -uo pipefail
# GitHub's token formats: classic and fine-grained PATs, OAuth, user-to-
# server, server-to-server (installation) and refresh tokens.
pattern='(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}'
roots=${NO_CREDS_ROOTS:-"$HOME /workspaces /tmp /etc /run /opt /usr/local /var/tmp"}
found=0
hit() { echo "FOUND $*"; found=1; }
ok() { echo "ok    $*"; }

# Environment: this shell's, and every process's it can read.
if env | grep -Eq "$pattern"; then
	hit "in this environment: $(env | grep -E "$pattern" | cut -d= -f1 | tr '\n' ' ')"
else ok "environment"; fi
[ "${NO_CREDS_PROC:-1}" = 0 ] || for f in /proc/[0-9]*/environ; do
	[ -r "$f" ] || continue
	tr '\0' '\n' <"$f" 2>/dev/null | grep -Eq "$pattern" && hit "in the environment of process ${f//[^0-9]/}"
done
for v in GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_PAT; do
	[ -n "${!v:-}" ] && hit "\$$v is set"
done

# Git: credentials in config (extraHeader, URLs with a password), stored
# credentials, helpers that hold them.
gitcfg=$(git config --list --show-origin 2>/dev/null || true)
if grep -Eiq "$pattern|extraheader.*authorization|https://[^/@:]+:[^@]+@" <<<"$gitcfg"; then
	hit "in git config: $(grep -Ei "$pattern|extraheader|https://[^/@:]+:[^@]+@" <<<"$gitcfg" | cut -f1 | sort -u | tr '\n' ' ')"
else ok "git config"; fi
for f in "$HOME/.git-credentials" "${XDG_CONFIG_HOME:-$HOME/.config}/git/credentials" "$HOME/.config/gh/hosts.yml"; do
	[ -s "$f" ] && hit "credential file $f"
done
grep -Eq 'credential\..*helper=(store|cache|osxkeychain|manager)' <<<"$gitcfg" && hit "a git credential helper that stores credentials"

# Files anywhere it can read under the roots.
for root in $roots; do
	[ -d "$root" ] || continue
	while IFS= read -r f; do hit "in file $f"; done < <(grep -rIlE --exclude-dir=.git/objects "$pattern" "$root" 2>/dev/null)
done
[ "$found" = 0 ] && ok "files under: $roots"

# Valet's token: expected, only reported.
if [ -s "$HOME/.valet/token" ] || env | grep -q 'vlt_sess_'; then
	echo "info  Valet session token present (expected: it only reaches Valet)"
fi

if [ "$found" = 0 ]; then echo "No GitHub credential found."; else echo "GitHub credentials found."; fi
exit $found
