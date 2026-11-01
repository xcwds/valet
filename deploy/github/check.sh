#!/usr/bin/env bash
# Check a repository's second wall (RFC decision 4) with your own gh login:
# the protections Valet relies on are in force, and Valet's App can't
# bypass them. Exit 1 if anything is missing.
#
#   deploy/github/check.sh owner/name [--app-id ID]
#
# It reads the rules GitHub applies to the default branch and to an agent
# branch (including organization rulesets), so it works however they were
# set up. Seeing bypass lists needs admin on the repository.
set -uo pipefail
[ $# -ge 1 ] || { sed -n '2,10p' "$0"; exit 2; }
repo=$1
app_id=""
[ "${2:-}" = --app-id ] && app_id=${3:-}
if [ "${2:-}" = --app-id ] && ! [[ "$app_id" =~ ^[1-9][0-9]*$ ]]; then
	# A bad ID would make every bypass comparison fail silently.
	echo "--app-id: \"$app_id\" is not a GitHub App ID (a number, from the App's settings page)" >&2
	exit 2
fi
gh=${GH:-gh}
status=0
ok() { echo "ok    $*"; }
warn() { echo "WARN  $*"; }
fail() { echo "FAIL  $*"; status=1; }

default=$("$gh" api "repos/$repo" --jq .default_branch) || { echo "cannot read $repo" >&2; exit 2; }

# Rules in force on a branch, as a JSON array.
rules() { "$gh" api "repos/$repo/rules/branches/$1" 2>/dev/null || echo '[]'; }
has() { jq -e --arg t "$2" 'any(.[]; .type == $t)' <<<"$1" >/dev/null; }

main_rules=$(rules "$default")
if jq -e 'any(.[]; .type == "pull_request" and .parameters.require_code_owner_review == true and .parameters.required_approving_review_count >= 1)' <<<"$main_rules" >/dev/null; then
	ok "$default: pull request with a code owner's approval required"
else
	fail "$default: no rule requiring a pull request approved by a code owner"
fi
if jq -e 'any(.[]; .type == "pull_request" and .parameters.require_last_push_approval == true)' <<<"$main_rules" >/dev/null; then
	ok "$default: the last pusher can't approve their own push"
else
	warn "$default: require_last_push_approval is off"
fi
has "$main_rules" non_fast_forward && ok "$default: force push blocked" || fail "$default: force push allowed"
has "$main_rules" deletion && ok "$default: deletion blocked" || fail "$default: deletion allowed"

agent_rules=$(rules "agent/valet-check")
has "$agent_rules" non_fast_forward && ok "agent/**: force push blocked" || fail "agent/**: force push allowed"
has "$agent_rules" deletion && ok "agent/**: deletion blocked" || fail "agent/**: deletion allowed"

owners=""
for path in .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS; do
	if "$gh" api "repos/$repo/contents/$path" --jq .path >/dev/null 2>&1; then owners=$path; break; fi
done
[ -n "$owners" ] && ok "CODEOWNERS at $owners (it must name people, never the App)" ||
	fail "no CODEOWNERS file: a code owner review can't be required without one"

# Who can bypass. The App must never be on a list (as itself or as any
# GitHub App when its ID isn't given).
tag_rulesets=0
for id in $("$gh" api "repos/$repo/rulesets?includes_parents=true" --jq '.[] | select(.enforcement == "active") | .id'); do
	rs=$("$gh" api "repos/$repo/rulesets/$id?includes_parents=true")
	name=$(jq -r .name <<<"$rs")
	[ "$(jq -r .target <<<"$rs")" = tag ] && tag_rulesets=$((tag_rulesets + 1))
	if ! jq -e 'has("bypass_actors")' <<<"$rs" >/dev/null; then
		warn "ruleset \"$name\": can't see its bypass list (needs admin)"
		continue
	fi
	if [ -n "$app_id" ]; then
		jq -e --argjson app "$app_id" 'any(.bypass_actors[]; .actor_type == "Integration" and .actor_id == $app)' <<<"$rs" >/dev/null &&
			fail "ruleset \"$name\": Valet's App ($app_id) can bypass it"
	else
		jq -e 'any(.bypass_actors[]; .actor_type == "Integration")' <<<"$rs" >/dev/null &&
			warn "ruleset \"$name\": a GitHub App can bypass it (pass --app-id to check it isn't Valet's)"
	fi
	jq -e 'any(.bypass_actors[]; .actor_type == "DeployKey")' <<<"$rs" >/dev/null &&
		warn "ruleset \"$name\": deploy keys can bypass it"
done
[ "$tag_rulesets" -gt 0 ] && ok "tags: $tag_rulesets active tag ruleset(s)" ||
	warn "no tag ruleset: an agent's token with contents: write could create tags through the API"

[ "$status" = 0 ] && echo "The second wall is up." || echo "The second wall has gaps: see docs/github-rulesets.md."
exit $status
