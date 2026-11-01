#!/usr/bin/env bash
# Create or update Valet's rulesets on a repository, with your own gh login
# (repository admin). Valet's GitHub App needs no Administration permission.
#
#   deploy/github/apply.sh owner/name
set -euo pipefail
[ $# -eq 1 ] || { sed -n '2,5p' "$0"; exit 2; }
repo=$1
gh=${GH:-gh}
dir=$(dirname "$0")
for f in "$dir"/protected-branches.json "$dir"/agent-branches.json "$dir"/tags.json; do
	name=$(jq -r .name "$f")
	id=$("$gh" api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id")
	if [ -n "$id" ]; then
		"$gh" api -X PUT "repos/$repo/rulesets/$id" --input "$f" >/dev/null
		echo "updated  $name"
	else
		"$gh" api -X POST "repos/$repo/rulesets" --input "$f" >/dev/null
		echo "created  $name"
	fi
done
echo "Check them with: $dir/check.sh $repo"
