#!/usr/bin/env bash
# Create a job for an agent container and leave its one-time enrollment code
# where the devcontainer mounts it.
#
#   deploy/devcontainer/new-job.sh implementer xcwds/site [--ttl 4h]
#
# Writes .devcontainer/enroll/code in the current directory (your project),
# or in $VALET_ENROLL_DIR. Then "Reopen in Container" within the code's
# lifetime (10 minutes by default).
set -euo pipefail
[ $# -ge 2 ] || { sed -n '2,9p' "$0"; exit 2; }
role=$1
shift
compose=${VALET_COMPOSE:-$(dirname "$0")/../compose.yaml}
dir=${VALET_ENROLL_DIR:-.devcontainer/enroll}
args=()
while [ $# -gt 0 ]; do
	case $1 in
	--*) args+=("$1" "$2"); shift 2 ;;
	*) args+=(--repo "$1"); shift ;;
	esac
done
out=$(docker compose -f "$compose" exec -T valet valet job create --role "$role" "${args[@]}" --enroll --json)
code=$(sed -n 's/.*"code": *"\(vlt_enroll_[a-z0-9]*\)".*/\1/p' <<<"$out")
job=$(sed -n 's/.*"job": *{ *"id": *"\(job-[a-z0-9]*\)".*/\1/p' <<<"$out")
[ -n "$code" ] || { echo "no enrollment code in: $out" >&2; exit 1; }
mkdir -p -m 0700 "$dir"
(umask 077 && printf '%s\n' "$code" >"$dir/code")
echo "job ${job:-?}: enrollment code written to $dir/code"
