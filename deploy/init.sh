#!/usr/bin/env bash
# One-time setup for deploy/compose.yaml: a data directory and a master key
# owned by you (Valet runs as your uid, not root), and .env recording that
# uid. Safe to re-run: it never replaces an existing key.
set -euo pipefail
cd "$(dirname "$0")"
image=${VALET_IMAGE:-ghcr.io/xcwds/valet:dev}

mkdir -p -m 0700 data secrets
chmod 0700 data secrets
if [ ! -f secrets/master.key ]; then
	docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets:/out" \
		--entrypoint /usr/local/bin/valet "$image" secrets init-key --out /out/master.key
	echo "Back up deploy/secrets/master.key somewhere safe: without it, stored secrets can't be decrypted."
fi
chmod 0600 secrets/master.key

# Valet never runs as root: run as root yourself, and the files go to the
# image's nonroot user (65532) instead.
uid=$(id -u) gid=$(id -g)
if [ "$uid" = 0 ]; then
	uid=65532 gid=65532
	chown -R "$uid:$gid" data secrets
fi
if [ ! -f .env ]; then
	printf 'VALET_UID=%s\nVALET_GID=%s\n' "$uid" "$gid" >.env
fi
echo "Ready: docker compose -f deploy/compose.yaml up -d"
