#!/usr/bin/env bash
# Run any track inside a container that can see ONLY your repo: not your home folder,
# SSH keys, cloud credentials or other projects. This is the OS-level control that
# permission rules alone can't give you.
#
#   environments/docker/run-sandboxed.sh /path/to/repo            # interactive shell
#   environments/docker/run-sandboxed.sh /path/to/repo claude     # start Claude Code inside
#
# Secrets: pass only the API key the track needs, via --env-file (never bake it into the image).
set -euo pipefail
KIT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
REPO="$(cd "${1:?usage: run-sandboxed.sh /path/to/repo [command]}" && pwd)"; shift || true
IMAGE=harness-kit:latest

docker build -q -t "$IMAGE" -f "$KIT_DIR/environments/devcontainer/.devcontainer/Dockerfile" "$KIT_DIR" >/dev/null

ENV_ARGS=()
[ -f "$REPO/.env.agent" ] && ENV_ARGS=(--env-file "$REPO/.env.agent")

exec docker run --rm -it \
  --read-only --tmpfs /tmp --tmpfs /home/dev \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory 4g \
  -v "$REPO:/workspace" \
  -v "$KIT_DIR:/kit:ro" \
  "${ENV_ARGS[@]}" \
  "$IMAGE" "${@:-bash}"
