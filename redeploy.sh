#!/usr/bin/env bash
#
# redeploy.sh — Rebuild (or pull) the Xalgorix image and recreate the dashboard
# container IN PLACE, without losing your login or your data.
#
# Why this exists
# ---------------
# The container reads its dashboard credentials (XALGORIX_USERNAME /
# XALGORIX_PASSWORD / XALGORIX_PASSWORD_HASH) from its runtime environment, NOT
# from the data volume. If you `docker rm` + `docker run` by hand and forget to
# pass them again, docker-entrypoint.sh sees no auth and generates a fresh
# random admin password — locking you out with your previously-saved password.
#
# This script:
#   1. Captures the running container's XALGORIX_*/GEMINI_*/AGENTMAIL_*/CAIDO_*
#      environment first, and re-applies it, so auth + integrations survive.
#   2. Reuses the same data volume, ports and restart policy.
#   3. Tags the outgoing image and keeps the old container for one cycle, so a
#      failed health check rolls back cleanly.
#
# Usage
# -----
#   ./redeploy.sh                       # build ./Dockerfile, recreate in place
#   ./redeploy.sh --pull                # docker pull IMAGE instead of building
#   ./redeploy.sh --no-build            # recreate from the current IMAGE as-is
#   ./redeploy.sh --image xalgord/xalgorix:latest
#   ./redeploy.sh --env-file ./my.env   # force an env-file (first deploy / override)
#
# Config (environment variable = default):
#   CONTAINER=xalgorix   IMAGE=xalgorix:local        PORT=9137
#   VOLUME=xalgorix-data DATA_MOUNT=/data            RESTART=unless-stopped
#   HEALTH_PATH=/login   HEALTH_TIMEOUT=90           BUILD_CONTEXT=<script dir>
#   BIND_ADDR=<empty>    # host interface for the published port. Empty binds
#           all interfaces (0.0.0.0). Set BIND_ADDR=127.0.0.1 to expose the
#           dashboard on loopback only (recommended behind a reverse proxy).
#   VERSION=<from cmd/xalgorix/main.go, else `git describe`>   # stamps the
#           dashboard version so a --build image reports vX.Y.Z, not "vdocker".
#   NUCLEI_REFRESH=1     # on `build`, re-pull the LATEST nuclei engine + vuln
#           templates (cache-bust). Set NUCLEI_REFRESH=0 to reuse Docker's cache.
#   NUCLEI_VERSION=<tag> # pin a specific nuclei engine (e.g. v3.11.1) for repro
#           builds; default `latest`. Only applied when NUCLEI_REFRESH != 0.
#
set -euo pipefail

CONTAINER="${CONTAINER:-xalgorix}"
IMAGE="${IMAGE:-xalgorix:local}"
PORT="${PORT:-9137}"
VOLUME="${VOLUME:-xalgorix-data}"
DATA_MOUNT="${DATA_MOUNT:-/data}"
RESTART="${RESTART:-unless-stopped}"
HEALTH_PATH="${HEALTH_PATH:-/login}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"
BIND_ADDR="${BIND_ADDR:-}"
BUILD_CONTEXT="${BUILD_CONTEXT:-$(cd "$(dirname "$0")" && pwd)}"

MODE="build"            # build | pull | none
ENV_FILE=""             # explicit --env-file overrides auto-capture

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}==>${NC} $*"; }
ok()   { echo -e "${GREEN}==>${NC} $*"; }
warn() { echo -e "${YELLOW}==>${NC} $*" >&2; }
die()  { echo -e "${RED}error:${NC} $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --pull)      MODE="pull" ;;
    --no-build)  MODE="none" ;;
    --build)     MODE="build" ;;
    --image)     IMAGE="${2:?--image needs a value}"; shift ;;
    --image=*)   IMAGE="${1#*=}" ;;
    --env-file)  ENV_FILE="${2:?--env-file needs a path}"; shift ;;
    --env-file=*) ENV_FILE="${1#*=}" ;;
    -h|--help)   sed -n '2,34p' "$0"; exit 0 ;;
    *)           die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || die "docker is required but not installed."

# Validate the published port before it reaches `docker -p`.
case "$PORT" in
  ''|*[!0-9]*) die "PORT must be numeric (got: '$PORT')" ;;
esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "PORT must be in 1-65535 (got: $PORT)"

# Guard the bind mount against path traversal. VOLUME is a Docker named volume
# or an absolute host path; DATA_MOUNT is the in-container target and must be
# absolute. Reject '..' in either so a stray env var can't mount, say, the host
# root or /etc into the container.
[[ "$VOLUME" != *..* ]] || die "VOLUME must not contain '..' (got: '$VOLUME')"
[[ "$VOLUME" =~ ^(/.+|[A-Za-z0-9][A-Za-z0-9_.-]*)$ ]] \
  || die "VOLUME must be a named volume or an absolute host path (got: '$VOLUME')"
[[ "$DATA_MOUNT" == /* && "$DATA_MOUNT" != *..* ]] \
  || die "DATA_MOUNT must be an absolute path without '..' (got: '$DATA_MOUNT')"

# ── 1. Preserve auth + integrations ─────────────────────────────────────────
# Prefer an explicit --env-file. Otherwise capture the running container's
# operator-provided env so credentials carry over the swap. Only .Config.Env
# (the vars passed at `docker run`) is captured — never entrypoint-generated
# secrets — so a container that was itself started without auth yields nothing
# and we warn loudly.
CAPTURED_ENV=""
cleanup() { [ -n "$CAPTURED_ENV" ] && rm -f "$CAPTURED_ENV" || true; }
trap cleanup EXIT

if [ -z "$ENV_FILE" ] && docker container inspect "$CONTAINER" >/dev/null 2>&1; then
  CAPTURED_ENV="$(mktemp)"
  docker container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER" \
    | grep -E '^(XALGORIX_|GEMINI_|AGENTMAIL_|CAIDO_)' > "$CAPTURED_ENV" || true
  if [ -s "$CAPTURED_ENV" ]; then
    ENV_FILE="$CAPTURED_ENV"
    info "Captured $(wc -l < "$ENV_FILE") env var(s) from the running '$CONTAINER' container."
  else
    rm -f "$CAPTURED_ENV"; CAPTURED_ENV=""
    warn "Running container exposed no XALGORIX_* env to capture."
  fi
fi

# Warn if the recreated container will have no dashboard auth and is not
# loopback-bound — the entrypoint will then mint a NEW random admin password.
if [ -n "$ENV_FILE" ]; then
  has_auth="$(grep -cE '^XALGORIX_(PASSWORD|PASSWORD_HASH)=.+' "$ENV_FILE" || true)"
else
  has_auth=0
fi
if [ "$has_auth" -eq 0 ]; then
  warn "No XALGORIX_PASSWORD/HASH will be passed — a random admin password"
  warn "will be generated (printed in 'docker logs $CONTAINER'). Pass --env-file"
  warn "to keep a stable login."
fi

# ── 2. Build or pull the image (tagging the outgoing one for rollback) ───────
repo="${IMAGE%:*}"; [ "$repo" = "$IMAGE" ] && repo="$IMAGE"
BACKUP_IMAGE="${repo}:prev"
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker tag "$IMAGE" "$BACKUP_IMAGE"
  info "Tagged current image as rollback: $BACKUP_IMAGE"
fi

case "$MODE" in
  build)
    [ -f "$BUILD_CONTEXT/Dockerfile" ] || die "no Dockerfile in $BUILD_CONTEXT (use --no-build or --pull)"
    # Stamp the real version into the binary (Dockerfile's ARG VERSION defaults
    # to "docker", which the dashboard shows as "vdocker"). Prefer the source's
    # `var version = "X"`, then `git describe`; leave unset to keep the default.
    VERSION="${VERSION:-$(sed -n 's/^var version = "\(.*\)"$/\1/p' "$BUILD_CONTEXT/cmd/xalgorix/main.go" 2>/dev/null | head -1)}"
    [ -z "$VERSION" ] && VERSION="$(git -C "$BUILD_CONTEXT" describe --tags 2>/dev/null | sed 's/^v//')"
    info "Building $IMAGE from $BUILD_CONTEXT (version=${VERSION:-docker}) ..."
    # Refresh nuclei (engine + templates) to the latest on every build unless
    # NUCLEI_REFRESH=0. The Dockerfile gates nuclei behind TOOLS_REFRESH, so a
    # changing value re-pulls the latest engine + vuln templates WITHOUT
    # re-running the heavy apt/tool layers. Pin with NUCLEI_VERSION=vX.Y.Z.
    REFRESH_ARG=""
    if [ "${NUCLEI_REFRESH:-1}" != "0" ]; then
      REFRESH_ARG="--build-arg TOOLS_REFRESH=$(date +%s)"
      [ -n "${NUCLEI_VERSION:-}" ] && REFRESH_ARG="$REFRESH_ARG --build-arg NUCLEI_VERSION=$NUCLEI_VERSION"
      info "nuclei: forcing latest engine + templates${NUCLEI_VERSION:+ (pinned $NUCLEI_VERSION)} — set NUCLEI_REFRESH=0 to reuse cache."
    fi
    docker build ${VERSION:+--build-arg VERSION="$VERSION"} $REFRESH_ARG -t "$IMAGE" "$BUILD_CONTEXT"
    ;;
  pull)
    info "Pulling $IMAGE ..."
    docker pull "$IMAGE"
    ;;
  none)
    docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not present (drop --no-build)"
    info "Reusing existing image $IMAGE (no build/pull)."
    ;;
esac

# ── 3. Recreate: rename the old container aside, run the new one ─────────────
PREV="${CONTAINER}_prev"
docker rm -f "$PREV" >/dev/null 2>&1 || true
HAD_OLD=false
if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
  docker stop "$CONTAINER" >/dev/null 2>&1 || true
  docker rename "$CONTAINER" "$PREV"
  HAD_OLD=true
  info "Kept previous container as '$PREV' for rollback."
fi

info "Starting new '$CONTAINER' from $IMAGE ..."
if ! docker run -d \
      --name "$CONTAINER" \
      --restart "$RESTART" \
      ${ENV_FILE:+--env-file "$ENV_FILE"} \
      -p "${BIND_ADDR:+$BIND_ADDR:}$PORT:$PORT" \
      -v "$VOLUME:$DATA_MOUNT" \
      "$IMAGE" --web >/dev/null; then
  warn "docker run failed — rolling back."
  [ "$HAD_OLD" = true ] && docker rename "$PREV" "$CONTAINER" && docker start "$CONTAINER" >/dev/null 2>&1 || true
  die "redeploy aborted."
fi

# ── 4. Health check, with rollback on failure ───────────────────────────────
info "Waiting for the dashboard on http://127.0.0.1:$PORT$HEALTH_PATH (up to ${HEALTH_TIMEOUT}s) ..."
healthy=false
deadline=$((SECONDS + HEALTH_TIMEOUT))
while [ $SECONDS -lt $deadline ]; do
  if curl -fsS -o /dev/null "http://127.0.0.1:$PORT$HEALTH_PATH" 2>/dev/null; then
    healthy=true; break
  fi
  # Bail early if the container has already exited.
  if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" != "true" ]; then
    break
  fi
  sleep 3
done

if [ "$healthy" != true ]; then
  warn "New container is not healthy. Rolling back to the previous container."
  docker logs --tail 30 "$CONTAINER" 2>&1 | sed 's/^/    /' || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "$HAD_OLD" = true ]; then
    docker rename "$PREV" "$CONTAINER" && docker start "$CONTAINER" >/dev/null 2>&1 \
      && ok "Rolled back — '$CONTAINER' is running the previous version." \
      || warn "Rollback failed; start it manually: docker start $CONTAINER"
  fi
  die "redeploy failed (image kept as $IMAGE; previous image is $BACKUP_IMAGE)."
fi

# ── 5. Success — drop the old container, report auth mode ────────────────────
[ "$HAD_OLD" = true ] && docker rm -f "$PREV" >/dev/null 2>&1 || true
ok "'$CONTAINER' is up and healthy on port $PORT (image $IMAGE)."
docker logs "$CONTAINER" 2>&1 | grep -iE "Authentication enabled|Generated one-time credentials|password:" | head -4 | sed 's/^/    /' || true
echo ""
echo "  Rollback if needed:"
echo "    docker rm -f $CONTAINER && docker run -d --name $CONTAINER --restart $RESTART \\"
echo "      ${ENV_FILE:+--env-file <your-env-file> }-p ${BIND_ADDR:+$BIND_ADDR:}$PORT:$PORT -v $VOLUME:$DATA_MOUNT $BACKUP_IMAGE --web"
