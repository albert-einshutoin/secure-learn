#!/usr/bin/env bash
# Verify the version-pinned CI daemon before the destructive fresh-stack gate.
set -euo pipefail

fail() {
  echo "Docker runtime contract failed: $*" >&2
  exit 1
}

if [[ -n "${DOCKER_HOST+x}" || -n "${DOCKER_CONTEXT+x}" ]]; then
  fail "Docker target override variables must remain unset."
fi

# setup-docker-action returns a complete unix:/// URI. Requiring the canonical
# scheme here prevents relative paths, remote endpoints, and double-prefix bugs.
[[ "${EXPECTED_DOCKER_SOCKET:-}" =~ ^unix:///[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] \
  || fail "The setup action must provide an absolute local Unix socket URI."

context="$(docker context show)"
[[ "$context" == "secure-learn-ci" ]] || fail "Unexpected Docker context."

endpoint="$(docker context inspect "$context" --format '{{.Endpoints.docker.Host}}')"
[[ "$endpoint" == "$EXPECTED_DOCKER_SOCKET" ]] \
  || fail "The active context must use the setup action's exact local Unix socket."

read -r engine_version api_version < <(
  docker version --format '{{.Server.Version}} {{.Server.APIVersion}}'
)
[[ "$engine_version" == "29.6.2" ]] || fail "Docker Engine 29.6.2 is required."
[[ "$api_version" =~ ^([0-9]+)\.([0-9]+)$ ]] || fail "Malformed Docker API version."
api_major="${BASH_REMATCH[1]}"
api_minor="${BASH_REMATCH[2]}"
(( 10#$api_major > 1 || (10#$api_major == 1 && 10#$api_minor >= 49) )) \
  || fail "Docker API 1.49 or later is required."

compose_version="$(docker compose version --short)"
[[ "$compose_version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
  || fail "A stable Docker Compose release is required."
compose_major="${BASH_REMATCH[1]}"
compose_minor="${BASH_REMATCH[2]}"
(( 10#$compose_major > 2 || (10#$compose_major == 2 && 10#$compose_minor >= 36) )) \
  || fail "Docker Compose 2.36.0 or later is required."

echo "Docker runtime contract verified."
