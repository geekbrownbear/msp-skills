#!/bin/sh
# Build one connector image from the tree rather than from a published release.
#
# This fork carries fixes that are not released yet, and the default image
# downloads release binaries, so without this a change is invisible to the
# deployment it was written for until a release is cut.
#
# Usage:  ./docker/build-from-source.sh <slug>
# Then:   set <SLUG>_VERSION=source in docker/.env and bring the stack up.

set -eu

slug="${1:-}"
if [ -z "${slug}" ]; then
    echo "usage: $0 <slug>" >&2
    exit 2
fi

here=$(unset CDPATH; cd -- "$(dirname -- "$0")" && pwd)
repo=$(dirname "${here}")
src="${repo}/skills/${slug}/cli"

if [ ! -f "${src}/go.mod" ]; then
    echo "no Go module at skills/${slug}/cli" >&2
    exit 1
fi

# Assemble the build context in a temp dir. The Dockerfile needs the module
# plus the entrypoint, and the entrypoint lives in docker/. Copying it into the
# connector tree instead would leave an untracked stray file in the repo.
ctx=$(mktemp -d)
cleanup() { rm -rf "${ctx}"; }
trap cleanup EXIT INT TERM

tar -cf - -C "${src}" . | tar -xf - -C "${ctx}"
cp "${here}/entrypoint.sh" "${ctx}/docker-entrypoint.sh"

echo "building msp-skills/${slug}:source from ${src}"
docker build \
    -f "${here}/Dockerfile.connector.source" \
    --build-arg "SLUG=${slug}" \
    --build-arg "CLI_BINARY=${slug}-cli" \
    --build-arg "MCP_BINARY=${slug}-mcp" \
    -t "msp-skills/${slug}:source" \
    "${ctx}"

echo
echo "built msp-skills/${slug}:source"
echo "to use it, add this to docker/.env:"
echo "  $(echo "${slug}" | tr 'a-z-' 'A-Z_')_VERSION=source"
