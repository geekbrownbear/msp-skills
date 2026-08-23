#!/bin/sh
# Container entrypoint for an msp-skills connector. Hand-authored.
#
# Runs the MCP server by default. `cli <args>` runs the companion CLI instead,
# which is how `docker compose exec <slug> cli sync --full` and `cli doctor`
# work.
#
# Two credential on-ramps beyond plain environment variables:
#   FOO_FILE=/run/secrets/foo   reads the value from that file (Docker secrets)
#   MSP_CREDENTIAL_PROVIDER=cmd runs cmd once, consuming KEY=VALUE lines
#
# Both are honest about their limit: the value ends up in this process's
# environment either way, so `docker exec <ctr> env` still shows it. What they
# buy is keeping the secret out of the compose file and out of `docker inspect`.

set -eu

log() {
    echo "entrypoint: $*" >&2
}

die() {
    log "$*"
    exit 1
}

# Expand any FOO_FILE into FOO. Docker secrets land as files, and this is the
# convention the ecosystem already expects.
expand_file_vars() {
    for name in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)_FILE=.*/\1/p'); do
        path=$(printenv "${name}_FILE" 2>/dev/null || true)
        [ -n "${path}" ] || continue
        [ -r "${path}" ] || die "${name}_FILE points at ${path}, which is not readable"
        value=$(cat "${path}")
        [ -n "${value}" ] || log "warning: ${path} is empty, so ${name} is empty"
        export "${name}=${value}"
        unset "${name}_FILE"
    done
}

# Run an operator-supplied command that prints KEY=VALUE lines. This is the
# graduation path to Vault, Infisical or 1Password: one small script, no change
# to anything else in the deployment.
run_credential_provider() {
    [ -n "${MSP_CREDENTIAL_PROVIDER:-}" ] || return 0
    log "running credential provider: ${MSP_CREDENTIAL_PROVIDER}"
    output=$(sh -c "${MSP_CREDENTIAL_PROVIDER}") || die "credential provider failed"
    echo "${output}" | while IFS= read -r line; do
        case "${line}" in
            ''|'#'*) continue ;;
        esac
        case "${line}" in
            *=*) ;;
            *) die "credential provider printed a line that is not KEY=VALUE: ${line}" ;;
        esac
    done
    # Applied in this shell rather than the subshell above, which cannot export
    # into the parent.
    set -a
    # shellcheck disable=SC2046
    eval "$(echo "${output}" | grep -E '^[A-Za-z_][A-Za-z0-9_]*=')"
    set +a
}

# /data holds the SQLite mirror. Catch an unwritable mount here, with a message
# naming the cause, rather than letting the store fail later with an errno.
check_data_dir() {
    [ -d /data ] || die "/data does not exist in this image"
    if ! touch /data/.write-probe 2>/dev/null; then
        die "/data is not writable by uid $(id -u). A named volume inherits ownership from the image; a bind mount does not, and needs 'chown -R 10001:10001' on the host path."
    fi
    rm -f /data/.write-probe
}

expand_file_vars
run_credential_provider
check_data_dir

cli="${MSP_CLI_BINARY:?image is missing MSP_CLI_BINARY}"
mcp="${MSP_MCP_BINARY:?image is missing MSP_MCP_BINARY}"

# The MCP server defaults to binding 127.0.0.1:7777, which is right on a laptop
# and useless in a container: nothing outside the network namespace can reach
# it, including the gateway. The binary takes --addr but has no environment
# fallback for it, unlike --transport which reads PP_MCP_TRANSPORT. So the image
# supplies one.
#
# Binding 0.0.0.0 inside the container is not a widening of exposure. The
# container's network namespace is the boundary, the compose file publishes no
# ports, and check_compose.py fails the build if anyone adds one.
mcp_args() {
    if [ "${PP_MCP_TRANSPORT:-stdio}" = "http" ]; then
        echo "--addr ${PP_MCP_ADDR:-0.0.0.0:7777}"
    fi
}

case "${1:-}" in
    cli)
        shift
        exec "${cli}" "$@"
        ;;
    mcp)
        shift
        # shellcheck disable=SC2046
        exec "${mcp}" $(mcp_args) "$@"
        ;;
    '')
        # shellcheck disable=SC2046
        exec "${mcp}" $(mcp_args)
        ;;
    -*)
        exec "${mcp}" "$@"
        ;;
    *)
        # Anything else is a deliberate override, e.g. `sh` to poke around.
        exec "$@"
        ;;
esac
