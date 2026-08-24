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
    # Quiet by default. Now that `cli` re-enters the entrypoint, this ran on
    # every `docker compose exec`, prefixing real command output with a line
    # about plumbing. Failures below are still always reported.
    [ -n "${MSP_DEBUG:-}" ] && log "running credential provider: ${MSP_CREDENTIAL_PROVIDER}"
    if ! output=$(sh -c "${MSP_CREDENTIAL_PROVIDER}" 2>&1); then
        log "ERROR: credential provider failed: ${output}"
        case "${output}" in
            *"Is a directory"*)
                log ""
                log "       The secret file did not exist on the Docker host when this"
                log "       container was created, so Docker manufactured a DIRECTORY at"
                log "       that path. Docker does this for any bind-mounted file whose"
                log "       host path is missing."
                log ""
                log "       On the Docker host:"
                log "         1. remove the junk directory:  rmdir <secrets-dir>/<slug>.env"
                log "         2. create the real file (an empty file is fine for a"
                log "            connector you have no credentials for yet):"
                log "              touch <secrets-dir>/<slug>.env"
                log "              chown 10001:10001 <secrets-dir>/<slug>.env"
                log "              chmod 0400 <secrets-dir>/<slug>.env"
                log "         3. recreate this container so the mount picks up the file"
                ;;
            *"Permission denied"*)
                log ""
                log "       This container runs as uid $(id -u). A bind-mounted secret"
                log "       file must be readable by that uid: the host file's own mode"
                log "       and owner apply inside the container, and a file owned by"
                log "       your login account at mode 0600 is not readable here."
                log ""
                log "       On the Docker host:  chown 10001:10001 <file> && chmod 0400 <file>"
                ;;
        esac
        exit 1
    fi
    # Parse KEY=VALUE lines WITHOUT eval. The first version eval'd the lines,
    # and a value containing a space (NINJAONE_OAUTH_SCOPE="monitoring
    # management" is a legitimate one) made the shell execute the second word
    # as a command. That is a crash for an honest value and arbitrary command
    # execution for a dishonest one. export "$name=$value" assigns the value
    # verbatim, whatever it contains.
    #
    # The here-doc keeps the loop in this shell; a pipe would put it in a
    # subshell whose exports die with it.
    while IFS= read -r line; do
        case "${line}" in
            ''|'#'*) continue ;;
        esac
        case "${line}" in
            *=*) ;;
            *) die "credential provider printed a line that is not KEY=VALUE: ${line}" ;;
        esac
        name=${line%%=*}
        value=${line#*=}
        case "${name}" in
            [A-Za-z_]*) ;;
            *) die "credential provider printed an invalid variable name: ${name}" ;;
        esac
        case "${name}" in
            *[!A-Za-z0-9_]*) die "credential provider printed an invalid variable name: ${name}" ;;
        esac
        export "${name}=${value}"
    done <<PROVIDER_EOF
${output}
PROVIDER_EOF
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
# Under MSP_SECRETS_RELOAD the provider runs inside the serve loop, once per
# (re)start, so values re-read on every reload rather than freezing at boot.
if [ "${MSP_SECRETS_RELOAD:-}" != "1" ]; then
    run_credential_provider
fi
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
# A stdio-only MCP server in a container is a silent crash loop: it reads EOF on
# stdin immediately, exits 0, and the restart policy starts it again forever
# while logging nothing at all. Observed with blumira, whose binary predates the
# transport flag and ignores unknown flags without complaint, so --help prints
# nothing and there is no way to ask it politely.
#
# The http-capable binaries embed the PP_MCP_TRANSPORT string; the stdio-only
# ones do not. Checking for it turns an undiagnosable restart loop into one
# clear line naming the connector, the cause and the fix.
assert_http_capable() {
    [ "${PP_MCP_TRANSPORT:-stdio}" = "http" ] || return 0
    if ! grep -qa "PP_MCP_TRANSPORT" "$(command -v "${mcp}")" 2>/dev/null; then
        log "ERROR: ${MSP_SLUG:-this connector} was built before the MCP server"
        log "       learned --transport, so it can only speak stdio and cannot"
        log "       serve HTTP. In a container it would exit immediately and"
        log "       restart forever without logging anything."
        log ""
        log "       See Servosity/msp-skills#241. Until that lands, this"
        log "       connector cannot run as a service. Remove it from"
        log "       COMPOSE_PROFILES in docker/.env."
        exit 1
    fi
}

mcp_args() {
    if [ "${PP_MCP_TRANSPORT:-stdio}" = "http" ]; then
        echo "--addr ${PP_MCP_ADDR:-0.0.0.0:7777}"
    fi
}

# secret_mtime prints the mtime of the mounted secrets file, or 0.
secret_mtime() {
    stat -c %Y /run/secrets/connector.env 2>/dev/null || echo 0
}

# serve_with_reload runs the MCP server and restarts it when the mounted
# secrets file changes.
#
# Credentials are read once at startup, so without this a credential written
# after the container started is invisible until someone recreates the
# container, which needs Docker access. Watching the file instead means the
# setup UI (or any operator edit) needs only write access to the secrets
# directory: the connector notices and reloads itself. This is what lets a
# setup surface help the stack without holding the Docker socket, which is
# root on the host.
#
# Only armed when MSP_SECRETS_RELOAD=1, which the secrets overlay sets; a
# plain env-file deployment keeps exec-and-forget semantics.
serve_with_reload() {
    while :; do
        stamp=$(secret_mtime)
        run_credential_provider
        # shellcheck disable=SC2046
        "${mcp}" $(mcp_args) "$@" &
        srv=$!
        while kill -0 "${srv}" 2>/dev/null; do
            sleep 5
            if [ "$(secret_mtime)" != "${stamp}" ]; then
                log "secrets file changed; reloading ${MSP_SLUG:-connector}"
                kill "${srv}" 2>/dev/null
                wait "${srv}" 2>/dev/null || true
                continue 2
            fi
        done
        # server exited on its own; propagate rather than looping a crash
        wait "${srv}" 2>/dev/null
        exit $?
    done
}

case "${1:-}" in
    cli)
        shift
        # Under reload mode the top-level provider run is deferred into the
        # serve loop, which an exec'd CLI never enters, so run it here or
        # `docker compose exec <slug> cli doctor` authenticates as nobody.
        # Caught live: the server had credentials and the CLI beside it did not.
        if [ "${MSP_SECRETS_RELOAD:-}" = "1" ]; then
            run_credential_provider
        fi
        exec "${cli}" "$@"
        ;;
    mcp)
        shift
        assert_http_capable
        if [ "${MSP_SECRETS_RELOAD:-}" = "1" ]; then
            serve_with_reload "$@"
        fi
        # shellcheck disable=SC2046
        exec "${mcp}" $(mcp_args) "$@"
        ;;
    '')
        assert_http_capable
        if [ "${MSP_SECRETS_RELOAD:-}" = "1" ]; then
            serve_with_reload
        fi
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
