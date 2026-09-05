#!/usr/bin/env bash
# Render docker/dockhand-stack.yml: ONE self-contained compose file for an
# external stack manager (dockhand / portainer).
#
# It merges every overlay -- the generated connector compose.yml, the gateway,
# the control plane, and (if MSP_SECRETS_DIR is set) the host-secrets overlay --
# with the gateway profile active, then strips `profiles:` and `build:` so the
# manager adopts the images already built on the host instead of trying to build
# them (a build context only resolves on the workstation, not in the manager).
#
# Run PER HOST after filling in docker/.env; the output embeds this host's bind
# addresses and secret paths, so it is gitignored -- never commit it.
#
#   cd docker && ./render-dockhand-stack.sh
#
# Then import docker/dockhand-stack.yml into dockhand. The control-plane secrets
# are read from the environment at render time (docker/.env): set
#   CONTROL_PLANE_SSO_TICKET_KEY   (MUST equal the console's SSO_TICKET_KEY)
#   CONTROL_PLANE_SSO_ALLOWED_REDIRECTS   (the console's /auth/callback URL[s])
#   CONTROL_PLANE_EXTERNAL_URL, MSP_CONTROL_PLANE_BIND, MSP_GATEWAY_BIND,
#   MSP_GATEWAY_CONFIG
# See docker/README.md.
set -euo pipefail
cd "$(dirname "$0")"

# Load operator settings (bind addresses, secret paths, profiles, secrets).
[ -f .env ] && { set -a; . ./.env; set +a; }

files=(-f compose.yml -f compose.gateway.yml -f compose.control-plane.yml)
[ -n "${MSP_SECRETS_DIR:-}" ] && files+=(-f compose.secrets.yml)

# The gateway profile also carries the control plane; keep any connector
# profiles from COMPOSE_PROFILES.
export COMPOSE_PROFILES="$(printf '%s,gateway' "${COMPOSE_PROFILES:-}" | sed 's/^,//')"

# `docker compose config` merges + interpolates (no daemon needed). Then drop
# each service's `profiles:` and `build:` blocks (indent-4 keys and their
# deeper-indented bodies) so the file is a pure, adoptable stack.
docker compose "${files[@]}" config | python3 -c '
import sys
out, skip = [], False
for line in sys.stdin.read().splitlines():
    if not line.strip():
        if not skip:
            out.append(line)
        continue
    indent = len(line) - len(line.lstrip(" "))
    if skip:
        if indent > 4:
            continue
        skip = False
    key = line.lstrip()
    if indent == 4 and (key.startswith("profiles:") or key.startswith("build:")):
        skip = True
        continue
    out.append(line)
sys.stdout.write("\n".join(out) + "\n")
' > dockhand-stack.yml

echo "wrote docker/dockhand-stack.yml (profiles active: $COMPOSE_PROFILES)"
echo "next: import it into dockhand, and confirm the control-plane secrets are set."
