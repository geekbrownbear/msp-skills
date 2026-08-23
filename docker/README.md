# Self-hosted connectors with Docker

Run the connectors as services on one host you control, instead of on every
technician's laptop, so vendor credentials and customer mirrors live in one
place that gets backed up.

This is an additional deployment mode. The laptop install is still the default
and still needs no Docker, no Node, no Python and no database.

## Rules that are not negotiable

**Never expose this to the internet.** The MCP servers have no authentication of
their own. Nothing in this directory publishes a connector port, and
`check_compose.py` fails the build if a service grows a `ports:` entry. Reach
them over a LAN or VPN only.

**Local disk only.** The store uses SQLite in WAL mode, which needs working
POSIX advisory locks. NFS and SMB corrupt the database rather than returning an
error. Verified working on ZFS, including concurrent CLI reads while the MCP
server serves the same file.

**One writer host.** Never share a volume between hosts or stacks.

## Quick start

```sh
cp .env.example .env                     # profiles and version pins
cp env/halopsa.env.example env/halopsa.env
$EDITOR env/halopsa.env                  # fill in credentials

docker compose --profile halopsa up -d
docker compose exec halopsa cli doctor   # the real configuration check
docker compose exec halopsa cli sync --full
```

`doctor` is the check that matters. It reports where each credential came from
(`env:HALOPSA_CLIENT_ID`, `config`, `none`) rather than whether a file exists.

## Where credentials live

Three options, in increasing order of how much they keep off your workstation.

**Tier 1, `docker/env/<slug>.env`.** Generated examples sit beside each. These
are read by Compose *on the machine running the CLI*, which for a remote daemon
is your workstation. Anyone who can run `docker inspect` on the Docker host can
read the values.

**Tier 2, `compose.secrets.yml`.** Credentials live on the Docker host instead.
Set `MSP_SECRETS_DIR` in `.env` to a directory there holding one `<slug>.env`
per connector, then:

```sh
docker compose -f compose.yml -f compose.secrets.yml --profile halopsa up -d
```

Each file must be readable by **uid 10001**, which is what the containers run
as. The host file's own owner and mode apply inside the container, so a file
owned by your login account at `0600` gives `cat: Permission denied`:

```sh
chown 10001:10001 "$MSP_SECRETS_DIR"/*.env
chmod 0400 "$MSP_SECRETS_DIR"/*.env
chmod 0700 "$MSP_SECRETS_DIR"
```

**Tier 3, a secret store.** Any `FOO_FILE=/path` becomes `FOO` at startup, so
Docker secrets work as-is. `MSP_CREDENTIAL_PROVIDER=<command>` runs a command
once and consumes `KEY=VALUE` lines, which is how you reach Vault, Infisical or
1Password without changing anything else.

All three end with the value in the container's environment, so `docker exec
<ctr> env` still shows it. What the later tiers buy is keeping the secret out of
your workstation and out of the compose file.

## Sizing

Measured against a live tenant rather than estimated:

| | |
|---|---|
| Idle memory | ~10 MB per connector |
| Peak during `sync --full` | **2.28 GiB** |
| Mirror after a full sync | 1.3 GB (340 MB on ZFS with compression) |
| Image size | 38 MB to 79 MB |

`mem_limit` defaults to `4g` for that reason. Do not lower it to something that
looks tidier: a sync that runs out of cgroup memory does not fail cleanly. A
write to a memory-mapped page the cgroup cannot back raises SIGBUS, which
surfaces as a Go runtime fault inside `modernc.org/sqlite _walIndexAppend` and
reads exactly like disk corruption. The other half of the time it is a silent
SIGKILL. Neither mentions memory.

Plan volume capacity from the mirror size, not the image size.

## Backups, and what is in them

Back up the named volumes, not the containers. Use `VACUUM INTO` rather than
`tar` over a live WAL database.

**The volume can contain a live credential.** A connector that mints an OAuth
token caches it to `/data/.local/share/<slug>-cli/credentials.toml`, so a
restored snapshot carries a working tenant credential with it. Credentials
supplied through the environment are not written (that guard is
[#268](https://github.com/Servosity/msp-skills/issues/268)), but the minted
token is. Track
[#270](https://github.com/Servosity/msp-skills/issues/270) for a
`<PREFIX>_NO_CONFIG_WRITE` switch; the generator already sets it for any
connector whose binary honours it.

## Upgrades and rollback

`tools/maintainer/skills.json` is repo-global, so a `git pull` moves every
connector's version at once. Pin the ones you care about in `.env`:

```
HALOPSA_VERSION=0.2.12
```

**Rolling back is a one-way door without a snapshot.** An older binary refuses a
store schema written by a newer one (`database schema version %d is newer than
supported version %d`). Snapshot the volume before you lower a pin.

Note also that the registry version is the version of the connector *in the
tree*, which is not always a published release. If a build fails with a missing
release asset, the error names the pin to set.

## Building from the tree

The default image downloads published release binaries and verifies the
`.sha256` files that ship beside them. That is integrity, not provenance: the
checksums come from the same workflow as the binaries, and nothing is signed.

To run a connector with local changes:

```sh
./docker/build-from-source.sh cipp
# then set CIPP_VERSION=source in .env
```

## Connectors that cannot run as a service

A few connectors predate the MCP `--transport` flag and can only speak stdio.
In a container that means they exit immediately and restart forever. The
entrypoint detects this and refuses to start with an explanation rather than
looping silently. See
[#241](https://github.com/Servosity/msp-skills/issues/241).

## The gateway

Connectors publish no ports, so the gateway is not the recommended path to them,
it is the only one. That is what makes its audit log a record of every call
rather than a record of the polite ones.

```sh
# docker/.env
MSP_GATEWAY_BIND=10.0.0.5          # a specific LAN address, never 0.0.0.0
MSP_GATEWAY_PORT=8080
MSP_GATEWAY_CONFIG=/srv/msp/gateway.json

docker compose -f compose.yml -f compose.gateway.yml --profile gateway up -d
```

Each technician gets their own bearer token. Store only its digest:

```sh
printf '%s' "$TOKEN" | sha256sum        # put this in token_sha256
```

A grant is per actor, per connector, per tool. Deny beats allow, an empty allow
list means nothing rather than everything, and a tool that is not annotated
read-only counts as a write. That last rule matters more than it looks:
`<slug>_execute` takes an arbitrary endpoint id and reaches every write the
vendor exposes, and it carries no annotation at all.

Point a client at one connector per entry:

```sh
claude mcp add --transport http halopsa http://10.0.0.5:8080/mcp/halopsa \
  --header "Authorization: Bearer $TOKEN"
```

Every call is recorded in a hash-chained log, denials included. Editing or
removing a line breaks every hash after it:

```sh
docker compose -f compose.yml -f compose.gateway.yml exec gateway \
  msp-mcp-gateway -verify-audit /var/lib/msp-mcp-gateway/audit.jsonl
```

Arguments are hashed rather than recorded verbatim by default, because tool
arguments routinely carry customer names and ticket bodies and an audit log that
stores them is itself a liability. Set `arguments_mode` to `full` only
deliberately.

The gateway is new security-critical code. Review it before it fronts anything
that matters.

## What this does not solve

**Securing the Docker host.** Anyone with daemon access can read every
credential and run the CLI directly. That is normal for self-hosted software and
is the operator's layer. Least-privilege vendor API scopes remain the meaningful
control.

**Prompt injection.** A ticket body that says "delete all tickets" still reaches
the model. This narrows the network blast radius, not the semantic one.

**The vendor's view of who acted.** One container holds one vendor credential
set, so the vendor records the integration, not the technician. That is how any
integration holding an API key appears. Per-technician attribution means running
a second instance with that technician's own credentials.
