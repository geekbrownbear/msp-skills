#!/usr/bin/env python3
"""CI gate for the generated Docker deployment.

Three jobs, in order of how much damage they prevent:

1. No connector service publishes a port. The MCP servers have no
   authentication of their own, so a `ports:` entry puts a fully privileged,
   unauthenticated server on the LAN. This is checked textually and
   independently of the drift check, because it is the one mistake a hurried
   operator makes while debugging and it must fail even if someone edits the
   generator to match.
2. The committed output matches what the generator produces. Same contract as
   build-catalog.py: drift fails CI rather than shipping.
3. Structural invariants every service must hold (HOME=/data, read_only, a
   volume, a DNS-safe name, an env example).

Deliberately no YAML dependency: nothing else in tools/maintainer/ has one, and
the format here is generated and therefore known.
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCKER = REPO / "docker"
COMPOSE = DOCKER / "compose.yml"
GENERATOR = REPO / "tools" / "maintainer" / "build_compose.py"

# Compose service names become hostnames on the internal network.
DNS_SAFE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

REQUIRED_LINES = {
    "HOME: /data": "storage relocation",
    "read_only: true": "read-only root filesystem",
    "no-new-privileges:true": "privilege escalation guard",
}


def fail(errors):
    print("FAIL: docker deployment gate")
    for e in errors:
        print(f"  - {e}")
    print("\nRegenerate with: python3 tools/maintainer/build_compose.py")
    return 1


def parse_services(text):
    """Return {service_name: [lines]} for the top-level `services:` mapping."""
    lines = text.splitlines()
    services, current, buf = {}, None, []
    in_services = False
    for line in lines:
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if in_services and re.match(r"^[a-zA-Z_]", line):
            break  # left the services block (networks:, volumes:, ...)
        if not in_services:
            continue
        m = re.match(r"^  ([A-Za-z0-9][A-Za-z0-9._-]*):\s*$", line)
        if m:
            if current:
                services[current] = buf
            current, buf = m.group(1), []
            continue
        if current is not None:
            buf.append(line)
    if current:
        services[current] = buf
    return services


def main():
    errors = []

    if not COMPOSE.is_file():
        return fail([f"{COMPOSE.relative_to(REPO)} is missing. Run the generator."])

    text = COMPOSE.read_text()
    services = parse_services(text)

    if not services:
        return fail(["parsed 0 services out of docker/compose.yml; the format changed"])

    # 1. published ports, the dangerous one
    for name, body in services.items():
        for line in body:
            if re.match(r"^\s*(ports|expose):\s*", line):
                errors.append(
                    f"service '{name}' publishes a port ({line.strip()!r}). Connectors "
                    "must not be reachable except through the gateway: they have no "
                    "authentication of their own."
                )
    # also catch one outside a recognised service block
    for line in text.splitlines():
        if re.match(r"^\s+ports:\s*$", line) and "ports:" not in str(
            [l for b in services.values() for l in b]
        ):
            errors.append(f"a `ports:` entry appears in compose.yml: {line.strip()!r}")

    # 2. structural invariants
    registry = json.loads((REPO / "tools" / "maintainer" / "skills.json").read_text())["skills"]
    for name, body in services.items():
        blob = "\n".join(body)
        if not DNS_SAFE.match(name):
            errors.append(
                f"service '{name}' is not a DNS-safe hostname; it must match "
                f"{DNS_SAFE.pattern}"
            )
        for needle, why in REQUIRED_LINES.items():
            if needle not in blob:
                errors.append(f"service '{name}' is missing {needle!r} ({why})")
        if f"{name}-data:/data" not in blob:
            errors.append(f"service '{name}' does not mount its own named volume")
        if name not in registry:
            errors.append(f"service '{name}' is not in skills.json")
        example = DOCKER / "env" / f"{name}.env.example"
        if not example.is_file():
            errors.append(f"service '{name}' has no docker/env/{name}.env.example")

    # 3. drift: the generator is the source of truth.
    # Generate into a temp directory rather than in place. A gate that rewrites
    # the file it is checking passes on the second run and destroys whatever the
    # operator had edited, which is the opposite of what a drift check is for.
    with tempfile.TemporaryDirectory() as tmp:
        proc = subprocess.run(
            [sys.executable, str(GENERATOR), tmp],
            capture_output=True,
            text=True,
            cwd=str(REPO),
        )
        if proc.returncode != 0:
            errors.append(f"build_compose.py failed: {proc.stderr.strip()[:300]}")
        else:
            tmpdir = Path(tmp)
            expected = {
                p.relative_to(tmpdir).as_posix(): p.read_bytes()
                for p in sorted(tmpdir.rglob("*"))
                if p.is_file()
            }
            # Compare only what the generator owns. docker/ also holds
            # hand-authored files (README.md, Dockerfile.connector, msp.sh) and
            # operator-owned ones (.env, env/<slug>.env, both gitignored).
            actual = {
                rel: (DOCKER / rel).read_bytes()
                for rel in expected
                if (DOCKER / rel).is_file()
            }
            for rel in sorted(set(expected) | set(actual)):
                if rel not in actual:
                    errors.append(f"docker/{rel} is missing; regenerate and commit it")
                elif rel not in expected:
                    errors.append(f"docker/{rel} is not produced by the generator")
                elif expected[rel] != actual[rel]:
                    errors.append(f"docker/{rel} does not match the generator output")

    if errors:
        return fail(errors)

    print(f"PASS: docker deployment gate ({len(services)} connector services)")
    print("  no published ports, generated output current, invariants hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
