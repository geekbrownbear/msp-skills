#!/usr/bin/env python3
"""check_env_schema.py - assert every env var a connector READS is DECLARED.

Each skill's manifest.json carries `server.mcp_config.env`, the list of
environment variables an install surface prompts for. Claude Desktop's .mcpb
bundle, the docs generator, and any deployment tooling all read it as the
authoritative credential schema for that connector.

Nothing kept it honest. A connector could read HALOPSA_TOKEN_URL, or
THREATLOCKER_API_KEY, and simply not say so - and three connectors carrying the
live_verified badge (quickbooks, threatlocker, cove) declared almost none of the
credentials their binaries actually require. The binaries work; the manifests
were wrong, so the install surface prompted for the wrong things and the
operator discovered the gap as a runtime auth failure three network hops from
the cause.

DESIGN NOTE - the denylist polarity is deliberate.

An earlier version of this check used an allowlist: a regex of what "looks
like" a credential (_API_KEY, _SECRET, _TOKEN...). It silently missed
AUTOTASK_API_INTEGRATION_CODE and AUTOTASK_PSA_USER_NAME because those suffixes
were not in the pattern, and then reported them as phantom declarations - a
confident, wrong answer in both directions at once.

So this walks the other way: everything a connector reads is a candidate, and
only known framework plumbing is subtracted. A false positive is visible and
costs one denylist entry. A false negative ships a credential schema that is
quietly incomplete, which is the bug this exists to catch.

Usage:
    check_env_schema.py [--slug SLUG] [--json]

Exit codes:
    0  every connector declares what it reads
    1  at least one divergence
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Framework plumbing. Never a user credential, never belongs in a manifest.
NOISE_EXACT = {
    "AGENT_ID", "NO_COLOR", "NO_INPUT", "CI", "HOME", "PATH", "USER",
    "USERNAME", "TMPDIR", "TERM", "EDITOR", "PAGER", "SHELL", "LANG",
}
NOISE_SUFFIX = re.compile(
    r"_(CLI_PATH|CONFIG|DB|DB_PATH|DATA_DIR|STATE_DIR|CACHE_DIR|HOME"
    r"|NO_LEARN|LEARN_SESSION|LEARN_NO_CAPTURE|LEARN_SURFACE|USER_AGENT"
    r"|FEEDBACK_ENDPOINT|FEEDBACK_AUTO_SEND|LEDGER_DIR|DEBUG|VERBOSE"
    r"|TIMEOUT|PAGE_SIZE|MAX_PAGES|DISABLED|NO_CONFIG_WRITE)$"
)
NOISE_PREFIX = re.compile(
    r"^(PP_|PRINTING_PRESS_|XDG_|PRESEED_|GOCACHE|GOPATH|HTTPS?_PROXY|NO_PROXY)"
)

# Declared-but-unread is tolerated for this one: the platform layer reads it
# through a different path than os.Getenv.
DECLARED_EXEMPT = {"PRINTING_PRESS_CLIENT_PROFILE"}

GETENV = re.compile(r'os\.Getenv\(\s*"([A-Z][A-Z0-9_]*)"\s*\)')


def is_noise(var: str) -> bool:
    return (
        var in NOISE_EXACT
        or NOISE_PREFIX.match(var) is not None
        or NOISE_SUFFIX.search(var) is not None
    )


def vars_read(cli_dir: Path) -> set:
    """Every env var the shipped code reads, excluding tests.

    Test files are excluded deliberately: credentials_perms_test.go reads
    USERNAME to resolve a Windows account name, which is not a credential and
    would otherwise be reported against six connectors.
    """
    found = set()
    for go in cli_dir.rglob("*.go"):
        if go.name.endswith("_test.go"):
            continue
        for var in GETENV.findall(go.read_text(errors="ignore")):
            if not is_noise(var):
                found.add(var)
    return found


def vars_declared(manifest: Path) -> set:
    data = json.loads(manifest.read_text())
    env = (data.get("server", {}).get("mcp_config", {}) or {}).get("env") or {}
    return set(env.keys())


def audit(slug_filter=None):
    results = []
    for manifest in sorted(REPO.glob("skills/*/manifest.json")):
        slug = manifest.parent.name
        if slug_filter and slug != slug_filter:
            continue
        cli_dir = manifest.parent / "cli"
        if not cli_dir.is_dir():
            continue  # markdown-only skill
        declared = vars_declared(manifest)
        read = vars_read(cli_dir)
        results.append({
            "slug": slug,
            "undeclared": sorted(read - declared),
            "unread": sorted(declared - read - DECLARED_EXEMPT),
        })
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    results = audit(args.slug)
    bad = [r for r in results if r["undeclared"] or r["unread"]]

    if args.json:
        print(json.dumps(results, indent=2))
        return 1 if bad else 0

    for r in bad:
        for var in r["undeclared"]:
            print(f"FAIL: {r['slug']} reads {var} but manifest.json does not declare it")
        for var in r["unread"]:
            print(f"FAIL: {r['slug']} declares {var} but no non-test source reads it")

    if bad:
        n = sum(len(r["undeclared"]) + len(r["unread"]) for r in bad)
        print(f"\ncheck_env_schema FAILED: {n} finding(s) across {len(bad)} skill(s).")
        print("Every variable a connector reads must appear in manifest.json's")
        print("server.mcp_config.env, or the install surface prompts for the wrong set.")
        return 1

    if not results:
        print("check_env_schema FAILED: no skills found. Refusing to report a pass")
        print("on an empty set - this means the repo root resolved wrong.")
        return 1

    print(f"PASS: env schema matches source for {len(results)} skill(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
