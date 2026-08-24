#!/usr/bin/env python3
"""Generate docker/setup/catalog.json for the setup UI.

Merges every connector's manifest.json (the machine-readable credential schema
the binaries actually honour, fixed fleet-wide on this branch) with
docker/setup/hints.json (hand-authored field guidance learned by configuring
real tenants). The UI renders entirely from this file.
"""

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HINTS = REPO / "docker" / "setup" / "hints.json"
OUT = REPO / "docker" / "setup" / "catalog.json"


def main():
    hints = json.loads(HINTS.read_text())
    skills = json.loads((REPO / "tools" / "maintainer" / "skills.json").read_text())["skills"]
    catalog = {"global": hints.get("global", {}), "connectors": []}

    for slug in sorted(skills):
        mpath = REPO / "skills" / slug / "manifest.json"
        if not mpath.is_file() or not (REPO / "skills" / slug / "cli").is_dir():
            continue
        man = json.loads(mpath.read_text())
        env = (man.get("server") or {}).get("mcp_config", {}).get("env") or {}
        uc = man.get("user_config") or {}
        chints = (hints.get("connectors") or {}).get(slug, {})
        fields = []
        for name, ref in sorted(env.items()):
            key = str(ref).strip("${}").replace("user_config.", "")
            e = uc.get(key, {})
            h = chints.get(name, {})
            desc = re.sub(r"\s+", " ", (e.get("description") or "")).strip()
            required = e.get("required")
            # the manifest's own prose wins over a missing flag, same rule the
            # env-file generator uses
            if required is not True and re.match(r"^optional[.,: ]", desc, re.I):
                required = False
            fields.append({
                "name": name,
                "label": h.get("label") or name,
                "derive": h.get("derive"),
                "required": bool(required) if required is not None else None,
                "sensitive": bool(e.get("sensitive", "SECRET" in name or "TOKEN" in name or "KEY" in name or "PASSWORD" in name)),
                "help": h.get("help") or desc,
                "example": h.get("example", ""),
                "pattern": h.get("pattern", ""),
            })
        entry = skills[slug]
        catalog["connectors"].append({
            "slug": slug,
            "display_name": entry.get("display_name", slug),
            "vendor": entry.get("vendor", ""),
            "category": entry.get("category", ""),
            "tagline": entry.get("tagline", ""),
            "fields": fields,
            "hinted": slug in (hints.get("connectors") or {}),
        })

    OUT.write_text(json.dumps(catalog, indent=1) + "\n")
    hinted = sum(1 for c in catalog["connectors"] if c["hinted"])
    print(f"wrote {OUT.relative_to(REPO)}: {len(catalog['connectors'])} connectors, {hinted} with hand-authored hints")
    return 0


if __name__ == "__main__":
    sys.exit(main())
