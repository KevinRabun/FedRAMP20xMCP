"""
Refresh the bundled FedRAMP Consolidated Rules snapshot.

Downloads the current fedramp-consolidated-rules.json from FedRAMP/rules,
reports the version change and which rule/KSI/definition IDs were added or
removed, and (with --write) replaces src/fedramp_20x_mcp/rules_data/ copy.

After --write, rebuild the crosswalk (scripts/build_rules_crosswalk.py), list
stale references (scripts/migrate_rule_ids.py) and run
tests/test_rules_alignment.py. Removed IDs need a crosswalk OVERRIDES entry
or the crosswalk build fails, by design.

Usage:
    python scripts/update_rules_snapshot.py [--write] [--url URL]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = REPO_ROOT / "src" / "fedramp_20x_mcp" / "rules_data" / "fedramp-consolidated-rules.json"
DEFAULT_URL = "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json"


def ids(doc: dict) -> dict[str, set[str]]:
    frr = {i for f in doc.get("FRR", {}).values() for s in f.get("data", {}).values()
           for g in s.values() if isinstance(g, dict) for i in g}
    ksi = {i for c in doc.get("KSI", {}).values() for i in c.get("indicators", {})}
    frd = {i for s in doc.get("FRD", {}).get("data", {}).values() for i in s}
    return {"FRR": frr, "KSI": ksi, "FRD": frd}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--write", action="store_true", help="replace the bundled snapshot")
    args = ap.parse_args()

    with urllib.request.urlopen(args.url, timeout=60) as resp:  # noqa: S310 (https URL)
        raw = resp.read()
    new = json.loads(raw.decode("utf-8"))
    old_raw = SNAPSHOT.read_bytes()
    old = json.loads(old_raw.decode("utf-8"))

    ov, nv = old["info"].get("version"), new["info"].get("version")
    print(f"bundled {ov} sha256 {hashlib.sha256(old_raw).hexdigest()[:16]}")
    print(f"remote  {nv} sha256 {hashlib.sha256(raw).hexdigest()[:16]}")
    if raw == old_raw:
        print("identical; nothing to do")
        return 0

    o, n = ids(old), ids(new)
    for section in ("FRR", "KSI", "FRD"):
        added, removed = sorted(n[section] - o[section]), sorted(o[section] - n[section])
        print(f"{section}: {len(o[section])} -> {len(n[section])}"
              f"{'  added ' + ', '.join(added) if added else ''}"
              f"{'  removed ' + ', '.join(removed) if removed else ''}")

    if args.write:
        SNAPSHOT.write_bytes(raw)
        print(f"wrote {SNAPSHOT.relative_to(REPO_ROOT)}; now run scripts/build_rules_crosswalk.py")
    else:
        print("dry run; pass --write to replace the snapshot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
