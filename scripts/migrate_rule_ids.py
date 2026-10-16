"""
Rewrite legacy FedRAMP rule/KSI IDs in this repository to their CR26 IDs.

Uses src/fedramp_20x_mcp/rules_data/legacy-crosswalk.json (see
scripts/build_rules_crosswalk.py). Only whole-ID tokens are replaced; IDs that
are already current, placeholders (KSI-XXX-NN) and unknown IDs are left alone
and reported so a person can decide what they should be.

Usage:
    python scripts/migrate_rule_ids.py [--apply] [PATH ...]

Without --apply it prints what would change. Defaults to src/, data/, docs/,
examples/, .azuredevops/, .github/ and the top-level markdown files. Tests are
excluded by default because several of them exercise legacy-ID resolution on
purpose.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "src" / "fedramp_20x_mcp" / "rules_data"
DEFAULT_PATHS = ["src", "data", "docs", "examples", ".azuredevops", ".github",
                 "README.md", "CONTRIBUTING.md", "TESTING.md"]
SUFFIXES = {".py", ".txt", ".yaml", ".yml", ".md", ".json", ".bicep", ".tf"}
SKIP_PARTS = {"__pycache__", "rules_data", "__fedramp_cache__", ".venv", ".git"}

ID_RE = re.compile(r"\b(?:KSI|FRR|[A-Z]{3})-[A-Z0-9]{2,3}(?:-[A-Z0-9]{2,3}){0,3}\b")


def load_current_ids() -> set[str]:
    doc = json.loads((RULES_DIR / "fedramp-consolidated-rules.json").read_text(encoding="utf-8"))
    ids = set(doc["FRD"]["data"].get("all", {}))
    for fam in doc["FRR"].values():
        for scope in fam["data"].values():
            for group in scope.values():
                ids |= set(group)
    for cat in doc["KSI"].values():
        ids |= set(cat["indicators"])
    return ids


def iter_files(paths: list[str]):
    for p in paths:
        path = (REPO_ROOT / p).resolve()
        if path.is_file():
            yield path
        elif path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix in SUFFIXES and not SKIP_PARTS & set(f.parts):
                    yield f


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="write changes")
    ap.add_argument("paths", nargs="*", default=DEFAULT_PATHS)
    args = ap.parse_args()

    current = load_current_ids()
    crosswalk = json.loads((RULES_DIR / "legacy-crosswalk.json").read_text(encoding="utf-8"))["crosswalk"]
    replaced: Counter = Counter()
    unknown: Counter = Counter()
    changed_files = 0

    for f in iter_files(args.paths):
        text = f.read_text(encoding="utf-8")

        def sub(m: re.Match) -> str:
            tok = m.group(0)
            if tok in current:
                return tok
            entry = crosswalk.get(tok)
            if entry and entry["current_ids"]:
                replaced[tok] += 1
                return entry["current_ids"][0]
            if tok.startswith(("KSI-", "FRR-")):
                unknown[tok] += 1
            return tok

        new = ID_RE.sub(sub, text)
        if new != text:
            changed_files += 1
            rel = f.relative_to(REPO_ROOT)
            print(f"{'updated' if args.apply else 'would update'}: {rel}")
            if args.apply:
                f.write_text(new, encoding="utf-8", newline="")

    print(f"\n{sum(replaced.values())} replacements of {len(replaced)} legacy IDs in {changed_files} files")
    if unknown:
        print("Unresolved IDs (not current, not in crosswalk):")
        for tok, n in sorted(unknown.items()):
            print(f"  {tok}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
