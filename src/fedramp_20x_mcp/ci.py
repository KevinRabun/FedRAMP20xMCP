"""
FedRAMP 20x pattern scan for CI/CD pipelines.

Runs the same pattern engine the MCP tools use, over a directory tree, without
an MCP client. Writes three files to --output-dir:

  findings.json  machine-readable findings plus summary and provenance
  report.md      human-readable report for build summaries and reviewers
  run.json       provenance only: tool version, rules version and sha256,
                 patterns, inputs, CI context, timestamps

Every run records which FedRAMP Consolidated Rules release (version and
sha256) it evaluated against, so stored evidence can be traced to the exact
rules text it used.

Usage:
    fedramp-20x-scan PATH [--output-dir DIR] [--fail-on high]
                     [--families IAM,SVC] [--profile web-app] [--exclude GLOB ...]

Exit codes: 0 no finding at or above --fail-on, 1 threshold reached, 2 error.
"""

from __future__ import annotations

import argparse
import asyncio
import fnmatch
import hashlib
import json
import logging
import os
import platform
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__ as TOOL_VERSION
from .analyzers.application_context import ApplicationContext
from .analyzers.base import Finding, Severity
from .analyzers.generic_analyzer import GenericPatternAnalyzer, PatternLoader
from .data_loader import get_data_loader

logger = logging.getLogger("fedramp_20x_mcp.ci")

LANGUAGE_BY_SUFFIX: Dict[str, str] = {
    ".py": "python",
    ".cs": "csharp",
    ".java": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".jsx": "typescript",
    ".bicep": "bicep",
    ".tf": "terraform",
    ".ps1": "powershell",
    ".psm1": "powershell",
}

DEFAULT_EXCLUDES = [
    ".git/*", "*/.git/*", ".claude/*", "*/.claude/*", ".worktrees/*", "node_modules/*", "*/node_modules/*", ".venv/*", "*/.venv/*",
    "venv/*", "*/venv/*", "*/__pycache__/*", "*/bin/*", "*/obj/*", "*/dist/*",
    "*/build/*", ".terraform/*", "*/.terraform/*",
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _is_catch_all(pattern) -> bool:
    """True when every language of a pattern matches any text (regex '.*', no AST/other queries)."""
    langs = getattr(pattern, "languages", None) or {}
    if not langs:
        return False
    for spec in langs.values():
        if not isinstance(spec, dict):
            return False
        detectors = {k: v for k, v in spec.items() if v}
        if set(detectors) - {"regex_fallback"}:
            return False
        if str(detectors.get("regex_fallback", "")).strip() not in (".*", "^.*$", ".+"):
            return False
    return True


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def find_files(root: Path, excludes: List[str]) -> List[Path]:
    if root.is_file():
        return [root] if root.suffix.lower() in LANGUAGE_BY_SUFFIX else []
    files = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in LANGUAGE_BY_SUFFIX:
            continue
        rel = _rel(p, root)
        if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(f"./{rel}", g) for g in excludes):
            continue
        files.append(p)
    return files


def _ci_context() -> Dict[str, str]:
    """Collect build provenance from Azure DevOps or GitHub Actions env vars."""
    env = os.environ
    if env.get("TF_BUILD"):
        return {
            "system": "azure-devops",
            "buildId": env.get("BUILD_BUILDID", ""),
            "buildNumber": env.get("BUILD_BUILDNUMBER", ""),
            "pipeline": env.get("BUILD_DEFINITIONNAME", ""),
            "repository": env.get("BUILD_REPOSITORY_NAME", ""),
            "sourceBranch": env.get("BUILD_SOURCEBRANCH", ""),
            "sourceVersion": env.get("BUILD_SOURCEVERSION", ""),
            "requestedFor": env.get("BUILD_REQUESTEDFOR", ""),
            "collectionUri": env.get("SYSTEM_COLLECTIONURI", ""),
            "project": env.get("SYSTEM_TEAMPROJECT", ""),
        }
    if env.get("GITHUB_ACTIONS"):
        return {
            "system": "github-actions",
            "buildId": env.get("GITHUB_RUN_ID", ""),
            "buildNumber": env.get("GITHUB_RUN_NUMBER", ""),
            "pipeline": env.get("GITHUB_WORKFLOW", ""),
            "repository": env.get("GITHUB_REPOSITORY", ""),
            "sourceBranch": env.get("GITHUB_REF", ""),
            "sourceVersion": env.get("GITHUB_SHA", ""),
            "requestedFor": env.get("GITHUB_ACTOR", ""),
        }
    return {"system": "local"}


def _finding_dict(f: Finding, root: Path, rules: Dict) -> Dict:
    d = f.to_dict()
    try:
        d["file_path"] = _rel(Path(f.file_path), root) if f.file_path else d.get("file_path")
    except Exception:
        pass
    rid = f.requirement_id or f.ksi_id
    rule = rules.get(rid) if rid else None
    d["requirement_valid"] = rule is not None
    if rule is not None:
        d["requirement_name"] = rule.get("name", "")
    return d


def _cell(value) -> str:
    """Single-line, pipe-safe markdown table cell."""
    return " ".join(str(value if value is not None else "").split()).replace("|", "\\|")


def render_markdown(doc: Dict) -> str:
    s = doc["summary"]
    rules = doc["provenance"]["rules"]
    lines = [
        "# FedRAMP 20x Pattern Scan",
        "",
        f"- Rules: {rules.get('title', 'FedRAMP Consolidated Rules')} version {rules.get('version', '?')} "
        f"(last updated {rules.get('last_updated', '?')}, sha256 `{rules.get('sha256', '')[:16]}`)",
        f"- Files analyzed: {s['files_analyzed']} of {s['files_found']} found",
        f"- Issues: {s['issues']} (critical {s['by_severity'].get('critical', 0)}, high {s['by_severity'].get('high', 0)}, "
        f"medium {s['by_severity'].get('medium', 0)}, low {s['by_severity'].get('low', 0)})",
        f"- Good practices detected: {s['good_practices']}",
        f"- Gate: fail on `{doc['gate']['fail_on']}` or higher, result **{doc['gate']['result']}**",
        "",
        "Pattern findings are signals for review, not a determination of compliance. "
        "Each requirement ID links a finding to the CR26 rule or KSI it informs.",
        "",
    ]
    issues = [f for f in doc["findings"] if not f.get("good_practice")]
    if issues:
        lines += ["## Findings", "", "| Severity | Requirement | File | Line | Title |", "|---|---|---|---|---|"]
        for f in sorted(issues, key=lambda x: (-SEVERITY_RANK.get(x["severity"], 0), x.get("file_path") or "")):
            req = f.get("requirement_id") or "unmapped"
            if f.get("requirement_name"):
                req = f"{req} ({f['requirement_name']})"
            elif not f.get("requirement_valid"):
                req = f"{req} (not a CR26 ID)"
            lines.append(f"| {_cell(f['severity'])} | {_cell(req)} | `{_cell(f.get('file_path'))}` | "
                         f"{_cell(f.get('line_number'))} | {_cell(f.get('title'))} |")
        lines.append("")
    by_req = doc["summary"]["by_requirement"]
    if by_req:
        lines += ["## By requirement", "", "| Requirement | Issues |", "|---|---|"]
        lines += [f"| {_cell(k)} | {v} |" for k, v in sorted(by_req.items())]
        lines.append("")
    reminders = doc["summary"].get("review_reminders") or {}
    if reminders:
        lines += ["## Rules to review outside code", "",
                  "These rules apply to the scanned resources but code alone cannot show whether they are met. "
                  "They are not counted as issues.", ""]
        lines += [f"- {_cell(rid)}" for rid in reminders]
        lines.append("")
    if doc["summary"]["errors"]:
        lines += ["## Files that could not be analyzed", ""]
        lines += [f"- `{e['file']}`: {e['error']}" for e in doc["summary"]["errors"]]
        lines.append("")
    return "\n".join(lines)


async def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: {root} does not exist", file=sys.stderr)
        return 2

    loader = get_data_loader()
    data = await loader.load_data()
    rules_meta = loader.get_rules_metadata()
    requirements = data.get("requirements", {})

    patterns_dir = args.patterns_dir or os.environ.get("FEDRAMP_PATTERNS_DIR")
    pattern_loader = PatternLoader(patterns_dir)
    pattern_loader.load_patterns()
    analyzer = GenericPatternAnalyzer(pattern_loader)
    pattern_count = len(pattern_loader.get_all_patterns())
    if pattern_count == 0:
        print(f"error: no patterns loaded from {pattern_loader.patterns_dir}", file=sys.stderr)
        return 2

    families = [f.strip().upper() for f in args.families.split(",")] if args.families else None
    context = ApplicationContext.from_string(args.profile) if args.profile else None
    excludes = DEFAULT_EXCLUDES + (args.exclude or [])

    started = datetime.now(timezone.utc)
    files = find_files(root, excludes)
    findings: List[Dict] = []
    errors: List[Dict] = []
    # Catch-all "compliance" patterns (regex ".*") flag every file for a rule
    # that code cannot show either way. They are review reminders, not
    # detections: listed once per rule, kept out of issues and the gate
    # unless --include-review-reminders is set.
    reminder_ids = {pid for pid, p in pattern_loader._patterns.items() if _is_catch_all(p)}
    reminders: Dict[str, set] = {}
    analyzed = 0
    for path in files:
        rel = _rel(path, root)
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            errors.append({"file": rel, "error": str(e)})
            continue
        try:
            result = analyzer.analyze(
                code=code,
                language=LANGUAGE_BY_SUFFIX[path.suffix.lower()],
                file_path=str(path),
                families=families,
                application_context=context,
            )
        except Exception as e:
            errors.append({"file": rel, "error": f"{type(e).__name__}: {e}"})
            continue
        analyzed += 1
        for f in result.findings:
            d = _finding_dict(f, root, requirements)
            if f.pattern_id in reminder_ids:
                reminders.setdefault(d.get("requirement_id") or f.pattern_id, set()).add(d.get("file_path"))
                if not args.include_review_reminders:
                    continue
                d["review_reminder"] = True
            findings.append(d)
    finished = datetime.now(timezone.utc)

    issues = [f for f in findings if not f.get("good_practice")]
    by_sev = Counter(f["severity"] for f in issues)
    by_req = Counter((f.get("requirement_id") or "unmapped") for f in issues)
    threshold = SEVERITY_RANK[args.fail_on] if args.fail_on != "none" else None
    tripped = threshold is not None and any(SEVERITY_RANK.get(f["severity"], 0) >= threshold for f in issues)

    provenance = {
        "tool": {"name": "fedramp-20x-mcp", "version": TOOL_VERSION, "command": "fedramp-20x-scan"},
        "rules": {k: rules_meta.get(k, "") for k in ("title", "version", "last_updated", "sha256", "source")},
        "patterns": {"directory": str(pattern_loader.patterns_dir), "count": pattern_count},
        "input": {"path": str(root), "families": families, "profile": args.profile, "excludes": excludes},
        "ci": _ci_context(),
        "host": {"python": platform.python_version(), "platform": platform.platform()},
        "startedAt": started.isoformat().replace("+00:00", "Z"),
        "collectedAt": finished.isoformat().replace("+00:00", "Z"),
    }
    doc = {
        "schema": "fedramp-20x-scan/v1",
        "provenance": provenance,
        "gate": {"fail_on": args.fail_on, "result": "fail" if tripped else "pass"},
        "summary": {
            "files_found": len(files),
            "review_reminders": {rid: len(fs) for rid, fs in sorted(reminders.items())},
            "files_analyzed": analyzed,
            "issues": len(issues),
            "good_practices": len(findings) - len(issues),
            "by_severity": dict(by_sev),
            "by_requirement": dict(by_req),
            "invalid_requirement_ids": sorted({f.get("requirement_id") for f in findings
                                               if f.get("requirement_id") and not f.get("requirement_valid")}),
            "errors": errors,
        },
        "findings": findings,
    }

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(doc), encoding="utf-8")
    run = dict(provenance)
    run["outputs"] = {
        name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in ("findings.json", "report.md")
    }
    (out / "run.json").write_text(json.dumps(run, indent=2), encoding="utf-8")

    print(f"Rules {rules_meta.get('version')} ({rules_meta.get('source')})")
    print(f"Analyzed {analyzed}/{len(files)} files with {pattern_count} patterns: "
          f"{len(issues)} issues {dict(by_sev)}; gate {doc['gate']['result']}")
    print(f"Wrote {out / 'findings.json'}, {out / 'report.md'}, {out / 'run.json'}")
    if os.environ.get("TF_BUILD"):
        print(f"##vso[task.uploadsummary]{(out / 'report.md').resolve()}")
        for sev in ("critical", "high", "medium", "low"):
            print(f"##vso[task.setvariable variable=fedramp_{sev}_count;isOutput=true]{by_sev.get(sev, 0)}")
    if errors:
        print(f"warning: {len(errors)} files could not be analyzed (see findings.json)", file=sys.stderr)
    return 1 if tripped else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fedramp-20x-scan", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", help="file or directory to scan")
    p.add_argument("--output-dir", default="fedramp-scan", help="where to write findings.json, report.md, run.json")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high",
                   help="exit 1 if any issue is at or above this severity (default high)")
    p.add_argument("--families", help="comma-separated pattern families to include (default all)")
    p.add_argument("--profile", help="application profile to reduce false positives (e.g. web-app, cli-tool)")
    p.add_argument("--exclude", action="append", help="extra glob (relative path) to skip; repeatable")
    p.add_argument("--include-review-reminders", action="store_true",
                   help="count catch-all compliance reminder patterns as issues (default: list them separately)")
    p.add_argument("--patterns-dir", help="pattern YAML directory (default: repo data/patterns or FEDRAMP_PATTERNS_DIR)")
    p.add_argument("--verbose", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, stream=sys.stderr)
    try:
        return asyncio.run(run_scan(args))
    except Exception as e:  # report and exit 2 rather than a traceback in CI logs
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
