#!/usr/bin/env python3
"""
FedRAMP 20x pattern scan from any CI/CD system, without an MCP client.

This is a thin wrapper over the `fedramp-20x-scan` command (module
fedramp_20x_mcp.ci), kept so existing pipeline references to this script keep
working. Prefer calling `fedramp-20x-scan` directly.

Usage:
    python ci_cd_integration.py <file_or_directory> [--format json|markdown] [--fail-on high]

Exit codes:
    0  no issue at or above --fail-on
    1  issues at or above --fail-on
    2  analysis error

Output: findings.json, report.md and run.json in --output-dir (default
./fedramp-scan). run.json records the FedRAMP Consolidated Rules version and
sha256 used, so the output is storable as evidence (see
.azuredevops/templates/evidence-upload-steps.yml and
examples/azure_evidence_store.py).
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from fedramp_20x_mcp.ci import main as scan_main  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown",
                        help="what to print to stdout after the scan")
    parser.add_argument("--output-dir", default="fedramp-scan")
    parser.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "none"])
    args, passthrough = parser.parse_known_args()

    rc = scan_main([args.path, "--output-dir", args.output_dir, "--fail-on", args.fail_on, *passthrough])
    if rc in (0, 1):
        out = Path(args.output_dir) / ("findings.json" if args.format == "json" else "report.md")
        print(out.read_text(encoding="utf-8"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
