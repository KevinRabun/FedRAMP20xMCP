#!/usr/bin/env python3
"""
Store a directory of evidence in Azure Blob Storage (WORM container), Python
equivalent of .azuredevops/templates/evidence-upload-steps.yml.

Layout (same as the pipeline template and the IntelliGRC.CRM reports):
    <container>/<report>/<yyyy-MM-dd>/<runId>/<files>
      run.json             provenance (kept if the source dir already has one)
      sha256-manifest.txt  sha256 of every other file

Rules this follows, matching the evidence account baseline:
  - Entra ID only (DefaultAzureCredential): the account has shared keys
    disabled, so there is no key, SAS or connection string option.
  - Never overwrite: the container has time-based immutability and versioning
    is off, so upload_blob(overwrite=False) and a name collision is an error.
  - Verify by listing the prefix back and comparing the blob count.

Requires: pip install azure-identity azure-storage-blob
Network: the account is private-endpoint only; run from a host on that network.

Usage:
    python azure_evidence_store.py SOURCE_DIR --report fedramp20x-ksi-evidence \
        [--account intellievidence] [--container vdr-reports] [--run-id ID] [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ACCOUNT = os.environ.get("EVIDENCE_STORAGE_ACCOUNT", "intellievidence")
DEFAULT_CONTAINER = os.environ.get("EVIDENCE_CONTAINER", "vdr-reports")


def stage_manifest(source: Path, report: str, run_id: str) -> tuple[list[Path], str]:
    """Write run.json (if absent) and sha256-manifest.txt; return files and prefix."""
    if not source.is_dir() or not any(source.iterdir()):
        raise SystemExit(f"error: {source} is empty or missing")
    if " " in report or report.startswith("/") or ".." in report:
        raise SystemExit(f"error: invalid report name {report!r}")
    now = datetime.now(timezone.utc)
    prefix = f"{report.rstrip('/')}/{now:%Y-%m-%d}/{run_id}"

    run_json = source / "run.json"
    if not run_json.exists():
        run_json.write_text(json.dumps({
            "report": report,
            "runId": run_id,
            "host": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME", ""),
            "user": os.environ.get("USERNAME") or os.environ.get("USER", ""),
            "collectedAt": now.isoformat().replace("+00:00", "Z"),
        }, indent=2), encoding="utf-8")

    manifest = source / "sha256-manifest.txt"
    files = sorted(p for p in source.rglob("*") if p.is_file() and p != manifest)
    manifest.write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  ./{p.relative_to(source).as_posix()}\n" for p in files
    ), encoding="utf-8")
    return files + [manifest], prefix


def upload(source: Path, files: list[Path], prefix: str, account: str, container: str) -> str:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    service = BlobServiceClient(f"https://{account}.blob.core.windows.net", credential=DefaultAzureCredential())
    client = service.get_container_client(container)
    for p in files:
        name = f"{prefix}/{p.relative_to(source).as_posix()}"
        with p.open("rb") as fh:
            client.upload_blob(name, fh, overwrite=False)  # WORM: a collision must fail
    stored = sum(1 for _ in client.list_blobs(name_starts_with=f"{prefix}/"))
    if stored != len(files):
        raise SystemExit(f"error: stored {stored} blobs under {prefix}, expected {len(files)}")
    return f"https://{account}.blob.core.windows.net/{container}/{prefix}/"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("--report", required=True, help="top-level folder, e.g. fedramp20x-ksi-evidence")
    ap.add_argument("--account", default=DEFAULT_ACCOUNT)
    ap.add_argument("--container", default=DEFAULT_CONTAINER)
    ap.add_argument("--run-id", default=None, help="default: local-<utc time>-<random>")
    ap.add_argument("--dry-run", action="store_true", help="write manifest and list, no Azure calls")
    args = ap.parse_args()

    run_id = args.run_id or f"local-{datetime.now(timezone.utc):%H%M%S}-{uuid.uuid4().hex[:8]}"
    source = Path(args.source)
    files, prefix = stage_manifest(source, args.report, run_id)
    print(f"{len(files)} files -> {args.account}/{args.container}/{prefix}")
    if args.dry_run:
        for p in files:
            print(f"  {p.relative_to(source).as_posix()}")
        return 0
    print(f"Verified at {upload(source, files, prefix, args.account, args.container)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
