#!/usr/bin/env python3
"""
Collect point-in-time Azure configuration evidence for selected CR26 KSIs.

Each collector is a read-only Azure Resource Graph query. For every KSI the
script writes, under --output-dir:

  <KSI-ID>/query.kql     the exact query that produced the evidence
  <KSI-ID>/result.json   the query output (rows), as returned by Azure
  <KSI-ID>/summary.json  KSI name and statement from the loaded rules, row
                         count, and the collector's pass/review signal
  run.json               rules version/sha256, subscriptions, timestamps

The KSI name and statement are read from the FedRAMP Consolidated Rules the
package loads (not hardcoded here), so a renamed or retired KSI fails the run
instead of producing mislabeled evidence.

These queries are evidence inputs, not a compliance determination: they show
configuration state an assessor or the KSI owner reviews against the KSI.

Usage (az CLI logged in with Reader on the target subscriptions):
    python collect_ksi_evidence.py --output-dir out [--subscriptions id1,id2] [--ksi KSI-SVC-SIN ...]
    python collect_ksi_evidence.py --list          # show collectors, validate KSI IDs
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from fedramp_20x_mcp.data_loader import get_data_loader

# KSI -> (description, KQL, field that marks a row as needing review).
# Rows returned are the resources in scope; "needs_review" rows are the ones
# whose configuration does not obviously meet the KSI and need a human look.
COLLECTORS: dict[str, dict] = {
    "KSI-SVC-SIN": {
        "description": "Storage accounts: encryption, TLS, public access and shared-key settings",
        "kql": """
resources
| where type =~ 'microsoft.storage/storageaccounts'
| project id, name, resourceGroup, subscriptionId, location,
    minimumTlsVersion = tostring(properties.minimumTlsVersion),
    httpsOnly = tobool(properties.supportsHttpsTrafficOnly),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    allowBlobPublicAccess = tobool(properties.allowBlobPublicAccess),
    allowSharedKeyAccess = tobool(properties.allowSharedKeyAccess),
    infrastructureEncryption = tobool(properties.encryption.requireInfrastructureEncryption),
    keySource = tostring(properties.encryption.keySource)
| extend needs_review = minimumTlsVersion != 'TLS1_2' or httpsOnly != true
    or allowBlobPublicAccess == true or allowSharedKeyAccess != false
""",
    },
    "KSI-SVC-ASM": {
        "description": "Key Vaults: RBAC authorization, purge protection, soft delete, public access",
        "kql": """
resources
| where type =~ 'microsoft.keyvault/vaults'
| project id, name, resourceGroup, subscriptionId, location,
    enableRbacAuthorization = tobool(properties.enableRbacAuthorization),
    enablePurgeProtection = tobool(properties.enablePurgeProtection),
    enableSoftDelete = tobool(properties.enableSoftDelete),
    publicNetworkAccess = tostring(properties.publicNetworkAccess)
| extend needs_review = enableRbacAuthorization != true or enablePurgeProtection != true
""",
    },
    "KSI-CNA-RNT": {
        "description": "NSG rules allowing inbound traffic from any source",
        "kql": """
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| mv-expand rule = properties.securityRules
| where tostring(rule.properties.direction) == 'Inbound' and tostring(rule.properties.access) == 'Allow'
| extend src = tostring(rule.properties.sourceAddressPrefix)
| where src in ('*', '0.0.0.0/0', 'Internet', 'Any')
| project id, name, resourceGroup, subscriptionId,
    rule = tostring(rule.name), src,
    destPorts = tostring(rule.properties.destinationPortRange),
    priority = toint(rule.properties.priority)
| extend needs_review = true
""",
    },
    "KSI-IAM-ELP": {
        "description": "Owner and User Access Administrator assignments at subscription or management group scope",
        "kql": """
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend roleDefinitionId = tolower(tostring(properties.roleDefinitionId)),
    scope = tostring(properties.scope),
    principalType = tostring(properties.principalType),
    principalId = tostring(properties.principalId)
| where roleDefinitionId endswith '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    or roleDefinitionId endswith '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
| where scope matches regex @'^/subscriptions/[^/]+$' or scope startswith '/providers/Microsoft.Management'
| project id, scope, principalId, principalType,
    role = iff(roleDefinitionId endswith '8e3af657-a8ff-443c-a75c-2fe8c4bcb635', 'Owner', 'User Access Administrator')
| extend needs_review = true
""",
    },
}


def run_query(kql: str, subscriptions: list[str]) -> list[dict]:
    az = shutil.which("az") or shutil.which("az.cmd")
    if not az:
        raise RuntimeError("az CLI not found")
    rows: list[dict] = []
    skip_token = None
    while True:
        cmd = [az, "graph", "query", "-q", kql, "--first", "1000", "-o", "json", "--only-show-errors"]
        if subscriptions:
            cmd += ["--subscriptions", *subscriptions]
        if skip_token:
            cmd += ["--skip-token", skip_token]
        out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
        page = json.loads(out)
        rows.extend(page.get("data", []))
        skip_token = page.get("skip_token")
        if not skip_token:
            return rows


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output-dir", default="ksi-evidence")
    ap.add_argument("--subscriptions", default="", help="comma-separated subscription ids (default: all visible)")
    ap.add_argument("--ksi", action="append", help="limit to these KSIs (repeatable)")
    ap.add_argument("--list", action="store_true", help="list collectors and validate KSI IDs, no Azure calls")
    args = ap.parse_args()

    loader = get_data_loader()
    await loader.load_data()
    meta = loader.get_rules_metadata()

    selected = args.ksi or list(COLLECTORS)
    unknown = [k for k in selected if k not in COLLECTORS]
    if unknown:
        print(f"error: no collector for {unknown}", file=sys.stderr)
        return 2
    missing = [k for k in selected if loader.get_ksi(k) is None or loader.get_ksi(k).get("id") != k]
    if missing:
        print(f"error: not a KSI in rules {meta.get('version')}: {missing}", file=sys.stderr)
        return 2

    if args.list:
        for k in selected:
            print(f"{k}  {loader.get_ksi(k)['name']}: {COLLECTORS[k]['description']}")
        print(f"rules {meta.get('version')} ({meta.get('source')})")
        return 0

    subs = [s.strip() for s in args.subscriptions.split(",") if s.strip()]
    out = Path(args.output_dir)
    started = datetime.now(timezone.utc)
    results = {}
    for k in selected:
        ksi = loader.get_ksi(k)
        rows = run_query(COLLECTORS[k]["kql"], subs)
        review = sum(1 for r in rows if r.get("needs_review"))
        d = out / k
        d.mkdir(parents=True, exist_ok=True)
        (d / "query.kql").write_text(COLLECTORS[k]["kql"].strip() + "\n", encoding="utf-8")
        (d / "result.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
        summary = {
            "ksi_id": k,
            "ksi_name": ksi.get("name", ""),
            "ksi_statement": ksi.get("statement", ""),
            "collector": COLLECTORS[k]["description"],
            "resources": len(rows),
            "needs_review": review,
        }
        (d / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        results[k] = {"resources": len(rows), "needs_review": review}
        print(f"{k}: {len(rows)} resources, {review} need review")

    run = {
        "collector": "examples/azure-devops/collect_ksi_evidence.py",
        "rules": {x: meta.get(x, "") for x in ("title", "version", "last_updated", "sha256", "source")},
        "subscriptions": subs or "all visible to the identity",
        "results": results,
        "startedAt": started.isoformat().replace("+00:00", "Z"),
        "collectedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    (out / "run.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
