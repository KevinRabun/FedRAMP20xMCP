"""
Evidence Automation Example for FedRAMP 20x KSIs

This example demonstrates how to use the new evidence automation features
to get recommendations, queries, and artifact lists for automated evidence
collection for specific KSI requirements.
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import azure_evidence_store  # noqa: E402  (sibling example module)
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader  # noqa: E402
from fedramp_20x_mcp.tools.ksi import (  # noqa: E402
    get_ksi_evidence_automation_impl,
    get_ksi_evidence_queries_impl,
    get_ksi_evidence_artifacts_impl
)


async def example_iam_01_evidence_automation():
    """
    Example: Get evidence automation for KSI-IAM-APM (Phishing-Resistant MFA)
    
    This demonstrates how to automate evidence collection for MFA compliance.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Evidence Automation for KSI-IAM-APM (Phishing-Resistant MFA)")
    print("="*80)
    
    # Initialize data loader
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    
    # Get evidence automation recommendations
    print("\n1. EVIDENCE AUTOMATION RECOMMENDATIONS")
    print("-" * 80)
    recommendations = await get_ksi_evidence_automation_impl("KSI-IAM-APM", data_loader)
    print(recommendations)
    
    # Get evidence collection queries
    print("\n2. EVIDENCE COLLECTION QUERIES")
    print("-" * 80)
    queries = await get_ksi_evidence_queries_impl("KSI-IAM-APM", data_loader)
    print(queries)
    
    # Get evidence artifacts list
    print("\n3. EVIDENCE ARTIFACTS TO COLLECT")
    print("-" * 80)
    artifacts = await get_ksi_evidence_artifacts_impl("KSI-IAM-APM", data_loader)
    print(artifacts)


async def example_cna_01_evidence_automation():
    """
    Example: Get evidence automation for KSI-CNA-RNT (Restrict Network Traffic)
    
    This demonstrates how to automate evidence collection for network security.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Evidence Automation for KSI-CNA-RNT (Restrict Network Traffic)")
    print("="*80)
    
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    
    # Get evidence automation recommendations
    print("\n1. EVIDENCE AUTOMATION RECOMMENDATIONS")
    print("-" * 80)
    recommendations = await get_ksi_evidence_automation_impl("KSI-CNA-RNT", data_loader)
    print(recommendations)
    
    # Get evidence collection queries (Azure Resource Graph queries for NSG rules)
    print("\n2. EVIDENCE COLLECTION QUERIES (NSG Rules, Firewall Policies)")
    print("-" * 80)
    queries = await get_ksi_evidence_queries_impl("KSI-CNA-RNT", data_loader)
    print(queries)


async def example_save_guidance_as_evidence(output_dir: str, upload: bool):
    """
    Example: write the evidence-automation guidance for a few KSIs to disk,
    stamped with the rules version it came from, and optionally store it in
    the WORM evidence account (see azure_evidence_store.py).

    Guidance is not evidence of implementation by itself; storing it records
    which collection method was planned against which rules release, which is
    what an assessor asks for alongside the collected data.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Save KSI evidence-automation guidance with rules provenance")
    print("="*80)

    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    meta = data_loader.get_rules_metadata()

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for ksi_id in ("KSI-IAM-APM", "KSI-CNA-RNT", "KSI-SVC-SIN"):
        ksi = data_loader.get_ksi(ksi_id)
        if ksi is None:
            raise SystemExit(f"{ksi_id} is not a KSI in rules {meta.get('version')}")
        guidance = await get_ksi_evidence_automation_impl(ksi_id, data_loader)
        (out / f"{ksi_id}-automation.md").write_text(guidance, encoding="utf-8")
        print(f"  {ksi_id} ({ksi['name']}) -> {ksi_id}-automation.md")

    (out / "run.json").write_text(json.dumps({
        "producer": "examples/evidence_automation_example.py",
        "rules": {k: meta.get(k, "") for k in ("title", "version", "last_updated", "sha256", "source")},
    }, indent=2), encoding="utf-8")
    print(f"Rules {meta.get('version')} recorded in {out / 'run.json'}")

    if upload:
        files, prefix = azure_evidence_store.stage_manifest(out, "fedramp20x-ksi-guidance", "local-example")
        uri = azure_evidence_store.upload(out, files, prefix, azure_evidence_store.DEFAULT_ACCOUNT,
                                          azure_evidence_store.DEFAULT_CONTAINER)
        print(f"Stored and verified at {uri}")


async def main():
    """Run all examples."""
    parser = argparse.ArgumentParser(description="FedRAMP 20x KSI evidence automation examples")
    parser.add_argument("--output-dir", default="ksi-guidance")
    parser.add_argument("--upload", action="store_true",
                        help="store the saved guidance in the evidence account (Entra auth, private network)")
    args = parser.parse_args()

    print("\n" + "="*80)
    print("FEDRAMP 20x KSI EVIDENCE AUTOMATION EXAMPLES")
    print("="*80)

    await example_iam_01_evidence_automation()
    await example_cna_01_evidence_automation()
    await example_save_guidance_as_evidence(args.output_dir, args.upload)

    print("\n" + "="*80)
    print("EXAMPLES COMPLETE")
    print("="*80)


if __name__ == "__main__":
    asyncio.run(main())
