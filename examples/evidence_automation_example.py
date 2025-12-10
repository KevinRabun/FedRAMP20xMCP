"""
Evidence Automation Example for FedRAMP 20x KSIs

This example demonstrates how to use the new evidence automation features
to get recommendations, queries, and artifact lists for automated evidence
collection for specific KSI requirements.
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from src.fedramp_20x_mcp.tools.ksi import (
    get_ksi_evidence_automation_impl,
    get_ksi_evidence_queries_impl,
    get_ksi_evidence_artifacts_impl
)


async def example_iam_01_evidence_automation():
    """
    Example: Get evidence automation for KSI-IAM-01 (Phishing-Resistant MFA)
    
    This demonstrates how to automate evidence collection for MFA compliance.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Evidence Automation for KSI-IAM-01 (Phishing-Resistant MFA)")
    print("="*80)
    
    # Initialize data loader
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    
    # Get evidence automation recommendations
    print("\n1. EVIDENCE AUTOMATION RECOMMENDATIONS")
    print("-" * 80)
    recommendations = await get_ksi_evidence_automation_impl("KSI-IAM-01", data_loader)
    print(recommendations)
    
    # Get evidence collection queries
    print("\n2. EVIDENCE COLLECTION QUERIES")
    print("-" * 80)
    queries = await get_ksi_evidence_queries_impl("KSI-IAM-01", data_loader)
    print(queries)
    
    # Get evidence artifacts list
    print("\n3. EVIDENCE ARTIFACTS TO COLLECT")
    print("-" * 80)
    artifacts = await get_ksi_evidence_artifacts_impl("KSI-IAM-01", data_loader)
    print(artifacts)


async def example_cna_01_evidence_automation():
    """
    Example: Get evidence automation for KSI-CNA-01 (Restrict Network Traffic)
    
    This demonstrates how to automate evidence collection for network security.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Evidence Automation for KSI-CNA-01 (Restrict Network Traffic)")
    print("="*80)
    
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    
    # Get evidence automation recommendations
    print("\n1. EVIDENCE AUTOMATION RECOMMENDATIONS")
    print("-" * 80)
    recommendations = await get_ksi_evidence_automation_impl("KSI-CNA-01", data_loader)
    print(recommendations)
    
    # Get evidence collection queries (Azure Resource Graph queries for NSG rules)
    print("\n2. EVIDENCE COLLECTION QUERIES (NSG Rules, Firewall Policies)")
    print("-" * 80)
    queries = await get_ksi_evidence_queries_impl("KSI-CNA-01", data_loader)
    print(queries)


async def example_direct_analyzer_access():
    """
    Example: Access evidence automation directly from KSI analyzers
    
    This demonstrates the programmatic API for evidence automation.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Direct Analyzer Access for Evidence Automation")
    print("="*80)
    
    # Get factory and analyzer
    factory = get_factory()
    analyzer = factory.get_analyzer("KSI-IAM-01")
    
    if not analyzer:
        print("ERROR: Analyzer not found")
        return
    
    # Get recommendations programmatically
    print("\n1. Get Evidence Automation Recommendations (Programmatic)")
    print("-" * 80)
    recommendations = analyzer.get_evidence_automation_recommendations()
    
    print(f"KSI ID: {recommendations['ksi_id']}")
    print(f"KSI Name: {recommendations['ksi_name']}")
    print(f"Evidence Type: {recommendations['evidence_type']}")
    print(f"Automation Feasibility: {recommendations['automation_feasibility']}")
    print(f"Implementation Effort: {recommendations['implementation_effort']}")
    
    print(f"\nAzure Services Required: {len(recommendations['azure_services'])}")
    for svc in recommendations['azure_services']:
        print(f"  - {svc['service']}: {svc['purpose']}")
    
    print(f"\nCollection Methods: {len(recommendations['collection_methods'])}")
    for method in recommendations['collection_methods']:
        print(f"  - {method['method']} ({method['frequency']})")
    
    # Get queries programmatically
    print("\n2. Get Evidence Collection Queries (Programmatic)")
    print("-" * 80)
    queries = analyzer.get_evidence_collection_queries()
    
    print(f"Total Queries: {len(queries)}")
    for query in queries:
        print(f"\n  Query: {query['name']}")
        print(f"  Type: {query['query_type']}")
        print(f"  Data Source: {query['data_source']}")
        print(f"  Schedule: {query['schedule']}")
    
    # Get artifacts programmatically
    print("\n3. Get Evidence Artifacts (Programmatic)")
    print("-" * 80)
    artifacts = analyzer.get_evidence_artifacts()
    
    print(f"Total Artifacts: {len(artifacts)}")
    for artifact in artifacts:
        print(f"\n  Artifact: {artifact['artifact_name']}")
        print(f"  Type: {artifact['artifact_type']}")
        print(f"  Format: {artifact['format']}")
        print(f"  Frequency: {artifact['frequency']}")


async def example_list_all_automation():
    """
    Example: List all KSIs with evidence automation implemented
    
    This demonstrates how to discover which KSIs have automation support.
    """
    print("\n" + "="*80)
    print("EXAMPLE: List All KSIs with Evidence Automation")
    print("="*80)
    
    factory = get_factory()
    
    # Find KSIs with evidence automation
    automated_ksis = []
    manual_ksis = []
    
    for ksi_id, analyzer in sorted(factory._analyzers.items()):
        if analyzer.RETIRED:
            continue
        
        recommendations = analyzer.get_evidence_automation_recommendations()
        
        if recommendations['automation_feasibility'] != 'manual-only':
            automated_ksis.append({
                'ksi_id': ksi_id,
                'name': analyzer.KSI_NAME,
                'feasibility': recommendations['automation_feasibility'],
                'effort': recommendations['implementation_effort']
            })
        else:
            manual_ksis.append({
                'ksi_id': ksi_id,
                'name': analyzer.KSI_NAME
            })
    
    print(f"\nKSIs with Evidence Automation: {len(automated_ksis)}")
    print("-" * 80)
    for ksi in automated_ksis[:10]:  # Show first 10
        print(f"{ksi['ksi_id']}: {ksi['name']}")
        print(f"  Feasibility: {ksi['feasibility'].upper()}, Effort: {ksi['effort'].upper()}")
    
    if len(automated_ksis) > 10:
        print(f"\n... and {len(automated_ksis) - 10} more")
    
    print(f"\nKSIs Requiring Manual Evidence Collection: {len(manual_ksis)}")
    print("-" * 80)
    for ksi in manual_ksis[:5]:  # Show first 5
        print(f"{ksi['ksi_id']}: {ksi['name']}")
    
    if len(manual_ksis) > 5:
        print(f"\n... and {len(manual_ksis) - 5} more")


async def main():
    """Run all examples."""
    print("\n" + "="*80)
    print("FEDRAMP 20x KSI EVIDENCE AUTOMATION EXAMPLES")
    print("="*80)
    print("\nThis demonstrates the new evidence automation features that help")
    print("organizations automate evidence collection for FedRAMP compliance.")
    
    # Run examples
    await example_iam_01_evidence_automation()
    await example_cna_01_evidence_automation()
    await example_direct_analyzer_access()
    await example_list_all_automation()
    
    print("\n" + "="*80)
    print("EXAMPLES COMPLETE")
    print("="*80)
    print("\nNext Steps:")
    print("1. Use get_ksi_evidence_automation to get recommendations for your KSIs")
    print("2. Use get_ksi_evidence_queries to get ready-to-use Azure queries")
    print("3. Use get_ksi_evidence_artifacts to understand what to collect")
    print("4. Use get_infrastructure_code_for_ksi to get Bicep/Terraform templates")
    print("5. Use get_evidence_collection_code to get Python/C#/PowerShell code")


if __name__ == "__main__":
    asyncio.run(main())
