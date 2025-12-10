"""
Evidence Automation Implementation Helper

This script helps implement evidence automation for KSIs systematically by:
1. Showing the next KSI to implement
2. Displaying the KSI details
3. Generating a template for implementation
4. Validating the implementation
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from src.fedramp_20x_mcp.data_loader import FedRAMPDataLoader
import asyncio


# Priority order for implementation (Phase 1 - high automation potential)
PRIORITY_ORDER = [
    "KSI-MLA-01",  # Centralized Logging
    "KSI-MLA-02",  # Log Retention
    "KSI-IAM-02",  # Privileged Access Management
    "KSI-CNA-03",  # Infrastructure as Code
    "KSI-SVC-04",  # Configuration Automation
    "KSI-SVC-06",  # Patch Management
    "KSI-CED-01",  # Credential Storage
    "KSI-AFR-04",  # Vulnerability Detection
    "KSI-AFR-06",  # Authorization Data Sharing
    "KSI-INR-01",  # Incident Detection
]


def get_next_ksi():
    """Get the next KSI that needs evidence automation."""
    factory = get_factory()
    
    # Check priority list first
    for ksi_id in PRIORITY_ORDER:
        analyzer = factory.get_analyzer(ksi_id)
        if analyzer and not analyzer.RETIRED:
            rec = analyzer.get_evidence_automation_recommendations()
            if rec['automation_feasibility'] == 'manual-only':
                return ksi_id, analyzer
    
    # Fall back to any unimplemented KSI
    for ksi_id, analyzer in sorted(factory._analyzers.items()):
        if analyzer.RETIRED:
            continue
        rec = analyzer.get_evidence_automation_recommendations()
        if rec['automation_feasibility'] == 'manual-only':
            return ksi_id, analyzer
    
    return None, None


def show_implementation_status():
    """Show current implementation status."""
    factory = get_factory()
    
    implemented = []
    not_implemented = []
    
    for ksi_id, analyzer in sorted(factory._analyzers.items()):
        if analyzer.RETIRED:
            continue
        rec = analyzer.get_evidence_automation_recommendations()
        if rec['automation_feasibility'] != 'manual-only':
            implemented.append(ksi_id)
        else:
            not_implemented.append(ksi_id)
    
    print("\n" + "="*80)
    print("EVIDENCE AUTOMATION IMPLEMENTATION STATUS")
    print("="*80)
    print(f"\n✅ Implemented: {len(implemented)}/65 ({len(implemented)/65*100:.1f}%)")
    for ksi in implemented:
        print(f"   {ksi}")
    
    print(f"\n⏳ Remaining: {len(not_implemented)}/65 ({len(not_implemented)/65*100:.1f}%)")
    
    # Show next 5 in priority order
    next_ksis = [k for k in PRIORITY_ORDER if k in not_implemented][:5]
    if next_ksis:
        print("\n📋 Next Priority KSIs:")
        for i, ksi in enumerate(next_ksis, 1):
            print(f"   {i}. {ksi}")


def show_ksi_details(ksi_id, analyzer):
    """Show details about a KSI to help with implementation."""
    print("\n" + "="*80)
    print(f"KSI DETAILS: {ksi_id}")
    print("="*80)
    print(f"\n📌 Name: {analyzer.KSI_NAME}")
    print(f"📌 Statement: {analyzer.KSI_STATEMENT}")
    print(f"📌 Family: {analyzer.FAMILY} - {analyzer.FAMILY_NAME}")
    print(f"📌 Code Detectable: {analyzer.CODE_DETECTABLE}")
    print(f"📌 Implementation Status: {analyzer.IMPLEMENTATION_STATUS}")
    
    print("\n📌 NIST Controls:")
    for ctrl_id, ctrl_name in analyzer.NIST_CONTROLS[:5]:
        print(f"   - {ctrl_id}: {ctrl_name}")
    if len(analyzer.NIST_CONTROLS) > 5:
        print(f"   ... and {len(analyzer.NIST_CONTROLS) - 5} more")


def generate_implementation_template(ksi_id, analyzer):
    """Generate a template for implementing evidence automation."""
    print("\n" + "="*80)
    print(f"IMPLEMENTATION TEMPLATE FOR {ksi_id}")
    print("="*80)
    
    # Suggest evidence type based on KSI characteristics
    if "log" in analyzer.KSI_STATEMENT.lower() or "monitor" in analyzer.KSI_STATEMENT.lower():
        evidence_type = "log-based"
        automation = "high"
    elif "configuration" in analyzer.KSI_STATEMENT.lower() or "infrastructure" in analyzer.KSI_STATEMENT.lower():
        evidence_type = "config-based"
        automation = "high"
    elif "metric" in analyzer.KSI_STATEMENT.lower() or "performance" in analyzer.KSI_STATEMENT.lower():
        evidence_type = "metric-based"
        automation = "high"
    else:
        evidence_type = "process-based"
        automation = "medium"
    
    print(f"\n💡 Suggested Evidence Type: {evidence_type}")
    print(f"💡 Suggested Automation Feasibility: {automation}")
    
    print("\n" + "-"*80)
    print("COPY THIS TEMPLATE TO THE ANALYZER FILE:")
    print("-"*80)
    
    template = f'''
    # ============================================================================
    # EVIDENCE AUTOMATION METHODS
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get evidence automation recommendations for {ksi_id}.
        
        Returns structured guidance for automating evidence collection demonstrating
        {analyzer.KSI_NAME}.
        """
        return {{
            "ksi_id": self.KSI_ID,
            "ksi_name": self.KSI_NAME,
            "evidence_type": "{evidence_type}",
            "automation_feasibility": "{automation}",
            "azure_services": [
                {{
                    "service": "Azure Service Name",
                    "purpose": "What this service does for evidence collection",
                    "configuration": "How to configure it",
                    "cost": "Cost estimate"
                }},
                # Add more services
            ],
            "collection_methods": [
                {{
                    "method": "Collection Method Name",
                    "description": "What evidence this collects",
                    "frequency": "daily",
                    "data_points": [
                        "Data point 1",
                        "Data point 2",
                        "Data point 3"
                    ]
                }},
                # Add more methods
            ],
            "storage_requirements": {{
                "retention_period": "3 years minimum (FedRAMP Moderate)",
                "format": "json",
                "immutability": "Required",
                "encryption": "AES-256 at rest, TLS 1.2+ in transit",
                "estimated_size": "Size estimate"
            }},
            "api_integration": {{
                "frr_ads_endpoints": [
                    f"/evidence/{{self.KSI_ID.lower()}}/endpoint1",
                    f"/evidence/{{self.KSI_ID.lower()}}/endpoint2"
                ],
                "authentication": "Azure AD OAuth 2.0 with client credentials",
                "response_format": "JSON with FIPS 140-2 validated signatures",
                "rate_limits": "Per Azure service limits"
            }},
            "code_examples": {{
                "python": "Uses Azure SDK for Python - describe implementation",
                "csharp": "Uses Azure SDK for .NET - describe implementation",
                "powershell": "Uses Az PowerShell module - describe implementation"
            }},
            "infrastructure_templates": {{
                "bicep": "Deploys [services] for automated evidence collection",
                "terraform": "Deploys [services] for automated evidence collection"
            }},
            "retention_policy": "3 years minimum per FedRAMP Moderate requirements",
            "implementation_effort": "medium",
            "implementation_time": "2-4 weeks",
            "prerequisites": [
                "Prerequisite 1",
                "Prerequisite 2",
                "Prerequisite 3"
            ],
            "notes": "Evidence automation for {ksi_id} - add Azure WAF references and implementation notes."
        }}
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get Azure queries for collecting {ksi_id} evidence.
        """
        return [
            {{
                "name": "Query Name",
                "query_type": "kusto",  # or "resource_graph", "rest_api"
                "query": """Query text here""",
                "data_source": "Azure Service Name",
                "schedule": "daily",
                "output_format": "json",
                "description": "What this query retrieves"
            }},
            # Add more queries
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts for {ksi_id}.
        """
        return [
            {{
                "artifact_name": "artifact-name.json",
                "artifact_type": "log",  # or "config", "report", "policy"
                "description": "What this artifact demonstrates",
                "collection_method": "How to collect it",
                "format": "json",
                "frequency": "daily",
                "retention": "3 years"
            }},
            # Add more artifacts
        ]
'''
    
    print(template)
    
    print("\n" + "-"*80)
    print("IMPLEMENTATION STEPS:")
    print("-"*80)
    print(f"1. Open: src/fedramp_20x_mcp/analyzers/ksi/{ksi_id.lower().replace('-', '_')}.py")
    print("2. Add the three methods above to the file (before the end of class)")
    print("3. Customize the Azure services, queries, and artifacts")
    print("4. Test: python -c \"from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory; factory = get_factory(); analyzer = factory.get_analyzer('{ksi_id}'); print(analyzer.get_evidence_automation_recommendations())\"")
    print("5. Run tests: python tests/test_ksi_evidence_automation.py")
    print("6. Update tracker: docs/evidence-automation-implementation-tracker.md")


async def main():
    """Main workflow."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Evidence Automation Implementation Helper')
    parser.add_argument('--status', action='store_true', help='Show implementation status')
    parser.add_argument('--next', action='store_true', help='Show next KSI to implement')
    parser.add_argument('--ksi', type=str, help='Show template for specific KSI')
    
    args = parser.parse_args()
    
    if args.status or (not args.next and not args.ksi):
        show_implementation_status()
    
    if args.next:
        ksi_id, analyzer = get_next_ksi()
        if ksi_id:
            show_ksi_details(ksi_id, analyzer)
            generate_implementation_template(ksi_id, analyzer)
        else:
            print("\n✅ All KSIs have evidence automation implemented!")
    
    if args.ksi:
        factory = get_factory()
        analyzer = factory.get_analyzer(args.ksi)
        if analyzer:
            show_ksi_details(args.ksi, analyzer)
            generate_implementation_template(args.ksi, analyzer)
        else:
            print(f"\n❌ KSI '{args.ksi}' not found")


if __name__ == "__main__":
    asyncio.run(main())
