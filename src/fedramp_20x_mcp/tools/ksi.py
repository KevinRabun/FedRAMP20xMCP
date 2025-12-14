"""
FedRAMP 20x MCP Server - Ksi Tools

This module contains tool implementation functions for ksi.
"""
import json
import logging
from typing import Any
from ..analyzers.ksi.factory import get_factory

logger = logging.getLogger(__name__)

async def get_ksi_impl(ksi_id: str, data_loader) -> str:
    """
    Get detailed information about a specific Key Security Indicator.

    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-01")

    Returns:
        Detailed KSI information
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the KSI
        ksi = data_loader.get_ksi(ksi_id)
        
        if not ksi:
            return f"Key Security Indicator {ksi_id} not found. Use list_ksi() to see all available indicators."
        
        # Format the KSI information
        result = f"# Key Security Indicator: {ksi.get('id', ksi_id)}\n\n"
        
        # Add all KSI fields
        for key, value in ksi.items():
            if key not in ["id", "document", "document_name", "section"]:
                result += f"**{key.replace('_', ' ').title()}:**\n"
                if isinstance(value, (dict, list)):
                    result += f"```json\n{json.dumps(value, indent=2)}\n```\n\n"
                else:
                    result += f"{value}\n\n"
        
        # Add context
        result += f"**Document:** {ksi.get('document_name', 'Unknown')}\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error fetching KSI {ksi_id}: {e}")
        return f"Error retrieving KSI {ksi_id}: {str(e)}"



async def list_ksi_impl(data_loader) -> str:
    """
    List all Key Security Indicators with their implementation status.

    Returns:
        Complete list of all Key Security Indicators with status
    """
    try:
        # Get all KSI metadata from data loader
        ksis = data_loader.list_all_ksi()
        
        if not ksis:
            return "No Key Security Indicators found."
        
        # Sort by KSI ID
        sorted_ksis = sorted(ksis, key=lambda x: x.get('id', ''))
        
        # Group by family
        families = {}
        for ksi in sorted_ksis:
            ksi_id = ksi.get('id')
            family = ksi.get('family', 'UNKNOWN')
            if family not in families:
                families[family] = []
            families[family].append(ksi)
        
        # Format the results
        result = f"# Key Security Indicators\n\n"
        result += f"**Total:** {len(ksis)} KSIs\n\n"
        
        # Count by status
        implemented = sum(1 for k in ksis if k.get('implementation_status') == 'IMPLEMENTED')
        not_implemented = sum(1 for k in ksis if k.get('implementation_status') == 'NOT_IMPLEMENTED')
        retired = sum(1 for k in ksis if k.get('retired', False))
        code_detectable = sum(1 for k in ksis if k.get('code_detectable', False) and not k.get('retired', False))
        active = len(ksis) - retired
        
        result += f"**Status Summary:**\n"
        result += f"- ✅ Implemented: {implemented}\n"
        result += f"- ⏳ Not Implemented: {not_implemented}\n"
        result += f"- 🔄 Retired: {retired}\n"
        result += f"- 💻 Code-Detectable: {code_detectable}\n"
        result += f"- 📄 Process-Based: {active - code_detectable}\n\n"
        
        # List by family
        for family in sorted(families.keys()):
            family_ksis = families[family]
            family_name = family_ksis[0].get('family_name', family)
            result += f"## {family} - {family_name} ({len(family_ksis)} KSIs)\n\n"
            
            for ksi in family_ksis:
                ksi_id = ksi.get('id')
                ksi_name = ksi.get('name', ksi_id)
                status = ksi.get('implementation_status', 'NOT_IMPLEMENTED')
                is_retired = ksi.get('retired', False)
                is_code_detectable = ksi.get('code_detectable', False)
                
                status_icon = "✅" if status == "IMPLEMENTED" else "⏳"
                if is_retired:
                    status_icon = "🔄"
                
                code_icon = "💻" if is_code_detectable else "📄"
                
                result += f"- {status_icon} {code_icon} **{ksi_id}**: {ksi_name}"
                
                if is_retired:
                    result += " (RETIRED)"
                elif not is_code_detectable:
                    result += " (Process/Documentation)"
                    
                result += "\n"
            
            result += "\n"
        
        result += "\n*Legend:*\n"
        result += "- ✅ = Implemented\n"
        result += "- ⏳ = Not Implemented\n"
        result += "- 🔄 = Retired\n"
        result += "- 💻 = Code-Detectable\n"
        result += "- 📄 = Process-Based\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing KSI: {e}")
        return f"Error listing KSIs: {str(e)}"


async def get_ksi_implementation_summary_impl(data_loader) -> str:
    """
    Get a summary of KSI implementation status across all families.

    Returns:
        Summary statistics and breakdown by family
    """
    try:
        # Get all KSI metadata from data loader
        ksis = data_loader.list_all_ksi()
        
        if not ksis:
            return "No Key Security Indicators found."
        
        # Calculate statistics
        total_ksis = len(ksis)
        active_ksis = sum(1 for k in ksis if not k.get('retired', False))
        implemented = sum(1 for k in ksis if k.get('implementation_status') == 'IMPLEMENTED' and not k.get('retired', False))
        code_detectable = sum(1 for k in ksis if k.get('code_detectable', False) and not k.get('retired', False))
        process_based = active_ksis - code_detectable
        retired = total_ksis - active_ksis
        
        # Calculate coverage
        if code_detectable > 0:
            coverage_pct = (implemented / code_detectable) * 100
        else:
            coverage_pct = 0
        
        # Group by family
        families = {}
        for ksi in ksis:
            ksi_id = ksi.get('id')
            family = ksi.get('family', 'UNKNOWN')
            if family not in families:
                families[family] = {
                    "name": ksi.get('family_name', family),
                    "total": 0,
                    "implemented": 0,
                    "code_detectable": 0,
                    "retired": 0
                }
            
            families[family]["total"] += 1
            if ksi.get('implementation_status') == "IMPLEMENTED" and not ksi.get('retired', False):
                families[family]["implemented"] += 1
            if ksi.get('code_detectable', False) and not ksi.get('retired', False):
                families[family]["code_detectable"] += 1
            if ksi.get('retired', False):
                families[family]["retired"] += 1
        
        # Format the results
        result = "# KSI Implementation Summary\n\n"
        result += f"## Overall Status\n\n"
        result += f"- **Total KSIs:** {total_ksis}\n"
        result += f"- **Active KSIs:** {active_ksis} ({retired} retired)\n"
        result += f"- **Implemented:** {implemented}/{code_detectable} code-detectable KSIs ({coverage_pct:.1f}%)\n"
        result += f"- **Code-Detectable:** {code_detectable} KSIs\n"
        result += f"- **Process-Based:** {process_based} KSIs\n\n"
        
        result += f"## By Family\n\n"
        
        for family in sorted(families.keys()):
            stats = families[family]
            family_active = stats["total"] - stats["retired"]
            
            if stats["code_detectable"] > 0:
                family_pct = (stats["implemented"] / stats["code_detectable"]) * 100
            else:
                family_pct = 0
            
            status_icon = "✅" if stats["implemented"] == stats["code_detectable"] and stats["code_detectable"] > 0 else "⏳"
            
            result += f"### {status_icon} {family} - {stats['name']}\n"
            result += f"- Total: {stats['total']} KSIs"
            if stats["retired"] > 0:
                result += f" ({stats['retired']} retired)"
            result += "\n"
            result += f"- Implemented: {stats['implemented']}/{stats['code_detectable']} code-detectable"
            if stats["code_detectable"] > 0:
                result += f" ({family_pct:.0f}%)"
            result += "\n"
            result += f"- Process-based: {family_active - stats['code_detectable']} KSIs\n\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting implementation summary: {e}")
        return f"Error getting implementation summary: {str(e)}"


async def get_ksi_evidence_automation_impl(ksi_id: str, data_loader) -> str:
    """
    Get evidence automation recommendations for a specific KSI.
    
    Provides detailed guidance on how to automate evidence collection including:
    - Azure services needed
    - Collection methods and queries
    - Storage requirements
    - Code examples and infrastructure templates
    
    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-01")
    
    Returns:
        Evidence automation recommendations in structured format
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the analyzer from factory
        factory = get_factory()
        analyzer = factory.get_analyzer(ksi_id)
        
        if not analyzer:
            return f"KSI '{ksi_id}' not found. Use list_ksi to see all available KSIs."
        
        # Check if KSI is retired
        if analyzer.RETIRED:
            return f"KSI '{ksi_id}' is retired. Evidence automation recommendations not available."
        
        # Get recommendations
        recommendations = analyzer.get_evidence_automation_recommendations()
        
        # Format the output
        result = f"# Evidence Automation: {recommendations['ksi_id']} - {recommendations['ksi_name']}\n\n"
        
        result += f"**Evidence Type:** {recommendations['evidence_type']}\n"
        result += f"**Automation Feasibility:** {recommendations['automation_feasibility'].upper()}\n"
        result += f"**Implementation Effort:** {recommendations['implementation_effort'].upper()}\n\n"
        
        if recommendations.get('implementation_time'):
            result += f"**Estimated Time:** {recommendations['implementation_time']}\n\n"
        
        # Azure Services
        if recommendations.get('azure_services'):
            result += "## Azure Services\n\n"
            result += "*Note: Microsoft Defender for Cloud is recommended (not mandatory) for streamlining compliance. Alternative tools like Qualys, Tenable, or Trivy can be used for vulnerability scanning.*\n\n"
            for svc in recommendations['azure_services']:
                result += f"### {svc['service']}\n"
                result += f"- **Purpose:** {svc['purpose']}\n"
                result += f"- **Configuration:** {svc['configuration']}\n\n"
        
        # Collection Methods
        if recommendations.get('collection_methods'):
            result += "## Evidence Collection Methods\n\n"
            for method in recommendations['collection_methods']:
                result += f"### {method['method']}\n"
                result += f"{method['description']}\n\n"
                result += f"**Frequency:** {method['frequency']}\n\n"
                if method.get('data_points'):
                    result += "**Data Points:**\n"
                    for dp in method['data_points']:
                        result += f"- {dp}\n"
                    result += "\n"
        
        # Storage Requirements
        if recommendations.get('storage_requirements'):
            storage = recommendations['storage_requirements']
            result += "## Storage Requirements\n\n"
            for key, value in storage.items():
                result += f"- **{key.replace('_', ' ').title()}:** {value}\n"
            result += "\n"
        
        # API Integration
        if recommendations.get('api_integration') and recommendations['api_integration'].get('frr_ads_endpoints'):
            api = recommendations['api_integration']
            result += "## FRR-ADS API Integration\n\n"
            result += f"**Authentication:** {api.get('authentication', 'N/A')}\n"
            result += f"**Response Format:** {api.get('response_format', 'JSON')}\n\n"
            result += "**Endpoints:**\n"
            for endpoint in api.get('frr_ads_endpoints', []):
                result += f"- `{endpoint}`\n"
            result += "\n"
        
        # Prerequisites
        if recommendations.get('prerequisites'):
            result += "## Prerequisites\n\n"
            for prereq in recommendations['prerequisites']:
                result += f"- {prereq}\n"
            result += "\n"
        
        # Available Code Examples
        if recommendations.get('code_examples'):
            result += "## Available Code Examples\n\n"
            for lang, desc in recommendations['code_examples'].items():
                result += f"- **{lang.upper()}:** {desc}\n"
            result += "\n"
            result += "*Use `get_evidence_collection_code` tool to retrieve actual code.*\n\n"
        
        # Available Infrastructure Templates
        if recommendations.get('infrastructure_templates'):
            result += "## Available Infrastructure Templates\n\n"
            for iac, desc in recommendations['infrastructure_templates'].items():
                result += f"- **{iac.upper()}:** {desc}\n"
            result += "\n"
            result += "*Use `get_infrastructure_code_for_ksi` tool to retrieve actual templates.*\n\n"
        
        # Notes
        if recommendations.get('notes'):
            result += "## Implementation Notes\n\n"
            result += f"{recommendations['notes']}\n\n"
        
        # Retention Policy
        result += "## Retention Policy\n\n"
        result += f"{recommendations.get('retention_policy', 'Per FedRAMP requirements')}\n\n"
        
        result += "---\n"
        result += "*Generated by FedRAMP 20x MCP Server - Evidence Automation Tool*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting evidence automation for {ksi_id}: {e}")
        return f"Error retrieving evidence automation recommendations: {str(e)}"


async def get_ksi_evidence_queries_impl(ksi_id: str, data_loader) -> str:
    """
    Get evidence collection queries for a specific KSI.
    
    Returns KQL, Resource Graph, and REST API queries for collecting evidence
    from Azure services.
    
    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-01")
    
    Returns:
        Collection queries in structured format
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the analyzer from factory
        factory = get_factory()
        analyzer = factory.get_analyzer(ksi_id)
        
        if not analyzer:
            return f"KSI '{ksi_id}' not found. Use list_ksi to see all available KSIs."
        
        if analyzer.RETIRED:
            return f"KSI '{ksi_id}' is retired. Evidence queries not available."
        
        # Get queries
        queries = analyzer.get_evidence_collection_queries()
        
        if not queries:
            return f"No evidence collection queries available for {ksi_id}. This KSI may require manual evidence collection."
        
        # Format output
        result = f"# Evidence Collection Queries: {ksi_id}\n\n"
        result += f"**Total Queries:** {len(queries)}\n\n"
        
        for i, query in enumerate(queries, 1):
            result += f"## Query {i}: {query['name']}\n\n"
            result += f"**Type:** {query['query_type']}\n"
            result += f"**Data Source:** {query['data_source']}\n"
            result += f"**Schedule:** {query['schedule']}\n"
            result += f"**Output Format:** {query['output_format']}\n\n"
            
            if query.get('description'):
                result += f"**Description:** {query['description']}\n\n"
            
            result += "**Query:**\n```\n"
            result += query['query']
            result += "\n```\n\n"
        
        result += "---\n"
        result += "*Use these queries with Azure CLI, PowerShell, or Azure SDKs to automate evidence collection.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting evidence queries for {ksi_id}: {e}")
        return f"Error retrieving evidence queries: {str(e)}"


async def get_ksi_evidence_artifacts_impl(ksi_id: str, data_loader) -> str:
    """
    Get list of evidence artifacts that should be collected for a specific KSI.
    
    Returns detailed information about what files, logs, and reports to collect
    to demonstrate compliance.
    
    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-01")
    
    Returns:
        Evidence artifacts list with collection details
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the analyzer from factory
        factory = get_factory()
        analyzer = factory.get_analyzer(ksi_id)
        
        if not analyzer:
            return f"KSI '{ksi_id}' not found. Use list_ksi to see all available KSIs."
        
        if analyzer.RETIRED:
            return f"KSI '{ksi_id}' is retired. Evidence artifacts not available."
        
        # Get artifacts
        artifacts = analyzer.get_evidence_artifacts()
        
        if not artifacts:
            return f"No evidence artifacts defined for {ksi_id}. This KSI may require manual evidence collection or custom artifact definitions."
        
        # Format output
        result = f"# Evidence Artifacts: {ksi_id}\n\n"
        result += f"**Total Artifacts:** {len(artifacts)}\n\n"
        
        # Group by type
        by_type = {}
        for artifact in artifacts:
            atype = artifact['artifact_type']
            if atype not in by_type:
                by_type[atype] = []
            by_type[atype].append(artifact)
        
        for atype in sorted(by_type.keys()):
            result += f"## {atype.upper()} Artifacts\n\n"
            
            for artifact in by_type[atype]:
                result += f"### {artifact['artifact_name']}\n\n"
                result += f"**Description:** {artifact['description']}\n\n"
                result += f"**Collection Method:** {artifact['collection_method']}\n\n"
                result += f"**Details:**\n"
                result += f"- Format: {artifact['format']}\n"
                result += f"- Frequency: {artifact['frequency']}\n"
                result += f"- Retention: {artifact['retention']}\n\n"
        
        result += "---\n"
        result += "*Store all artifacts in immutable Azure Blob Storage with legal hold or time-based retention policies.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting evidence artifacts for {ksi_id}: {e}")
        return f"Error retrieving evidence artifacts: {str(e)}"
