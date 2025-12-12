"""
FedRAMP 20x MCP Server - FRR Tools

This module contains tool implementation functions for FedRAMP Requirements (FRR) analysis.
Provides code analysis capabilities for vulnerability detection, secure configuration, 
cryptographic modules, and other FedRAMP 20x requirement families.
"""
import json
import logging
from typing import Any, Optional
from ..analyzers.frr.factory import get_factory

logger = logging.getLogger(__name__)


async def analyze_frr_code_impl(
    frr_id: str,
    code: str,
    language: str,
    file_path: Optional[str] = None,
    data_loader: Any = None
) -> str:
    """
    Analyze code against a specific FedRAMP requirement.
    
    Detects compliance issues in application code, infrastructure as code,
    or CI/CD pipelines for the specified FRR.
    
    Args:
        frr_id: The FRR identifier (e.g., "FRR-VDR-01", "FRR-RSC-01")
        code: The code to analyze
        language: Programming language or platform 
                 (python, csharp, java, typescript, bicep, terraform, 
                  github-actions, azure-pipelines, gitlab-ci)
        file_path: Optional file path for context
        data_loader: Data loader instance
        
    Returns:
        Analysis results with findings and recommendations
    """
    try:
        # Get the analyzer from factory
        factory = get_factory()
        analyzer = factory.get_analyzer(frr_id)
        
        if not analyzer:
            # List available FRRs
            available = factory.list_frrs()
            return f"FRR '{frr_id}' not found. Available FRRs: {', '.join(available[:10])}... (use list_frrs_by_family to see all)"
        
        # Analyze the code
        result = analyzer.analyze(code, language, file_path or "")
        
        # Format the output
        output = f"# FRR Analysis: {frr_id} - {analyzer.FRR_NAME}\n\n"
        output += f"**File:** {file_path or 'N/A'}\n"
        output += f"**Language:** {language}\n"
        output += f"**Family:** {analyzer.FAMILY} ({analyzer.FAMILY_NAME})\n\n"
        
        # Related KSIs
        if analyzer.RELATED_KSIS:
            output += f"**Related KSIs:** {', '.join(analyzer.RELATED_KSIS)}\n\n"
        
        # Findings
        if result.findings:
            output += f"## Findings ({len(result.findings)} issues detected)\n\n"
            
            for i, finding in enumerate(result.findings, 1):
                output += f"### {i}. {finding.title}\n"
                output += f"- **Severity:** {finding.severity.value.upper()}\n"
                output += f"- **Line:** {finding.line_number}\n\n"
                output += f"{finding.description}\n\n"
                
                if finding.code_snippet:
                    output += f"**Code:**\n```{language}\n{finding.code_snippet}\n```\n\n"
                
                if finding.recommendation:
                    output += f"**Remediation:**\n{finding.recommendation}\n\n"
                
                output += "---\n\n"
        else:
            output += "## ✅ No Issues Found\n\n"
            output += f"Code complies with {frr_id} requirements.\n\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error analyzing code for {frr_id}: {e}", exc_info=True)
        return f"Error analyzing code for {frr_id}: {str(e)}"


async def analyze_all_frrs_impl(
    code: str,
    language: str,
    file_path: Optional[str] = None,
    data_loader: Any = None
) -> str:
    """
    Analyze code against all FedRAMP requirements.
    
    Performs comprehensive analysis across all 199 FRR requirements.
    
    Args:
        code: The code to analyze
        language: Programming language or platform
        file_path: Optional file path for context
        data_loader: Data loader instance
        
    Returns:
        Complete analysis results across all FRRs
    """
    try:
        factory = get_factory()
        result = factory.analyze_all_frrs(code, language, file_path or "")
        
        # Format the output
        output = f"# Comprehensive FRR Analysis\n\n"
        output += f"**File:** {file_path or 'N/A'}\n"
        output += f"**Language:** {language}\n"
        output += f"**Total FRRs:** {len(factory.list_frrs())}\n\n"
        
        # Group findings by family
        family_findings = {}
        for finding in result.findings:
            frr_id = finding.requirement_id or finding.ksi_id
            # Extract family from FRR ID (FRR-VDR-01 -> VDR)
            if frr_id and '-' in frr_id:
                parts = frr_id.split('-')
                if len(parts) >= 2:
                    family = parts[1]
                    if family not in family_findings:
                        family_findings[family] = []
                    family_findings[family].append(finding)
        
        # Summary
        if result.findings:
            output += f"## Summary\n\n"
            output += f"**Total Issues:** {len(result.findings)}\n\n"
            
            # By family
            output += "**By Family:**\n"
            for family in sorted(family_findings.keys()):
                findings = family_findings[family]
                output += f"- **{family}:** {len(findings)} issues\n"
            output += "\n"
            
            # By severity
            severity_counts = {}
            for finding in result.findings:
                sev = finding.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            output += "**By Severity:**\n"
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in severity_counts:
                    output += f"- **{severity.upper()}:** {severity_counts[severity]}\n"
            output += "\n"
            
            # Detailed findings by family
            output += "## Detailed Findings\n\n"
            for family in sorted(family_findings.keys()):
                findings = family_findings[family]
                output += f"### {family} Family ({len(findings)} issues)\n\n"
                
                for i, finding in enumerate(findings, 1):
                    output += f"#### {i}. {finding.title}\n"
                    output += f"- **FRR:** {finding.requirement_id}\n"
                    output += f"- **Severity:** {finding.severity.value.upper()}\n"
                    output += f"- **Line:** {finding.line_number}\n\n"
                    output += f"{finding.description}\n\n"
                    
                    if finding.recommendation:
                        output += f"**Remediation:** {finding.recommendation}\n\n"
                output += "\n"
        else:
            output += "## ✅ No Issues Found\n\n"
            output += "Code complies with all analyzed FedRAMP requirements.\n\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error analyzing code for all FRRs: {e}", exc_info=True)
        return f"Error analyzing code: {str(e)}"


async def analyze_frr_family_impl(
    family: str,
    code: str,
    language: str,
    file_path: Optional[str] = None,
    data_loader: Any = None
) -> str:
    """
    Analyze code against all requirements in a specific FRR family.
    
    Args:
        family: Family code (VDR, RSC, UCM, SCN, ADS, CCM, MAS, ICP, FSI, PVA, KSI)
        code: The code to analyze
        language: Programming language or platform
        file_path: Optional file path for context
        data_loader: Data loader instance
        
    Returns:
        Analysis results for the specified family
    """
    try:
        factory = get_factory()
        results = factory.analyze_by_family(family.upper(), code, language, file_path or "")
        
        # Get family FRRs for context
        family_frrs = factory.list_frrs_by_family(family.upper())
        
        # Combine all findings from results list
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        # Format the output
        output = f"# {family.upper()} Family Analysis\n\n"
        output += f"**File:** {file_path or 'N/A'}\n"
        output += f"**Language:** {language}\n"
        output += f"**FRRs in Family:** {len(family_frrs)}\n\n"
        
        if all_findings:
            output += f"## Findings ({len(result.findings)} issues detected)\n\n"
            
            for i, finding in enumerate(result.findings, 1):
                output += f"### {i}. {finding.title}\n"
                output += f"- **FRR:** {finding.requirement_id}\n"
                output += f"- **Severity:** {finding.severity.value.upper()}\n"
                output += f"- **Line:** {finding.line_number}\n\n"
                output += f"{finding.description}\n\n"
                
                if finding.code_snippet:
                    output += f"**Code:**\n```{language}\n{finding.code_snippet}\n```\n\n"
                
                if finding.recommendation:
                    output += f"**Remediation:**\n{finding.recommendation}\n\n"
                
                output += "---\n\n"
        else:
            output += "## ✅ No Issues Found\n\n"
            output += f"Code complies with {family.upper()} family requirements.\n\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error analyzing code for {family} family: {e}", exc_info=True)
        return f"Error analyzing code for {family} family: {str(e)}"


async def list_frrs_by_family_impl(family: str, data_loader: Any = None) -> str:
    """
    List all FRR requirements in a specific family.
    
    Args:
        family: Family code (VDR, RSC, UCM, SCN, ADS, CCM, MAS, ICP, FSI, PVA, KSI)
        data_loader: Data loader instance
        
    Returns:
        List of FRRs in the specified family
    """
    try:
        factory = get_factory()
        frr_ids = factory.list_frrs_by_family(family.upper())
        
        if not frr_ids:
            available_families = set()
            for frr_id in factory.list_frrs():
                if '-' in frr_id:
                    parts = frr_id.split('-')
                    if len(parts) >= 2:
                        available_families.add(parts[1])
            
            return f"No FRRs found for family '{family}'. Available families: {', '.join(sorted(available_families))}"
        
        # Get analyzer details for each FRR
        output = f"# {family.upper()} Family Requirements\n\n"
        output += f"**Total:** {len(frr_ids)} requirements\n\n"
        
        for frr_id in frr_ids:
            analyzer = factory.get_analyzer(frr_id)
            if analyzer:
                impl_icon = "✅" if analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED" else "⏳"
                code_icon = "💻" if analyzer.CODE_DETECTABLE else "📄"
                
                output += f"- {impl_icon} {code_icon} **{frr_id}**: {analyzer.FRR_NAME}\n"
        
        output += "\n*Legend:*\n"
        output += "- ✅ = Implemented analyzer\n"
        output += "- ⏳ = Not yet implemented\n"
        output += "- 💻 = Code-detectable\n"
        output += "- 📄 = Process-based\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error listing FRRs for family {family}: {e}", exc_info=True)
        return f"Error listing FRRs for family {family}: {str(e)}"


async def get_frr_metadata_impl(frr_id: str, data_loader: Any = None) -> str:
    """
    Get detailed metadata for a specific FRR.
    
    Args:
        frr_id: The FRR identifier (e.g., "FRR-VDR-01")
        data_loader: Data loader instance
        
    Returns:
        Detailed FRR metadata including NIST controls, related KSIs, and detection strategy
    """
    try:
        factory = get_factory()
        metadata = factory.get_frr_metadata(frr_id)
        
        if not metadata:
            return f"FRR '{frr_id}' not found. Use list_frrs_by_family to see available FRRs."
        
        # Format the output
        output = f"# {metadata['frr_id']}: {metadata['frr_name']}\n\n"
        
        output += f"**Family:** {metadata['family']} ({metadata.get('family_name', 'N/A')})\n"
        output += f"**Statement:** {metadata['frr_statement']}\n\n"
        
        # Impact levels
        impacts = []
        if metadata.get('impact_low'):
            impacts.append('Low')
        if metadata.get('impact_moderate'):
            impacts.append('Moderate')
        if impacts:
            output += f"**Impact Levels:** {', '.join(impacts)}\n\n"
        
        # NIST Controls
        if metadata.get('nist_controls'):
            output += "**NIST Controls:**\n"
            for control in metadata['nist_controls']:
                if isinstance(control, tuple):
                    output += f"- **{control[0]}**: {control[1]}\n"
                else:
                    output += f"- {control}\n"
            output += "\n"
        
        # Related KSIs
        if metadata.get('related_ksis'):
            output += f"**Related KSIs:** {', '.join(metadata['related_ksis'])}\n\n"
        
        # Implementation status
        output += f"**Code Detectable:** {'Yes' if metadata.get('code_detectable') else 'No'}\n"
        output += f"**Implementation Status:** {metadata.get('implementation_status', 'N/A')}\n\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting metadata for {frr_id}: {e}", exc_info=True)
        return f"Error getting metadata for {frr_id}: {str(e)}"


async def get_frr_evidence_automation_impl(frr_id: str, data_loader: Any = None) -> str:
    """
    Get evidence automation recommendations for a specific FRR.
    
    Provides detailed guidance on automating evidence collection including:
    - Azure services needed
    - Collection methods and queries (KQL, REST API)
    - Storage requirements
    - Evidence artifacts to collect
    
    Args:
        frr_id: The FRR identifier (e.g., "FRR-VDR-01")
        data_loader: Data loader instance
        
    Returns:
        Evidence automation recommendations in structured format
    """
    try:
        factory = get_factory()
        analyzer = factory.get_analyzer(frr_id)
        
        if not analyzer:
            return f"FRR '{frr_id}' not found. Use list_frrs_by_family to see available FRRs."
        
        # Get recommendations
        recommendations = analyzer.get_evidence_automation_recommendations()
        queries = analyzer.get_evidence_collection_queries()
        artifacts = analyzer.get_evidence_artifacts()
        
        # Format the output
        output = f"# Evidence Automation: {frr_id} - {analyzer.FRR_NAME}\n\n"
        
        # Handle both structured dict and simple dict formats
        if isinstance(recommendations, dict):
            output += f"**Evidence Type:** {recommendations.get('evidence_type', 'N/A')}\n"
            automation_feasibility = recommendations.get('automation_feasibility', 'N/A')
            if automation_feasibility != 'N/A':
                output += f"**Automation Feasibility:** {automation_feasibility.upper()}\n\n"
            else:
                output += f"**Automation Feasibility:** N/A\n\n"
        else:
            output += "**Evidence Type:** N/A\n"
            output += "**Automation Feasibility:** N/A\n\n"
        
        # Azure Services
        if isinstance(recommendations, dict) and recommendations.get('azure_services'):
            output += "## Azure Services\n\n"
            output += "*Note: Microsoft Defender for Cloud is recommended (not mandatory) for FedRAMP 20x compliance. Alternative tools like Qualys, Tenable, or Azure Policy can also be used.*\n\n"
            for svc in recommendations['azure_services']:
                output += f"- {svc}\n"
            output += "\n"
        
        # Collection Methods
        if isinstance(recommendations, dict) and recommendations.get('collection_methods'):
            output += "## Collection Methods\n\n"
            for method in recommendations['collection_methods']:
                output += f"- {method}\n"
            output += "\n"
        
        # Implementation Steps
        if isinstance(recommendations, dict) and recommendations.get('implementation_steps'):
            output += "## Implementation Steps\n\n"
            for i, step in enumerate(recommendations['implementation_steps'], 1):
                output += f"{i}. {step}\n"
            output += "\n"
        
        # Handle legacy simple dict format (for backwards compatibility)
        if isinstance(recommendations, dict) and not recommendations.get('azure_services'):
            output += "## Automation Recommendations\n\n"
            for key, value in recommendations.items():
                if key not in ['frr_id', 'frr_name', 'evidence_type', 'automation_feasibility', 'update_frequency', 'responsible_party']:
                    output += f"**{key.replace('_', ' ').title()}:** {value}\n"
            output += "\n"
        
        # Evidence Collection Queries - handle both list of dicts and dict of lists
        if queries:
            output += "## Evidence Collection Queries\n\n"
            if isinstance(queries, list):
                # New format: list of dicts
                for query in queries:
                    if isinstance(query, dict):
                        output += f"### {query.get('query_name', 'Query')}\n"
                        output += f"**Type:** {query.get('query_type', 'N/A')}\n\n"
                        output += f"**Purpose:** {query.get('purpose', 'N/A')}\n\n"
                        output += f"```\n{query.get('query', '')}\n```\n\n"
            elif isinstance(queries, dict):
                # Legacy format: dict of lists
                for query_type, query_list in queries.items():
                    output += f"### {query_type.replace('_', ' ').title()}\n"
                    if isinstance(query_list, list):
                        for query_str in query_list:
                            output += f"```\n{query_str}\n```\n\n"
        
        # Evidence Artifacts - handle both list of dicts and simple list
        if artifacts:
            output += "## Evidence Artifacts\n\n"
            if isinstance(artifacts, list) and len(artifacts) > 0:
                if isinstance(artifacts[0], dict):
                    # New format: list of dicts
                    for artifact in artifacts:
                        output += f"### {artifact.get('artifact_name', 'Artifact')}\n"
                        output += f"- **Type:** {artifact.get('artifact_type', 'N/A')}\n"
                        output += f"- **Description:** {artifact.get('description', 'N/A')}\n"
                        output += f"- **Collection:** {artifact.get('collection_method', 'N/A')}\n"
                        output += f"- **Storage:** {artifact.get('storage_location', 'N/A')}\n\n"
                else:
                    # Legacy format: simple list of strings
                    for artifact in artifacts:
                        output += f"- {artifact}\n"
                    output += "\n"
        
        # Update Frequency
        if isinstance(recommendations, dict):
            if recommendations.get('update_frequency'):
                output += f"**Update Frequency:** {recommendations['update_frequency']}\n"
            if recommendations.get('responsible_party'):
                output += f"**Responsible Party:** {recommendations['responsible_party']}\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting evidence automation for {frr_id}: {e}", exc_info=True)
        return f"Error getting evidence automation for {frr_id}: {str(e)}"


async def get_frr_implementation_status_impl(data_loader: Any = None) -> str:
    """
    Get implementation status summary across all FRR analyzers.
    
    Returns:
        Status summary by family with implementation statistics
    """
    try:
        factory = get_factory()
        status = await factory.get_implementation_status_summary()
        
        # Format the output
        output = "# FRR Implementation Status\n\n"
        
        output += f"## Overall Statistics\n\n"
        output += f"- **Total FRRs:** {status['total_frrs']}\n"
        output += f"- **Implemented:** {status['implemented']}\n"
        output += f"- **Partial:** {status['partial']}\n"
        output += f"- **Not Implemented:** {status['not_implemented']}\n"
        output += f"- **Code-Detectable:** {status['code_detectable']}\n"
        output += f"- **Implementation Rate:** {status['implementation_rate']:.1f}%\n\n"
        
        # Group by family for detailed breakdown
        families = {}
        factory = get_factory()
        for frr_id, analyzer in factory._analyzers.items():
            family = analyzer.FAMILY
            if family not in families:
                families[family] = {"total": 0, "implemented": 0, "code_detectable": 0}
            families[family]["total"] += 1
            if analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED":
                families[family]["implemented"] += 1
            if analyzer.CODE_DETECTABLE:
                families[family]["code_detectable"] += 1
        
        output += "## By Family\n\n"
        
        for family, stats in sorted(families.items()):
            impl_rate = (stats['implemented'] / stats['total'] * 100) if stats['total'] > 0 else 0
            status_icon = "✅" if impl_rate == 100 else "⏳"
            
            output += f"### {status_icon} {family} ({stats['total']} requirements)\n"
            output += f"- Implemented: {stats['implemented']}/{stats['total']} ({impl_rate:.0f}%)\n"
            output += f"- Code-Detectable: {stats['code_detectable']}\n\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting implementation status: {e}", exc_info=True)
        return f"Error getting implementation status: {str(e)}"
