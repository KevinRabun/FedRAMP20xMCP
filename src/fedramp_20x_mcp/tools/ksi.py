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
        # Get all KSI analyzers from factory
        factory = get_factory()
        analyzers = factory._analyzers
        
        if not analyzers:
            return "No Key Security Indicators found."
        
        # Sort by KSI ID
        sorted_analyzers = sorted(analyzers.items(), key=lambda x: x[0])
        
        # Group by family
        families = {}
        for ksi_id, analyzer in sorted_analyzers:
            family = analyzer.FAMILY
            if family not in families:
                families[family] = []
            families[family].append((ksi_id, analyzer))
        
        # Format the results
        result = f"# Key Security Indicators\n\n"
        result += f"**Total:** {len(analyzers)} KSIs\n\n"
        
        # Count by status
        implemented = sum(1 for a in analyzers.values() if a.IMPLEMENTATION_STATUS == "IMPLEMENTED")
        not_implemented = sum(1 for a in analyzers.values() if a.IMPLEMENTATION_STATUS == "NOT_IMPLEMENTED")
        retired = sum(1 for a in analyzers.values() if a.RETIRED)
        code_detectable = sum(1 for a in analyzers.values() if a.CODE_DETECTABLE and not a.RETIRED)
        
        result += f"**Status Summary:**\n"
        result += f"- ✅ Implemented: {implemented}\n"
        result += f"- ⏳ Not Implemented: {not_implemented}\n"
        result += f"- 🔄 Retired: {retired}\n"
        result += f"- 💻 Code-Detectable: {code_detectable}\n"
        result += f"- 📄 Process-Based: {len(analyzers) - code_detectable - retired}\n\n"
        
        # List by family
        for family in sorted(families.keys()):
            family_analyzers = families[family]
            family_name = family_analyzers[0][1].FAMILY_NAME
            result += f"## {family} - {family_name} ({len(family_analyzers)} KSIs)\n\n"
            
            for ksi_id, analyzer in family_analyzers:
                status_icon = "✅" if analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED" else "⏳"
                if analyzer.RETIRED:
                    status_icon = "🔄"
                
                code_icon = "💻" if analyzer.CODE_DETECTABLE else "📄"
                
                result += f"- {status_icon} {code_icon} **{ksi_id}**: {analyzer.KSI_NAME}"
                
                if analyzer.RETIRED:
                    result += " (RETIRED)"
                elif not analyzer.CODE_DETECTABLE:
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
        # Get all KSI analyzers from factory
        factory = get_factory()
        analyzers = factory._analyzers
        
        if not analyzers:
            return "No Key Security Indicators found."
        
        # Calculate statistics
        total_ksis = len(analyzers)
        active_ksis = sum(1 for a in analyzers.values() if not a.RETIRED)
        implemented = sum(1 for a in analyzers.values() if a.IMPLEMENTATION_STATUS == "IMPLEMENTED" and not a.RETIRED)
        code_detectable = sum(1 for a in analyzers.values() if a.CODE_DETECTABLE and not a.RETIRED)
        process_based = active_ksis - code_detectable
        retired = total_ksis - active_ksis
        
        # Calculate coverage
        if code_detectable > 0:
            coverage_pct = (implemented / code_detectable) * 100
        else:
            coverage_pct = 0
        
        # Group by family
        families = {}
        for ksi_id, analyzer in analyzers.items():
            family = analyzer.FAMILY
            if family not in families:
                families[family] = {
                    "name": analyzer.FAMILY_NAME,
                    "total": 0,
                    "implemented": 0,
                    "code_detectable": 0,
                    "retired": 0
                }
            
            families[family]["total"] += 1
            if analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED" and not analyzer.RETIRED:
                families[family]["implemented"] += 1
            if analyzer.CODE_DETECTABLE and not analyzer.RETIRED:
                families[family]["code_detectable"] += 1
            if analyzer.RETIRED:
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
        return f"Error retrieving KSI: {str(e)}"