"""
FedRAMP 20x MCP Server - Ksi Tools

This module contains tool implementation functions for ksi.
"""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

async def get_ksi_impl(ksi_id: str, data_loader) -> str:
    """
    Get detailed information about a specific Key Security Indicator.

    Args:
        ksi_id: The KSI identifier (e.g., "KSI-ALL-01")

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
    List all Key Security Indicators.

    Returns:
        Complete list of all Key Security Indicators
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get all KSI
        ksi_list = data_loader.list_all_ksi()
        
        if not ksi_list:
            return "No Key Security Indicators found in the data."
        
        # Sort by ID
        sorted_ksi = sorted(ksi_list, key=lambda x: x.get("id", ""))
        
        # Format the results
        result = f"# Key Security Indicators\n\n"
        result += f"Total: {len(ksi_list)} indicators\n\n"
        
        for ksi in sorted_ksi:
            ksi_id = ksi.get("id", "Unknown")
            title = ksi.get("title", ksi.get("name", "No title"))
            result += f"- **{ksi_id}**: {title}\n"
        
        result += "\n*Use get_ksi(ksi_id) to see full details for any indicator.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing KSI: {e}")
        return f"Error retrieving KSI: {str(e)}"