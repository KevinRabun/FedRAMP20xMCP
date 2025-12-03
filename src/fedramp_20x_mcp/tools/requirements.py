"""
FedRAMP 20x MCP Server - Requirements Tools

This module contains tool implementation functions for requirements.
"""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

async def get_control_impl(control_id: str, data_loader) -> str:
    """
    Get detailed information about a specific FedRAMP 20x requirement.

    Args:
        control_id: The requirement identifier (e.g., "FRD-ALL-01", "VDR-ALL-02")

    Returns:
        Detailed information about the requirement including definition,
        notes, references, and related information
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the requirement
        req = data_loader.get_control(control_id)
        
        if not req:
            return f"Requirement {control_id} not found in FedRAMP 20x data."
        
        # Format the requirement information
        result = f"# Requirement: {req.get('id', control_id)}\n\n"
        
        # Add term if present
        if "term" in req:
            result += f"## Term: {req['term']}\n\n"
        
        # Add definition
        if "definition" in req:
            result += f"**Definition:**\n{req['definition']}\n\n"
        
        # Add alternatives
        if "alts" in req and req["alts"]:
            result += f"**Also known as:** {', '.join(req['alts'])}\n\n"
        
        # Add notes
        if "note" in req:
            result += f"**Note:**\n{req['note']}\n\n"
        elif "notes" in req and isinstance(req["notes"], list):
            result += "**Notes:**\n"
            for note in req["notes"]:
                result += f"- {note}\n"
            result += "\n"
        
        # Add references
        if "reference" in req:
            ref_url = req.get("reference_url", "")
            if ref_url:
                result += f"**Reference:** [{req['reference']}]({ref_url})\n\n"
            else:
                result += f"**Reference:** {req['reference']}\n\n"
        
        # Add document context
        result += f"**Document:** {req.get('document_name', 'Unknown')}\n"
        result += f"**Section:** {req.get('section', 'Unknown')}\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error fetching requirement {control_id}: {e}")
        return f"Error retrieving requirement {control_id}: {str(e)}"



async def list_family_controls_impl(family: str, data_loader) -> str:
    """
    List all requirements within a specific document family.

    Args:
        family: The document family identifier (e.g., "FRD", "VDR", "CCM")

    Returns:
        List of all requirements in the specified family with brief descriptions
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get family requirements
        reqs = data_loader.get_family_controls(family)
        
        if not reqs:
            return f"No requirements found for family {family}. Common families include: FRD (FedRAMP Definitions), VDR (Vulnerability Detection and Response), CCM (Collaborative Continuous Monitoring), etc."
        
        # Format the results
        result = f"# Requirements in Family: {family.upper()}\n\n"
        result += f"Found {len(reqs)} requirements:\n\n"
        
        for req in reqs:
            req_id = req.get("id", "Unknown")
            term = req.get("term", req.get("title", "No term"))
            result += f"- **{req_id}**: {term}\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing family {family}: {e}")
        return f"Error retrieving family {family}: {str(e)}"



async def search_requirements_impl(keywords: str, data_loader) -> str:
    """
    Search for FedRAMP 20x requirements containing specific keywords.

    Args:
        keywords: Keywords to search for in requirement text (space-separated)

    Returns:
        Matching requirements with IDs and relevant excerpts
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Search for requirements
        reqs = data_loader.search_controls(keywords)
        
        if not reqs:
            return f"No requirements found matching keywords: '{keywords}'"
        
        # Format the results
        result = f"# Search Results for: '{keywords}'\n\n"
        result += f"Found {len(reqs)} matching requirements:\n\n"
        
        # Limit to first 20 results to avoid overwhelming output
        for req in reqs[:20]:
            req_id = req.get("id", "Unknown")
            term = req.get("term", "")
            definition = req.get("definition", "")
            
            result += f"## {req_id}"
            if term:
                result += f": {term}"
            result += "\n"
            
            # Show a snippet of the definition
            if definition:
                snippet = definition[:200] + "..." if len(definition) > 200 else definition
                result += f"{snippet}\n\n"
            else:
                result += "Match found in requirement data.\n\n"
        
        if len(reqs) > 20:
            result += f"\n*Showing first 20 of {len(reqs)} results. Refine your search for more specific results.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error searching for '{keywords}': {e}")
        return f"Error searching for '{keywords}': {str(e)}"