"""
FedRAMP 20x MCP Server - Definitions Tools

This module contains tool implementation functions for definitions.
"""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

async def get_definition_impl(term: str, data_loader) -> str:
    """
    Get the FedRAMP definition for a specific term.

    Args:
        term: The term to look up (e.g., "vulnerability", "agency", "cloud service offering")

    Returns:
        Definition with notes and references if available
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the definition
        definition = data_loader.get_definition(term)
        
        if not definition:
            return f"No FedRAMP definition found for term: '{term}'. Try searching with search_definitions() to find related terms."
        
        # Format the definition
        result = f"# FedRAMP Definition: {definition.get('term', term)}\n\n"
        
        # Add ID
        if "id" in definition:
            result += f"**ID:** {definition['id']}\n\n"
        
        # Add definition
        if "definition" in definition:
            result += f"**Definition:**\n{definition['definition']}\n\n"
        
        # Add alternatives
        if "alts" in definition and definition["alts"]:
            result += f"**Also known as:** {', '.join(definition['alts'])}\n\n"
        
        # Add notes
        if "note" in definition:
            result += f"**Note:**\n{definition['note']}\n\n"
        elif "notes" in definition and isinstance(definition["notes"], list):
            result += "**Notes:**\n"
            for note in definition["notes"]:
                result += f"- {note}\n"
            result += "\n"
        
        # Add references
        if "reference" in definition:
            ref_url = definition.get("reference_url", "")
            if ref_url:
                result += f"**Reference:** [{definition['reference']}]({ref_url})\n\n"
            else:
                result += f"**Reference:** {definition['reference']}\n\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error fetching definition for '{term}': {e}")
        return f"Error retrieving definition for '{term}': {str(e)}"



async def list_definitions_impl(data_loader) -> str:
    """
    List all FedRAMP definitions with their terms.

    Returns:
        Complete list of FedRAMP definition terms
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get all definitions
        definitions = data_loader.list_all_definitions()
        
        if not definitions:
            return "No FedRAMP definitions found."
        
        # Sort by ID
        sorted_defs = sorted(definitions, key=lambda x: x.get("id", ""))
        
        # Format the results
        result = f"# FedRAMP Definitions\n\n"
        result += f"Total: {len(definitions)} definitions\n\n"
        
        for definition in sorted_defs:
            def_id = definition.get("id", "Unknown")
            term = definition.get("term", "No term")
            result += f"- **{def_id}**: {term}\n"
        
        result += "\n*Use get_definition(term) to see full details for any term.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing definitions: {e}")
        return f"Error retrieving definitions: {str(e)}"



async def search_definitions_impl(keywords: str, data_loader) -> str:
    """
    Search FedRAMP definitions by keywords.

    Args:
        keywords: Keywords to search for in definitions

    Returns:
        Matching definitions with terms and brief descriptions
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Search definitions
        definitions = data_loader.search_definitions(keywords)
        
        if not definitions:
            return f"No definitions found matching keywords: '{keywords}'"
        
        # Format the results
        result = f"# Definition Search Results for: '{keywords}'\n\n"
        result += f"Found {len(definitions)} matching definitions:\n\n"
        
        for definition in definitions[:20]:
            def_id = definition.get("id", "Unknown")
            term = definition.get("term", "No term")
            def_text = definition.get("definition", "")
            
            result += f"## {def_id}: {term}\n"
            
            # Show a snippet
            if def_text:
                snippet = def_text[:150] + "..." if len(def_text) > 150 else def_text
                result += f"{snippet}\n\n"
        
        if len(definitions) > 20:
            result += f"\n*Showing first 20 of {len(definitions)} results.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error searching definitions for '{keywords}': {e}")
        return f"Error searching definitions for '{keywords}': {str(e)}"