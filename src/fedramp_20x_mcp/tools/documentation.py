"""
FedRAMP 20x MCP Server - Documentation Tools

This module contains tool implementation functions for documentation.
"""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

async def search_documentation_impl(keywords: str, data_loader) -> str:
    """
    Search FedRAMP documentation markdown files for specific keywords.
    
    This searches the official FedRAMP documentation from https://github.com/FedRAMP/docs/tree/main/docs
    including guides, overviews, and detailed documentation for each standard.
    
    Args:
        keywords: Keywords to search for in the documentation
    
    Returns:
        Matching documentation sections with context
    """
    try:
        # Ensure documentation is loaded
        await data_loader.load_documentation()
        
        # Search documentation
        results = data_loader.search_documentation(keywords)
        
        if not results:
            return f"No documentation found matching '{keywords}'.\n\nTry:\n- Different keywords\n- More general terms\n- list_documentation_files() to see all available docs"
        
        result = f"# Documentation Search Results for '{keywords}'\n\n"
        result += f"Found {len(results)} matches across FedRAMP documentation.\n\n"
        
        # Group results by file
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for match in results:
            filename = match['filename']
            if filename not in by_file:
                by_file[filename] = []
            by_file[filename].append(match)
        
        # Show results grouped by file (limit to first 10 files)
        for filename in list(by_file.keys())[:10]:
            matches = by_file[filename]
            result += f"## {filename}\n\n"
            result += f"{len(matches)} match(es) found\n\n"
            
            # Show first 3 matches from this file
            for match in matches[:3]:
                result += f"**Line {match['line_number']}:**\n"
                result += f"```\n{match['context']}\n```\n\n"
            
            if len(matches) > 3:
                result += f"*...and {len(matches) - 3} more matches in this file*\n\n"
        
        if len(by_file) > 10:
            result += f"\n*Showing first 10 of {len(by_file)} files with matches. Refine your search for more specific results.*\n"
        
        result += "\n**Tip:** Use `get_documentation_file(filename)` to read the full content of any file.\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error searching documentation for '{keywords}': {e}")
        return f"Error searching documentation: {str(e)}"



async def get_documentation_file_impl(filename: str, data_loader) -> str:
    """
    Get the full content of a specific FedRAMP documentation file.
    
    Args:
        filename: The markdown filename (e.g., "overview.md", "key-security-indicators.md")
    
    Returns:
        Full markdown content of the documentation file
    """
    try:
        # Ensure documentation is loaded
        await data_loader.load_documentation()
        
        # Get the file content
        content = data_loader.get_documentation_file(filename)
        
        if not content:
            available = data_loader.list_documentation_files()
            return f"Documentation file '{filename}' not found.\n\n**Available files:**\n" + '\n'.join(f"- {f}" for f in available)
        
        result = f"# {filename}\n\n"
        result += content
        
        return result
        
    except Exception as e:
        logger.error(f"Error fetching documentation file '{filename}': {e}")
        return f"Error retrieving documentation file: {str(e)}"



async def list_documentation_files_impl(data_loader) -> str:
    """
    List all available FedRAMP documentation files.
    
    Returns:
        List of all markdown documentation files from https://github.com/FedRAMP/docs/tree/main/docs
    """
    try:
        # Ensure documentation is loaded
        await data_loader.load_documentation()
        
        # Get list of files
        files = data_loader.list_documentation_files()
        
        if not files:
            return "No documentation files found."
        
        result = "# Available FedRAMP Documentation Files\n\n"
        result += f"**Total:** {len(files)} files\n\n"
        
        # Group by type
        standards = [f for f in files if f not in ['overview.md', 'guidelines.md', 'index.md'] and not f.startswith('20x') and not f.startswith('rev5')]
        guides = [f for f in files if f in ['overview.md', 'guidelines.md', 'index.md']]
        other = [f for f in files if f not in standards and f not in guides]
        
        if standards:
            result += "## FedRAMP 20x Standards\n\n"
            for f in sorted(standards):
                result += f"- {f}\n"
            result += "\n"
        
        if guides:
            result += "## General Documentation\n\n"
            for f in sorted(guides):
                result += f"- {f}\n"
            result += "\n"
        
        if other:
            result += "## Other Documentation\n\n"
            for f in sorted(other):
                result += f"- {f}\n"
            result += "\n"
        
        result += "**Usage:** Use `get_documentation_file(filename)` to read any file's full content.\n"
        result += "**Search:** Use `search_documentation(keywords)` to find specific information.\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing documentation files: {e}")
        return f"Error listing documentation files: {str(e)}"