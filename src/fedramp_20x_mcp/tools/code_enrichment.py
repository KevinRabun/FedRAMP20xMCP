"""
Code Enrichment for FedRAMP 20x MCP Server

This module provides functions to enrich generated code and IaC templates
with specific KSI and FRR requirement metadata in comments.
"""
import re
from typing import List, Dict, Any, Optional


def get_requirement_header(
    ksi_ids: Optional[List[str]] = None,
    frr_ids: Optional[List[str]] = None,
    data_loader: Any = None,
    language: str = "bicep"
) -> str:
    """
    Generate a detailed requirement header comment block for code/IaC.
    
    Args:
        ksi_ids: List of KSI IDs (e.g., ["KSI-IAM-01", "KSI-MLA-01"])
        frr_ids: List of FRR IDs (e.g., ["FRR-VDR-01", "FRR-ADS-01"])
        data_loader: DataLoader instance to fetch metadata
        language: Programming language for comment syntax
    
    Returns:
        Formatted comment block with requirement details
    """
    comment_start, comment_prefix, comment_end = _get_comment_syntax(language)
    
    lines = []
    lines.append(comment_start)
    lines.append(f"{comment_prefix} FedRAMP 20x Compliance Requirements")
    lines.append(f"{comment_prefix} ==========================================")
    
    # Add KSI requirements
    if ksi_ids and data_loader:
        lines.append(f"{comment_prefix}")
        lines.append(f"{comment_prefix} Key Security Indicators (KSI):")
        for ksi_id in ksi_ids:
            ksi = data_loader.get_ksi(ksi_id)
            if ksi:
                name = ksi.get("name", "")
                description = ksi.get("description", "")
                lines.append(f"{comment_prefix}")
                lines.append(f"{comment_prefix} {ksi_id}: {name}")
                if description:
                    # Wrap long descriptions
                    desc_lines = _wrap_text(description, 70)
                    for desc_line in desc_lines:
                        lines.append(f"{comment_prefix}   {desc_line}")
    
    # Add FRR requirements
    if frr_ids and data_loader:
        lines.append(f"{comment_prefix}")
        lines.append(f"{comment_prefix} FedRAMP Requirements (FRR):")
        for frr_id in frr_ids:
            frr = data_loader.get_control(frr_id)  # FRRs are stored as controls
            if frr:
                name = frr.get("name", "")
                description = frr.get("description", "")
                lines.append(f"{comment_prefix}")
                lines.append(f"{comment_prefix} {frr_id}: {name}")
                if description:
                    desc_lines = _wrap_text(description, 70)
                    for desc_line in desc_lines:
                        lines.append(f"{comment_prefix}   {desc_line}")
    
    lines.append(f"{comment_prefix} ==========================================")
    if comment_end:
        lines.append(comment_end)
    
    return "\n".join(lines)


def get_inline_requirement_comment(
    requirement_id: str,
    data_loader: Any,
    language: str = "bicep",
    compact: bool = False
) -> str:
    """
    Generate an inline comment for a specific requirement.
    
    Args:
        requirement_id: KSI or FRR ID (e.g., "KSI-IAM-01" or "FRR-VDR-01")
        data_loader: DataLoader instance to fetch metadata
        language: Programming language for comment syntax
        compact: If True, use compact format (ID and name only)
    
    Returns:
        Formatted inline comment
    """
    _, comment_prefix, _ = _get_comment_syntax(language)
    
    # Determine if KSI or FRR
    is_ksi = requirement_id.startswith("KSI-")
    metadata = data_loader.get_ksi(requirement_id) if is_ksi else data_loader.get_control(requirement_id)  # FRRs are controls
    
    if not metadata:
        return f"{comment_prefix} {requirement_id}"
    
    name = metadata.get("name", "")
    
    if compact:
        return f"{comment_prefix} {requirement_id}: {name}"
    
    description = metadata.get("description", "")
    if description:
        # For inline, keep it short
        short_desc = description[:100] + "..." if len(description) > 100 else description
        return f"{comment_prefix} {requirement_id}: {name} - {short_desc}"
    
    return f"{comment_prefix} {requirement_id}: {name}"


def enrich_bicep_template(
    template: str,
    ksi_ids: Optional[List[str]] = None,
    frr_ids: Optional[List[str]] = None,
    data_loader: Any = None
) -> str:
    """
    Enrich Bicep template with KSI/FRR requirement comments.
    
    Args:
        template: Original Bicep template content
        ksi_ids: List of KSI IDs to document
        frr_ids: List of FRR IDs to document
        data_loader: DataLoader instance
    
    Returns:
        Enriched template with requirement headers
    """
    if not data_loader or (not ksi_ids and not frr_ids):
        return template
    
    header = get_requirement_header(ksi_ids, frr_ids, data_loader, "bicep")
    
    # Insert after the first comment block or at the top
    lines = template.split('\n')
    insert_index = 0
    
    # Skip existing header comments
    for i, line in enumerate(lines):
        if line.strip() and not line.strip().startswith('//'):
            insert_index = i
            break
    
    lines.insert(insert_index, header)
    lines.insert(insert_index + 1, "")
    
    return '\n'.join(lines)


def enrich_csharp_code(
    code: str,
    ksi_ids: Optional[List[str]] = None,
    frr_ids: Optional[List[str]] = None,
    data_loader: Any = None
) -> str:
    """
    Enrich C# code with KSI/FRR requirement comments.
    
    Args:
        code: Original C# code
        ksi_ids: List of KSI IDs to document
        frr_ids: List of FRR IDs to document
        data_loader: DataLoader instance
    
    Returns:
        Enriched code with requirement headers
    """
    if not data_loader or (not ksi_ids and not frr_ids):
        return code
    
    header = get_requirement_header(ksi_ids, frr_ids, data_loader, "csharp")
    
    # Insert after using statements
    lines = code.split('\n')
    insert_index = 0
    
    # Find end of using statements
    for i, line in enumerate(lines):
        if line.strip().startswith('using '):
            insert_index = i + 1
        elif line.strip() and not line.strip().startswith('using '):
            break
    
    lines.insert(insert_index, header)
    lines.insert(insert_index + 1, "")
    
    return '\n'.join(lines)


def add_requirement_tags(
    template: str,
    ksi_ids: Optional[List[str]] = None,
    frr_ids: Optional[List[str]] = None,
    language: str = "bicep"
) -> str:
    """
    Add requirement ID tags to Azure resource definitions.
    
    For Bicep/Terraform, adds tags to resource definitions.
    For code, adds attributes/decorators where appropriate.
    
    Args:
        template: Original template/code
        ksi_ids: List of KSI IDs
        frr_ids: List of FRR IDs
        language: Target language
    
    Returns:
        Template with requirement tags added
    """
    if not ksi_ids and not frr_ids:
        return template
    
    all_requirements = (ksi_ids or []) + (frr_ids or [])
    requirements_str = ", ".join(all_requirements)
    
    if language == "bicep":
        # Add to tags object in Bicep resources
        tag_line = f"  Compliance: 'FedRAMP 20x'\n  Requirements: '{requirements_str}'"
        
        # Find tags sections and enhance them
        pattern = r'(tags:\s*{[^}]*)'
        replacement = rf"\1\n  {tag_line}"
        return re.sub(pattern, replacement, template)
    
    elif language == "terraform":
        # Add to tags map in Terraform resources
        tag_block = f'  compliance     = "FedRAMP 20x"\n  requirements   = "{requirements_str}"'
        pattern = r'(tags\s*=\s*{[^}]*)'
        replacement = rf"\1\n  {tag_block}"
        return re.sub(pattern, replacement, template)
    
    return template


def _get_comment_syntax(language: str) -> tuple[str, str, str]:
    """
    Get comment syntax for a language.
    
    Returns:
        Tuple of (start, prefix, end) for multi-line comments
    """
    syntax_map = {
        "bicep": ("//", "//", ""),
        "terraform": ("//", "//", ""),
        "python": ('"""', "", '"""'),
        "csharp": ("/*", " *", " */"),
        "java": ("/*", " *", " */"),
        "typescript": ("/*", " *", " */"),
        "javascript": ("/*", " *", " */"),
        "powershell": ("<#", "#", "#>"),
    }
    
    return syntax_map.get(language.lower(), ("//", "//", ""))


def _wrap_text(text: str, width: int) -> List[str]:
    """Wrap text to specified width."""
    words = text.split()
    lines = []
    current_line = []
    current_length = 0
    
    for word in words:
        if current_length + len(word) + 1 <= width:
            current_line.append(word)
            current_length += len(word) + 1
        else:
            if current_line:
                lines.append(" ".join(current_line))
            current_line = [word]
            current_length = len(word)
    
    if current_line:
        lines.append(" ".join(current_line))
    
    return lines
