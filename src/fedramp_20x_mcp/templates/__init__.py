"""
Infrastructure and code templates for FedRAMP 20x evidence collection.

This module provides Bicep, Terraform, and code generation templates
organized by KSI family (IAM, MLA, AFR, CNA, RPL, SVC).
"""

from pathlib import Path

# Template directory
TEMPLATES_DIR = Path(__file__).parent

def load_template(category: str, name: str) -> str:
    """
    Load a template file by category and name.
    
    Args:
        category: Template category (bicep, terraform, code)
        name: Template name (iam, mla, afr, cna, rpl, svc, generic)
    
    Returns:
        Template content as string
    
    Raises:
        FileNotFoundError: If template doesn't exist
    """
    template_path = TEMPLATES_DIR / category / f"{name}.txt"
    
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    
    return template_path.read_text(encoding='utf-8')


def get_infrastructure_template(ksi_family: str, infra_type: str) -> str:
    """
    Get infrastructure template for a KSI family.
    
    Args:
        ksi_family: KSI family code (iam, mla, afr, cna, rpl, svc)
        infra_type: Infrastructure type (bicep, terraform)
    
    Returns:
        Template content wrapped in markdown code blocks
    """
    try:
        template = load_template(infra_type, ksi_family.lower())
        return template
    except FileNotFoundError:
        # Fall back to generic template
        template = load_template(infra_type, 'generic')
        return template


def get_code_template(ksi_family: str, language: str) -> str:
    """
    Get code generation template for a KSI family.
    
    Args:
        ksi_family: KSI family code (iam, mla, afr, cna, rpl, svc)  
        language: Programming language (python, csharp, powershell, java, typescript)
    
    Returns:
        Code template content
    """
    try:
        # Try family-specific template
        template_name = f"{ksi_family.lower()}_{language.lower()}"
        template = load_template('code', template_name)
        return template
    except FileNotFoundError:
        # Fall back to generic template
        template_name = f"generic_{language.lower()}"
        template = load_template('code', template_name)
        return template
