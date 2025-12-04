"""
Infrastructure as Code (IaC) analyzers for FedRAMP 20x compliance.

This module provides backward compatibility by re-exporting analyzers
from their dedicated language-specific modules:
- BicepAnalyzer: Analyzes Azure Bicep templates
- TerraformAnalyzer: Analyzes Terraform configurations (azurerm provider)

For direct imports, use the specific analyzer modules:
- from .bicep_analyzer import BicepAnalyzer
- from .terraform_analyzer import TerraformAnalyzer
"""

from .bicep_analyzer import BicepAnalyzer
from .terraform_analyzer import TerraformAnalyzer

__all__ = ['BicepAnalyzer', 'TerraformAnalyzer']
