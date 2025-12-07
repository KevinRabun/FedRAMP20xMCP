"""
KSI-centric analyzers for FedRAMP 20x compliance.

Each KSI analyzer is self-contained with:
- Official FedRAMP 20x metadata embedded
- All language implementations (Python, C#, Java, TypeScript, Bicep, Terraform)
- CI/CD pipeline analysis (GitHub Actions, Azure Pipelines, GitLab CI)

Architecture:
- One file per KSI (e.g., ksi_iam_06.py)
- Each file contains all language-specific detection logic
- Factory pattern for dynamic discovery and analysis
"""

from .base import BaseKSIAnalyzer
from .factory import KSIAnalyzerFactory, get_factory

__all__ = [
    'BaseKSIAnalyzer',
    'KSIAnalyzerFactory',
    'get_factory',
]
