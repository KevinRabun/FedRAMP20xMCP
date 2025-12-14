"""
KSI-centric analyzers for FedRAMP 20x compliance - Pattern-Based Architecture.

Uses GenericPatternAnalyzer for all KSI detection with:
- Official FedRAMP 20x metadata embedded in patterns
- All language implementations (Python, C#, Java, TypeScript, Bicep, Terraform)
- CI/CD pipeline analysis (GitHub Actions, Azure Pipelines, GitLab CI)

Architecture:
- Pattern-based detection (248 patterns loaded from YAML files)
- Factory provides backward-compatible API
- All analysis delegated to GenericPatternAnalyzer
"""

from .base import BaseKSIAnalyzer
from .factory import KSIAnalyzerFactory, get_factory

__all__ = [
    'BaseKSIAnalyzer',
    'KSIAnalyzerFactory',
    'get_factory',
]
