"""
FedRAMP Requirement (FRR) Analyzers - Pattern-Based Architecture

This package provides pattern-based analysis for FedRAMP 20x requirements families:
- VDR: Vulnerability Detection and Response
- RSC: Recommended Secure Configuration
- SCN: Significant Change Notifications
- UCM: Using Cryptographic Modules
- ADS: Authorization Data Sharing
- CCM: Collaborative Continuous Monitoring
- MAS: Minimum Assessment Scope
- ICP: Incident Communications Procedures

Uses GenericPatternAnalyzer for code detection across:
- Application code (Python, C#, Java, TypeScript/JavaScript)
- Infrastructure as Code (Bicep, Terraform)
- CI/CD pipelines (GitHub Actions, Azure Pipelines, GitLab CI)
"""

from .base import BaseFRRAnalyzer
from .factory import FRRAnalyzerFactory, get_factory

__all__ = [
    "BaseFRRAnalyzer",
    "FRRAnalyzerFactory",
    "get_factory"
]
