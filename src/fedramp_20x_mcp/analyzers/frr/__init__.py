"""
FedRAMP Requirement (FRR) Analyzers

This package contains code analyzers for FedRAMP 20x requirements families:
- VDR: Vulnerability Detection and Response
- RSC: Recommended Secure Configuration
- SCN: Significant Change Notifications
- UCM: Using Cryptographic Modules
- ADS: Authorization Data Sharing
- CCM: Collaborative Continuous Monitoring
- MAS: Minimum Assessment Scope
- ICP: Incident Communications Procedures

Each FRR analyzer can detect compliance issues in:
- Application code (Python, C#, Java, TypeScript/JavaScript)
- Infrastructure as Code (Bicep, Terraform)
- CI/CD pipelines (GitHub Actions, Azure Pipelines, GitLab CI)
"""

from .base import BaseFRRAnalyzer
from .factory import FRRAnalyzerFactory, get_factory
from .frr_vdr_01 import FRR_VDR_01_Analyzer

__all__ = [
    "BaseFRRAnalyzer",
    "FRRAnalyzerFactory",
    "get_factory",
    "FRR_VDR_01_Analyzer"
]
