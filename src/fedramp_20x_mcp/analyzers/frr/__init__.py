"""
FedRAMP Requirement (FRR) Analyzers - Pattern-Based Architecture

This package provides pattern-based analysis for FedRAMP 20x requirements families:
- VDR: Vulnerability Detection and Response
- VER: Vulnerability Evaluation and Reporting
- SCG: Secure Configuration Guide
- SCN: Significant Change Notifications
- CMU: Cryptographic Module Use
- CDS: Certification Data Sharing
- CCM: Collaborative Continuous Monitoring
- MAS: Minimum Assessment Scope
- IEC: Incident Evaluation and Communication
- IVV: Independent Verification and Validation
- AFC: Addressing FedRAMP Communication
- AGU, FRC, SDR: agency use, certification and security decision records

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
