"""
KSI-CED-03: Development and Engineering Education

Require and monitor the effectiveness of role-specific training provided to development and engineering staff that covers best practices for delivering secure software.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CED_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CED-03: Development and Engineering Education
    
    **Official Statement:**
    Require and monitor the effectiveness of role-specific training provided to development and engineering staff that covers best practices for delivering secure software.
    
    **Family:** CED - Cybersecurity Education
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cp-3
    - ir-2
    - ps-6
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Require and monitor the effectiveness of role-specific training provided to development and engineer...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CED-03"
    KSI_NAME = "Development and Engineering Education"
    KSI_STATEMENT = """Require and monitor the effectiveness of role-specific training provided to development and engineering staff that covers best practices for delivering secure software."""
    FAMILY = "CED"
    FAMILY_NAME = "Cybersecurity Education"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cp-3", "Contingency Training"),
        ("ir-2", "Incident Response Training"),
        ("ps-6", "Access Agreements")
    ]
    CODE_DETECTABLE = False
    IMPLEMENTATION_STATUS = "NOT_IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-CED-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement Python-specific detection logic
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CED-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CED-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CED-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CED-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CED-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CED-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CED-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CED-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
