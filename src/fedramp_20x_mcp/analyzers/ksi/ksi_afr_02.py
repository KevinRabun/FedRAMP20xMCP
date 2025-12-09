"""
KSI-AFR-02: Key Security Indicators

Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indicators (KSIs - you are here), develop automated validation of status and progress to the greatest extent possible, and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-02: Key Security Indicators
    
    **Official Statement:**
    Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indicators (KSIs - you are here), develop automated validation of status and progress to the greatest extent possible, and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indica...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    **Note:** This KSI is not intended to create an infinite loop; unlike other KSI-AFR themed indicators, this KSI is addressed by otherwise addressing all the KSIs.
    """
    
    KSI_ID = "KSI-AFR-02"
    KSI_NAME = "Key Security Indicators"
    KSI_STATEMENT = """Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indicators (KSIs - you are here), develop automated validation of status and progress to the greatest extent possible, and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = []
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
        Analyze Python code for KSI-AFR-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
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
        Analyze C# code for KSI-AFR-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-02 compliance.
        
        Detects:
        - Missing compliance validation steps
        - Missing security goal tracking
        - Missing progress monitoring
        """
        findings = []
        lines = code.split('\n')
        
        # Check for compliance validation steps
        has_compliance_check = bool(re.search(r'(compliance|fedramp|security.*(validation|check|scan))', code, re.IGNORECASE))
        has_status_reporting = bool(re.search(r'(status|progress).*(report|track|monitor)', code, re.IGNORECASE))
        has_gates = bool(re.search(r'(gate|approval|review)', code, re.IGNORECASE))
        
        if not has_compliance_check:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing automated compliance validation",
                description="GitHub Actions workflow lacks automated compliance validation steps. KSI-AFR-02 requires automated validation of security goals and progress.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add compliance validation step: - name: Validate Compliance\n  run: ./scripts/validate-security-goals.sh"
            ))
        
        if not has_status_reporting:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing progress monitoring",
                description="Workflow does not report security goal progress. KSI-AFR-02 requires monitoring and reporting of status.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add status reporting: - name: Report Security Status\n  run: ./scripts/report-security-progress.sh"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-02 compliance.
        
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

