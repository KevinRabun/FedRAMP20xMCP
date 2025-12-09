"""
KSI-RPL-04: Recovery Testing

Regularly test the capability to recover from incidents and contingencies.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_RPL_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-RPL-04: Recovery Testing
    
    **Official Statement:**
    Regularly test the capability to recover from incidents and contingencies.
    
    **Family:** RPL - Recovery Planning
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cp-2.1
    - cp-2.3
    - cp-4
    - cp-4.1
    - cp-6
    - cp-6.1
    - cp-9.1
    - cp-10
    - ir-3
    - ir-3.2
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-RPL-04"
    KSI_NAME = "Recovery Testing"
    KSI_STATEMENT = """Regularly test the capability to recover from incidents and contingencies."""
    FAMILY = "RPL"
    FAMILY_NAME = "Recovery Planning"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cp-2.1", "Coordinate with Related Plans"),
        ("cp-2.3", "Resume Mission and Business Functions"),
        ("cp-4", "Contingency Plan Testing"),
        ("cp-4.1", "Coordinate with Related Plans"),
        ("cp-6", "Alternate Storage Site"),
        ("cp-6.1", "Separation from Primary Site"),
        ("cp-9.1", "Testing for Reliability and Integrity"),
        ("cp-10", "System Recovery and Reconstitution"),
        ("ir-3", "Incident Response Testing"),
        ("ir-3.2", "Coordination with Related Plans")
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
        Analyze Python code for KSI-RPL-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
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
        Analyze C# code for KSI-RPL-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-RPL-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-RPL-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-RPL-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-RPL-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-RPL-04 compliance.
        
        Detects:
        - Missing recovery testing automation
        - Missing backup restoration validation
        - Missing RTO/RPO verification
        """
        findings = []
        lines = code.split('\n')
        
        # Check for recovery testing
        has_recovery_test = bool(re.search(r'(recovery.*test|restore.*test|backup.*validation)', code, re.IGNORECASE))
        has_restore_job = bool(re.search(r'(restore|recovery):.*\n.*runs-on', code, re.IGNORECASE))
        has_scheduled_test = bool(re.search(r'schedule.*\n.*recovery|recovery.*\n.*schedule', code, re.IGNORECASE))
        has_rto_rpo_check = bool(re.search(r'(rto|rpo|recovery.*time|recovery.*point)', code, re.IGNORECASE))
        
        if not has_recovery_test:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing automated recovery testing",
                description="No automated recovery testing detected. KSI-RPL-04 requires regularly testing capability to recover from backup.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add recovery test: - name: Test Backup Recovery\n  run: ./scripts/test-restore.sh"
            ))
        
        if not has_scheduled_test:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing scheduled recovery testing",
                description="No scheduled (regular) recovery testing. KSI-RPL-04 requires periodic validation of recovery capability.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add scheduled test: on:\n  schedule:\n    - cron: '0 3 * * 0'  # Weekly on Sunday at 3 AM"
            ))
        
        if not has_rto_rpo_check:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing RTO/RPO verification",
                description="No verification of Recovery Time Objective (RTO) or Recovery Point Objective (RPO). KSI-RPL-04 requires testing against defined objectives.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add RTO/RPO check: - name: Verify RTO/RPO\n  run: ./scripts/measure-recovery-time.sh"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-RPL-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-RPL-04 compliance.
        
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

