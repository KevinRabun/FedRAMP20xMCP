"""
KSI-PIY-06: Security Investment Effectiveness

Monitor the effectiveness of the organization's investments in achieving security objectives.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_06_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-06: Security Investment Effectiveness
    
    **Official Statement:**
    Monitor the effectiveness of the organization's investments in achieving security objectives.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-5
    - ca-2
    - cp-2.1
    - cp-4.1
    - ir-3.2
    - pm-3
    - sa-2
    - sa-3
    - sr-2.1
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Monitor the effectiveness of the organization's investments in achieving security objectives....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-PIY-06"
    KSI_NAME = "Security Investment Effectiveness"
    KSI_STATEMENT = """Monitor the effectiveness of the organization's investments in achieving security objectives."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-5", "ca-2", "cp-2.1", "cp-4.1", "ir-3.2", "pm-3", "sa-2", "sa-3", "sr-2.1"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "NOT_IMPLEMENTED"
    RETIRED = False
    
    def __init__(self):
        super().__init__(
            ksi_id=self.KSI_ID,
            ksi_name=self.KSI_NAME,
            ksi_statement=self.KSI_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-PIY-06 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of the organization's investments in achieving securit...
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
        Analyze C# code for KSI-PIY-06 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of the organization's investments in achieving securit...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-06 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of the organization's investments in achieving securit...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-06 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of the organization's investments in achieving securit...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-06 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Monitor the effectiveness of the organization's investments in achieving securit...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-06 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Monitor the effectiveness of the organization's investments in achieving securit...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-06 compliance.
        
        Detects:
        - Missing scheduled vulnerability scans
        - Missing multi-environment scanning
        - Missing scan automation
        """
        findings = []
        lines = code.split('\n')
        
        # Check for scheduled scans
        has_schedule = bool(re.search(r'on:\s*schedule:|cron:', code, re.IGNORECASE))
        has_vuln_scanner = bool(re.search(r'(trivy|snyk|grype|anchore|vuln.*scan)', code, re.IGNORECASE))
        has_container_scan = bool(re.search(r'(docker.*scan|container.*security|image.*scan)', code, re.IGNORECASE))
        
        if not has_schedule:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing scheduled vulnerability scans",
                description="No scheduled (cron) vulnerability scanning detected. KSI-PIY-06 requires regular automated scans of all environments.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add scheduled scan: on:\n  schedule:\n    - cron: '0 2 * * *'  # Daily at 2 AM"
            ))
        
        if not has_vuln_scanner:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing vulnerability scanner",
                description="No vulnerability scanning tool configured. KSI-PIY-06 requires automated vulnerability detection.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add vulnerability scanner: - name: Trivy Scan\n  uses: aquasecurity/trivy-action@master"
            ))
        
        if not has_container_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing container vulnerability scanning",
                description="No container image scanning detected. KSI-PIY-06 requires scanning container images for vulnerabilities.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add container scan: - name: Scan Docker Image\n  run: trivy image ${{ env.IMAGE_NAME }}"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-06 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-06 compliance.
        
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
