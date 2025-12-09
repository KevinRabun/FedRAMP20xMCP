"""
KSI-PIY-08: Executive Support

Regularly measure executive support for achieving the organization's security objectives.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_08_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-08: Executive Support
    
    **Official Statement:**
    Regularly measure executive support for achieving the organization's security objectives.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-PIY-08"
    KSI_NAME = "Executive Support"
    KSI_STATEMENT = """Regularly measure executive support for achieving the organization's security objectives."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
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
        Analyze Python code for KSI-PIY-08 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly measure executive support for achieving the organization's security ob...
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
        Analyze C# code for KSI-PIY-08 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly measure executive support for achieving the organization's security ob...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-08 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly measure executive support for achieving the organization's security ob...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-08 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly measure executive support for achieving the organization's security ob...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-08 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Regularly measure executive support for achieving the organization's security ob...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-08 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Regularly measure executive support for achieving the organization's security ob...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-08 compliance.
        
        Detects:
        - Missing security scan stages
        - Missing early vulnerability detection
        - Missing fail-fast on security issues
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security scanning in CI/CD
        has_security_job = bool(re.search(r'(security|scan|sast|dast):.*\n.*runs-on', code, re.IGNORECASE))
        has_fail_fast = bool(re.search(r'(continue-on-error:\s*false|exit\s*1)', code, re.IGNORECASE))
        has_pr_scan = bool(re.search(r'pull_request.*\n.*security', code, re.IGNORECASE))
        has_early_scan = bool(re.search(r'(build.*security|security.*build)', code, re.IGNORECASE))
        
        if not has_security_job:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing dedicated security scan job",
                description="No dedicated security scanning job in pipeline. KSI-PIY-08 requires regular security scans in CI/CD to detect vulnerabilities early.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add security job: security-scan:\n  runs-on: ubuntu-latest\n  steps:\n    - name: Run Security Scan\n      run: ./scripts/security-scan.sh"
            ))
        
        if not has_pr_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing pull request security scanning",
                description="No security scanning on pull requests. KSI-PIY-08 requires scanning PRs to prevent vulnerable code from merging.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add PR trigger: on:\n  pull_request:\n    branches: [main]\njobs:\n  security-scan:"
            ))
        
        if not has_fail_fast:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing fail-fast on security issues",
                description="Pipeline doesn't fail on security findings. KSI-PIY-08 requires blocking builds when vulnerabilities are detected.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add fail-fast: - name: Fail on Vulnerabilities\n  run: |\n    if [ $VULN_COUNT -gt 0 ]; then exit 1; fi"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    

