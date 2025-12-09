"""
KSI-PIY-04: CISA Secure By Design

Monitor the effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-04: CISA Secure By Design
    
    **Official Statement:**
    Monitor the effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-5
    - au-3.3
    - cm-3.4
    - pl-8
    - pm-7
    - sa-3
    - sa-8
    - sc-4
    - sc-18
    - si-10
    - si-11
    - si-16
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Monitor the effectiveness of building security and privacy considerations into the Software Developm...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-PIY-04"
    KSI_NAME = "CISA Secure By Design"
    KSI_STATEMENT = """Monitor the effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-5", "Separation of Duties"),
        ("au-3.3", "Limit Personally Identifiable Information Elements"),
        ("cm-3.4", "Security and Privacy Representatives"),
        ("pl-8", "Security and Privacy Architectures"),
        ("pm-7", "Enterprise Architecture"),
        ("sa-3", "System Development Life Cycle"),
        ("sa-8", "Security and Privacy Engineering Principles"),
        ("sc-4", "Information in Shared System Resources"),
        ("sc-18", "Mobile Code"),
        ("si-10", "Information Input Validation"),
        ("si-11", "Error Handling"),
        ("si-16", "Memory Protection")
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
        Analyze Python code for KSI-PIY-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
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
        Analyze C# code for KSI-PIY-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-04 compliance.
        
        Detects:
        - Missing security gates in SDLC
        - Missing SAST/DAST integration
        - Missing secure by design practices
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security scanning integration
        has_sast = bool(re.search(r'(codeql|sonar|semgrep|snyk.*code)', code, re.IGNORECASE))
        has_dast = bool(re.search(r'(zap|burp|dast|dynamic.*scan)', code, re.IGNORECASE))
        has_security_gate = bool(re.search(r'(security.*(gate|check|review)|break.*build)', code, re.IGNORECASE))
        has_threat_model = bool(re.search(r'threat.*(model|analysis)', code, re.IGNORECASE))
        
        if not has_sast:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing SAST integration",
                description="No static application security testing (SAST) detected. KSI-PIY-04 requires security built into SDLC per CISA Secure By Design.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add SAST: - name: CodeQL Analysis\n  uses: github/codeql-action/analyze@v2"
            ))
        
        if not has_security_gate:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing security gate",
                description="No security gate to prevent insecure code from progressing. CISA Secure By Design requires security checks in SDLC.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add security gate: if: steps.security-scan.outputs.vulnerabilities > 0\n  run: exit 1"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-04 compliance.
        
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

