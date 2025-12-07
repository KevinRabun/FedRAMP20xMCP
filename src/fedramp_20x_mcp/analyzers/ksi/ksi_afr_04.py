"""
KSI-AFR-04: Vulnerability Detection and Response

Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-04: Vulnerability Detection and Response
    
    **Official Statement:**
    Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ca-2
    - ca-7
    - ca-7.6
    - ir-1
    - ir-4
    - ir-4.1
    - ir-5
    - ir-5.1
    - ir-6
    - ir-6.1
    - ir-6.2
    - pm-3
    - pm-5
    - pm-31
    - ra-2
    - ra-2.1
    - ra-3
    - ra-3.3
    - ra-5
    - ra-5.2
    - ra-5.3
    - ra-5.4
    - ra-5.5
    - ra-5.6
    - ra-5.7
    - ra-5.11
    - ra-9
    - ra-10
    - si-2
    - si-2.1
    - si-2.2
    - si-2.4
    - si-2.5
    - si-3
    - si-3.1
    - si-3.2
    - si-4
    - si-4.2
    - si-4.3
    - si-4.7
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Document the vulnerability detection and vulnerability response methodology used within the cloud se...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-AFR-04"
    KSI_NAME = "Vulnerability Detection and Response"
    KSI_STATEMENT = """Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ca-2", "ca-7", "ca-7.6", "ir-1", "ir-4", "ir-4.1", "ir-5", "ir-5.1", "ir-6", "ir-6.1", "ir-6.2", "pm-3", "pm-5", "pm-31", "ra-2", "ra-2.1", "ra-3", "ra-3.3", "ra-5", "ra-5.2", "ra-5.3", "ra-5.4", "ra-5.5", "ra-5.6", "ra-5.7", "ra-5.11", "ra-9", "ra-10", "si-2", "si-2.1", "si-2.2", "si-2.4", "si-2.5", "si-3", "si-3.1", "si-3.2", "si-4", "si-4.2", "si-4.3", "si-4.7"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
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
        Analyze Python code for KSI-AFR-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the vulnerability detection and vulnerability response methodology used...
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
        Analyze C# code for KSI-AFR-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-04 compliance.
        
        Detects:
        - Missing vulnerability scanning steps
        - Missing dependency scanning
        - Missing security scanning tools
        """
        findings = []
        lines = code.split('\n')
        
        # Check for vulnerability/security scanning
        has_vuln_scan = bool(re.search(r'(snyk|trivy|dependency-check|safety|bandit|semgrep|CodeQL)', code, re.IGNORECASE))
        if not has_vuln_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Vulnerability Scanning in CI/CD",
                description=f"GitHub Actions workflow '{file_path}' lacks vulnerability scanning. KSI-AFR-04 requires vulnerability detection.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add vulnerability scanning:

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    scan-ref: '.'
    format: 'sarif'
    output: 'trivy-results.sarif'

- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'trivy-results.sarif'

- name: Dependency scanning
  uses: actions/dependency-review-action@v3
```

Reference: FRR-AFR-04 - Vulnerability Detection and Response"""
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-04 compliance.
        
        Detects missing vulnerability scanning steps
        """
        findings = []
        lines = code.split('\n')
        
        has_vuln_scan = bool(re.search(r'(WhiteSource|Mend|Snyk|Trivy|OWASP|Fortify)', code, re.IGNORECASE))
        if not has_vuln_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Vulnerability Scanning",
                description=f"Azure Pipeline '{file_path}' lacks vulnerability scanning. KSI-AFR-04 requires vulnerability detection.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add vulnerability scanning task:

```yaml
- task: SnykSecurityScan@1
  inputs:
    serviceConnectionEndpoint: 'Snyk'
    testType: 'app'
    severityThreshold: 'high'
    monitorWhen: 'always'

- task: WhiteSourceBolt@21
  inputs:
    cwd: '$(System.DefaultWorkingDirectory)'
```

Reference: FRR-AFR-04"""
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-04 compliance.
        
        Detects missing vulnerability scanning jobs
        """
        findings = []
        lines = code.split('\n')
        
        has_vuln_scan = bool(re.search(r'(gemnasium|trivy|container_scanning|dependency_scanning|sast)', code, re.IGNORECASE))
        if not has_vuln_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Vulnerability Scanning",
                description=f"GitLab CI '{file_path}' lacks vulnerability scanning. KSI-AFR-04 requires vulnerability detection.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add GitLab security scanning:

```yaml
include:
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

dependency_scanning:
  stage: test
  allow_failure: false
```

Reference: FRR-AFR-04"""
            ))
        
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
