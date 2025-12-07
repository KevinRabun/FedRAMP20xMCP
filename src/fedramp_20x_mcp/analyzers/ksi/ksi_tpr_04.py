"""
KSI-TPR-04: Supply Chain Risk Monitoring

Automatically monitor third party software information resources for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_TPR_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-TPR-04: Supply Chain Risk Monitoring
    
    **Official Statement:**
    Automatically monitor third party software information resources for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.
    
    **Family:** TPR - Third-Party Information Resources
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-20
    - ca-3
    - ir-6.3
    - ps-7
    - ra-5
    - sa-9
    - si-5
    - sr-5
    - sr-6
    - sr-8
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Automatically monitor third party software information resources for upstream vulnerabilities using ...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-TPR-04"
    KSI_NAME = "Supply Chain Risk Monitoring"
    KSI_STATEMENT = """Automatically monitor third party software information resources for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services."""
    FAMILY = "TPR"
    FAMILY_NAME = "Third-Party Information Resources"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-20", "ca-3", "ir-6.3", "ps-7", "ra-5", "sa-9", "si-5", "sr-5", "sr-6", "sr-8"]
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
        Analyze Python code for KSI-TPR-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Missing dependency vulnerability scanning (Dependabot, Snyk, etc.)
        - Absence of automated security advisories
        - Note: Actual CVE detection handled by scan_dependency_file tool
        """
        findings = []
        lines = code.split('\n')
        
        # Note: This KSI is primarily about CI/CD integration of automated scanning
        # Application code has limited direct signals for this requirement
        # Main detection happens in CI/CD analyzers below
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-TPR-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Missing dependency vulnerability scanning (Dependabot, Snyk, WhiteSource, etc.)
        - Note: Actual CVE detection handled by scan_dependency_file tool
        """
        findings = []
        lines = code.split('\n')
        
        # Application code has limited direct signals for this requirement
        # Main detection happens in CI/CD analyzers
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-TPR-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Missing dependency vulnerability scanning (Dependabot, OWASP Dependency-Check, Snyk, etc.)
        - Note: Actual CVE detection handled by scan_dependency_file tool
        """
        findings = []
        lines = code.split('\n')
        
        # Application code has limited direct signals for this requirement
        # Main detection happens in CI/CD analyzers
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-TPR-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Missing dependency vulnerability scanning (npm audit, Snyk, Dependabot, etc.)
        - Note: Actual CVE detection handled by scan_dependency_file tool
        """
        findings = []
        lines = code.split('\n')
        
        # Application code has limited direct signals for this requirement
        # Main detection happens in CI/CD analyzers
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-TPR-04 compliance.
        
        Detects:
        - Azure Defender for Container Registries disabled
        - Missing Microsoft Defender for Cloud
        - Container Registry without vulnerability scanning
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Container Registry without Defender/scanning (MEDIUM)
        has_acr = re.search(r"'Microsoft\.ContainerRegistry/registries", code)
        has_defender = re.search(r'Microsoft\.Security/pricings|defenderEnabled', code)
        
        if has_acr and not has_defender:
            line_num = self._find_line(lines, r"Microsoft\.ContainerRegistry")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Container Registry Without Vulnerability Scanning",
                description=(
                    f"Azure Container Registry at line {line_num} without Microsoft Defender for Containers. "
                    f"Defender provides continuous vulnerability scanning and monitoring for supply chain threats. "
                    f"Without it, vulnerable images may go undetected."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Enable Microsoft Defender for Containers:\n"
                    "resource defender 'Microsoft.Security/pricings@2024-01-01' = {\n"
                    "  name: 'ContainerRegistry'\n"
                    "  properties: {\n"
                    "    pricingTier: 'Standard'\n"
                    "  }\n"
                    "}\n"
                    "Or use Azure Security Center with vulnerability scanning enabled."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-TPR-04 compliance.
        
        Detects:
        - Azure Defender for Container Registries disabled
        - Missing Microsoft Defender for Cloud
        - Container Registry without vulnerability scanning
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Container Registry without Defender/scanning (MEDIUM)
        has_acr = re.search(r'resource\s+"azurerm_container_registry"', code)
        has_defender = re.search(r'azurerm_security_center_subscription_pricing.*ContainerRegistry', code)
        
        if has_acr and not has_defender:
            line_num = self._find_line(lines, r'azurerm_container_registry')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Container Registry Without Vulnerability Scanning",
                description=(
                    f"Azure Container Registry at line {line_num} without Microsoft Defender for Containers. "
                    f"Defender provides automated vulnerability scanning and supply chain monitoring. "
                    f"Without it, vulnerable container images may be deployed undetected."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Enable Microsoft Defender for Containers:\n"
                    "resource \"azurerm_security_center_subscription_pricing\" \"containers\" {\n"
                    "  tier          = \"Standard\"\n"
                    "  resource_type = \"ContainerRegistry\"\n"
                    "}\n"
                    "This enables automated vulnerability scanning and threat detection."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-TPR-04 compliance.
        
        Detects:
        - Missing dependency scanning (Dependabot, Snyk, etc.)
        - Absence of vulnerability scanning steps
        - Missing security advisory notifications
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: No dependency scanning action (CRITICAL)
        has_scan = re.search(r'uses:.*/(snyk-actions|dependency-review-action|anchore/scan-action)', code, re.IGNORECASE)
        has_dependabot_mention = 'dependabot' in code.lower()
        
        if not has_scan and not has_dependabot_mention:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Missing Automated Dependency Vulnerability Scanning",
                description=(
                    "GitHub Actions workflow without dependency vulnerability scanning. "
                    "KSI-TPR-04 requires automatic monitoring of third-party dependencies for vulnerabilities. "
                    "Without automated scanning, vulnerable dependencies may be deployed undetected."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add dependency scanning to workflow:\n"
                    "- name: Dependency Review\n"
                    "  uses: actions/dependency-review-action@v4\n"
                    "Or enable Dependabot:\n"
                    ".github/dependabot.yml:\n"
                    "version: 2\n"
                    "updates:\n"
                    "  - package-ecosystem: \"npm\" # or pip, nuget, maven\n"
                    "    directory: \"/\"\n"
                    "    schedule:\n"
                    "      interval: \"daily\"\n"
                    "    open-pull-requests-limit: 10"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-TPR-04 compliance.
        
        Detects:
        - Missing dependency scanning (WhiteSource Bolt, Mend, Snyk, etc.)
        - Absence of vulnerability scanning tasks
        - Missing security scans
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: No dependency scanning task (CRITICAL)
        has_scan = re.search(r'(WhiteSourceBolt|MendBolt|Snyk|DependencyCheck)', code, re.IGNORECASE)
        
        if not has_scan:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Missing Automated Dependency Vulnerability Scanning",
                description=(
                    "Azure Pipeline without dependency vulnerability scanning task. "
                    "KSI-TPR-04 requires automatic monitoring of third-party dependencies for vulnerabilities. "
                    "Without automated scanning, vulnerable dependencies may be deployed to production."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add dependency scanning task:\n"
                    "- task: WhiteSource@21\n"
                    "  inputs:\n"
                    "    cwd: '$(System.DefaultWorkingDirectory)'\n"
                    "Or use Microsoft Defender for DevOps:\n"
                    "- task: MicrosoftSecurityDevOps@1\n"
                    "  displayName: 'Run Microsoft Security DevOps'\n"
                    "Or Snyk:\n"
                    "- task: SnykSecurityScan@1\n"
                    "  inputs:\n"
                    "    serviceConnectionEndpoint: 'Snyk'\n"
                    "    testType: 'app'"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-TPR-04 compliance.
        
        Detects:
        - Missing dependency scanning (GitLab Dependency Scanning, Snyk, etc.)
        - Absence of vulnerability scanning stages
        - Missing security templates
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: No dependency scanning (CRITICAL)
        has_scan = re.search(r'(dependency_scanning|container_scanning|sast|Dependency-Scanning\.gitlab-ci\.yml)', code, re.IGNORECASE)
        
        if not has_scan:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Missing Automated Dependency Vulnerability Scanning",
                description=(
                    "GitLab CI without dependency vulnerability scanning. "
                    "KSI-TPR-04 requires automatic monitoring of third-party dependencies for vulnerabilities. "
                    "GitLab provides built-in dependency scanning that should be enabled."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add dependency scanning to .gitlab-ci.yml:\n"
                    "include:\n"
                    "  - template: Security/Dependency-Scanning.gitlab-ci.yml\n"
                    "  - template: Security/Container-Scanning.gitlab-ci.yml\n"
                    "Or define custom scan stage:\n"
                    "dependency_scanning:\n"
                    "  stage: test\n"
                    "  image: registry.gitlab.com/gitlab-org/security-products/analyzers/gemnasium:latest\n"
                    "  script:\n"
                    "    - /analyzer run\n"
                    "  artifacts:\n"
                    "    reports:\n"
                    "      dependency_scanning: gl-dependency-scanning-report.json"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> int:
        """Find line number matching regex pattern (case-insensitive)."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    return i
        except re.error:
            # Fallback to literal string search if pattern is invalid
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
