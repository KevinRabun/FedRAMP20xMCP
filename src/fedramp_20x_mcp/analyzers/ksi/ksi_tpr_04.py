"""
KSI-TPR-04 Enhanced: Supply Chain Risk Monitoring

Automatically monitor third party software information resources for upstream vulnerabilities 
using mechanisms that may include contractual notification requirements or active monitoring services.

Enhanced with AST-based analysis where applicable.
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import CodeLanguage


class KSI_TPR_04_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-TPR-04: Supply Chain Risk Monitoring
    
    **Official Statement:**
    Automatically monitor third party software information resources for upstream vulnerabilities 
    using mechanisms that may include contractual notification requirements or active monitoring services.
    
    **Family:** TPR - Third-Party Information Resources
    
    **NIST Controls:** ac-20, ca-3, ir-6.3, ps-7, ra-5, sa-9, si-5, sr-5, sr-6, sr-8
    
    **Detection Strategy:**
    - CI/CD: Missing dependency scanning (Dependabot, Snyk, Mend, GitLab Security)
    - IaC: Container registries without vulnerability scanning (Azure Defender)
    - Application: Limited direct signals (handled by scan_dependency_file tool)
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript (minimal checks)
    - IaC: Bicep, Terraform (regex-based)
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI (regex-based)
    """
    
    KSI_ID = "KSI-TPR-04"
    KSI_NAME = "Supply Chain Risk Monitoring"
    KSI_STATEMENT = "Automatically monitor third party software information resources for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services."
    FAMILY = "TPR"
    NIST_CONTROLS = [
        ("ac-20", "Use of External Systems"),
        ("ca-3", "Information Exchange"),
        ("ir-6.3", "Supply Chain Coordination"),
        ("ps-7", "External Personnel Security"),
        ("ra-5", "Vulnerability Monitoring and Scanning"),
        ("sa-9", "External System Services"),
        ("si-5", "Security Alerts, Advisories, and Directives"),
        ("sr-5", "Acquisition Strategies, Tools, and Methods"),
        ("sr-6", "Supplier Assessments and Reviews"),
        ("sr-8", "Notification Agreements")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    # Known vulnerability scanning tools/services
    VULNERABILITY_SCANNERS = {
        'github_actions': ['snyk-actions', 'dependency-review-action', 'anchore/scan-action', 'aquasecurity/trivy-action', 'dependabot'],
        'azure_pipelines': ['WhiteSourceBolt', 'MendBolt', 'Snyk', 'DependencyCheck', 'MicrosoftSecurityDevOps'],
        'gitlab_ci': ['dependency_scanning', 'container_scanning', 'Dependency-Scanning.gitlab-ci.yml'],
        'python': ['safety', 'bandit', 'pip-audit'],
        'dotnet': ['dotnet-outdated', 'OWASP.DependencyCheck'],
        'npm': ['npm audit', 'snyk test', 'retire.js'],
        'maven': ['dependency-check-maven', 'versions-maven-plugin']
    }
    
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
        Analyze Python code for supply chain monitoring (minimal checks).
        
        Note: KSI-TPR-04 is primarily about CI/CD automation.
        Application code has limited direct signals. Main detection in CI/CD analyzers.
        Actual CVE detection handled by scan_dependency_file tool.
        """
        findings = []
        
        # Application code checks would be redundant with CI/CD checks
        # This KSI is about automated monitoring infrastructure, not code patterns
        
        return findings

    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# code for supply chain monitoring (minimal checks)."""
        findings = []
        # See _analyze_python notes
        return findings

    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code for supply chain monitoring (minimal checks)."""
        findings = []
        # See _analyze_python notes
        return findings

    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze JavaScript/TypeScript code for supply chain monitoring (minimal checks)."""
        findings = []
        # See _analyze_python notes
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================

    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for supply chain monitoring compliance.
        IaC uses regex-based analysis (no tree-sitter parser).
        
        Detects:
        - Azure Container Registry without Microsoft Defender for Containers
        - Missing vulnerability scanning for container images
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Container Registry without Defender/scanning (MEDIUM)
        has_acr = re.search(r"'Microsoft\.ContainerRegistry/registries", code)
        has_defender = re.search(r'Microsoft\.Security/pricings|defenderEnabled', code)
        
        if has_acr and not has_defender:
            line_num = self._find_text_line(lines, "ContainerRegistry")
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Container Registry Without Vulnerability Scanning",
                description=(
                    f"Azure Container Registry without Microsoft Defender for Containers. "
                    f"KSI-TPR-04 requires automated vulnerability monitoring of third-party software (container images). "
                    f"Defender provides continuous CVE scanning and supply chain threat detection."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Enable Microsoft Defender for Containers:\n"
                    "resource defender 'Microsoft.Security/pricings@2024-01-01' = {\n"
                    "  name: 'ContainerRegistry'\n"
                    "  properties: {\n"
                    "    pricingTier: 'Standard'  // Enables automated vulnerability scanning\n"
                    "  }\n"
                    "}\n"
                    "This provides:\n"
                    "- Automated CVE scanning for all pushed images\n"
                    "- Continuous monitoring of registries\n"
                    "- Integration with Microsoft Defender for Cloud\n"
                    "- Supply chain risk alerts"
                )
            ))
        
        return findings

    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for supply chain monitoring compliance.
        IaC uses regex-based analysis (no tree-sitter parser).
        
        Detects:
        - Azure Container Registry without Microsoft Defender for Containers
        - Missing vulnerability scanning for container images
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Container Registry without Defender/scanning (MEDIUM)
        has_acr = re.search(r'resource\s+"azurerm_container_registry"', code)
        has_defender = re.search(r'azurerm_security_center_subscription_pricing.*ContainerRegistry', code, re.DOTALL)
        
        if has_acr and not has_defender:
            line_num = self._find_text_line(lines, "azurerm_container_registry")
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Container Registry Without Vulnerability Scanning",
                description=(
                    f"Azure Container Registry without Microsoft Defender for Containers. "
                    f"KSI-TPR-04 requires automated vulnerability monitoring of third-party software (container images). "
                    f"Defender provides automated CVE scanning and supply chain threat detection."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Enable Microsoft Defender for Containers:\n"
                    "resource \"azurerm_security_center_subscription_pricing\" \"containers\" {\n"
                    "  tier          = \"Standard\"\n"
                    "  resource_type = \"ContainerRegistry\"\n"
                    "}\n"
                    "This enables:\n"
                    "- Automated vulnerability scanning for all images\n"
                    "- Real-time CVE detection and alerting\n"
                    "- Supply chain threat intelligence\n"
                    "- Integration with Azure Security Center"
                )
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for supply chain monitoring compliance.
        
        Detects:
        - Missing dependency vulnerability scanning (Dependabot, Snyk, dependency-review-action)
        - Absence of automated CVE monitoring
        """
        findings = []
        lines = code.split('\n')
        
        # Remove YAML comments (lines starting with # or text after #)
        code_without_comments = '\n'.join(
            line.split('#')[0] for line in lines
        )
        
        # Check for dependency scanning actions
        has_scan = bool(re.search(
            r'uses:.*/?(snyk-actions|snyk/actions|dependency-review-action|anchore/scan-action|aquasecurity/trivy-action)',
            code_without_comments,
            re.IGNORECASE
        ))
        has_dependabot = 'dependabot' in code_without_comments.lower()
        
        if not has_scan and not has_dependabot:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Dependency Vulnerability Scanning",
                description=(
                    "GitHub Actions workflow without dependency vulnerability scanning. "
                    "KSI-TPR-04 requires automatic monitoring of third-party dependencies for CVEs. "
                    "Without automated scanning, vulnerable dependencies may reach production undetected."
                ),
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, context=5),
                recommendation=(
                    "Add dependency scanning to workflow:\n"
                    "jobs:\n"
                    "  dependency-review:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - name: Dependency Review\n"
                    "        uses: actions/dependency-review-action@v4\n"
                    "\n"
                    "Or enable Dependabot in .github/dependabot.yml:\n"
                    "version: 2\n"
                    "updates:\n"
                    "  - package-ecosystem: \"npm\"  # or pip, nuget, maven\n"
                    "    directory: \"/\"\n"
                    "    schedule:\n"
                    "      interval: \"daily\"\n"
                    "    open-pull-requests-limit: 10\n"
                    "\n"
                    "Or use Snyk:\n"
                    "      - name: Run Snyk\n"
                    "        uses: snyk/actions/node@master  # or python, dotnet, maven\n"
                    "        env:\n"
                    "          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}"
                )
            ))
        
        return findings

    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for supply chain monitoring compliance.
        
        Detects:
        - Missing dependency vulnerability scanning (Mend/WhiteSource, Snyk, Microsoft Security DevOps)
        - Absence of automated CVE monitoring
        """
        findings = []
        lines = code.split('\n')
        
        # Remove YAML comments
        code_without_comments = '\n'.join(
            line.split('#')[0] for line in lines
        )
        
        # Check for dependency scanning tasks
        has_scan = bool(re.search(
            r'(WhiteSource|MendBolt|Snyk|DependencyCheck|MicrosoftSecurityDevOps)',
            code_without_comments,
            re.IGNORECASE
        ))
        
        if not has_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Dependency Vulnerability Scanning",
                description=(
                    "Azure Pipeline without dependency vulnerability scanning task. "
                    "KSI-TPR-04 requires automatic monitoring of third-party dependencies for CVEs. "
                    "Without automated scanning, vulnerable packages may be deployed to production."
                ),
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, context=5),
                recommendation=(
                    "Add dependency scanning task (choose one):\n"
                    "\n"
                    "Option 1: Microsoft Defender for DevOps (Recommended):\n"
                    "- task: MicrosoftSecurityDevOps@1\n"
                    "  displayName: 'Run Microsoft Security DevOps'\n"
                    "  inputs:\n"
                    "    categories: 'dependencies'\n"
                    "\n"
                    "Option 2: Mend (formerly WhiteSource):\n"
                    "- task: WhiteSource@21\n"
                    "  inputs:\n"
                    "    cwd: '$(System.DefaultWorkingDirectory)'\n"
                    "    projectName: '$(Build.Repository.Name)'\n"
                    "\n"
                    "Option 3: Snyk:\n"
                    "- task: SnykSecurityScan@1\n"
                    "  inputs:\n"
                    "    serviceConnectionEndpoint: 'Snyk'\n"
                    "    testType: 'app'\n"
                    "    failOnIssues: true"
                )
            ))
        
        return findings

    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for supply chain monitoring compliance.
        
        Detects:
        - Missing dependency vulnerability scanning (GitLab Dependency Scanning, Container Scanning)
        - Absence of security templates
        """
        findings = []
        lines = code.split('\n')
        
        # Remove YAML comments
        code_without_comments = '\n'.join(
            line.split('#')[0] for line in lines
        )
        
        # Check for dependency scanning
        has_scan = bool(re.search(
            r'(dependency_scanning|container_scanning|sast|Dependency-Scanning\.gitlab-ci\.yml)',
            code_without_comments,
            re.IGNORECASE
        ))
        
        if not has_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Dependency Vulnerability Scanning",
                description=(
                    "GitLab CI without dependency vulnerability scanning. "
                    "KSI-TPR-04 requires automatic monitoring of third-party dependencies for CVEs. "
                    "GitLab provides built-in dependency scanning that should be enabled."
                ),
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, context=5),
                recommendation=(
                    "Add dependency scanning to .gitlab-ci.yml:\n"
                    "\n"
                    "include:\n"
                    "  - template: Security/Dependency-Scanning.gitlab-ci.yml\n"
                    "  - template: Security/Container-Scanning.gitlab-ci.yml\n"
                    "\n"
                    "Or define custom scan stage:\n"
                    "dependency_scanning:\n"
                    "  stage: test\n"
                    "  image: registry.gitlab.com/gitlab-org/security-products/analyzers/gemnasium:latest\n"
                    "  script:\n"
                    "    - /analyzer run\n"
                    "  artifacts:\n"
                    "    reports:\n"
                    "      dependency_scanning: gl-dependency-scanning-report.json\n"
                    "  only:\n"
                    "    - merge_requests\n"
                    "    - main"
                )
            ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_text_line(self, lines: List[str], text: str) -> int:
        """Find line number containing text (case-insensitive)."""
        text_lower = text.lower()
        for i, line in enumerate(lines, 1):
            if text_lower in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

