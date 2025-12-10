"""
KSI-TPR-04 Enhanced: Supply Chain Risk Monitoring

Automatically monitor third party software information resources for upstream vulnerabilities 
using mechanisms that may include contractual notification requirements or active monitoring services.

Enhanced with AST-based analysis where applicable.
"""

import re
from typing import List, Dict, Any
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

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-TPR-04.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Supply Chain Risk Monitoring",
            "evidence_type": "log-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Defender for Cloud",
                "GitHub Advanced Security",
                "Azure Container Registry",
                "Azure Monitor",
                "Azure Logic Apps"
            ],
            "collection_methods": [
                "GitHub Dependabot and Advanced Security to automatically detect vulnerable dependencies with CVE alerts",
                "Azure Container Registry vulnerability scanning with Microsoft Defender for Containers integration",
                "Microsoft Defender for Cloud continuous assessment of third-party software risks across Azure resources",
                "Azure Monitor alerts to notify security team of new HIGH/CRITICAL CVEs in production dependencies",
                "Azure Logic Apps to automate vendor notification workflows when upstream vulnerabilities are detected"
            ],
            "implementation_steps": [
                "1. Enable GitHub Dependabot across all repositories: (a) Configure Dependabot version updates with daily security-only checks, (b) Enable Dependabot alerts with email/Slack notifications, (c) Set auto-merge rules for LOW severity patches, (d) Require PR approval for MEDIUM/HIGH/CRITICAL patches",
                "2. Activate Azure Container Registry vulnerability scanning: (a) Enable Microsoft Defender for Containers for all ACR instances, (b) Configure continuous scanning for all pushed images, (c) Set image quarantine policies for HIGH/CRITICAL findings, (d) Generate weekly vulnerability scan reports",
                "3. Deploy Microsoft Defender for Cloud continuous monitoring: (a) Enable Defender for Servers, Containers, App Service, and Databases, (b) Configure vulnerability assessment agents on all VMs, (c) Set alert rules for new CVEs in installed packages, (d) Integrate with Azure Sentinel for centralized alerting",
                "4. Create Azure Monitor alert rules for supply chain risks: (a) Alert on Dependabot CVE detection (HIGH/CRITICAL severity), (b) Alert on ACR quarantined images due to vulnerabilities, (c) Alert on Defender recommendations for outdated/vulnerable software, (d) Route alerts to security team via email, Teams, or PagerDuty",
                "5. Build Azure Logic App vendor notification workflow: (a) Triggered by Defender/Dependabot CVE alerts, (b) Query vendor contract database for notification requirements, (c) Send automated email to vendor with CVE details and remediation request, (d) Create tracking ticket in Azure DevOps, (e) Set 7-day follow-up reminder",
                "6. Generate monthly evidence package: (a) Export Dependabot security alerts with remediation status, (b) Export ACR vulnerability scan results with quarantine logs, (c) Export Defender for Cloud continuous assessment findings, (d) Export vendor notification logs with response tracking"
            ],
            "evidence_artifacts": [
                "GitHub Dependabot Security Alerts with CVE details, severity ratings, and remediation tracking (patched/deferred/accepted risk)",
                "Azure Container Registry Vulnerability Scan Results showing continuous monitoring of all container images with quarantine logs",
                "Microsoft Defender for Cloud Continuous Assessment Report identifying third-party software vulnerabilities across Azure resources",
                "Azure Monitor Alert History for supply chain CVE notifications and automated vendor communications",
                "Vendor Notification Tracking Log from Azure Logic Apps showing upstream vulnerability communications and response SLAs"
            ],
            "update_frequency": "monthly",
            "responsible_party": "DevSecOps Team / Vulnerability Management Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "GitHub REST API",
                "query_name": "Dependabot security alerts with CVE tracking",
                "query": "GET https://api.github.com/repos/{owner}/{repo}/dependabot/alerts?state=open,fixed&severity=critical,high",
                "purpose": "Retrieve Dependabot security alerts showing automated CVE detection and remediation tracking"
            },
            {
                "query_type": "Azure Container Registry REST API",
                "query_name": "Container image vulnerability scan results",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/listUsages?api-version=2023-01-01-preview",
                "purpose": "Retrieve ACR vulnerability scan results showing continuous monitoring of container images"
            },
            {
                "query_type": "Microsoft Defender for Cloud REST API",
                "query_name": "Continuous assessment findings for third-party software",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01&$filter=properties/status/code eq 'Unhealthy' and properties/displayName contains 'vulnerabilities'",
                "purpose": "Retrieve Defender continuous assessment findings identifying vulnerable third-party software"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Supply chain CVE alert history",
                "query": """AzureActivity
| where OperationNameValue contains 'Microsoft.Security/assessments/write' or OperationNameValue contains 'Microsoft.ContainerRegistry/registries/quarantineRead'
| extend AlertType = case(
    OperationNameValue contains 'assessments', 'Defender CVE Alert',
    OperationNameValue contains 'quarantine', 'ACR Image Quarantine',
    'Other'
)
| summarize AlertCount = count(), LastAlert = max(TimeGenerated) by AlertType, ResourceGroup, bin(TimeGenerated, 1d)
| order by LastAlert desc""",
                "purpose": "Track history of supply chain CVE alerts and automated responses (Defender, ACR quarantine)"
            },
            {
                "query_type": "Azure Logic Apps REST API",
                "query_name": "Vendor notification workflow execution logs",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Logic/workflows/{workflowName}/runs?api-version=2016-06-01&$filter=status eq 'Succeeded'",
                "purpose": "Retrieve vendor notification workflow logs showing automated communications for upstream vulnerabilities"
            }
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect.
        
        Returns:
            List of artifact dictionaries
        """
        return [
            {
                "artifact_name": "GitHub Dependabot Security Alerts Report",
                "artifact_type": "CVE Alert Export",
                "description": "Complete list of Dependabot security alerts with CVE details, severity ratings, and remediation status (patched/deferred/accepted)",
                "collection_method": "GitHub REST API to retrieve Dependabot alerts filtered by severity (CRITICAL, HIGH)",
                "storage_location": "Azure Storage Account with monthly exports showing CVE detection and remediation timelines"
            },
            {
                "artifact_name": "Azure Container Registry Vulnerability Scan Results",
                "artifact_type": "Container Security Report",
                "description": "Vulnerability scan results for all container images with continuous monitoring status and quarantine logs",
                "collection_method": "Azure Container Registry REST API to retrieve vulnerability assessments from Microsoft Defender integration",
                "storage_location": "Azure Storage Account with weekly scan results and quarantine event logs"
            },
            {
                "artifact_name": "Defender for Cloud Continuous Assessment Report",
                "artifact_type": "Security Assessment Export",
                "description": "Continuous assessment findings identifying third-party software vulnerabilities across all Azure resources",
                "collection_method": "Microsoft Defender for Cloud REST API to export unhealthy vulnerability assessments",
                "storage_location": "Azure Storage Account with JSON exports organized by resource type and severity"
            },
            {
                "artifact_name": "Azure Monitor Supply Chain Alert History",
                "artifact_type": "Alert Log Export",
                "description": "History of supply chain CVE alerts from Defender and ACR with automated response tracking",
                "collection_method": "Azure Monitor KQL query exporting alert history for CVE detection and quarantine events",
                "storage_location": "Azure Log Analytics workspace with 12-month retention and alert correlation"
            },
            {
                "artifact_name": "Vendor Notification Workflow Logs",
                "artifact_type": "Azure Logic Apps Execution History",
                "description": "Logs of automated vendor notifications for upstream vulnerabilities including response tracking and SLA compliance",
                "collection_method": "Azure Logic Apps REST API to retrieve workflow execution history with success/failure status",
                "storage_location": "Azure Storage Account with workflow run history and vendor response timestamps"
            }
        ]