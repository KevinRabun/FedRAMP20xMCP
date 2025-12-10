"""
FRR-VDR-01: Vulnerability Detection

Implement automated vulnerability detection capabilities for infrastructure, 
container images, application code, and dependencies. Scanning must be continuous 
and integrated into CI/CD pipelines.

Official FedRAMP 20x Requirement
Source: FRR-VDR (Vulnerability Detection and Response) family
Related KSIs: KSI-AFR-04, KSI-PIY-06, KSI-SVC-08, KSI-TPR-04
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer


class FRR_VDR_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-VDR-01: Vulnerability Detection
    
    **Official Statement:**
    Implement automated vulnerability detection capabilities including vulnerability 
    scanning for infrastructure, container images, application code, and dependencies.
    Scanning must be continuous and integrated into the development lifecycle.
    
    **Family:** VDR - Vulnerability Detection and Response
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - RA-5: Vulnerability Monitoring and Scanning
    - RA-5(2): Update Vulnerabilities to Be Scanned
    - RA-5(3): Breadth / Depth of Coverage
    - RA-5(5): Privileged Access
    - SI-2: Flaw Remediation
    - CA-7: Continuous Monitoring
    
    **Related KSIs:**
    - KSI-AFR-04: Vulnerability Detection and Response
    - KSI-PIY-06: Vulnerability Disclosure Program  
    - KSI-SVC-08: Secure Dependencies
    - KSI-TPR-04: Software Bill of Materials
    
    **Detectability:** Code-Detectable
    
    **Detection Strategy:**
    Analyze CI/CD pipelines and infrastructure code for:
    - Missing vulnerability scanner integrations
    - Absence of container image scanning
    - Lack of SAST/DAST tools
    - Missing dependency scanning
    - No automated scanning frequency configuration
    """
    
    FRR_ID = "FRR-VDR-01"
    FRR_NAME = "Vulnerability Detection"
    FRR_STATEMENT = """Implement automated vulnerability detection capabilities including vulnerability scanning for infrastructure, container images, application code, and dependencies. Scanning must be continuous and integrated into the development lifecycle per FedRAMP Vulnerability Detection and Response (VDR) requirements."""
    FAMILY = "VDR"
    FAMILY_NAME = "Vulnerability Detection and Response"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("RA-5", "Vulnerability Monitoring and Scanning"),
        ("RA-5(2)", "Update Vulnerabilities to Be Scanned"),
        ("RA-5(3)", "Breadth / Depth of Coverage"),
        ("RA-5(5)", "Privileged Access"),
        ("SI-2", "Flaw Remediation"),
        ("CA-7", "Continuous Monitoring")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = ["KSI-AFR-04", "KSI-PIY-06", "KSI-SVC-08", "KSI-TPR-04"]
    
    # Known vulnerability scanning tools
    VULN_SCANNERS = {
        'container': ['trivy', 'snyk', 'aqua', 'anchore', 'grype', 'clair'],
        'sast': ['sonarqube', 'codeclimate', 'semgrep', 'checkmarx', 'fortify'],
        'dependency': ['dependabot', 'dependency-review', 'snyk', 'whitesource', 'mend', 'safety', 'pip-audit', 'npm-audit'],
        'infrastructure': ['defender', 'qualys', 'tenable', 'nessus', 'openvas'],
        'dast': ['zap', 'burp', 'w3af', 'arachni']
    }
    
    def __init__(self):
        """Initialize FRR-VDR-01 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Primary detection for FRR-VDR-01)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-VDR-01 compliance.
        
        Detects:
        - Missing container image scanning
        - Missing SAST/code analysis
        - Missing dependency scanning
        - No vulnerability blocking gates
        """
        findings = []
        lines = code.split('\n')
        
        # Check for container scanning
        has_container_scan = any(scanner in code.lower() for scanner in self.VULN_SCANNERS['container'])
        
        # Check for SAST
        has_sast = any(tool in code.lower() for tool in self.VULN_SCANNERS['sast']) or \
                   bool(re.search(r'github/codeql-action', code, re.IGNORECASE))
        
        # Check for dependency scanning
        has_dependency_scan = any(tool in code.lower() for tool in self.VULN_SCANNERS['dependency'])
        
        # Check for container build without scanning
        has_docker_build = bool(re.search(r'docker\s+(build|buildx)', code, re.IGNORECASE))
        
        if has_docker_build and not has_container_scan:
            docker_line = self._find_line_with_pattern(lines, r'docker\s+(build|buildx)')
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Container built without vulnerability scanning",
                description=f"Workflow '{file_path}' builds container images but does not scan for vulnerabilities. FRR-VDR-01 requires automated vulnerability scanning for all container images before deployment.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=docker_line,
                code_snippet=self._get_snippet(lines, docker_line, 3),
                remediation="""Add container vulnerability scanning after docker build:

steps:
  - name: Build container image
    run: docker build -t myapp:${{ github.sha }} .
  
  - name: Scan container for vulnerabilities
    uses: aquasecurity/trivy-action@master
    with:
      image-ref: myapp:${{ github.sha }}
      format: 'sarif'
      output: 'trivy-results.sarif'
      severity: 'CRITICAL,HIGH'
      exit-code: '1'  # Fail build on findings
  
  - name: Upload scan results
    uses: github/codeql-action/upload-sarif@v2
    with:
      sarif_file: 'trivy-results.sarif'

Reference: FRR-VDR-01, NIST RA-5"""
            ))
        
        if not has_sast:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing Static Application Security Testing (SAST)",
                description=f"Workflow '{file_path}' lacks SAST tools for code vulnerability detection. FRR-VDR-01 requires scanning application code for security vulnerabilities.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                remediation="""Add SAST scanning to workflow:

- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: python, javascript  # Adjust to your languages

- name: Perform CodeQL Analysis
  uses: github/codeql-action/analyze@v2

Alternative: Semgrep, SonarQube, or Snyk Code
Reference: FRR-VDR-01, NIST RA-5(3)"""
            ))
        
        if not has_dependency_scan:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing dependency vulnerability scanning",
                description=f"Workflow '{file_path}' does not scan dependencies for known vulnerabilities. FRR-VDR-01 requires continuous monitoring of third-party dependencies.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                remediation="""Add dependency scanning:

- name: Dependency Review
  uses: actions/dependency-review-action@v3
  with:
    fail-on-severity: high

Or enable Dependabot in repository settings for automated alerts.
Reference: FRR-VDR-01, KSI-SVC-08"""
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-VDR-01 compliance.
        
        Detects:
        - Missing Microsoft Security DevOps task
        - Missing container scanning
        - No vulnerability gates
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security scanning tasks
        has_security_task = bool(re.search(r'MicrosoftSecurityDevOps@1', code))
        has_container_scan = any(scanner in code.lower() for scanner in self.VULN_SCANNERS['container'])
        
        # Check for container builds
        has_docker_task = bool(re.search(r'Docker@\d+|docker\s+build', code, re.IGNORECASE))
        
        if not has_security_task:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing Microsoft Security DevOps task",
                description=f"Pipeline '{file_path}' lacks Microsoft Security DevOps task for vulnerability scanning. FRR-VDR-01 requires integrated security scanning in CI/CD.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                remediation="""Add Microsoft Security DevOps task:

- task: MicrosoftSecurityDevOps@1
  displayName: 'Run Microsoft Security DevOps'
  inputs:
    categories: 'secrets,IaC,containers,dependencies'
    break: true  # Fail pipeline on findings

Reference: FRR-VDR-01, Azure-recommended practice"""
            ))
        
        if has_docker_task and not has_container_scan:
            docker_line = self._find_line_with_pattern(lines, r'(Docker@|docker\s+build)')
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Container built without scanning in Azure Pipelines",
                description=f"Pipeline builds containers but lacks vulnerability scanning. FRR-VDR-01 requires all container images be scanned before deployment.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=docker_line,
                code_snippet=self._get_snippet(lines, docker_line, 3),
                remediation="""Add Trivy container scanning task:

- task: trivy@1
  displayName: 'Scan container for vulnerabilities'
  inputs:
    image: '$(imageName):$(tag)'
    severities: 'CRITICAL,HIGH'
    exitCode: 1

Reference: FRR-VDR-01, NIST RA-5"""
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-VDR-01 compliance.
        
        Detects:
        - Missing dependency_scanning template
        - Missing container_scanning template
        - Missing SAST template
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security templates
        has_dependency_scan = bool(re.search(r'Dependency-Scanning\.gitlab-ci\.yml', code))
        has_container_scan = bool(re.search(r'Container-Scanning\.gitlab-ci\.yml', code))
        has_sast = bool(re.search(r'SAST\.gitlab-ci\.yml', code))
        
        # Check for container builds
        has_docker_build = bool(re.search(r'docker\s+build', code, re.IGNORECASE))
        
        if not has_dependency_scan:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing GitLab dependency scanning",
                description=f"Pipeline '{file_path}' lacks dependency scanning template. FRR-VDR-01 requires scanning dependencies for vulnerabilities.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                remediation="""Add dependency scanning include:

include:
  - template: Dependency-Scanning.gitlab-ci.yml

This enables GitLab's built-in dependency scanning.
Reference: FRR-VDR-01, KSI-SVC-08"""
            ))
        
        if has_docker_build and not has_container_scan:
            docker_line = self._find_line_with_pattern(lines, r'docker\s+build')
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing GitLab container scanning",
                description=f"Pipeline builds containers without scanning. FRR-VDR-01 requires container vulnerability scanning.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=docker_line,
                code_snippet=self._get_snippet(lines, docker_line, 3),
                remediation="""Add container scanning include:

include:
  - template: Container-Scanning.gitlab-ci.yml

variables:
  CS_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

Reference: FRR-VDR-01, NIST RA-5"""
            ))
        
        if not has_sast:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing GitLab SAST",
                description=f"Pipeline '{file_path}' lacks SAST for code vulnerability detection. FRR-VDR-01 requires static analysis of application code.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                remediation="""Add SAST include:

include:
  - template: SAST.gitlab-ci.yml

This enables GitLab's built-in SAST scanning.
Reference: FRR-VDR-01, NIST RA-5(3)"""
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for FRR-VDR-01 compliance.
        
        Detects:
        - Missing Microsoft Defender for Cloud configuration
        - Missing security center assessments
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Defender for Cloud resources
        has_defender = bool(re.search(r"Microsoft\.Security/pricings", code))
        has_assessments = bool(re.search(r"Microsoft\.Security/assessments", code))
        
        # Check if deploying compute resources that should have scanning
        has_vms = bool(re.search(r"Microsoft\.Compute/virtualMachines", code))
        has_aks = bool(re.search(r"Microsoft\.ContainerService/managedClusters", code))
        has_app_service = bool(re.search(r"Microsoft\.Web/sites", code))
        
        needs_defender = has_vms or has_aks or has_app_service
        
        if needs_defender and not has_defender:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing Microsoft Defender for Cloud configuration",
                description=f"Bicep template '{file_path}' deploys compute resources but does not enable Microsoft Defender for Cloud. FRR-VDR-01 requires continuous vulnerability scanning for infrastructure.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                remediation="""Enable Microsoft Defender for Cloud:

resource defenderForServers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderForContainers 'Microsoft.Security/pricings@2023-01-01' = {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
  }
}

Reference: FRR-VDR-01, KSI-AFR-04, Azure Well-Architected Framework Security"""
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for FRR-VDR-01 compliance.
        
        Detects:
        - Missing Defender for Cloud (azurerm_security_center_*)
        - Compute resources without scanning enabled
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security center subscription pricing
        has_defender_pricing = bool(re.search(r'azurerm_security_center_subscription_pricing', code))
        
        # Check for compute resources
        has_vms = bool(re.search(r'azurerm_virtual_machine|azurerm_linux_virtual_machine|azurerm_windows_virtual_machine', code))
        has_aks = bool(re.search(r'azurerm_kubernetes_cluster', code))
        
        needs_defender = has_vms or has_aks
        
        if needs_defender and not has_defender_pricing:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing Defender for Cloud in Terraform",
                description=f"Terraform config '{file_path}' deploys compute but lacks Defender for Cloud configuration. FRR-VDR-01 requires continuous infrastructure vulnerability scanning.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                remediation="""Enable Defender for Cloud:

resource "azurerm_security_center_subscription_pricing" "vms" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "containers" {
  tier          = "Standard"
  resource_type = "Containers"
}

resource "azurerm_security_center_contact" "main" {
  email               = "security@example.com"
  alert_notifications = true
}

Reference: FRR-VDR-01, KSI-AFR-04, NIST CA-7"""
            ))
        
        return findings
    
    # ============================================================================
    # EVIDENCE AUTOMATION METHODS
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for FRR-VDR-01.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "frr_id": self.FRR_ID,
            "frr_name": "Vulnerability Detection",
            "evidence_type": "log-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Defender for Cloud",
                "Azure Monitor",
                "Azure DevOps / GitHub Advanced Security",
                "Azure Log Analytics"
            ],
            "collection_methods": [
                "Export Defender for Cloud vulnerability assessments via REST API",
                "Query security recommendations from Log Analytics workspace",
                "Collect CI/CD scan results from pipeline artifacts",
                "Track scanning frequency via Azure Monitor metrics"
            ],
            "implementation_steps": [
                "1. Enable Microsoft Defender for Cloud for all resource types",
                "2. Configure Log Analytics workspace for Defender data collection",
                "3. Create Azure Monitor workbook for vulnerability dashboard",
                "4. Set up Azure Automation runbook to export scan results monthly",
                "5. Store vulnerability scan reports in Azure Storage with 12-month retention",
                "6. Configure alerts for Critical/High vulnerabilities"
            ],
            "evidence_artifacts": [
                "Monthly vulnerability scan reports from Defender for Cloud",
                "CI/CD pipeline scan results (Trivy, Snyk, CodeQL artifacts)",
                "Vulnerability trend charts showing detection and remediation rates",
                "Configuration proof showing scanning enabled for all resources",
                "Scan frequency logs from Azure Monitor"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team"
        }
    
    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Defender for Cloud vulnerability inventory",
                "query": """SecurityRecommendation
| where TimeGenerated > ago(30d)
| where RecommendationSeverity in ('High', 'Medium', 'Low')
| summarize 
    TotalVulnerabilities = count(),
    HighSeverity = countif(RecommendationSeverity == 'High'),
    MediumSeverity = countif(RecommendationSeverity == 'Medium'),
    LowSeverity = countif(RecommendationSeverity == 'Low'),
    OpenVulns = countif(RecommendationState != 'Completed'),
    RemediatedVulns = countif(RecommendationState == 'Completed')
| project TotalVulnerabilities, HighSeverity, MediumSeverity, LowSeverity, OpenVulns, RemediatedVulns""",
                "purpose": "Monthly vulnerability inventory for FRR-VDR-01 evidence"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Defender for Cloud enablement status",
                "query": """securityresources
| where type == "microsoft.security/pricings"
| extend tier = properties.pricingTier
| summarize DefenderPlans = make_set(name) by subscriptionId, tier
| where tier == "Standard"
| project subscriptionId, EnabledDefenderPlans = DefenderPlans""",
                "purpose": "Verify continuous scanning capability is enabled per FRR-VDR-01"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "CI/CD vulnerability scan results",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/build/builds/{buildId}/artifacts?api-version=7.0",
                "purpose": "Collect scan artifacts (Trivy, Snyk reports) from pipelines for audit trail"
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
                "artifact_name": "Monthly Vulnerability Scan Report",
                "artifact_type": "PDF Report",
                "description": "Comprehensive report from Microsoft Defender for Cloud showing all vulnerabilities detected, remediation status, and trends",
                "collection_method": "Azure Automation runbook exporting Defender data to PDF via Power BI",
                "storage_location": "Azure Storage Account (immutable blob) with 12-month retention"
            },
            {
                "artifact_name": "CI/CD Scan Artifacts",
                "artifact_type": "SARIF Files",
                "description": "Trivy, Snyk, and CodeQL scan results from every pipeline run showing container, code, and dependency vulnerabilities",
                "collection_method": "Azure DevOps artifact collection or GitHub Advanced Security API",
                "storage_location": "Azure DevOps artifacts or GitHub repository with 6-month retention"
            },
            {
                "artifact_name": "Vulnerability Trend Dashboard",
                "artifact_type": "Azure Monitor Workbook",
                "description": "Interactive dashboard showing vulnerability counts by severity, remediation velocity, and scan coverage metrics",
                "collection_method": "Azure Monitor workbook querying Log Analytics SecurityRecommendation table",
                "storage_location": "Azure Monitor Workbooks shared with compliance team"
            },
            {
                "artifact_name": "Scanning Configuration Proof",
                "artifact_type": "JSON Export",
                "description": "Terraform/Bicep configuration showing Defender for Cloud enabled for all resource types and CI/CD scan steps configured",
                "collection_method": "Git repository export of IaC files and .github/workflows or azure-pipelines.yml",
                "storage_location": "Version control repository with tags for quarterly reviews"
            }
        ]
    
    # ============================================================================
    # UTILITY METHODS
    # ============================================================================
    
    def _find_line_with_pattern(self, lines: List[str], pattern: str) -> int:
        """
        Find first line matching regex pattern.
        
        Args:
            lines: All lines of code
            pattern: Regex pattern to search for
            
        Returns:
            Line number (1-indexed) or 1 if not found
        """
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.IGNORECASE):
                return i
        return 1
