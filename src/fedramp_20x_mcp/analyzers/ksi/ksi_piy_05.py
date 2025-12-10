"""
KSI-PIY-05: Evaluate Implementations

Document methods used to evaluate information resource implementations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_05_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-05: Evaluate Implementations
    
    **Official Statement:**
    Document methods used to evaluate information resource implementations.
    
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
    
    KSI_ID = "KSI-PIY-05"
    KSI_NAME = "Evaluate Implementations"
    KSI_STATEMENT = """Document methods used to evaluate information resource implementations."""
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
        Analyze Python code for KSI-PIY-05 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Document methods used to evaluate information resource implementations....
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
        Analyze C# code for KSI-PIY-05 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Document methods used to evaluate information resource implementations....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-05 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Document methods used to evaluate information resource implementations....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-05 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Document methods used to evaluate information resource implementations....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-05 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document methods used to evaluate information resource implementations....
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-05 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document methods used to evaluate information resource implementations....
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-05 compliance.
        
        Detects:
        - Missing automated code scanning
        - Missing security code review automation
        - Missing vulnerability scanning
        """
        findings = []
        lines = code.split('\n')
        
        # Check for comprehensive scanning
        has_code_scan = bool(re.search(r'(codeql|sonarqube|sonarcloud)', code, re.IGNORECASE))
        has_vuln_scan = bool(re.search(r'(snyk|trivy|grype|anchore)', code, re.IGNORECASE))
        has_secret_scan = bool(re.search(r'(gitleaks|trufflehog|detect.*secrets)', code, re.IGNORECASE))
        has_dependency_scan = bool(re.search(r'(dependabot|dependency.*(check|review|scan))', code, re.IGNORECASE))
        
        if not has_code_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing automated code scanning",
                description="No automated code scanning tool detected. KSI-PIY-05 requires automated code scanning integrated into development.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add CodeQL: - name: Initialize CodeQL\n  uses: github/codeql-action/init@v2\n  with:\n    languages: python, javascript"
            ))
        
        if not has_secret_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing secret scanning",
                description="No secret scanning detected. KSI-PIY-05 requires comprehensive security scanning including secrets.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add secret scanning: - name: GitLeaks Scan\n  uses: gitleaks/gitleaks-action@v2"
            ))
        
        if not has_dependency_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing dependency scanning",
                description="No dependency vulnerability scanning. KSI-PIY-05 requires scanning of dependencies for vulnerabilities.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Enable GitHub Dependabot or add: - name: Dependency Scan\n  uses: snyk/actions/node@master"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Evaluate Implementations",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": ["Azure DevOps", "Microsoft Defender for Cloud", "Azure Policy", "Power BI", "Azure Monitor"],
            "collection_methods": [
                "Azure DevOps to document evaluation methods in Design Review work items with Architecture Decision Records (ADRs)",
                "Microsoft Defender for Cloud to evaluate implementation security posture with Secure Score and recommendations",
                "Azure Policy to validate implementations meet baseline configurations and compliance standards",
                "Power BI to track evaluation metrics: ADR completion rate, security score trends, policy compliance over time",
                "Azure Monitor to track implementation validation frequency and identify unevaluated deployments"
            ],
            "implementation_steps": [
                "1. Create Azure DevOps Design Review process: (a) Work item type 'Design Review' with fields: ServiceName, ArchitectureDiagram, SecurityControls, ComplianceRequirements, EvaluationMethod, ReviewDate, Approvers, (b) Require ADRs (Architecture Decision Records) documenting evaluation rationale, (c) Approval gate: Security Architect + Cloud Architect sign-off before implementation",
                "2. Evaluate with Microsoft Defender for Cloud: (a) Run Defender assessment for new implementations (VMs, databases, storage, networking), (b) Validate Secure Score >= 80% before production deployment, (c) Remediate Critical/High recommendations within 30 days, (d) Re-evaluate quarterly and track score trends",
                "3. Validate with Azure Policy: (a) Policy: Require baseline configurations (TLS 1.2+, HTTPS-only, private endpoints), (b) Policy: Require compliance tagging (NIST 800-53, FedRAMP), (c) Scan new deployments for policy violations within 24 hours, (d) Generate implementation compliance report",
                "4. Build Power BI Evaluation Metrics Dashboard: (a) ADR completion rate by service (target 100%), (b) Security Score trends post-implementation (target >= 80%), (c) Policy compliance rate for new implementations (target >= 95%), (d) Time from deployment to evaluation (target < 7 days)",
                "5. Track with Azure Monitor: (a) Log Design Review work item lifecycle (creation, approval, implementation), (b) Track Defender assessment frequency (target: quarterly), (c) Alert on unevaluated deployments (> 7 days old), (d) Generate quarterly evaluation effectiveness report",
                "6. Generate quarterly evidence package: (a) Export DevOps Design Review work items with ADRs and approvals, (b) Export Defender Secure Score by service with recommendation compliance, (c) Export Azure Policy implementation compliance report, (d) Export Power BI dashboard showing >= 95% evaluation compliance"
            ],
            "evidence_artifacts": [
                "Azure DevOps Design Review Work Items with Architecture Decision Records (ADRs) and security architect approvals",
                "Microsoft Defender for Cloud Secure Score Report showing >= 80% score for new implementations with remediation tracking",
                "Azure Policy Implementation Compliance Report validating baseline configurations and compliance tagging (>= 95%)",
                "Power BI Evaluation Metrics Dashboard tracking ADR completion (100%), Secure Score trends, and evaluation timeliness (< 7d)",
                "Azure Monitor Evaluation Frequency Report tracking Design Review lifecycle and unevaluated deployment alerts"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Security Architect / Cloud Architect"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Azure DevOps REST API", "query_name": "Design Review work items with ADRs", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\\nBody: {\\\"query\\\": \\\"SELECT [System.Id], [System.Title], [Custom.ServiceName], [Custom.EvaluationMethod], [Custom.ReviewDate], [Custom.Approvers], [Custom.ADRComplete] FROM WorkItems WHERE [System.WorkItemType] = 'Design Review' ORDER BY [Custom.ReviewDate] DESC\\\"}", "purpose": "Retrieve Design Review work items with evaluation methods (ADRs) and security architect approvals"},
            {"query_type": "Microsoft Defender for Cloud REST API", "query_name": "Secure Score by service with recommendations", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01&$expand=recommendations", "purpose": "Retrieve Secure Score for implementations with recommendation compliance (target >= 80%)"},
            {"query_type": "Azure Policy REST API", "query_name": "Implementation policy compliance", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&$filter=policyDefinitionName eq 'require-baseline-config' or policyDefinitionName eq 'require-compliance-tagging'", "purpose": "Retrieve policy compliance for new implementations (baseline configs, compliance tagging)"},
            {"query_type": "Power BI REST API", "query_name": "Evaluation metrics and compliance rates", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(EvaluationMetrics, EvaluationMetrics[ServiceName], 'TotalImplementations', COUNT(EvaluationMetrics[ImplementationID]), 'ADRComplete', COUNTIF(EvaluationMetrics[ADRComplete] = TRUE), 'SecureScoreAvg', AVERAGE(EvaluationMetrics[SecureScore]), 'PolicyCompliant', COUNTIF(EvaluationMetrics[PolicyCompliance] = 'Compliant'))\\\"}]}", "purpose": "Calculate evaluation metrics: ADR completion (100%), Secure Score avg (>= 80%), policy compliance (>= 95%)"},
            {"query_type": "Azure Monitor KQL", "query_name": "Evaluation frequency and unevaluated deployments", "query": "AzureActivity\n| where OperationNameValue contains 'Microsoft.Resources/deployments/write'\n| join kind=leftouter (AzureDevOpsWorkItems\n    | where WorkItemType == 'Design Review') on $left.ResourceId == $right.ResourceId\n| extend Evaluated = iff(isnotnull(WorkItemId), 'Yes', 'No'), DaysSinceDeployment = datetime_diff('day', now(), TimeGenerated)\n| where Evaluated == 'No' and DaysSinceDeployment > 7\n| summarize UnevaluatedDeployments = count() by SubscriptionId, ResourceGroup, bin(TimeGenerated, 7d)", "purpose": "Track unevaluated deployments (> 7 days old) and evaluation frequency compliance"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "DevOps Design Review Work Items", "artifact_type": "Design Review Documentation", "description": "Complete Design Review work items with Architecture Decision Records (ADRs), evaluation methods, and security architect approvals", "collection_method": "Azure DevOps REST API to export Design Review work items with ADR completion status", "storage_location": "Azure DevOps database with historical design review tracking and approval audit trail"},
            {"artifact_name": "Defender Secure Score Report", "artifact_type": "Security Posture Evaluation", "description": "Secure Score by service (>= 80% target) with security recommendations and remediation tracking for new implementations", "collection_method": "Microsoft Defender for Cloud REST API to export secureScores with recommendation compliance", "storage_location": "Azure Storage Account with quarterly Secure Score snapshots and trend analysis"},
            {"artifact_name": "Azure Policy Implementation Compliance Report", "artifact_type": "Configuration Validation Report", "description": "Policy compliance for new implementations: baseline configurations (TLS, HTTPS, private endpoints), compliance tagging (>= 95% target)", "collection_method": "Azure Policy REST API to retrieve policyStates for implementation validation policies", "storage_location": "Azure Storage Account with monthly implementation compliance reports"},
            {"artifact_name": "Power BI Evaluation Metrics Dashboard", "artifact_type": "Evaluation Effectiveness Dashboard", "description": "Dashboard showing ADR completion (100%), Secure Score trends (>= 80%), policy compliance (>= 95%), evaluation timeliness (< 7d)", "collection_method": "Power BI REST API to export evaluation metrics for executive reporting", "storage_location": "SharePoint with quarterly PDF snapshots for architecture review board"},
            {"artifact_name": "Azure Monitor Evaluation Frequency Report", "artifact_type": "Evaluation Tracking Report", "description": "Report tracking Design Review lifecycle, evaluation frequency (quarterly), and unevaluated deployments (> 7 days old)", "collection_method": "Azure Monitor KQL query analyzing deployment activity and Design Review work item correlation", "storage_location": "Azure Log Analytics workspace with quarterly evaluation effectiveness summaries"}
        ]
    
