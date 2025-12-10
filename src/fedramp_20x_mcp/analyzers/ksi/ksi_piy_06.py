"""
KSI-PIY-06: Security Investment Effectiveness

Monitor the effectiveness of the organization's investments in achieving security objectives.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
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
    NIST_CONTROLS = [
        ("ac-5", "Separation of Duties"),
        ("ca-2", "Control Assessments"),
        ("cp-2.1", "Coordinate with Related Plans"),
        ("cp-4.1", "Coordinate with Related Plans"),
        ("ir-3.2", "Coordination with Related Plans"),
        ("pm-3", "Information Security and Privacy Resources"),
        ("sa-2", "Allocation of Resources"),
        ("sa-3", "System Development Life Cycle"),
        ("sr-2.1", "Establish SCRM Team")
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

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Security Investment Effectiveness",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": ["Azure Cost Management", "Microsoft Defender for Cloud", "Power BI", "Azure DevOps", "Microsoft Dataverse"],
            "collection_methods": [
                "Azure Cost Management to track security spending (Defender, Sentinel, Key Vault, Firewall, security tooling) with cost allocation tags",
                "Microsoft Defender for Cloud to measure security effectiveness with Secure Score improvement and vulnerability reduction metrics",
                "Power BI to correlate security investment with security outcomes (ROI: Cost per Secure Score point, cost per vulnerability remediated)",
                "Azure DevOps to track security project investments (training, tooling, remediation) with budget vs. actual spend",
                "Microsoft Dataverse to maintain security investment registry with business justification and effectiveness tracking"
            ],
            "implementation_steps": [
                "1. Tag resources with Azure Cost Management: (a) Tag security resources: CostCenter=Security, Category=Defender|Sentinel|Firewall|KeyVault|Tooling, (b) Create cost allocation report showing security spending by category, (c) Track monthly security spend trends, (d) Compare to budget and forecast annual security costs",
                "2. Measure effectiveness with Defender for Cloud: (a) Track Secure Score improvement over time (target: +5% per quarter), (b) Track vulnerability reduction (Critical/High resolved per quarter), (c) Track MTTD (Mean Time To Detect) and MTTR (Mean Time To Remediate), (d) Calculate security effectiveness: Vulnerabilities resolved / Total vulnerabilities detected",
                "3. Build Power BI Security Investment ROI Dashboard: (a) Security spend by category with trend analysis, (b) Secure Score per $1000 invested (ROI metric), (c) Vulnerabilities remediated per $1000 invested, (d) Cost avoidance: Prevented incidents * Average breach cost ($4.45M per IBM 2023 report)",
                "4. Track projects in Azure DevOps: (a) Security project work items with budget tracking (Training, Tooling, Remediation), (b) Track actual spend vs. budget per project, (c) Link projects to security outcomes (Secure Score improvement, vulnerability reduction), (d) Calculate project ROI: Outcome value / Project cost",
                "5. Maintain registry in Microsoft Dataverse: (a) Table: security_investments with columns: investmentid, category, cost, justification, secure_score_improvement, vulnerabilities_resolved, roi, (b) Quarterly review with CISO to validate effectiveness, (c) Defund low-ROI investments and increase high-ROI investments",
                "6. Generate quarterly evidence package: (a) Export Azure Cost Management security spend report, (b) Export Defender Secure Score improvement and vulnerability reduction metrics, (c) Export Power BI ROI dashboard showing cost per security outcome, (d) Export Dataverse investment registry with ROI analysis"
            ],
            "evidence_artifacts": [
                "Azure Cost Management Security Spend Report with cost allocation by category (Defender, Sentinel, Firewall, tooling)",
                "Microsoft Defender for Cloud Effectiveness Metrics: Secure Score improvement (+5% per quarter), vulnerability reduction (Critical/High)",
                "Power BI Security Investment ROI Dashboard showing cost per Secure Score point, cost per vulnerability remediated, and cost avoidance",
                "Azure DevOps Security Project Budget Tracking with actual vs. budget spend and project-level ROI calculations",
                "Microsoft Dataverse Security Investment Registry with business justification, effectiveness tracking, and quarterly ROI review"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "CISO / Finance / Security Operations"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Azure Cost Management REST API", "query_name": "Security spend by category", "query": "POST https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.CostManagement/query?api-version=2021-10-01\\nBody: {\\\"type\\\": \\\"ActualCost\\\", \\\"timeframe\\\": \\\"Custom\\\", \\\"timePeriod\\\": {\\\"from\\\": \\\"2024-01-01\\\", \\\"to\\\": \\\"2024-12-31\\\"}, \\\"dataset\\\": {\\\"granularity\\\": \\\"Monthly\\\", \\\"filter\\\": {\\\"tags\\\": {\\\"name\\\": \\\"CostCenter\\\", \\\"operator\\\": \\\"In\\\", \\\"values\\\": [\\\"Security\\\"]}}, \\\"grouping\\\": [{\\\"type\\\": \\\"Tag\\\", \\\"name\\\": \\\"Category\\\"}]}}", "purpose": "Retrieve security spending by category (Defender, Sentinel, Firewall, tooling) with monthly trend analysis"},
            {"query_type": "Microsoft Defender for Cloud REST API", "query_name": "Secure Score improvement and vulnerability reduction", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01\\nGET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01&$filter=properties/status/code eq 'Unhealthy'", "purpose": "Retrieve Secure Score trends and vulnerability counts (Critical/High) to measure security effectiveness"},
            {"query_type": "Power BI REST API", "query_name": "Security investment ROI metrics", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(SecurityInvestments, SecurityInvestments[Category], 'TotalCost', SUM(SecurityInvestments[Cost]), 'SecureScoreImprovement', SUM(SecurityInvestments[SecureScoreImprovement]), 'VulnerabilitiesResolved', SUM(SecurityInvestments[VulnerabilitiesResolved]), 'CostPerSecureScorePoint', DIVIDE(SUM(SecurityInvestments[Cost]), SUM(SecurityInvestments[SecureScoreImprovement]), 0), 'CostPerVulnerability', DIVIDE(SUM(SecurityInvestments[Cost]), SUM(SecurityInvestments[VulnerabilitiesResolved]), 0))\\\"}]}", "purpose": "Calculate security investment ROI: Cost per Secure Score point, cost per vulnerability remediated, cost avoidance"},
            {"query_type": "Azure DevOps REST API", "query_name": "Security project budget vs. actual", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\\nBody: {\\\"query\\\": \\\"SELECT [System.Id], [System.Title], [Custom.Budget], [Custom.ActualSpend], [Custom.SecureScoreImprovement], [Custom.VulnerabilitiesResolved] FROM WorkItems WHERE [System.WorkItemType] = 'Security Project' ORDER BY [Custom.ActualSpend] DESC\\\"}", "purpose": "Retrieve security project budgets with actual spend, Secure Score improvement, and ROI calculations"},
            {"query_type": "Microsoft Dataverse Web API", "query_name": "Security investment registry with ROI", "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/security_investments?$select=investmentid,category,cost,justification,secure_score_improvement,vulnerabilities_resolved,roi&$orderby=roi desc", "purpose": "Retrieve security investment registry with ROI analysis for quarterly effectiveness review"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "Azure Cost Management Security Spend Report", "artifact_type": "Financial Report", "description": "Security spending by category (Defender, Sentinel, Firewall, tooling) with monthly trends and budget vs. actual comparisons", "collection_method": "Azure Cost Management REST API to export ActualCost with CostCenter=Security tag filter", "storage_location": "Azure Storage Account with monthly cost reports for CFO/CISO review"},
            {"artifact_name": "Defender Effectiveness Metrics", "artifact_type": "Security Posture Report", "description": "Secure Score improvement (+5% per quarter target), vulnerability reduction (Critical/High resolved), MTTD/MTTR metrics", "collection_method": "Microsoft Defender for Cloud REST API to export Secure Score trends and vulnerability assessments", "storage_location": "Azure Storage Account with quarterly effectiveness snapshots"},
            {"artifact_name": "Power BI Security Investment ROI Dashboard", "artifact_type": "ROI Analysis Dashboard", "description": "Dashboard showing cost per Secure Score point, cost per vulnerability remediated, cost avoidance from prevented incidents", "collection_method": "Power BI REST API to export ROI metrics correlating security spend with security outcomes", "storage_location": "SharePoint with quarterly PDF snapshots for executive reporting to Board of Directors"},
            {"artifact_name": "DevOps Security Project Budget Tracking", "artifact_type": "Project Budget Report", "description": "Security project budgets with actual spend, linked to security outcomes (Secure Score improvement, vulnerability reduction), project-level ROI", "collection_method": "Azure DevOps REST API to export Security Project work items with budget and outcome tracking", "storage_location": "Azure DevOps analytics database with project-level ROI for portfolio management"},
            {"artifact_name": "Dataverse Security Investment Registry", "artifact_type": "Investment Registry Database", "description": "Complete security investment registry with business justification, cost, effectiveness metrics, and quarterly ROI review with CISO", "collection_method": "Microsoft Dataverse Web API to export security_investments with ROI analysis", "storage_location": "Microsoft Dataverse with quarterly effectiveness reviews and investment portfolio optimization"}
        ]
    
