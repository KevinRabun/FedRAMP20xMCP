"""
KSI-PIY-08: Executive Support

Regularly measure executive support for achieving the organization's security objectives.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
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

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Executive Support",
            "evidence_type": "process-based",
            "automation_feasibility": "medium",
            "azure_services": ["Microsoft Defender for Cloud", "Azure DevOps", "Power BI", "Microsoft Dataverse", "SharePoint"],
            "collection_methods": [
                "Microsoft Defender for Cloud Secure Score to measure executive-level security posture and trend executive engagement impact",
                "Azure DevOps Boards to track security initiatives with executive sponsorship, budget allocation, and priority assignments",
                "Power BI Executive Security Dashboard to present security metrics (Secure Score, vulnerability trends, incident rates) to leadership",
                "Microsoft Dataverse to log executive security reviews (quarterly CISO briefings, Board reporting) with action item tracking",
                "SharePoint to publish executive security policies signed by CISO/CEO demonstrating top-down security commitment"
            ],
            "implementation_steps": [
                "1. Track Secure Score with Defender for Cloud: (a) Measure Secure Score trends (target: +5% per quarter), (b) Correlate Secure Score improvements with executive security initiatives (budget increases, policy changes), (c) Generate quarterly executive Secure Score report with improvement attribution, (d) Present to Board of Directors quarterly",
                "2. Create Azure DevOps Security Initiatives tracking: (a) Work item type 'Security Initiative' with fields: InitiativeName, ExecutiveSponsor, Budget, Priority (Critical/High/Medium), Status (Planned/Active/Completed), Impact (Secure Score, vulnerability reduction), (b) Require executive sponsor approval before funding, (c) Track initiative outcomes and ROI",
                "3. Build Power BI Executive Security Dashboard: (a) Secure Score trends with executive initiative correlation, (b) Vulnerability reduction by severity (Critical/High/Medium), (c) Incident frequency and MTTR trends, (d) Security investment ROI (cost per Secure Score point), (e) Present quarterly to CISO, CEO, Board",
                "4. Log executive reviews in Microsoft Dataverse: (a) Table: executive_security_reviews with columns: reviewid, reviewdate, attendees (CISO, CEO, Board members), topics, action_items, next_review_date, (b) Track action item completion (target: 100% within 30 days), (c) Automate quarterly review reminders",
                "5. Publish executive policies on SharePoint: (a) Information Security Policy signed by CEO/CISO, (b) Data Protection Policy signed by CEO/CISO, (c) Incident Response Policy signed by CEO/CISO, (d) Annual policy review and re-signature by executive leadership, (e) Track policy acknowledgment from all employees (target: 100%)",
                "6. Generate quarterly evidence package: (a) Export Defender Secure Score trends with executive initiative attribution, (b) Export DevOps Security Initiative work items with executive sponsorship, (c) Export Power BI executive dashboard with security metrics, (d) Export Dataverse executive review logs with action item tracking, (e) Export SharePoint executive-signed security policies"
            ],
            "evidence_artifacts": [
                "Microsoft Defender Secure Score Executive Report showing trends (+5% per quarter) with correlation to executive security initiatives",
                "Azure DevOps Security Initiative Work Items with executive sponsorship, budget allocation, priority assignments, and impact tracking",
                "Power BI Executive Security Dashboard presenting Secure Score, vulnerability trends, incident rates, and security investment ROI to Board",
                "Microsoft Dataverse Executive Security Review Logs documenting quarterly CISO/CEO/Board briefings with action item completion tracking",
                "SharePoint Executive-Signed Security Policies (Information Security, Data Protection, Incident Response) with annual review and employee acknowledgment"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "CISO / Executive Leadership / Board of Directors"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Microsoft Defender for Cloud REST API", "query_name": "Secure Score trends with executive initiative correlation", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01\\nJoin with Azure DevOps Security Initiatives to correlate Secure Score improvements with executive-sponsored initiatives", "purpose": "Retrieve Secure Score trends and correlate improvements with executive security initiatives (budget, policy changes)"},
            {"query_type": "Azure DevOps REST API", "query_name": "Security initiatives with executive sponsorship", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\\nBody: {\\\"query\\\": \\\"SELECT [System.Id], [System.Title], [Custom.ExecutiveSponsor], [Custom.Budget], [Custom.Priority], [Custom.Status], [Custom.Impact] FROM WorkItems WHERE [System.WorkItemType] = 'Security Initiative' ORDER BY [Custom.Priority] DESC\\\"}", "purpose": "Retrieve security initiatives with executive sponsorship, budget allocation, priority, and impact tracking (Secure Score, vulnerability reduction)"},
            {"query_type": "Power BI REST API", "query_name": "Executive security metrics for Board reporting", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(ExecutiveSecurityMetrics, ExecutiveSecurityMetrics[Quarter], 'SecureScoreAvg', AVERAGE(ExecutiveSecurityMetrics[SecureScore]), 'VulnerabilitiesReduced', SUM(ExecutiveSecurityMetrics[VulnerabilitiesReduced]), 'IncidentCount', SUM(ExecutiveSecurityMetrics[IncidentCount]), 'SecurityInvestment', SUM(ExecutiveSecurityMetrics[SecurityInvestment]), 'ROI', DIVIDE(SUM(ExecutiveSecurityMetrics[SecureScoreImprovement]), SUM(ExecutiveSecurityMetrics[SecurityInvestment]), 0))\\\"}]}", "purpose": "Calculate executive security metrics for Board presentations: Secure Score, vulnerability trends, incident rates, security ROI"},
            {"query_type": "Microsoft Dataverse Web API", "query_name": "Executive security review logs with action items", "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/executive_security_reviews?$select=reviewid,reviewdate,attendees,topics,action_items,action_item_completion_rate&$orderby=reviewdate desc", "purpose": "Retrieve executive security review logs documenting quarterly CISO/CEO/Board briefings with action item completion tracking"},
            {"query_type": "SharePoint REST API", "query_name": "Executive-signed security policies", "query": "GET https://{tenant}.sharepoint.com/sites/{site}/_api/web/lists/getbytitle('Executive Security Policies')/items?$select=Title,PolicyName,SignedBy,SignatureDate,LastReviewDate,EmployeeAcknowledgmentRate", "purpose": "Retrieve executive-signed security policies (Information Security, Data Protection, Incident Response) with annual review and employee acknowledgment"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "Defender Secure Score Executive Report", "artifact_type": "Executive Security Metrics", "description": "Secure Score trends (+5% per quarter target) with correlation to executive security initiatives (budget increases, policy changes)", "collection_method": "Microsoft Defender for Cloud REST API to export Secure Score with Azure DevOps initiative correlation", "storage_location": "Azure Storage Account with quarterly executive reports for Board presentations"},
            {"artifact_name": "DevOps Security Initiative Work Items", "artifact_type": "Executive Initiative Registry", "description": "Security initiatives with executive sponsorship (CISO, CEO), budget allocation, priority assignments, status tracking, and impact metrics", "collection_method": "Azure DevOps REST API to export Security Initiative work items with executive metadata", "storage_location": "Azure DevOps database with historical initiative tracking and ROI analysis"},
            {"artifact_name": "Power BI Executive Security Dashboard", "artifact_type": "Board-Level Security Dashboard", "description": "Executive dashboard for quarterly Board presentations: Secure Score trends, vulnerability reduction, incident rates, security investment ROI", "collection_method": "Power BI REST API to export executive security metrics for Board reporting", "storage_location": "SharePoint with quarterly PDF snapshots for Board of Directors archive"},
            {"artifact_name": "Dataverse Executive Security Review Logs", "artifact_type": "Executive Meeting Documentation", "description": "Logs of quarterly CISO/CEO/Board security briefings with attendees, topics discussed, action items assigned, and completion tracking (100% within 30d)", "collection_method": "Microsoft Dataverse Web API to export executive_security_reviews with action item metadata", "storage_location": "Microsoft Dataverse with automated quarterly review reminders and action item escalation"},
            {"artifact_name": "SharePoint Executive-Signed Security Policies", "artifact_type": "Executive Policy Documentation", "description": "Security policies signed by CEO/CISO: Information Security Policy, Data Protection Policy, Incident Response Policy with annual review and employee acknowledgment (100%)", "collection_method": "SharePoint REST API to retrieve executive-signed policies with signature dates and acknowledgment rates", "storage_location": "SharePoint policy library with version history, executive signatures, and employee acknowledgment tracking"}
        ]
    
