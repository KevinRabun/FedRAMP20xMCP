"""
KSI-RPL-02: Recovery Plan

Develop and maintain a recovery plan that aligns with the defined recovery objectives.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_RPL_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-RPL-02: Recovery Plan
    
    **Official Statement:**
    Develop and maintain a recovery plan that aligns with the defined recovery objectives.
    
    **Family:** RPL - Recovery Planning
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cp-2
    - cp-2.1
    - cp-2.3
    - cp-4.1
    - cp-6
    - cp-6.1
    - cp-6.3
    - cp-7
    - cp-7.1
    - cp-7.2
    - cp-7.3
    - cp-8
    - cp-8.1
    - cp-8.2
    - cp-10
    - cp-10.2
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-RPL-02"
    KSI_NAME = "Recovery Plan"
    KSI_STATEMENT = """Develop and maintain a recovery plan that aligns with the defined recovery objectives."""
    FAMILY = "RPL"
    FAMILY_NAME = "Recovery Planning"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cp-2", "Contingency Plan"),
        ("cp-2.1", "Coordinate with Related Plans"),
        ("cp-2.3", "Resume Mission and Business Functions"),
        ("cp-4.1", "Coordinate with Related Plans"),
        ("cp-6", "Alternate Storage Site"),
        ("cp-6.1", "Separation from Primary Site"),
        ("cp-6.3", "Accessibility"),
        ("cp-7", "Alternate Processing Site"),
        ("cp-7.1", "Separation from Primary Site"),
        ("cp-7.2", "Accessibility"),
        ("cp-7.3", "Priority of Service"),
        ("cp-8", "Telecommunications Services"),
        ("cp-8.1", "Priority of Service Provisions"),
        ("cp-8.2", "Single Points of Failure"),
        ("cp-10", "System Recovery and Reconstitution"),
        ("cp-10.2", "Transaction Recovery")
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
        Analyze Python code for KSI-RPL-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
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
        Analyze C# code for KSI-RPL-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-RPL-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-RPL-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep template for KSI-RPL-02 compliance.
        
        Detects:
        - Missing backup vault configuration
        - Missing backup policies
        - Missing retention policies
        - Missing geo-redundant storage
        """
        findings = []
        lines = code.split('\n')
        
        # Check for backup infrastructure
        has_backup_vault = bool(re.search(r'Microsoft\.RecoveryServices/vaults', code, re.IGNORECASE))
        has_backup_policy = bool(re.search(r'backupPolicies|backup.*policy', code, re.IGNORECASE))
        has_retention = bool(re.search(r'retention.*policy|retention.*period', code, re.IGNORECASE))
        has_geo_redundancy = bool(re.search(r'(GeoRedundant|ZoneRedundant)', code, re.IGNORECASE))
        has_vm_backup = bool(re.search(r'Microsoft\.RecoveryServices.*protectedItems', code, re.IGNORECASE))
        
        if not has_backup_vault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Azure Backup Vault",
                description="No Recovery Services Vault configured. KSI-RPL-02 requires automated backup infrastructure aligned with recovery plan.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add Recovery Services Vault: resource backupVault 'Microsoft.RecoveryServices/vaults@2023-01-01' = { name: 'vault-backup-prod', properties: { } }"
            ))
        
        if not has_backup_policy:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing backup policy",
                description="No backup policy configured. KSI-RPL-02 requires backup schedules and retention policies.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add backup policy with schedule: schedulePolicy: { scheduleRunFrequency: 'Daily', scheduleRunTimes: ['2023-01-01T02:00:00Z'] }"
            ))
        
        if not has_geo_redundancy:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing geo-redundant backup storage",
                description="Backup storage not configured for geo-redundancy. KSI-RPL-02 recovery plan should include geographic redundancy.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Configure geo-redundancy: properties: { storageType: 'GeoRedundant', storageTypeState: 'Locked' }"
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Recovery Plan",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": ["Azure Site Recovery", "Azure DevOps", "SharePoint", "Power Automate", "Azure Monitor"],
            "collection_methods": [
                "Azure Site Recovery to define and maintain recovery plans with step-by-step runbooks",
                "Azure DevOps to store recovery procedures as living documentation with version control",
                "SharePoint to publish recovery plans with approval workflows and annual review requirements",
                "Power Automate to trigger recovery plan updates when infrastructure changes occur",
                "Azure Monitor to track recovery plan execution metrics (success rate, execution time)"
            ],
            "implementation_steps": [
                "1. Build Azure Site Recovery Plans: (a) Create recovery plans per tier (Tier1-Critical, Tier2-Important, Tier3-Normal), (b) Define sequenced recovery steps (start VMs, restore databases, validate connectivity, failover traffic), (c) Add manual approval gates for production failover, (d) Document rollback procedures",
                "2. Store runbooks in Azure DevOps: (a) Create Wiki pages for each recovery plan with Markdown runbooks, (b) Include prerequisites, step-by-step instructions, rollback procedures, contact escalation, (c) Link to ASR recovery plans via resource IDs, (d) Require pull request approval for updates",
                "3. Configure SharePoint recovery plan library: (a) Publish approved recovery plans to SharePoint, (b) Approval workflow: Service Owner → SOC Manager → CISO, (c) Set annual review reminders with escalation if overdue, (d) Track plan version history and approval dates",
                "4. Build Power Automate update workflow: (a) Trigger on Azure Resource Graph changes (VM added/removed, network topology change), (b) Create DevOps work item 'Review Recovery Plan' assigned to service owner, (c) Send reminder emails at 7 days and 14 days if not completed, (d) Update Dataverse with plan review status",
                "5. Track execution with Azure Monitor: (a) Log ASR recovery plan executions (test or production), (b) Capture execution time, success/failure status, manual approvals, (c) Alert on recovery plan failures or RTO breaches, (d) Generate monthly execution summary report",
                "6. Generate quarterly evidence package: (a) Export ASR recovery plans with runbook steps, (b) Export DevOps Wiki recovery procedures with version history, (c) Export SharePoint approval records showing annual reviews, (d) Export Azure Monitor execution logs with success rates"
            ],
            "evidence_artifacts": [
                "Azure Site Recovery Plans with sequenced recovery steps, manual approval gates, and rollback procedures",
                "Azure DevOps Wiki Recovery Runbooks with step-by-step instructions, prerequisites, and contact escalation",
                "SharePoint Recovery Plan Library with approval workflows and annual review tracking",
                "Power Automate Update Workflow Logs showing automated recovery plan reviews triggered by infrastructure changes",
                "Azure Monitor Recovery Execution Report tracking test and production recovery plan executions with success rates"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Business Continuity Manager / Service Owner"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Azure Site Recovery REST API", "query_name": "Recovery plans with runbook steps", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/replicationRecoveryPlans?api-version=2022-10-01", "purpose": "Retrieve ASR recovery plans with sequenced steps, approval gates, and failover procedures"},
            {"query_type": "Azure DevOps REST API", "query_name": "Recovery procedure Wiki pages", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wiki/wikis/{wikiIdentifier}/pages?path=/Recovery-Plans&api-version=7.0&recursionLevel=Full", "purpose": "Retrieve recovery runbooks from DevOps Wiki with version history and update tracking"},
            {"query_type": "SharePoint REST API", "query_name": "Recovery plan library with approval", "query": "GET https://{tenant}.sharepoint.com/sites/{site}/_api/web/lists/getbytitle('Recovery Plans')/items?$select=Title,ServiceName,ApprovalStatus,ApprovedBy,LastReviewDate,NextReviewDate", "purpose": "Retrieve published recovery plans with approval workflow history and annual review tracking"},
            {"query_type": "Power Automate REST API", "query_name": "Recovery plan update workflow logs", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Logic/workflows/{workflowName}/runs?api-version=2016-06-01&$filter=status eq 'Succeeded'", "purpose": "Retrieve workflow logs showing automated recovery plan reviews triggered by infrastructure changes"},
            {"query_type": "Azure Monitor KQL", "query_name": "Recovery plan execution metrics", "query": "AzureDiagnostics\n| where Category == 'AzureSiteRecoveryJobs'\n| where OperationName contains 'RecoveryPlan'\n| summarize TotalExecutions = count(), Successful = countif(ResultType == 'Success'), Failed = countif(ResultType == 'Failure'), AvgDurationMinutes = avg(DurationMs) / 60000 by RecoveryPlanName, bin(TimeGenerated, 30d)\n| extend SuccessRate = round((todouble(Successful) / TotalExecutions) * 100, 2)", "purpose": "Track recovery plan execution success rates and duration to validate RTO compliance"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "Azure Site Recovery Plans", "artifact_type": "Recovery Configuration", "description": "Complete recovery plans with sequenced steps (VM start, database restore, traffic failover), manual approval gates, and rollback procedures", "collection_method": "Azure Site Recovery REST API to export replicationRecoveryPlans with full runbook details", "storage_location": "Azure Storage Account with quarterly snapshots for version tracking"},
            {"artifact_name": "DevOps Wiki Recovery Runbooks", "artifact_type": "Procedure Documentation", "description": "Step-by-step recovery procedures with prerequisites, execution instructions, rollback steps, and contact escalation", "collection_method": "Azure DevOps REST API to export Wiki pages from /Recovery-Plans with version history", "storage_location": "Azure DevOps Wiki with Git version control for change tracking"},
            {"artifact_name": "SharePoint Recovery Plan Library", "artifact_type": "Approved Documentation Repository", "description": "Published recovery plans with approval workflows (Service Owner → SOC → CISO) and annual review tracking", "collection_method": "SharePoint REST API to retrieve recovery plan documents with approval metadata and review dates", "storage_location": "SharePoint Online with version history and approval workflow audit trail"},
            {"artifact_name": "Power Automate Update Workflow Logs", "artifact_type": "Process Automation Logs", "description": "Logs of automated recovery plan reviews triggered by Azure Resource Graph topology changes (VMs added/removed)", "collection_method": "Power Automate REST API to retrieve workflow execution history with success/failure status", "storage_location": "Azure Storage Account with workflow run logs for process audit"},
            {"artifact_name": "Azure Monitor Recovery Execution Report", "artifact_type": "Execution Metrics", "description": "Recovery plan execution metrics showing success rates (>= 95% target), duration vs. RTO, and test/production executions", "collection_method": "Azure Monitor KQL query calculating execution success rates and duration from AzureSiteRecoveryJobs logs", "storage_location": "Azure Log Analytics workspace with monthly execution summaries"}
        ]
    
