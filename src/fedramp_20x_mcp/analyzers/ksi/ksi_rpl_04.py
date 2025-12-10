"""
KSI-RPL-04: Recovery Testing

Regularly test the capability to recover from incidents and contingencies.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_RPL_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-RPL-04: Recovery Testing
    
    **Official Statement:**
    Regularly test the capability to recover from incidents and contingencies.
    
    **Family:** RPL - Recovery Planning
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cp-2.1
    - cp-2.3
    - cp-4
    - cp-4.1
    - cp-6
    - cp-6.1
    - cp-9.1
    - cp-10
    - ir-3
    - ir-3.2
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-RPL-04"
    KSI_NAME = "Recovery Testing"
    KSI_STATEMENT = """Regularly test the capability to recover from incidents and contingencies."""
    FAMILY = "RPL"
    FAMILY_NAME = "Recovery Planning"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cp-2.1", "Coordinate with Related Plans"),
        ("cp-2.3", "Resume Mission and Business Functions"),
        ("cp-4", "Contingency Plan Testing"),
        ("cp-4.1", "Coordinate with Related Plans"),
        ("cp-6", "Alternate Storage Site"),
        ("cp-6.1", "Separation from Primary Site"),
        ("cp-9.1", "Testing for Reliability and Integrity"),
        ("cp-10", "System Recovery and Reconstitution"),
        ("ir-3", "Incident Response Testing"),
        ("ir-3.2", "Coordination with Related Plans")
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
        Analyze Python code for KSI-RPL-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
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
        Analyze C# code for KSI-RPL-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-RPL-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-RPL-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-RPL-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-RPL-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Regularly test the capability to recover from incidents and contingencies....
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-RPL-04 compliance.
        
        Detects:
        - Missing recovery testing automation
        - Missing backup restoration validation
        - Missing RTO/RPO verification
        """
        findings = []
        lines = code.split('\n')
        
        # Check for recovery testing
        has_recovery_test = bool(re.search(r'(recovery.*test|restore.*test|backup.*validation)', code, re.IGNORECASE))
        has_restore_job = bool(re.search(r'(restore|recovery):.*\n.*runs-on', code, re.IGNORECASE))
        has_scheduled_test = bool(re.search(r'schedule.*\n.*recovery|recovery.*\n.*schedule', code, re.IGNORECASE))
        has_rto_rpo_check = bool(re.search(r'(rto|rpo|recovery.*time|recovery.*point)', code, re.IGNORECASE))
        
        if not has_recovery_test:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing automated recovery testing",
                description="No automated recovery testing detected. KSI-RPL-04 requires regularly testing capability to recover from backup.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add recovery test: - name: Test Backup Recovery\n  run: ./scripts/test-restore.sh"
            ))
        
        if not has_scheduled_test:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing scheduled recovery testing",
                description="No scheduled (regular) recovery testing. KSI-RPL-04 requires periodic validation of recovery capability.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add scheduled test: on:\n  schedule:\n    - cron: '0 3 * * 0'  # Weekly on Sunday at 3 AM"
            ))
        
        if not has_rto_rpo_check:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing RTO/RPO verification",
                description="No verification of Recovery Time Objective (RTO) or Recovery Point Objective (RPO). KSI-RPL-04 requires testing against defined objectives.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add RTO/RPO check: - name: Verify RTO/RPO\n  run: ./scripts/measure-recovery-time.sh"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-RPL-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-RPL-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Recovery Testing",
            "evidence_type": "log-based",
            "automation_feasibility": "high",
            "azure_services": ["Azure Site Recovery", "Azure DevOps", "Azure Monitor", "Power BI", "Microsoft Dataverse"],
            "collection_methods": [
                "Azure Site Recovery to execute quarterly DR test failovers with automated validation",
                "Azure DevOps Pipelines to automate recovery test execution (backup restore, failover validation)",
                "Azure Monitor to track recovery test results, execution time vs. RTO, and success/failure rates",
                "Power BI to visualize recovery test history, RTO compliance trends, and recurring failures",
                "Microsoft Dataverse to log recovery test outcomes with lessons learned and remediation tracking"
            ],
            "implementation_steps": [
                "1. Schedule Azure Site Recovery test failovers: (a) Quarterly test failover schedule for all Tier 1/2 services, (b) Use isolated virtual networks to avoid production impact, (c) Validate application functionality post-failover (health checks, smoke tests), (d) Measure actual RTO vs. documented RTO, (e) Execute failback and cleanup",
                "2. Automate recovery tests with Azure DevOps: (a) Create 'Recovery Test' pipeline triggered quarterly, (b) Steps: Initiate ASR test failover → Run automated smoke tests → Measure RTO → Capture results → Failback, (c) Publish test results to Azure DevOps Test Plans, (d) Create work items for failures requiring remediation",
                "3. Track results with Azure Monitor: (a) Log ASR test failover executions with success/failure status, (b) Capture execution time and compare to RTO targets, (c) Alert on test failures or RTO breaches, (d) Generate quarterly test summary report",
                "4. Build Power BI Recovery Test Dashboard: (a) Recovery test history by service and tier, (b) RTO compliance: Actual vs. Target (Green < 90%, Yellow 90-100%, Red > 100%), (c) Recurring failures and remediation status, (d) Test frequency compliance (quarterly target)",
                "5. Log outcomes in Microsoft Dataverse: (a) Table: recovery_test_log with columns: testid, servicename, testdate, success, actual_rto, target_rto, failures, lessonslearned, remediation_status, (b) Automate record creation from DevOps pipeline results, (c) Track remediation items with due dates and ownership",
                "6. Generate quarterly evidence package: (a) Export ASR test failover logs with execution details, (b) Export DevOps pipeline test results with smoke test outcomes, (c) Export Azure Monitor RTO compliance metrics, (d) Export Power BI dashboard showing >= 95% test success, (e) Export Dataverse recovery test log with lessons learned"
            ],
            "evidence_artifacts": [
                "Azure Site Recovery Test Failover Logs showing quarterly DR tests with isolated networks and cleanup",
                "Azure DevOps Recovery Test Pipeline Results with automated smoke tests and RTO measurements",
                "Azure Monitor Recovery Test Report tracking success rates (>= 95%) and RTO compliance vs. targets",
                "Power BI Recovery Test Dashboard visualizing test history, RTO trends, and recurring failure remediation",
                "Microsoft Dataverse Recovery Test Log with test outcomes, lessons learned, and remediation tracking"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Business Continuity Manager / DevOps Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Azure Site Recovery REST API", "query_name": "Test failover execution logs", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/replicationJobs?api-version=2022-10-01&$filter=contains(properties.activityId, 'TestFailover') and startTime ge {quarterStartDate}", "purpose": "Retrieve ASR test failover logs showing quarterly DR tests with execution details and cleanup status"},
            {"query_type": "Azure DevOps REST API", "query_name": "Recovery test pipeline results", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/pipelines/{pipelineId}/runs?api-version=7.0&$filter=createdDate ge {quarterStartDate}", "purpose": "Retrieve DevOps pipeline runs for Recovery Test pipelines with smoke test results and RTO measurements"},
            {"query_type": "Azure Monitor KQL", "query_name": "Recovery test RTO compliance", "query": "AzureDiagnostics\n| where Category == 'AzureSiteRecoveryJobs' and OperationName contains 'TestFailover'\n| extend ActualRTO = DurationMs / 60000\n| join kind=inner (datatable(RecoveryPlanName:string, TargetRTO:int) ['Tier1-Recovery', 240, 'Tier2-Recovery', 1440]) on RecoveryPlanName\n| extend RTOCompliance = iff(ActualRTO <= TargetRTO, 'Pass', 'Fail')\n| summarize TotalTests = count(), Passed = countif(RTOCompliance == 'Pass'), Failed = countif(RTOCompliance == 'Fail'), AvgActualRTO = avg(ActualRTO) by RecoveryPlanName, bin(TimeGenerated, 90d)\n| extend ComplianceRate = round((todouble(Passed) / TotalTests) * 100, 2)", "purpose": "Calculate recovery test RTO compliance rates (>= 95% target) by comparing actual vs. target RTO"},
            {"query_type": "Power BI REST API", "query_name": "Recovery test history and trends", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(RecoveryTestLog, RecoveryTestLog[ServiceName], 'TotalTests', COUNT(RecoveryTestLog[TestID]), 'Successful', COUNTIF(RecoveryTestLog[Success] = TRUE), 'RTOCompliant', COUNTIF(RecoveryTestLog[ActualRTO] <= RecoveryTestLog[TargetRTO]), 'RemediationComplete', COUNTIF(RecoveryTestLog[RemediationStatus] = 'Completed'))\\\"}]}", "purpose": "Calculate recovery test success rates and RTO compliance trends for executive dashboard"},
            {"query_type": "Microsoft Dataverse Web API", "query_name": "Recovery test log with lessons learned", "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/recovery_test_log_records?$select=testid,servicename,testdate,success,actual_rto,target_rto,lessonslearned,remediation_status&$filter=testdate ge {quarterStartDate}", "purpose": "Retrieve recovery test outcomes with lessons learned and remediation tracking for continuous improvement"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "Azure Site Recovery Test Failover Logs", "artifact_type": "DR Test Execution Logs", "description": "Complete test failover logs showing quarterly DR tests in isolated networks, application validation, and cleanup execution", "collection_method": "Azure Site Recovery REST API to export replicationJobs filtered for TestFailover operations", "storage_location": "Azure Storage Account with quarterly test logs for audit trail"},
            {"artifact_name": "DevOps Recovery Test Pipeline Results", "artifact_type": "Automated Test Results", "description": "Pipeline execution results with automated smoke tests, RTO measurements (actual vs. target), and test outcome (Pass/Fail)", "collection_method": "Azure DevOps REST API to export pipeline runs for Recovery Test pipelines with test result details", "storage_location": "Azure DevOps Test Plans with historical test results and trend analysis"},
            {"artifact_name": "Azure Monitor Recovery Test Report", "artifact_type": "RTO Compliance Report", "description": "Recovery test report showing success rates (>= 95% target), RTO compliance (actual vs. target), and test frequency compliance (quarterly)", "collection_method": "Azure Monitor KQL query calculating RTO compliance from AzureSiteRecoveryJobs logs", "storage_location": "Azure Log Analytics workspace with quarterly test summaries"},
            {"artifact_name": "Power BI Recovery Test Dashboard", "artifact_type": "Test Analytics Dashboard", "description": "Dashboard showing recovery test history, RTO trends, recurring failures with remediation status, and test frequency compliance", "collection_method": "Power BI REST API to export dashboard metrics for recovery test success and RTO compliance", "storage_location": "SharePoint with quarterly PDF snapshots for executive reporting"},
            {"artifact_name": "Dataverse Recovery Test Log", "artifact_type": "Test Outcome Database", "description": "Complete recovery test log with test outcomes, lessons learned, remediation items, and continuous improvement tracking", "collection_method": "Microsoft Dataverse Web API to export recovery_test_log_records with quarterly filter", "storage_location": "Microsoft Dataverse with automated integration from DevOps pipeline results"}
        ]
    
