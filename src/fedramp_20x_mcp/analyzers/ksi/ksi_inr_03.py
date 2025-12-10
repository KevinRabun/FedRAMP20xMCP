"""
KSI-INR-03: Incident After Action Reports

Generate after action reports and regularly incorporate lessons learned into operations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_INR_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-INR-03: Incident After Action Reports
    
    **Official Statement:**
    Generate after action reports and regularly incorporate lessons learned into operations.
    
    **Family:** INR - Incident Response
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ir-3
    - ir-4
    - ir-4.1
    - ir-8
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-INR-03"
    KSI_NAME = "Incident After Action Reports"
    KSI_STATEMENT = """Generate after action reports and regularly incorporate lessons learned into operations."""
    FAMILY = "INR"
    FAMILY_NAME = "Incident Response"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ir-3", "Incident Response Testing"),
        ("ir-4", "Incident Handling"),
        ("ir-4.1", "Automated Incident Handling Processes"),
        ("ir-8", "Incident Response Plan")
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
        Analyze Python code for KSI-INR-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Generate after action reports and regularly incorporate lessons learned into ope...
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
        Analyze C# code for KSI-INR-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Generate after action reports and regularly incorporate lessons learned into ope...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-INR-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Generate after action reports and regularly incorporate lessons learned into ope...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-INR-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Generate after action reports and regularly incorporate lessons learned into ope...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-INR-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Generate after action reports and regularly incorporate lessons learned into ope...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-INR-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Generate after action reports and regularly incorporate lessons learned into ope...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-INR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-INR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-INR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Incident After Action Reports",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": ["Azure DevOps", "Microsoft Dataverse", "Power Automate", "Power BI", "SharePoint"],
            "collection_methods": [
                "Azure DevOps Boards to template and track After Action Report (AAR) creation with required fields (timeline, root cause, lessons learned)",
                "Power Automate to trigger AAR creation automatically when incidents are closed in Sentinel with severity >= HIGH",
                "Microsoft Dataverse to store AARs with lessons learned taxonomy and remediation tracking",
                "Power BI to analyze AAR implementation rates and track incorporation of lessons learned into operations",
                "SharePoint to publish AARs for team review with approval workflows and training material integration"
            ],
            "implementation_steps": [
                "1. Create Azure DevOps AAR template: (a) Work item type 'After Action Report' with required fields: Incident ID, Timeline, Root Cause Analysis, What Went Well, What Went Wrong, Lessons Learned, Preventative Actions, Responsible Party, Implementation Date, (b) Link to parent Security Incident work item, (c) Set AAR completion deadline (7 days after incident closure)",
                "2. Build Power Automate AAR workflow: (a) Trigger on Sentinel incident status change to 'Closed' with Severity >= High, (b) Create AAR work item in Azure DevOps automatically, (c) Assign to incident owner and SOC manager, (d) Send reminder emails at 3 days and 6 days if not completed, (e) Escalate to CISO if overdue",
                "3. Configure Microsoft Dataverse Lessons Learned Table: (a) Columns: AARID, IncidentID, LessonCategory (Process/Technology/People), LessonDescription, PreventativeAction, ImplementationStatus, Owner, DueDate, (b) Automate record creation from completed AARs, (c) Tag lessons with MITRE ATT&CK tactics for trend analysis",
                "4. Build Power BI Lessons Learned Dashboard: (a) AAR completion rate (target >= 95% within 7 days), (b) Lessons learned implementation status (Planned/In Progress/Completed), (c) Recurring incident patterns addressed by preventative actions, (d) Time-to-implement for process improvements",
                "5. Create SharePoint AAR Library: (a) Publish completed AARs with redacted sensitive details, (b) Approval workflow requiring SOC manager and CISO sign-off, (c) Tag AARs by incident type for searchability, (d) Integrate AARs into security awareness training materials",
                "6. Generate quarterly evidence package: (a) Export DevOps AARs with completion timeline, (b) Export Dataverse lessons learned with implementation tracking, (c) Export Power BI dashboard showing >= 95% AAR completion, (d) Export SharePoint AAR library with approval history"
            ],
            "evidence_artifacts": [
                "Azure DevOps After Action Report Work Items with root cause analysis, lessons learned, and preventative actions",
                "Microsoft Dataverse Lessons Learned Database with implementation tracking and MITRE ATT&CK taxonomy",
                "Power BI Lessons Learned Implementation Dashboard showing >= 95% AAR completion and remediation status",
                "SharePoint After Action Report Library with approved AARs and integration into training materials",
                "Power Automate AAR Workflow Logs showing automated AAR creation and completion tracking"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Incident Response Team / Security Operations Manager"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Azure DevOps REST API", "query_name": "After Action Report work items", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\\nBody: {\\\"query\\\": \\\"SELECT [System.Id], [System.Title], [Custom.IncidentID], [Custom.RootCause], [Custom.LessonsLearned], [Custom.PreventativeActions], [Custom.CompletionDate] FROM WorkItems WHERE [System.WorkItemType] = 'After Action Report' ORDER BY [System.CreatedDate] DESC\\\"}", "purpose": "Retrieve AARs with root cause analysis and lessons learned documentation"},
            {"query_type": "Microsoft Dataverse Web API", "query_name": "Lessons learned with implementation status", "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/lessons_learned_records?$select=aarid,lessoncategory,lessondescription,preventativeaction,implementationstatus&$filter=createddate ge {quarterStartDate}", "purpose": "Retrieve lessons learned with implementation tracking to demonstrate operational integration"},
            {"query_type": "Power BI REST API", "query_name": "AAR completion and lessons learned implementation rates", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(AARRecords, AARRecords[Status], 'TotalAARs', COUNT(AARRecords[AARID]), 'CompletedOnTime', COUNTIF(AARRecords[Status] = 'Completed' && AARRecords[CompletionDays] <= 7), 'LessonsImplemented', COUNTIF(AARRecords[ImplementationStatus] = 'Completed'))\\\"}]}", "purpose": "Calculate AAR completion rates (>= 95% within 7 days) and lessons learned implementation status"},
            {"query_type": "SharePoint REST API", "query_name": "AAR library with approval history", "query": "GET https://{tenant}.sharepoint.com/sites/{site}/_api/web/lists/getbytitle('After Action Reports')/items?$select=Title,IncidentID,ApprovalStatus,ApprovedBy,PublishDate", "purpose": "Retrieve published AARs with approval workflow history demonstrating executive review"},
            {"query_type": "Power Automate REST API", "query_name": "AAR workflow execution logs", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Logic/workflows/{workflowName}/runs?api-version=2016-06-01&$filter=status eq 'Succeeded'", "purpose": "Retrieve AAR workflow logs showing automated AAR creation and completion tracking"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "DevOps After Action Report Work Items", "artifact_type": "Work Item Export", "description": "Complete set of AARs with root cause analysis, lessons learned, and preventative actions linked to incidents", "collection_method": "Azure DevOps REST API to export AAR work items with full history and attachments", "storage_location": "Azure DevOps database with 7-year retention for audit trail"},
            {"artifact_name": "Dataverse Lessons Learned Database", "artifact_type": "Lessons Learned Registry", "description": "Centralized lessons learned with implementation status, MITRE ATT&CK taxonomy, and ownership tracking", "collection_method": "Microsoft Dataverse Web API to export lessons_learned_records with implementation details", "storage_location": "Microsoft Dataverse with automated integration into operational procedures"},
            {"artifact_name": "Power BI Lessons Learned Implementation Dashboard", "artifact_type": "Analytics Dashboard", "description": "Dashboard showing AAR completion >= 95%, lessons learned implementation status, and recurring pattern mitigation", "collection_method": "Power BI REST API to export dashboard metrics demonstrating operational integration of lessons learned", "storage_location": "SharePoint with quarterly snapshots for trend analysis and executive reporting"},
            {"artifact_name": "SharePoint After Action Report Library", "artifact_type": "Document Repository", "description": "Published AARs with approval workflows, executive sign-off, and integration into security training materials", "collection_method": "SharePoint REST API to retrieve AAR documents with approval metadata and version history", "storage_location": "SharePoint Online with approval workflow tracking and access controls"},
            {"artifact_name": "Power Automate AAR Workflow Logs", "artifact_type": "Process Automation Logs", "description": "Logs of automated AAR creation, reminder escalations, and completion tracking showing systematic AAR process", "collection_method": "Power Automate REST API to retrieve workflow execution history with success/failure status", "storage_location": "Azure Storage Account with workflow run logs for process audit"}
        ]
    
