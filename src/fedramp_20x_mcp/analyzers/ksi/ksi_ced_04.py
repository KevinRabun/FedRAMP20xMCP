"""
KSI-CED-04: Incident Response and Disaster Recovery Education

Require and monitor the effectiveness of role-specific training to staff involved with incident response or disaster recovery.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CED_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CED-04: Incident Response and Disaster Recovery Education
    
    **Official Statement:**
    Require and monitor the effectiveness of role-specific training to staff involved with incident response or disaster recovery.
    
    **Family:** CED - Cybersecurity Education
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Require and monitor the effectiveness of role-specific training to staff involved with incident resp...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CED-04"
    KSI_NAME = "Incident Response and Disaster Recovery Education"
    KSI_STATEMENT = """Require and monitor the effectiveness of role-specific training to staff involved with incident response or disaster recovery."""
    FAMILY = "CED"
    FAMILY_NAME = "Cybersecurity Education"
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
        Analyze Python code for KSI-CED-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training to staff involve...
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
        Analyze C# code for KSI-CED-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training to staff involve...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CED-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training to staff involve...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CED-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training to staff involve...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CED-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training to staff involve...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CED-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training to staff involve...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CED-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CED-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CED-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-CED-04.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Incident Response and Disaster Recovery Education",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Viva Learning",
                "Microsoft Sentinel",
                "Azure Site Recovery",
                "Microsoft Dataverse",
                "Power Automate"
            ],
            "collection_methods": [
                "Microsoft Sentinel to identify users assigned to incident response playbooks and security operations roles",
                "Microsoft Viva Learning to assign incident response training (forensics, containment, eradication, recovery)",
                "Azure Site Recovery to identify disaster recovery coordinators and assign DR training (runbook execution, failover, failback)",
                "Power Automate to trigger training when new users join SOC team or are assigned to DR runbooks",
                "Microsoft Dataverse to track IR/DR training completion and correlate with tabletop exercise participation"
            ],
            "implementation_steps": [
                "1. Configure Microsoft Sentinel role-based training triggers: (a) Create Logic App to monitor role assignments (Security Reader, Security Operator, Security Administrator, Incident Responder), (b) Trigger Power Automate flow to assign IR training in Viva Learning, (c) Set training deadline (14 days for new SOC members), (d) Send reminder emails and escalations",
                "2. Create incident response and disaster recovery curriculum: (a) NIST IR Lifecycle Training (Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned), (b) Azure-specific Incident Response (Sentinel playbooks, Defender alerts, forensics), (c) Disaster Recovery Procedures (Azure Site Recovery failover/failback, RTO/RPO validation), (d) Tabletop Exercise Facilitation and Participation",
                "3. Build Microsoft Dataverse IR/DR Training Table: (a) Columns: UserID, Role, TrainingType (IR/DR), CompletionDate, QuizScore, TabletopExerciseDate, IncidentParticipation, (b) Automate record creation via Power Automate on Sentinel/Site Recovery role assignment, (c) Track tabletop exercise participation and incident response involvement",
                "4. Integrate Azure Site Recovery with training assignments: (a) Identify users listed in DR runbooks and recovery plans, (b) Automatically assign DR training via Power Automate, (c) Require training completion before DR runbook execution permissions granted, (d) Track DR testing participation as ongoing training",
                "5. Create Power BI IR/DR Training Dashboard: (a) Training completion rates for SOC and DR teams, (b) Tabletop exercise participation tracking, (c) Real incident response participation vs. training completion, (d) Quiz scores and remediation assignments, (e) Training effectiveness (incident response time trends)",
                "6. Generate quarterly evidence package: (a) Export Dataverse IR/DR training records with role attribution, (b) Export Sentinel role assignments and training completion correlation, (c) Export tabletop exercise attendance and outcomes, (d) Export Power BI dashboard showing >= 95% IR/DR training completion"
            ],
            "evidence_artifacts": [
                "Microsoft Sentinel Role Assignments with IR Training Completion Status for all SOC personnel",
                "Microsoft Viva Learning IR/DR Training Completion Report for incident responders and disaster recovery coordinators",
                "Microsoft Dataverse IR/DR Training Records with tabletop exercise participation and real incident involvement",
                "Azure Site Recovery Runbook Assignments with DR Training Status for all recovery coordinators",
                "Power BI IR/DR Training Dashboard showing >= 95% training completion and tabletop exercise participation trends"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Security Operations Center (SOC) Manager / Business Continuity Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Microsoft Sentinel REST API",
                "query_name": "Sentinel role assignments for incident responders",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
                "purpose": "Retrieve Sentinel role assignments (Security Reader, Incident Responder, etc.) to identify users requiring IR training"
            },
            {
                "query_type": "Microsoft Graph API",
                "query_name": "Viva Learning IR/DR training completions",
                "query": "GET https://graph.microsoft.com/v1.0/users/{userId}/learning/courseActivities?$filter=(courseType eq 'IncidentResponse' or courseType eq 'DisasterRecovery') and status eq 'completed'",
                "purpose": "Retrieve training completion records for incident response and disaster recovery courses"
            },
            {
                "query_type": "Microsoft Dataverse Web API",
                "query_name": "IR/DR training records with tabletop exercise participation",
                "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/ir_dr_training_records?$select=userid,role,trainingtype,completiondate,tabletopexercisedate,incidentparticipation&$filter=completiondate ge {quarterStartDate}",
                "purpose": "Retrieve quarterly IR/DR training records with tabletop exercise and real incident participation"
            },
            {
                "query_type": "Azure Site Recovery REST API",
                "query_name": "DR runbook assignments for disaster recovery coordinators",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/replicationRecoveryPlans?api-version=2022-10-01",
                "purpose": "Retrieve disaster recovery plans and identify users assigned to runbooks requiring DR training"
            },
            {
                "query_type": "Power BI REST API",
                "query_name": "IR/DR training completion rates by team",
                "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(IR_DR_TrainingRecords, IR_DR_TrainingRecords[Role], 'CompletionRate', DIVIDE(COUNTROWS(FILTER(IR_DR_TrainingRecords, IR_DR_TrainingRecords[Status] = 'Completed')), COUNTROWS(IR_DR_TrainingRecords)), 'TabletopParticipationRate', DIVIDE(COUNTROWS(FILTER(IR_DR_TrainingRecords, IR_DR_TrainingRecords[TabletopExerciseDate] != BLANK())), COUNTROWS(IR_DR_TrainingRecords)))\\\"}]}",
                "purpose": "Calculate IR/DR training completion rates and tabletop exercise participation by role (SOC, DR coordinators)"
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
                "artifact_name": "Microsoft Sentinel Role Assignments with IR Training Status",
                "artifact_type": "Microsoft Sentinel Export",
                "description": "Complete list of Sentinel role assignments (Security Reader, Incident Responder, etc.) with training completion status",
                "collection_method": "Microsoft Sentinel REST API to retrieve role assignments and correlate with Viva Learning training records",
                "storage_location": "Azure Storage Account with quarterly exports showing SOC personnel and training compliance"
            },
            {
                "artifact_name": "Viva Learning IR/DR Training Completion Report",
                "artifact_type": "Microsoft Graph API Export",
                "description": "Training completion records for incident response and disaster recovery courses for all SOC and DR team members",
                "collection_method": "Microsoft Graph API to retrieve IR/DR course activities from Viva Learning",
                "storage_location": "Azure Storage Account with CSV exports organized by role (IR, DR, SOC)"
            },
            {
                "artifact_name": "Dataverse IR/DR Training Records with Exercise Participation",
                "artifact_type": "Microsoft Dataverse Export",
                "description": "Centralized training records with tabletop exercise participation and real incident response involvement",
                "collection_method": "Microsoft Dataverse Web API to export ir_dr_training_records with quarterly filter",
                "storage_location": "Azure Storage Account with JSON exports showing training and hands-on exercise participation"
            },
            {
                "artifact_name": "Azure Site Recovery Runbook Assignments with DR Training Status",
                "artifact_type": "Azure Site Recovery Export",
                "description": "Disaster recovery plans and runbook assignments with DR training completion status for all coordinators",
                "collection_method": "Azure Site Recovery REST API to retrieve recovery plans and correlate with Dataverse training records",
                "storage_location": "Azure Storage Account with recovery plan exports showing personnel and training compliance"
            },
            {
                "artifact_name": "Power BI IR/DR Training Dashboard",
                "artifact_type": "Power BI Report",
                "description": "Dashboard showing training completion rates >= 95%, tabletop exercise participation, and incident response time trends",
                "collection_method": "Power BI REST API to export dashboard metrics demonstrating SOC and DR team training effectiveness",
                "storage_location": "SharePoint with quarterly PDF snapshots for security leadership and FedRAMP compliance audits"
            }
        ]
    
