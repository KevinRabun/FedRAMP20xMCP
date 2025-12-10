"""
KSI-CED-02: Role-Specific Education

Require and monitor the effectiveness of role-specific training for high risk roles, including at least roles with privileged access.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CED_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CED-02: Role-Specific Education
    
    **Official Statement:**
    Require and monitor the effectiveness of role-specific training for high risk roles, including at least roles with privileged access.
    
    **Family:** CED - Cybersecurity Education
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - at-2
    - at-2.3
    - at-3
    - sr-11.1
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Require and monitor the effectiveness of role-specific training for high risk roles, including at le...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CED-02"
    KSI_NAME = "Role-Specific Education"
    KSI_STATEMENT = """Require and monitor the effectiveness of role-specific training for high risk roles, including at least roles with privileged access."""
    FAMILY = "CED"
    FAMILY_NAME = "Cybersecurity Education"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("at-2", "Literacy Training and Awareness"),
        ("at-2.3", "Social Engineering and Mining"),
        ("at-3", "Role-based Training"),
        ("sr-11.1", "Anti-counterfeit Training")
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
        Analyze Python code for KSI-CED-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training for high risk ro...
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
        Analyze C# code for KSI-CED-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training for high risk ro...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CED-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training for high risk ro...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CED-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training for high risk ro...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CED-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training for high risk ro...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CED-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training for high risk ro...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CED-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CED-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CED-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-CED-02.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Role-Specific Education",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Viva Learning",
                "Azure AD Privileged Identity Management",
                "Microsoft Defender for Cloud",
                "Microsoft Dataverse",
                "Power Automate"
            ],
            "collection_methods": [
                "Azure AD PIM integration to identify privileged users (Global Admin, Security Admin, Contributor, etc.)",
                "Microsoft Viva Learning to assign role-specific training (privileged access security, cloud admin best practices)",
                "Power Automate to trigger training assignments automatically when PIM role is activated or user joins privileged group",
                "Microsoft Dataverse to track role-specific training completion with role attribution (which role triggered training)",
                "Microsoft Defender for Cloud to recommend training based on security incidents or misconfigurations by privileged users"
            ],
            "implementation_steps": [
                "1. Configure Azure AD PIM role-based training triggers: (a) Create Logic App to monitor PIM role activations (Global Admin, Security Admin, etc.), (b) Trigger Power Automate flow to assign role-specific training in Viva Learning, (c) Set training deadline (7 days for new privileged users), (d) Send reminder emails via Power Automate",
                "2. Create role-specific training curriculum in Viva Learning: (a) Privileged Access Management training (for Global Admin, Security Admin), (b) Cloud Infrastructure Security (for Contributor, Owner roles), (c) Insider Threat Awareness (for roles with PII access), (d) Advanced Incident Response (for Security Operations roles)",
                "3. Build Microsoft Dataverse Privileged User Training Table: (a) Columns: UserID, Role, TrainingAssignedDate, CompletionDate, QuizScore, RoleActivationDate, (b) Automate record creation via Power Automate on PIM activation, (c) Flag users who complete training < 7 days after role assignment",
                "4. Integrate Defender for Cloud security recommendations: (a) Identify privileged users involved in security incidents, (b) Automatically assign remediation training based on incident type, (c) Track training completion as incident remediation step, (d) Generate monthly report of security incidents correlated with privileged user training status",
                "5. Create Power BI Role-Specific Training Dashboard: (a) Training completion rates by privileged role, (b) Time to complete training after role activation, (c) Quiz scores by role (identify high-risk roles needing more training), (d) Security incident correlation with training gaps",
                "6. Generate quarterly evidence package: (a) Export Dataverse privileged user training records with role attribution, (b) Export PIM role assignments and training completion correlation, (c) Export Defender security incidents with privileged user training status, (d) Export Power BI dashboard showing >= 95% role-specific training completion"
            ],
            "evidence_artifacts": [
                "Azure AD PIM Role Assignments with Training Completion Status for all privileged users",
                "Microsoft Viva Learning Role-Specific Training Completion Report organized by privileged role",
                "Microsoft Dataverse Privileged User Training Records with role attribution and quiz scores",
                "Microsoft Defender for Cloud Incident Correlation Report showing security events and privileged user training gaps",
                "Power BI Role-Specific Training Dashboard demonstrating >= 95% completion for all privileged roles"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Identity and Access Management Team / Security Training Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Microsoft Graph API",
                "query_name": "PIM role assignments for privileged users",
                "query": "GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal",
                "purpose": "Retrieve all privileged role assignments to identify users requiring role-specific training"
            },
            {
                "query_type": "Microsoft Graph API",
                "query_name": "Viva Learning role-specific training completions",
                "query": "GET https://graph.microsoft.com/v1.0/users/{userId}/learning/courseActivities?$filter=courseType eq 'RoleSpecific' and status eq 'completed'",
                "purpose": "Retrieve training completion records for role-specific courses (privileged access, cloud admin, etc.)"
            },
            {
                "query_type": "Microsoft Dataverse Web API",
                "query_name": "Privileged user training records with role attribution",
                "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/privileged_training_records?$select=userid,role,completiondate,quizscore,roleactivationdate&$filter=completiondate ge {quarterStartDate}",
                "purpose": "Retrieve quarterly privileged user training records with role and completion details"
            },
            {
                "query_type": "Microsoft Defender for Cloud REST API",
                "query_name": "Security incidents involving privileged users",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts?api-version=2021-01-01&$filter=properties/userPrincipalName in ({privilegedUserList})",
                "purpose": "Retrieve security alerts involving privileged users to correlate with training completion status"
            },
            {
                "query_type": "Power BI REST API",
                "query_name": "Role-specific training completion rates by privileged role",
                "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(PrivilegedTrainingRecords, PrivilegedTrainingRecords[Role], 'CompletionRate', DIVIDE(COUNTROWS(FILTER(PrivilegedTrainingRecords, PrivilegedTrainingRecords[Status] = 'Completed')), COUNTROWS(PrivilegedTrainingRecords)))\\\"}]}",
                "purpose": "Calculate training completion rates by privileged role (Global Admin, Security Admin, etc.)"
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
                "artifact_name": "Azure AD PIM Role Assignments with Training Status",
                "artifact_type": "Microsoft Graph API Export",
                "description": "Complete list of privileged role assignments with training completion status for each user",
                "collection_method": "Microsoft Graph API to retrieve PIM role assignments and correlate with Viva Learning training records",
                "storage_location": "Azure Storage Account with quarterly exports showing privileged users and training compliance"
            },
            {
                "artifact_name": "Viva Learning Role-Specific Training Completion Report",
                "artifact_type": "Microsoft Graph API Export",
                "description": "Training completion records organized by privileged role showing all role-holders completed required training",
                "collection_method": "Microsoft Graph API to retrieve role-specific course activities from Viva Learning",
                "storage_location": "Azure Storage Account with CSV exports by privileged role (Global Admin, Security Admin, etc.)"
            },
            {
                "artifact_name": "Dataverse Privileged User Training Records",
                "artifact_type": "Microsoft Dataverse Export",
                "description": "Centralized training records with role attribution, quiz scores, and time-to-complete metrics for privileged users",
                "collection_method": "Microsoft Dataverse Web API to export privileged_training_records table with quarterly filter",
                "storage_location": "Azure Storage Account with JSON exports showing role-specific training effectiveness"
            },
            {
                "artifact_name": "Defender for Cloud Incident Correlation Report",
                "artifact_type": "Security Alert Export",
                "description": "Security incidents involving privileged users correlated with training completion to identify training gaps",
                "collection_method": "Microsoft Defender for Cloud REST API to retrieve alerts involving privileged users and correlate with Dataverse training records",
                "storage_location": "Azure Storage Account with quarterly reports showing security incidents and training remediation"
            },
            {
                "artifact_name": "Power BI Role-Specific Training Dashboard",
                "artifact_type": "Power BI Report",
                "description": "Dashboard showing training completion rates by privileged role, quiz scores, and security incident correlation",
                "collection_method": "Power BI REST API to export dashboard metrics demonstrating >= 95% role-specific training completion",
                "storage_location": "SharePoint with quarterly PDF exports for executive and FedRAMP audit reporting"
            }
        ]
    
