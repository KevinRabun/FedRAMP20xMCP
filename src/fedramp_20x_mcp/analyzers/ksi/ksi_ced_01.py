"""
KSI-CED-01: General Education

Require and monitor the effectiveness of training given to all employees on policies, procedures, and security-related topics.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CED_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CED-01: General Education
    
    **Official Statement:**
    Require and monitor the effectiveness of training given to all employees on policies, procedures, and security-related topics.
    
    **Family:** CED - Cybersecurity Education
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - at-2
    - at-2.2
    - at-2.3
    - at-3.5
    - at-4
    - ir-2.3
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Require and monitor the effectiveness of training given to all employees on policies, procedures, an...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CED-01"
    KSI_NAME = "General Education"
    KSI_STATEMENT = """Require and monitor the effectiveness of training given to all employees on policies, procedures, and security-related topics."""
    FAMILY = "CED"
    FAMILY_NAME = "Cybersecurity Education"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("at-2", "Literacy Training and Awareness"),
        ("at-2.2", "Insider Threat"),
        ("at-2.3", "Social Engineering and Mining"),
        ("at-3.5", "Processing Personally Identifiable Information"),
        ("at-4", "Training Records"),
        ("ir-2.3", "Breach")
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
        Analyze Python code for KSI-CED-01 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of training given to all employees on poli...
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
        Analyze C# code for KSI-CED-01 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of training given to all employees on poli...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CED-01 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of training given to all employees on poli...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CED-01 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of training given to all employees on poli...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CED-01 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of training given to all employees on poli...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CED-01 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of training given to all employees on poli...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CED-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CED-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CED-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-CED-01.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "General Education",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Viva Learning",
                "Azure AD B2C",
                "Microsoft Dataverse",
                "Power BI",
                "Azure Monitor"
            ],
            "collection_methods": [
                "Microsoft Viva Learning integration with LMS (LinkedIn Learning, Coursera, Skillsoft) to track training completion and quiz scores",
                "Azure AD B2C custom attributes to store training completion dates and certification status per user",
                "Microsoft Dataverse to centralize training records (completion, effectiveness scores, remediation assignments)",
                "Power BI to visualize training metrics (completion rates, average quiz scores, time to complete, overdue training)",
                "Azure Monitor Application Insights to track user engagement with security awareness training portals"
            ],
            "implementation_steps": [
                "1. Configure Microsoft Viva Learning with LMS integration: (a) Connect to LinkedIn Learning, Coursera, or internal LMS, (b) Assign security awareness training courses (phishing, data handling, incident reporting), (c) Set completion requirements (all employees, annual refresh), (d) Enable quiz/assessment tracking",
                "2. Extend Azure AD B2C user profiles with custom training attributes: (a) 'SecurityTrainingCompletedDate' (datetime), (b) 'SecurityTrainingScore' (int), (c) 'SecurityCertificationStatus' (Compliant/Overdue/Exempt), (d) 'LastTrainingReminder' (datetime)",
                "3. Build Microsoft Dataverse Training Records Table: (a) Columns: UserID, TrainingType, CompletionDate, QuizScore, EffectivenessRating, RemediationRequired, (b) Automate record creation via Power Automate when Viva Learning reports completion, (c) Flag users with quiz scores < 80% for remediation",
                "4. Create Power BI Training Effectiveness Dashboard: (a) Overall completion rate by department, (b) Average quiz scores trending over time, (c) Overdue training by employee and manager, (d) Phishing simulation results correlated with training completion, (e) Remediation assignments and completion status",
                "5. Configure Azure Monitor Application Insights for training portal: (a) Track user logins to training portal, (b) Monitor training video watch time and completion rates, (c) Capture quiz submission events with anonymized scores, (d) Alert on low engagement rates (< 70% monthly logins)",
                "6. Generate quarterly evidence package: (a) Export Dataverse training records with completion proofs, (b) Export Power BI dashboard showing completion rates >= 95%, (c) Export Viva Learning course assignments and completions, (d) Export phishing simulation results showing training effectiveness"
            ],
            "evidence_artifacts": [
                "Microsoft Viva Learning Training Completion Report showing all employees completed assigned security awareness courses",
                "Azure AD B2C User Profile Export with SecurityTrainingCompletedDate and SecurityCertificationStatus attributes",
                "Microsoft Dataverse Training Records with quiz scores and remediation assignments for low-performing employees",
                "Power BI Training Effectiveness Dashboard showing >= 95% completion rate and trending quiz scores",
                "Phishing Simulation Results correlated with training completion to demonstrate training effectiveness (reduction in click rates)"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Human Resources / Security Awareness Team"
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
                "query_name": "Viva Learning training assignments and completions",
                "query": "GET https://graph.microsoft.com/v1.0/users/{userId}/learning/courseActivities?$filter=courseType eq 'SecurityAwareness'",
                "purpose": "Retrieve training completion records from Viva Learning for security awareness courses"
            },
            {
                "query_type": "Microsoft Graph API",
                "query_name": "Azure AD B2C user profiles with training attributes",
                "query": "GET https://graph.microsoft.com/v1.0/users?$select=id,displayName,extension_SecurityTrainingCompletedDate,extension_SecurityTrainingScore,extension_SecurityCertificationStatus",
                "purpose": "Retrieve user training status from Azure AD B2C custom attributes"
            },
            {
                "query_type": "Microsoft Dataverse Web API",
                "query_name": "Training records with effectiveness scores",
                "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/training_records?$select=userid,trainingtype,completiondate,quizscore,remediationrequired&$filter=completiondate ge {quarterStartDate}",
                "purpose": "Retrieve quarterly training records with quiz scores and remediation flags from Dataverse"
            },
            {
                "query_type": "Power BI REST API",
                "query_name": "Training effectiveness dashboard metrics",
                "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(TrainingRecords, TrainingRecords[Department], 'CompletionRate', DIVIDE(COUNTROWS(FILTER(TrainingRecords, TrainingRecords[Status] = 'Completed')), COUNTROWS(TrainingRecords)))\\\"}]}",
                "purpose": "Calculate training completion rates by department from Power BI dataset"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Training portal engagement metrics",
                "query": """customEvents
| where name in ('TrainingLoginEvent', 'CourseCompletionEvent', 'QuizSubmissionEvent')
| extend UserID = tostring(customDimensions.UserID), EventType = name, Timestamp = timestamp
| summarize TotalLogins = countif(EventType == 'TrainingLoginEvent'), TotalCompletions = countif(EventType == 'CourseCompletionEvent'), AvgQuizScore = avgif(toint(customDimensions.QuizScore), EventType == 'QuizSubmissionEvent') by bin(Timestamp, 30d)
| extend EngagementRate = round((todouble(TotalLogins) / 1000) * 100, 2)
| order by Timestamp desc""",
                "purpose": "Track user engagement with training portal and calculate monthly engagement rates"
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
                "artifact_name": "Viva Learning Training Completion Report",
                "artifact_type": "Microsoft Graph API Export",
                "description": "Complete list of security awareness training assignments and completions showing all employees completed required courses",
                "collection_method": "Microsoft Graph API to retrieve Viva Learning course activities filtered by SecurityAwareness category",
                "storage_location": "Azure Storage Account with quarterly exports organized by completion date"
            },
            {
                "artifact_name": "Azure AD B2C User Training Status Export",
                "artifact_type": "Microsoft Graph API Export",
                "description": "User profile export including SecurityTrainingCompletedDate, SecurityTrainingScore, and SecurityCertificationStatus attributes",
                "collection_method": "Microsoft Graph API to retrieve user profiles with training-related custom attributes",
                "storage_location": "Azure Storage Account with CSV exports showing current training compliance status"
            },
            {
                "artifact_name": "Dataverse Training Records with Effectiveness Scores",
                "artifact_type": "Microsoft Dataverse Export",
                "description": "Centralized training records including quiz scores, remediation assignments, and completion proofs",
                "collection_method": "Microsoft Dataverse Web API to export training_records table with quarterly filter",
                "storage_location": "Azure Storage Account with JSON exports showing training effectiveness (quiz scores, remediation status)"
            },
            {
                "artifact_name": "Power BI Training Effectiveness Dashboard",
                "artifact_type": "Power BI Report",
                "description": "Comprehensive dashboard showing completion rates, quiz score trends, overdue training, and department-level compliance",
                "collection_method": "Power BI REST API to export dashboard metrics and visualizations as PDF",
                "storage_location": "SharePoint with quarterly snapshots showing >= 95% completion rate for executive reporting"
            },
            {
                "artifact_name": "Phishing Simulation Results with Training Correlation",
                "artifact_type": "Security Awareness Report",
                "description": "Phishing simulation results correlated with training completion to demonstrate effectiveness (reduced click rates post-training)",
                "collection_method": "Export from phishing simulation platform (KnowBe4, Proofpoint, Cofense) and correlate with Dataverse training records",
                "storage_location": "Azure Storage Account with quarterly reports showing training impact on security behavior"
            }
        ]
    
