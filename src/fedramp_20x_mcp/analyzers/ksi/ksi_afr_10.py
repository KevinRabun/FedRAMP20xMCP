"""
KSI-AFR-10: Incident Communications Procedures

Integrate FedRAMP's Incident Communications Procedures (ICP) into incident response procedures and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_10_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-10: Incident Communications Procedures
    
    **Official Statement:**
    Integrate FedRAMP's Incident Communications Procedures (ICP) into incident response procedures and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
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
    
    KSI_ID = "KSI-AFR-10"
    KSI_NAME = "Incident Communications Procedures"
    KSI_STATEMENT = """Integrate FedRAMP's Incident Communications Procedures (ICP) into incident response procedures and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
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
        Analyze Python code for KSI-AFR-10 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Integrate FedRAMP's Incident Communications Procedures (ICP) into incident respo...
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
        Analyze C# code for KSI-AFR-10 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Integrate FedRAMP's Incident Communications Procedures (ICP) into incident respo...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-10 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Integrate FedRAMP's Incident Communications Procedures (ICP) into incident respo...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-10 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Integrate FedRAMP's Incident Communications Procedures (ICP) into incident respo...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-10 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Integrate FedRAMP's Incident Communications Procedures (ICP) into incident respo...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-10 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Integrate FedRAMP's Incident Communications Procedures (ICP) into incident respo...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-10 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-10 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-10 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-AFR-10.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Incident Communications Procedures",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Sentinel",
                "Azure Logic Apps",
                "Microsoft 365 (Exchange)",
                "Azure DevOps",
                "Azure Monitor"
            ],
            "collection_methods": [
                "Microsoft Sentinel incident management to track and document all security incidents with FedRAMP ICP integration",
                "Azure Logic Apps playbooks to automate FedRAMP incident notification workflows per ICP requirements",
                "Microsoft 365 email templates for standardized FedRAMP incident communications to PMO",
                "Azure DevOps work items to track incident response actions and communications with full audit trail"
            ],
            "implementation_steps": [
                "1. Create Sentinel automation playbook 'FedRAMP-Incident-Communication': (a) Triggered on High/Critical incidents, (b) Classify incident per FedRAMP ICP categories, (c) Determine notification requirements, (d) Auto-generate notification draft",
                "2. Configure email templates in Microsoft 365: (a) Initial notification template, (b) Status update template, (c) Incident closure template, (d) All templates include FedRAMP-required fields (incident ID, date/time, impact, actions)",
                "3. Build Azure DevOps integration: (a) Auto-create work item for each Sentinel incident, (b) Track communication timeline with comments, (c) Link to evidence artifacts, (d) Require approval before closing",
                "4. Establish Azure Monitor alerting for ICP SLAs: (a) Alert if incident not reported within 1 hour (High/Critical), (b) Alert if no status update within 24 hours, (c) Alert if closure notification not sent",
                "5. Create Logic App 'FedRAMP-ICP-Evidence-Collector': (a) Runs monthly, (b) Exports all incident communications from email, (c) Exports Sentinel incident timeline, (d) Exports DevOps work item history, (e) Packages all evidence",
                "6. Document ICP procedures in Azure DevOps wiki: (a) Incident classification criteria, (b) Notification timelines, (c) Communication templates, (d) Escalation procedures, (e) Version-controlled with approvals"
            ],
            "evidence_artifacts": [
                "Sentinel Incident Timeline Report showing all security incidents with communication timestamps and recipients",
                "FedRAMP Incident Notification Email Archive with delivery confirmations for all incident communications",
                "DevOps Incident Response Work Items with complete audit trail of communications and actions taken",
                "ICP Compliance Dashboard showing SLA adherence for incident notification and update timelines",
                "Incident Communications Procedure Documentation from Azure DevOps wiki with version history"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Incident Response Team / Security Operations Center (SOC)"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Microsoft Sentinel KQL",
                "query_name": "All incidents with FedRAMP communication tracking",
                "query": """SecurityIncident
| where TimeGenerated > ago(30d)
| where Severity in ('High', 'Critical')
| extend FirstNotification = todatetime(parse_json(AdditionalData).FedRAMPFirstNotification)
| extend LastUpdate = todatetime(parse_json(AdditionalData).FedRAMPLastUpdate)
| extend ClosureNotification = todatetime(parse_json(AdditionalData).FedRAMPClosureNotification)
| project TimeGenerated, IncidentNumber, Title, Severity, Status, FirstNotification, LastUpdate, ClosureNotification, Owner
| order by TimeGenerated desc""",
                "purpose": "Track all security incidents and their FedRAMP ICP communication milestones"
            },
            {
                "query_type": "Microsoft Graph API",
                "query_name": "FedRAMP incident notification emails",
                "query": "GET https://graph.microsoft.com/v1.0/users/fedramp-security@{organization}.com/messages?$filter=subject contains 'Incident' or subject contains 'INC-' and sentDateTime ge {startDate}",
                "purpose": "Retrieve all incident notification emails sent to FedRAMP PMO with metadata"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Incident response work items with communications",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\nBody: {\"query\": \"SELECT [System.Id], [System.Title], [System.State], [Custom.IncidentID], [Custom.FedRAMPNotified], [Custom.NotificationTimestamp] FROM WorkItems WHERE [System.WorkItemType] = 'Incident' AND [System.State] <> 'Closed' ORDER BY [System.CreatedDate] DESC\"}",
                "purpose": "List all incident response work items with FedRAMP communication status"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "ICP SLA compliance metrics",
                "query": """SecurityIncident
| where TimeGenerated > ago(90d)
| where Severity in ('High', 'Critical')
| extend FirstNotification = todatetime(parse_json(AdditionalData).FedRAMPFirstNotification)
| extend NotificationDelay = datetime_diff('minute', FirstNotification, TimeGenerated)
| summarize TotalIncidents = count(), OnTimeNotifications = countif(NotificationDelay <= 60), LateNotifications = countif(NotificationDelay > 60), AvgNotificationDelay = avg(NotificationDelay) by bin(TimeGenerated, 7d)
| extend ComplianceRate = round((todouble(OnTimeNotifications) / todouble(TotalIncidents)) * 100, 2)
| project TimeGenerated, TotalIncidents, OnTimeNotifications, LateNotifications, AvgNotificationDelay, ComplianceRate
| order by TimeGenerated desc""",
                "purpose": "Calculate ICP SLA compliance rates for incident notification timelines"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "ICP documentation version history",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories/Security-Procedures/commits?searchCriteria.itemPath=/FedRAMP-ICP&api-version=7.0",
                "purpose": "Track all updates to FedRAMP Incident Communications Procedure documentation with approvals"
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
                "artifact_name": "Sentinel Incident Timeline Report",
                "artifact_type": "Microsoft Sentinel Export",
                "description": "Complete timeline of all security incidents with FedRAMP communication timestamps (initial notification, updates, closure)",
                "collection_method": "Microsoft Sentinel KQL query exported to JSON with incident details and communication metadata",
                "storage_location": "Azure Storage Account with monthly incident reports and 12-month retention"
            },
            {
                "artifact_name": "FedRAMP Incident Notification Email Archive",
                "artifact_type": "Microsoft 365 Email Export",
                "description": "Archive of all incident-related emails sent to FedRAMP PMO with delivery confirmations and read receipts",
                "collection_method": "Microsoft Graph API to export emails from security mailbox filtered by incident-related subjects",
                "storage_location": "Azure Storage Account with immutable blob storage and litigation hold for 7 years"
            },
            {
                "artifact_name": "DevOps Incident Response Work Items",
                "artifact_type": "Azure DevOps Work Item Export",
                "description": "Complete set of incident response work items with communication audit trail, status updates, and resolution details",
                "collection_method": "Azure DevOps REST API to export work items with full history and attachments",
                "storage_location": "Azure DevOps database with work item retention and version history"
            },
            {
                "artifact_name": "ICP SLA Compliance Dashboard",
                "artifact_type": "Azure Monitor Workbook",
                "description": "Dashboard showing ICP SLA adherence metrics: on-time notifications, average delays, compliance rates by severity",
                "collection_method": "Azure Monitor workbook querying Sentinel SecurityIncident table with SLA calculations",
                "storage_location": "Azure Monitor Workbooks with monthly snapshots archived as PDF"
            },
            {
                "artifact_name": "FedRAMP ICP Documentation Package",
                "artifact_type": "Azure DevOps Wiki Export",
                "description": "Complete FedRAMP Incident Communications Procedures documentation with version history and approval records",
                "collection_method": "Azure DevOps Git API to export wiki repository with commit history and pull request approvals",
                "storage_location": "Azure Repos with branch protection and required security team reviewers"
            }
        ]
    

