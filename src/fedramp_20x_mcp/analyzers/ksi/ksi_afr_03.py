"""
KSI-AFR-03: Authorization Data Sharing

Determine how authorization data will be shared with all necessary parties in alignment with the FedRAMP Authorization Data Sharing (ADS) process and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-03: Authorization Data Sharing
    
    **Official Statement:**
    Determine how authorization data will be shared with all necessary parties in alignment with the FedRAMP Authorization Data Sharing (ADS) process and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-3
    - ac-4
    - au-2
    - au-3
    - au-6
    - ca-2
    - ir-4
    - ra-5
    - sc-8
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Determine how authorization data will be shared with all necessary parties in alignment with the Fed...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-AFR-03"
    KSI_NAME = "Authorization Data Sharing"
    KSI_STATEMENT = """Determine how authorization data will be shared with all necessary parties in alignment with the FedRAMP Authorization Data Sharing (ADS) process and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-3", "Access Enforcement"),
        ("ac-4", "Information Flow Enforcement"),
        ("au-2", "Event Logging"),
        ("au-3", "Content of Audit Records"),
        ("au-6", "Audit Record Review, Analysis, and Reporting"),
        ("ca-2", "Control Assessments"),
        ("ir-4", "Incident Handling"),
        ("ra-5", "Vulnerability Monitoring and Scanning"),
        ("sc-8", "Transmission Confidentiality and Integrity")
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
        Analyze Python code for KSI-AFR-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how authorization data will be shared with all necessary parties in al...
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
        Analyze C# code for KSI-AFR-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how authorization data will be shared with all necessary parties in al...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how authorization data will be shared with all necessary parties in al...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how authorization data will be shared with all necessary parties in al...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Determine how authorization data will be shared with all necessary parties in al...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Determine how authorization data will be shared with all necessary parties in al...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-AFR-03.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Authorization Data Sharing",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Azure Monitor",
                "Azure DevOps",
                "Azure Storage",
                "Microsoft Purview",
                "Azure Logic Apps"
            ],
            "collection_methods": [
                "Azure DevOps repos/wikis to store and version-control data sharing agreements and MOUs",
                "Microsoft Purview to track data assets, classifications, and sharing arrangements",
                "Azure Monitor workbooks to document authorized data flows and external connections",
                "Azure Logic Apps to automate notification workflows when new data sharing agreements are created or modified"
            ],
            "implementation_steps": [
                "1. Create Azure DevOps repository 'FedRAMP-Data-Sharing-Agreements' with branch protection and approval requirements",
                "2. Store all data sharing agreements, MOUs, and interconnection security agreements (ISAs) in the repo as versioned documents",
                "3. Configure Microsoft Purview to catalog all data assets and document approved sharing arrangements with classifications",
                "4. Build Azure Monitor workbook 'Data Sharing Authorization Matrix' showing: (a) External system name, (b) Data shared, (c) Agreement reference, (d) Authorization date, (e) Review date",
                "5. Create Azure Logic App triggered on repo commits to notify security team of new/modified data sharing agreements",
                "6. Generate monthly evidence package via Azure Automation runbook that exports: (a) All agreements from DevOps, (b) Purview data lineage, (c) Authorization matrix from Monitor"
            ],
            "evidence_artifacts": [
                "Data Sharing Agreement Repository with all MOUs, ISAs, and authorization documents with version history",
                "Microsoft Purview Data Catalog showing classified data assets and approved sharing configurations",
                "Data Sharing Authorization Matrix documenting all authorized external connections and data flows",
                "Agreement Review Log showing annual reviews of data sharing agreements with sign-offs",
                "Data Flow Diagrams from Azure Monitor workbook showing authorized data exchanges with external systems"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team / Data Owner"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Retrieve all data sharing agreements",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories/FedRAMP-Data-Sharing-Agreements/items?scopePath=/Agreements&recursionLevel=Full&api-version=7.0",
                "purpose": "List all stored data sharing agreements and MOUs with metadata"
            },
            {
                "query_type": "Microsoft Purview REST API",
                "query_name": "Get data assets with external sharing",
                "query": "POST https://{purview-account}.purview.azure.com/catalog/api/search/query?api-version=2022-03-01-preview\nBody: {\"keywords\": \"*\", \"filter\": {\"customAttributes\": {\"ExternalSharing\": \"Authorized\"}}}",
                "purpose": "Identify all data assets authorized for external sharing with classification labels"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "External data connections audit",
                "query": """AzureDiagnostics
| where Category == 'NetworkSecurityGroupFlowEvent' or Category == 'ApplicationGatewayAccessLog'
| where (DestinationIP !startswith '10.' and DestinationIP !startswith '172.' and DestinationIP !startswith '192.168.')
| extend IsAuthorized = iff(DestinationIP in (AuthorizedExternalIPs), 'Yes', 'No')
| summarize ConnectionCount = count() by SourceIP, DestinationIP, DestinationPort, IsAuthorized
| order by ConnectionCount desc""",
                "purpose": "Audit all external network connections and verify they match authorized data sharing agreements"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Resources with external data sharing configured",
                "query": """Resources
| where tags['DataSharing'] == 'External-Authorized'
| project name, type, resourceGroup, location, tags
| order by type asc""",
                "purpose": "Identify Azure resources configured for authorized external data sharing"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Data sharing agreement review history",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories/FedRAMP-Data-Sharing-Agreements/commits?searchCriteria.itemPath=/Agreements&api-version=7.0",
                "purpose": "Track all modifications to data sharing agreements for audit trail and annual review evidence"
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
                "artifact_name": "Data Sharing Agreement Repository",
                "artifact_type": "Azure DevOps Git Repository",
                "description": "Version-controlled repository containing all MOUs, ISAs, and data sharing agreements with approval workflows",
                "collection_method": "Azure DevOps REST API to export all documents with commit history and approval records",
                "storage_location": "Azure Repos with branch protection, required reviewers, and audit logging"
            },
            {
                "artifact_name": "Purview Data Catalog Export",
                "artifact_type": "Microsoft Purview JSON Export",
                "description": "Complete catalog of data assets with classifications, lineage, and external sharing authorizations",
                "collection_method": "Microsoft Purview REST API to export data catalog with sharing metadata",
                "storage_location": "Azure Storage Account with JSON files organized by data asset type"
            },
            {
                "artifact_name": "Data Sharing Authorization Matrix",
                "artifact_type": "Azure Monitor Workbook",
                "description": "Matrix documenting all authorized data sharing arrangements including external system, data type, agreement reference, and review dates",
                "collection_method": "Azure Monitor workbook exported as PDF via Azure Logic App",
                "storage_location": "Azure Storage Account with monthly snapshots and immutable retention"
            },
            {
                "artifact_name": "External Connection Audit Report",
                "artifact_type": "Network Flow Logs Analysis",
                "description": "Report showing all external network connections compared against authorized data sharing agreements",
                "collection_method": "Azure Monitor KQL query analyzing NSG flow logs and Application Gateway logs",
                "storage_location": "Azure Log Analytics workspace with 12-month retention"
            },
            {
                "artifact_name": "Agreement Review Log",
                "artifact_type": "Azure DevOps Work Items",
                "description": "Tracking log for annual reviews of data sharing agreements with completion dates and approver signatures",
                "collection_method": "Azure DevOps Boards API exporting work items tagged 'Data-Sharing-Review'",
                "storage_location": "Azure DevOps work item database with email notifications to reviewers"
            }
        ]
    

