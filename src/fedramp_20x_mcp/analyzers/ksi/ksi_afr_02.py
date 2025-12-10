"""
KSI-AFR-02: Key Security Indicators

Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indicators (KSIs - you are here), develop automated validation of status and progress to the greatest extent possible, and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-02: Key Security Indicators
    
    **Official Statement:**
    Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indicators (KSIs - you are here), develop automated validation of status and progress to the greatest extent possible, and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indica...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    **Note:** This KSI is not intended to create an infinite loop; unlike other KSI-AFR themed indicators, this KSI is addressed by otherwise addressing all the KSIs.
    """
    
    KSI_ID = "KSI-AFR-02"
    KSI_NAME = "Key Security Indicators"
    KSI_STATEMENT = """Set security goals for the cloud service offering based on FedRAMP 20x Phase Two Key Security Indicators (KSIs - you are here), develop automated validation of status and progress to the greatest extent possible, and persistently address all related requirements and recommendations."""
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
        Analyze Python code for KSI-AFR-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
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
        Analyze C# code for KSI-AFR-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Set security goals for the cloud service offering based on FedRAMP 20x Phase Two...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-02 compliance.
        
        Detects:
        - Missing compliance validation steps
        - Missing security goal tracking
        - Missing progress monitoring
        """
        findings = []
        lines = code.split('\n')
        
        # Check for compliance validation steps
        has_compliance_check = bool(re.search(r'(compliance|fedramp|security.*(validation|check|scan))', code, re.IGNORECASE))
        has_status_reporting = bool(re.search(r'(status|progress).*(report|track|monitor)', code, re.IGNORECASE))
        has_gates = bool(re.search(r'(gate|approval|review)', code, re.IGNORECASE))
        
        if not has_compliance_check:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing automated compliance validation",
                description="GitHub Actions workflow lacks automated compliance validation steps. KSI-AFR-02 requires automated validation of security goals and progress.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add compliance validation step: - name: Validate Compliance\n  run: ./scripts/validate-security-goals.sh"
            ))
        
        if not has_status_reporting:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing progress monitoring",
                description="Workflow does not report security goal progress. KSI-AFR-02 requires monitoring and reporting of status.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add status reporting: - name: Report Security Status\n  run: ./scripts/report-security-progress.sh"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-AFR-02.
        
        Note: This KSI is meta - it's about tracking implementation of all other KSIs.
        Evidence automation is achieved by implementing the other 64 KSIs.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Key Security Indicators",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "special_note": "This is a meta-KSI. Evidence is collected by implementing automated evidence collection for all other 64 active KSIs.",
            "azure_services": [
                "Azure Monitor",
                "Azure Automation",
                "Azure DevOps",
                "Azure Logic Apps",
                "Azure Storage"
            ],
            "collection_methods": [
                "Azure Monitor workbook to aggregate KSI implementation status across all 65 KSIs",
                "Azure Automation runbooks to execute evidence collection for each implemented KSI",
                "Azure DevOps pipelines to schedule and orchestrate KSI evidence gathering",
                "Azure Logic Apps to consolidate evidence artifacts into unified compliance reports"
            ],
            "implementation_steps": [
                "1. Create Azure Monitor workbook 'FedRAMP KSI Dashboard' with 65 rows (one per KSI)",
                "2. For each KSI, add workbook query to check: (a) Evidence automation implemented, (b) Last evidence collection date, (c) Compliance status",
                "3. Build Azure Automation runbook 'Collect-AllKSIEvidence' that iterates through all 65 KSIs and invokes their evidence collection methods",
                "4. Create Azure DevOps pipeline to run KSI evidence collection monthly (or per FedRAMP requirement)",
                "5. Store all evidence artifacts in Azure Storage with folder structure: /KSI-{FAMILY}-{NUMBER}/{YYYY-MM}/",
                "6. Generate consolidated KSI implementation report using Azure Logic App that reads from Storage and creates PDF summary"
            ],
            "evidence_artifacts": [
                "KSI Implementation Dashboard showing 65 KSIs with implementation status and last evidence date",
                "Consolidated KSI Evidence Package containing all 65 KSI evidence artifacts organized by family",
                "KSI Compliance Matrix mapping each KSI to NIST controls and FedRAMP requirements",
                "Evidence Collection Audit Log from Azure Automation showing all KSI collection runs",
                "Monthly KSI Summary Report with compliance percentages by family and impact level"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team / Compliance Officer"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "KSI implementation status aggregation",
                "query": """let KSIList = dynamic([\"IAM-01\", \"IAM-02\", \"IAM-03\", \"IAM-04\", \"IAM-05\", \"IAM-06\", \"IAM-07\", \"CNA-01\", \"CNA-02\", \"CNA-03\", \"CNA-04\", \"CNA-05\", \"CNA-06\", \"CNA-07\", \"CNA-08\", \"MLA-01\", \"MLA-02\", \"MLA-05\", \"MLA-07\", \"MLA-08\", \"AFR-01\", \"AFR-02\", \"AFR-03\", \"AFR-04\", \"AFR-05\", \"AFR-06\", \"AFR-07\", \"AFR-08\", \"AFR-09\", \"AFR-10\", \"AFR-11\", \"CMT-01\", \"CMT-02\", \"CMT-03\", \"CMT-04\", \"SVC-01\", \"SVC-02\", \"SVC-04\", \"SVC-05\", \"SVC-06\", \"SVC-07\", \"SVC-08\", \"SVC-09\", \"SVC-10\", \"INR-01\", \"INR-02\", \"INR-03\", \"CED-01\", \"CED-02\", \"CED-03\", \"CED-04\", \"PIY-01\", \"PIY-02\", \"PIY-03\", \"PIY-04\", \"PIY-05\", \"PIY-06\", \"PIY-07\", \"PIY-08\", \"RPL-01\", \"RPL-02\", \"RPL-03\", \"RPL-04\", \"TPR-01\", \"TPR-02\"]);
AutomationRunbook_CL
| where RunbookName_s startswith \"Collect-KSI-\"
| extend KSI_ID = extract(@\"Collect-KSI-([A-Z]{3}-\\d{2})\", 1, RunbookName_s)
| summarize LastCollection = max(TimeGenerated), CollectionCount = count(), LastStatus = any(Status_s) by KSI_ID
| project KSI_ID, LastCollection, CollectionCount, LastStatus
| order by KSI_ID asc""",
                "purpose": "Track which KSIs have evidence automation implemented and when evidence was last collected"
            },
            {
                "query_type": "Azure Storage REST API",
                "query_name": "Retrieve all KSI evidence artifacts",
                "query": "GET https://{storageaccount}.blob.core.windows.net/ksi-evidence?restype=container&comp=list&prefix=KSI-",
                "purpose": "List all stored KSI evidence artifacts across all families for compliance reporting"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Azure services used for KSI evidence automation",
                "query": """Resources
| where tags['Purpose'] == 'KSI-Evidence-Automation'
| summarize ServiceCount = count() by type
| project AzureService = type, ResourceCount = ServiceCount
| order by ResourceCount desc""",
                "purpose": "Identify all Azure resources supporting KSI evidence automation infrastructure"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "KSI evidence pipeline execution history",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/pipelines/{pipelineId}/runs?api-version=7.0",
                "purpose": "Track execution history of KSI evidence collection pipelines for audit trail"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "KSI compliance rate by family",
                "query": """let TotalKSIs = 65;
let FamilyCounts = dynamic({\"IAM\": 7, \"CNA\": 8, \"MLA\": 5, \"AFR\": 11, \"CMT\": 4, \"SVC\": 9, \"INR\": 3, \"CED\": 4, \"PIY\": 8, \"RPL\": 4, \"TPR\": 2});
AutomationRunbook_CL
| where RunbookName_s startswith \"Collect-KSI-\"
| extend KSI_Family = extract(@\"Collect-KSI-([A-Z]{3})-\", 1, RunbookName_s)
| where Status_s == \"Completed\"
| summarize ImplementedKSIs = dcount(RunbookName_s) by KSI_Family
| extend TotalInFamily = toint(FamilyCounts[KSI_Family])
| extend ComplianceRate = round((todouble(ImplementedKSIs) / todouble(TotalInFamily)) * 100, 2)
| project KSI_Family, ImplementedKSIs, TotalInFamily, ComplianceRate
| order by ComplianceRate desc""",
                "purpose": "Calculate KSI implementation compliance percentage by family for executive reporting"
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
                "artifact_name": "KSI Implementation Dashboard",
                "artifact_type": "Azure Monitor Workbook",
                "description": "Interactive dashboard showing implementation status, last evidence collection date, and compliance status for all 65 KSIs",
                "collection_method": "Azure Monitor workbook querying Azure Automation job history and Azure Storage evidence artifacts",
                "storage_location": "Azure Monitor Workbooks shared with Cloud Security Team"
            },
            {
                "artifact_name": "Consolidated KSI Evidence Package",
                "artifact_type": "ZIP Archive",
                "description": "Complete set of evidence artifacts from all 65 KSIs organized by family folders",
                "collection_method": "Azure Logic App that downloads all evidence from Azure Storage and creates timestamped ZIP file",
                "storage_location": "Azure Storage Account with immutable blob storage and 7-year retention"
            },
            {
                "artifact_name": "KSI Compliance Matrix",
                "artifact_type": "Excel Spreadsheet",
                "description": "Matrix mapping each of 65 KSIs to NIST 800-53 controls, FedRAMP requirements, implementation status, and evidence location",
                "collection_method": "Azure Automation runbook generating Excel file from KSI metadata and evidence collection status",
                "storage_location": "Azure DevOps artifacts repository with version control"
            },
            {
                "artifact_name": "Evidence Collection Audit Log",
                "artifact_type": "Azure Automation Job History",
                "description": "Complete audit trail of all KSI evidence collection executions including timestamps, status, and error logs",
                "collection_method": "Azure Automation job history exported via PowerShell script to CSV",
                "storage_location": "Azure Log Analytics workspace with 12-month retention and alerting"
            },
            {
                "artifact_name": "Monthly KSI Summary Report",
                "artifact_type": "PDF Report",
                "description": "Executive summary showing KSI compliance percentages, trends, gaps, and recommendations by family and impact level",
                "collection_method": "Azure Logic App querying KSI dashboard data and generating PDF via Power BI REST API",
                "storage_location": "Azure Storage Account with automated distribution to stakeholders via email"
            }
        ]
    

