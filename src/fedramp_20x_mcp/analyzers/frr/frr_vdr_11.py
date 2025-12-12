"""
FRR-VDR-11: Documenting Reasons

Providers MUST document the reason and resulting implications for their customers when choosing not to meet FedRAMP recommendations in this process; this documentation MUST be included in the _authorization data_ for the _cloud service offering_.

Official FedRAMP 20x Requirement
Source: FRR-VDR (Vulnerability Detection and Response) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_VDR_11_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-VDR-11: Documenting Reasons
    
    **Official Statement:**
    Providers MUST document the reason and resulting implications for their customers when choosing not to meet FedRAMP recommendations in this process; this documentation MUST be included in the _authorization data_ for the _cloud service offering_.
    
    **Family:** VDR - Vulnerability Detection and Response
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-VDR-11"
    FRR_NAME = "Documenting Reasons"
    FRR_STATEMENT = """Providers MUST document the reason and resulting implications for their customers when choosing not to meet FedRAMP recommendations in this process; this documentation MUST be included in the _authorization data_ for the _cloud service offering_."""
    FAMILY = "VDR"
    FAMILY_NAME = "Vulnerability Detection and Response"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("RA-5", "Vulnerability Monitoring and Scanning"),
        ("SI-2", "Flaw Remediation"),
        ("CA-7", "Continuous Monitoring"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-04"  # Vulnerability Detection and Response
    ]
    
    def __init__(self):
        """Initialize FRR-VDR-11 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for FRR-VDR-11 compliance using AST.
        
        TODO: Implement Python analysis
        - Use ASTParser(CodeLanguage.PYTHON)
        - Use tree.root_node and code_bytes
        - Use find_nodes_by_type() for AST nodes
        - Fallback to regex if AST fails
        
        Detection targets:
        - TODO: List what patterns to detect
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST-based analysis
        # Example from FRR-VDR-08:
        # try:
        #     parser = ASTParser(CodeLanguage.PYTHON)
        #     tree = parser.parse(code)
        #     code_bytes = code.encode('utf8')
        #     
        #     if tree and tree.root_node:
        #         # Find relevant nodes
        #         nodes = parser.find_nodes_by_type(tree.root_node, 'node_type')
        #         for node in nodes:
        #             node_text = parser.get_node_text(node, code_bytes)
        #             # Check for violations
        #         
        #         return findings
        # except Exception:
        #     pass
        
        # TODO: Implement regex fallback
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-VDR-11 compliance using AST.
        
        TODO: Implement C# analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for C#
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-VDR-11 compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-VDR-11 compliance using AST.
        
        TODO: Implement TypeScript analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-VDR-11 compliance.
        
        TODO: Implement Bicep analysis
        - Detect relevant Azure resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Bicep regex patterns
        # Example:
        # resource_pattern = r"resource\s+\w+\s+'Microsoft\.\w+/\w+@[\d-]+'\s*="
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-VDR-11 compliance.
        
        TODO: Implement Terraform analysis
        - Detect relevant resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Terraform regex patterns
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-VDR-11 compliance.
        
        TODO: Implement GitHub Actions analysis
        - Check for required steps/actions
        - Verify compliance configuration
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitHub Actions analysis
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-VDR-11 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-VDR-11 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation for FRR-VDR-11.
        
        Returns:
            List of query dictionaries for collecting deviation documentation
        """
        return [
            {
                "query_type": "Azure Storage Account REST API",
                "query_name": "Retrieve deviation documentation from authorization data store",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/blobServices/default/containers/authorization-data/blobs?api-version=2022-09-01&prefix=deviations/",
                "purpose": "List all deviation documentation files stored in Azure Storage for the cloud service offering"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Resources with deviation tags",
                "query": """Resources
| where tags contains 'fedramp-deviation'
| project resourceId = id, resourceName = name, resourceType = type, 
    deviationReason = tags['fedramp-deviation-reason'], 
    customerImpact = tags['fedramp-deviation-impact'],
    approvalDate = tags['fedramp-deviation-approved'],
    resourceGroup, subscriptionId
| order by resourceName""",
                "purpose": "Identify Azure resources that have documented deviations from FedRAMP recommendations"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Deviation work items and approval records",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0 (WIQL: SELECT [System.Id], [System.Title], [Custom.DeviationReason], [Custom.CustomerImpact] FROM WorkItems WHERE [System.WorkItemType] = 'FedRAMP Deviation' AND [System.State] = 'Approved')",
                "purpose": "Query Azure DevOps for formal deviation requests and approval documentation"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Access logs for authorization data documentation",
                "query": """StorageBlobLogs
| where AccountName == 'authorizationdata'
| where ObjectKey contains 'deviations/'
| where OperationName in ('PutBlob', 'GetBlob')
| summarize LastModified = max(TimeGenerated), AccessCount = count() by ObjectKey, CallerIpAddress
| project ObjectKey, LastModified, AccessCount, CallerIpAddress
| order by LastModified desc""",
                "purpose": "Track creation and access of deviation documentation to ensure it's current and accessible for assessors"
            },
            {
                "query_type": "Microsoft Purview REST API",
                "query_name": "Data catalog search for FedRAMP deviation documents",
                "query": "POST https://{accountName}.purview.azure.com/catalog/api/search/query?api-version=2022-03-01-preview (body: {\"keywords\": \"FedRAMP deviation\", \"filter\": {\"and\": [{\"collectionId\": \"authorization-data\"}]}})",
                "purpose": "Search data catalog for all documents tagged as FedRAMP deviations to ensure comprehensive documentation"
            }
        ]
    
    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect for FRR-VDR-11.
        
        Returns:
            List of artifact dictionaries describing required documentation
        """
        return [
            {
                "artifact_name": "Deviation Documentation Register",
                "artifact_type": "Excel workbook or JSON file",
                "description": "Complete register of all instances where the provider chose not to meet FedRAMP recommendations, including deviation reason, customer impact analysis, and authorization data reference",
                "collection_method": "Query Azure Resource Graph for tagged resources and Azure Storage for documentation files, consolidate into structured register",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-11/deviation-register/{YYYY-MM}/"
            },
            {
                "artifact_name": "Customer Impact Assessment Documents",
                "artifact_type": "PDF/Word documents",
                "description": "Detailed assessment for each deviation explaining the resulting implications for customers, including security impact, operational considerations, and mitigation measures",
                "collection_method": "Retrieve from Azure Storage authorization-data container /deviations/{deviation-id}/customer-impact-assessment.pdf",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-11/customer-impact-assessments/"
            },
            {
                "artifact_name": "Authorization Data Package Inclusion Proof",
                "artifact_type": "PDF report with screenshots",
                "description": "Evidence showing that deviation documentation is included in the authorization data package submitted to FedRAMP, including table of contents excerpt and file listings",
                "collection_method": "Export authorization data package metadata from Azure Storage, capture screenshots of deviation section in SSP appendices",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-11/authorization-data-proof/{YYYY-MM}/"
            },
            {
                "artifact_name": "Deviation Approval Records",
                "artifact_type": "Azure DevOps work item export (JSON/Excel)",
                "description": "Formal approval records for each documented deviation, including approval date, approver identity (CISO, Authorizing Official), and approval rationale",
                "collection_method": "Export work items from Azure DevOps using REST API filtered for 'FedRAMP Deviation' work item type with 'Approved' state",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-11/approvals/{YYYY-MM}/"
            },
            {
                "artifact_name": "Deviation Documentation Access Audit Log",
                "artifact_type": "CSV file",
                "description": "Audit log showing creation, modification, and access of deviation documentation to demonstrate ongoing maintenance and assessor accessibility",
                "collection_method": "Query Azure Storage Analytics logs for blob operations on /deviations/ path using Azure Monitor KQL",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-11/access-logs/{YYYY-MM}/"
            },
            {
                "artifact_name": "Quarterly Deviation Review Report",
                "artifact_type": "PDF report",
                "description": "Quarterly executive report summarizing all active deviations, customer impact, any changes to deviation status, and plan for achieving full FedRAMP recommendation compliance",
                "collection_method": "Manual compilation by GRC team aggregating deviation register data, customer feedback, and remediation roadmap",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-11/quarterly-reviews/{YYYY-QQ}/"
            }
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for FRR-VDR-11.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "frr_id": self.FRR_ID,
            "frr_name": self.FRR_NAME,
            "primary_keyword": "MUST",
            "impact_levels": ["Low", "Moderate", "High"],
            "evidence_type": "manual (with automated collection support)",
            "automation_feasibility": "medium",
            "azure_services": [
                "Azure Storage Account (for authorization data storage)",
                "Azure Resource Graph (for tagged resource tracking)",
                "Azure DevOps (for deviation workflow and approvals)",
                "Azure Monitor (for access audit logs)",
                "Microsoft Purview (for data catalog and discovery)"
            ],
            "collection_methods": [
                "Azure Storage REST API to list and retrieve deviation documentation files",
                "Azure Resource Graph query to identify resources with 'fedramp-deviation' tags",
                "Azure DevOps work item queries for formal deviation approval records",
                "Azure Monitor KQL queries for documentation access audit logs",
                "Microsoft Purview search API for comprehensive deviation document discovery"
            ],
            "implementation_steps": [
                "1. Establish Azure Storage account with /authorization-data/deviations/ container for centralized documentation",
                "2. Implement Azure Resource tagging standard: 'fedramp-deviation', 'fedramp-deviation-reason', 'fedramp-deviation-impact', 'fedramp-deviation-approved'",
                "3. Configure Azure DevOps project with custom 'FedRAMP Deviation' work item type including fields for reason, customer impact, and approval workflow",
                "4. Enable Azure Storage Analytics and Azure Monitor integration for access logging",
                "5. Create Azure Logic App to automatically generate deviation register by querying Resource Graph, Storage API, and DevOps API monthly",
                "6. Implement Azure Function to validate that each deviation has required documentation (reason document, customer impact assessment, approval record) before marking as complete",
                "7. Configure Microsoft Purview to catalog all deviation documents with appropriate metadata for assessor discovery"
            ],
            "evidence_artifacts": [
                "Deviation Documentation Register (Excel/JSON)",
                "Customer Impact Assessment Documents (PDF/Word per deviation)",
                "Authorization Data Package Inclusion Proof (PDF with screenshots)",
                "Deviation Approval Records (Azure DevOps export)",
                "Deviation Documentation Access Audit Log (CSV)",
                "Quarterly Deviation Review Report (PDF)"
            ],
            "manual_validation_steps": [
                "1. For each documented deviation, verify that a clear reason is stated explaining why the FedRAMP recommendation was not met",
                "2. Review customer impact assessment to ensure implications are thoroughly analyzed (security, operational, compliance)",
                "3. Confirm deviation documentation is included in the authorization data package (check SSP appendix, RET supplements)",
                "4. Verify formal approval exists from appropriate authority (CISO, Authorizing Official) for each deviation",
                "5. Interview GRC team to understand deviation tracking process and quarterly review cadence",
                "6. Sample 3-5 deviations and trace from Resource Graph tag → Documentation file → DevOps approval → Authorization data inclusion"
            ],
            "update_frequency": "Real-time for new deviations, monthly register update, quarterly review report",
            "responsible_party": "GRC Team / Security Compliance Manager"
        }
