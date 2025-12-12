"""
FRR-VDR-TF-MO-01: 14-Day History

Providers SHOULD make all recent historical _vulnerability detection_ and _response_ activity available in a _machine-readable_ format for automated retrieval by all necessary parties (e.g. using an API service or similar); this information SHOULD be updated _persistently_, at least once every 14 days.

Official FedRAMP 20x Requirement
Source: FRR-VDR (Vulnerability Detection and Response) family
Primary Keyword: SHOULD
Impact Levels: Moderate
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_VDR_TF_MO_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-VDR-TF-MO-01: 14-Day History
    
    **Official Statement:**
    Providers SHOULD make all recent historical _vulnerability detection_ and _response_ activity available in a _machine-readable_ format for automated retrieval by all necessary parties (e.g. using an API service or similar); this information SHOULD be updated _persistently_, at least once every 14 days.
    
    **Family:** VDR - Vulnerability Detection and Response
    
    **Primary Keyword:** SHOULD
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    - High: No
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-VDR-TF-MO-01"
    FRR_NAME = "14-Day History"
    FRR_STATEMENT = """Providers SHOULD make all recent historical _vulnerability detection_ and _response_ activity available in a _machine-readable_ format for automated retrieval by all necessary parties (e.g. using an API service or similar); this information SHOULD be updated _persistently_, at least once every 14 days."""
    FAMILY = "VDR"
    FAMILY_NAME = "Vulnerability Detection and Response"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    IMPACT_HIGH = False
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
        """Initialize FRR-VDR-TF-MO-01 analyzer."""
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
        Analyze Python code for FRR-VDR-TF-MO-01 compliance using AST.
        
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
        Analyze C# code for FRR-VDR-TF-MO-01 compliance using AST.
        
        TODO: Implement C# analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for C#
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-VDR-TF-MO-01 compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-VDR-TF-MO-01 compliance using AST.
        
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
        Analyze Bicep infrastructure code for FRR-VDR-TF-MO-01 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-VDR-TF-MO-01 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-VDR-TF-MO-01 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-VDR-TF-MO-01 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-VDR-TF-MO-01 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get automated queries for collecting evidence of 14-day machine-readable VDR history availability.
        
        Returns structured queries for API service availability, machine-readable format verification,
        and 14-day update frequency tracking (Moderate impact - middle ground between 7-day High and 30-day Low).
        """
        return {
            "API service availability for VDR history": {
                "description": "Verify VDR history API services are available for automated retrieval by all necessary parties (14-day update cadence for Moderate impact)",
                "api_availability_query": """
                    AzureDiagnostics
                    | where Category == 'ApplicationGatewayAccess' or Category == 'ApiManagement'
                    | where RequestUri contains 'vulnerability' or RequestUri contains 'vdr' or RequestUri contains 'security'
                    | where httpMethod_s == 'GET'
                    | summarize RequestCount = count(), LastAccess = max(TimeGenerated), AvgResponseTime = avg(timeTaken_s) by RequestUri, resultCode_s
                    | extend APIAvailability = iff(resultCode_s startswith '2', 'Available', 'Degraded')
                    | project RequestUri, APIAvailability, RequestCount, LastAccess, AvgResponseTime
                """,
                "azure_resource_graph": """
                    Resources
                    | where type == 'microsoft.apimanagement/service' or type == 'microsoft.web/sites'
                    | where tags['Purpose'] contains 'VDR' or tags['Purpose'] contains 'Vulnerability' or name contains 'vdr' or name contains 'vulnerability'
                    | extend APIEndpoint = properties.gatewayUrl
                    | extend ProvisioningState = properties.provisioningState
                    | project name, resourceGroup, APIEndpoint, ProvisioningState, tags
                """
            },
            "Machine-readable format verification": {
                "description": "Verify VDR history is provided in machine-readable formats (JSON, XML, CSV) for automated processing",
                "format_verification_query": """
                    AzureDiagnostics
                    | where Category == 'ApiManagement' or Category == 'ApplicationInsights'
                    | where RequestUri contains 'vulnerability' or RequestUri contains 'vdr'
                    | extend ResponseFormat = case(
                        ResponseHeaders contains 'application/json', 'JSON',
                        ResponseHeaders contains 'application/xml', 'XML',
                        ResponseHeaders contains 'text/csv', 'CSV',
                        'Other'
                    )
                    | summarize RequestCount = count() by ResponseFormat
                    | extend MachineReadable = iff(ResponseFormat in ('JSON', 'XML', 'CSV'), 'Yes', 'No')
                    | project ResponseFormat, MachineReadable, RequestCount
                """,
                "storage_format_query": """
                    StorageBlobLogs
                    | where TimeGenerated > ago(14d)
                    | where Uri contains 'vdr-history' or Uri contains 'vulnerability-data'
                    | extend FileExtension = extract(@'\\.(\\w+)$', 1, Uri)
                    | extend MachineReadable = iff(FileExtension in ('json', 'xml', 'csv'), 'Yes', 'No')
                    | summarize FileCount = count(), LastModified = max(TimeGenerated) by FileExtension, MachineReadable
                    | project FileExtension, MachineReadable, FileCount, LastModified
                """
            },
            "14-day update frequency tracking": {
                "description": "Track persistent updates to VDR history at 14-day intervals (Moderate impact - middle between 7-day High and 30-day Low)",
                "update_frequency_query": """
                    AzureDiagnostics
                    | where Category == 'VulnerabilityData' or Category == 'VDRHistory'
                    | where OperationName contains 'Update' or OperationName contains 'Refresh'
                    | summarize UpdateEvents = count(), LastUpdate = max(TimeGenerated), FirstUpdate = min(TimeGenerated) by bin(TimeGenerated, 14d)
                    | extend DaysSinceLastUpdate = datetime_diff('day', now(), LastUpdate)
                    | extend FourteenDayCompliance = iff(DaysSinceLastUpdate <= 14, 'Compliant', 'NonCompliant')
                    | project UpdatePeriod = TimeGenerated, UpdateEvents, FirstUpdate, LastUpdate, DaysSinceLastUpdate, FourteenDayCompliance
                """,
                "scheduled_refresh_query": """
                    Resources
                    | where type == 'microsoft.automation/automationaccounts/schedules' or type == 'microsoft.logic/workflows'
                    | where properties.frequency == 'Week' and properties.interval == 2  // Bi-weekly = 14 days
                    | where name contains 'VDR' or name contains 'Vulnerability'
                    | extend ScheduleFrequency = strcat(properties.frequency, '-', properties.interval)
                    | extend Enabled = properties.enabled
                    | project name, resourceGroup, ScheduleFrequency, Enabled, NextRun = properties.nextRun
                """
            }
        }

    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts needed to demonstrate 14-day machine-readable VDR history compliance.
        
        Returns artifacts for API service availability, machine-readable format verification,
        and 14-day update frequency per FRR-VDR-TF-MO-01.
        """
        return [
            "API service endpoints for VDR history retrieval (REST APIs, GraphQL, or similar)",
            "API availability and performance metrics for VDR history services",
            "Machine-readable format verification: JSON/XML/CSV response headers and file extensions for VDR history data",
            "VDR history data samples in machine-readable formats (demonstration of automated retrieval capability)",
            "14-day update frequency logs showing persistent refreshes of VDR history data (Moderate impact: middle between 7-day High and 30-day Low)",
            "Scheduled job configurations for bi-weekly (14-day) VDR history updates",
            "API access logs showing automated retrieval by necessary parties (security teams, auditors, compliance tools)",
            "VDR history update timestamps for past 90 days demonstrating 14-day persistent update cadence"
        ]

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for FRR-VDR-TF-MO-01.
        
        Returns automation strategies for API service implementation, machine-readable format
        enforcement, and 14-day update scheduling.
        """
        return {
            "api_service_implementation": {
                "description": "Implement API service for automated VDR history retrieval by all necessary parties",
                "implementation": "Use Azure API Management or Azure Functions to expose VDR history via REST API with machine-readable responses (JSON/XML/CSV)",
                "rationale": "Enables automated retrieval per FRR-VDR-TF-MO-01 SHOULD requirement - VDR history available via API for necessary parties (Moderate impact)"
            },
            "machine_readable_format_enforcement": {
                "description": "Enforce machine-readable formats (JSON/XML/CSV) for all VDR history responses",
                "implementation": "Configure API Management policies to ensure Content-Type headers are application/json, application/xml, or text/csv; reject non-machine-readable formats",
                "rationale": "Ensures VDR history is in machine-readable format per FRR-VDR-TF-MO-01 for automated processing"
            },
            "fourteen_day_update_scheduling": {
                "description": "Schedule persistent VDR history updates every 14 days (bi-weekly cadence for Moderate impact)",
                "implementation": "Use Azure Automation with bi-weekly schedule or Logic Apps with recurrence trigger at 14-day intervals",
                "rationale": "Provides persistent 14-day updates per FRR-VDR-TF-MO-01 Moderate impact requirement (middle between 7-day High and 30-day Low)"
            },
            "update_frequency_monitoring": {
                "description": "Monitor VDR history update frequency to ensure 14-day SLA compliance",
                "implementation": "Use Azure Monitor alerts to detect missed 14-day updates, track last update timestamp, alert at 16-day mark if no refresh",
                "rationale": "Ensures continuous 14-day update cadence per FRR-VDR-TF-MO-01 SHOULD requirement (Moderate impact system)"
            },
            "api_access_tracking": {
                "description": "Track API access by necessary parties to demonstrate automated retrieval capability",
                "implementation": "Use API Management analytics to log access patterns, consumer identities, request volumes for VDR history API",
                "rationale": "Provides evidence that VDR history is available for automated retrieval by all necessary parties per requirement"
            }
        }
