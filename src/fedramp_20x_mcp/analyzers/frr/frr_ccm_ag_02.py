"""
FRR-CCM-AG-02: Consider Security Category

Agencies SHOULD consider the Security Category noted in their Authorization to Operate of the federal information system that includes the _cloud service offering_ in its boundary and assign appropriate information security resources for reviewing _Ongoing Authorization Reports_, attending _Quarterly Reviews_, and other ongoing _authorization data_.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_AG_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-AG-02: Consider Security Category
    
    **Official Statement:**
    Agencies SHOULD consider the Security Category noted in their Authorization to Operate of the federal information system that includes the _cloud service offering_ in its boundary and assign appropriate information security resources for reviewing _Ongoing Authorization Reports_, attending _Quarterly Reviews_, and other ongoing _authorization data_.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
    **Primary Keyword:** SHOULD
    
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
    
    FRR_ID = "FRR-CCM-AG-02"
    FRR_NAME = "Consider Security Category"
    FRR_STATEMENT = """Agencies SHOULD consider the Security Category noted in their Authorization to Operate of the federal information system that includes the _cloud service offering_ in its boundary and assign appropriate information security resources for reviewing _Ongoing Authorization Reports_, attending _Quarterly Reviews_, and other ongoing _authorization data_."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("PM-11", "Mission/Business Process Definition"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-AG-02 analyzer."""
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
        Analyze Python code for FRR-CCM-AG-02 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-AG-02 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-AG-02 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-AG-02 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-AG-02 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-AG-02 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-AG-02 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-AG-02 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-AG-02 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about resource allocation.
        Agencies SHOULD consider security category and assign appropriate resources for
        reviewing reports - this is a governance/resource management requirement for agencies,
        not a code implementation requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Returns Azure Resource Graph and KQL queries for evidence collection.
        
        Note: This is an AGENCY requirement. Evidence focuses on agency documentation
        of security categorization and resource allocation decisions.
        """
        return [
            # Query 1: Not applicable - this is agency-side evidence
            """// NOT APPLICABLE: This requirement applies to agency resource allocation
// Agencies must document security categorization and resource assignment
// Provider evidence: None - this is agency governance requirement""",
            
            # Query 2: Service provider metadata about security categories
            """// Optional: CSP can track which security categories are deployed
AzureResources
| where type == 'microsoft.web/sites' or type == 'microsoft.compute/virtualmachines'
| extend SecurityCategory = tostring(tags.SecurityCategory)
| where isnotempty(SecurityCategory)
| project name, type, SecurityCategory, resourceGroup
| summarize count() by SecurityCategory""",
            
            # Query 3: Not applicable - agency internal process
            """// NOT APPLICABLE: Agency internal resource allocation tracking
// Agencies should maintain staffing records for continuous monitoring
// Provider evidence: None - this is agency human resource requirement"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Agency ATO documentation showing security categorization",
            "Agency staffing plan for continuous monitoring activities",
            "Agency resource allocation decisions for review activities",
            "Agency attendance records for Quarterly Reviews",
            "Agency security personnel assignments to CSO monitoring",
            "Agency risk management framework (RMF) documentation",
            "Agency continuous monitoring strategy (ISCM)",
            "Agency budgetary allocation for security review activities",
            "Agency organizational charts showing security review roles",
            "Agency training records for personnel reviewing authorization data"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "Security Category Tracking",
                    "description": "Optional: Track deployed security categories for CSP reference",
                    "query": """AzureResources
| where isnotempty(tags.SecurityCategory)
| summarize count() by tostring(tags.SecurityCategory)""",
                    "schedule": "Quarterly",
                    "note": "CSP can track security categories but cannot enforce agency resource allocation"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Agency ATO Documentation",
                    "description": "Agency Authorization to Operate showing security category",
                    "location": "Agency-provided documentation / external",
                    "note": "Provider cannot generate this - agency-owned artifact"
                },
                {
                    "name": "Agency Staffing Plan",
                    "description": "Agency documentation of resource allocation for monitoring",
                    "location": "Agency-provided documentation / external",
                    "note": "Provider cannot generate this - agency-owned artifact"
                }
            ],
            "implementation_notes": [
                "This is an AGENCY requirement - agencies SHOULD allocate appropriate resources",
                "Provider responsibility: None - this is internal agency governance",
                "Agency responsibility: Consider security category when assigning staff",
                "Agency responsibility: Allocate appropriate resources for ongoing monitoring",
                "Higher security categories may require more experienced security personnel",
                "Agencies should budget for continuous monitoring activities",
                "Provider can support: Provide clear security categorization in documentation",
                "Provider can support: Facilitate agency participation in Quarterly Reviews",
                "Evidence source: Agency internal HR and budget documentation"
            ]
        }
