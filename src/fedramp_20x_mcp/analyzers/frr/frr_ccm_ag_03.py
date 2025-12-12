"""
FRR-CCM-AG-03: Senior Security Reviewer

Agencies SHOULD designate a senior information security official to review _Ongoing Authorization Reports_ and represent the agency at _Quarterly Reviews_ for _cloud service offerings_ included in agency information systems with a Security Category of High.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: SHOULD
Impact Levels: High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_AG_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-AG-03: Senior Security Reviewer
    
    **Official Statement:**
    Agencies SHOULD designate a senior information security official to review _Ongoing Authorization Reports_ and represent the agency at _Quarterly Reviews_ for _cloud service offerings_ included in agency information systems with a Security Category of High.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
    **Primary Keyword:** SHOULD
    
    **Impact Levels:**
    - Low: No
    - Moderate: No
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
    
    FRR_ID = "FRR-CCM-AG-03"
    FRR_NAME = "Senior Security Reviewer"
    FRR_STATEMENT = """Agencies SHOULD designate a senior information security official to review _Ongoing Authorization Reports_ and represent the agency at _Quarterly Reviews_ for _cloud service offerings_ included in agency information systems with a Security Category of High."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = False
    IMPACT_MODERATE = False
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("PM-1", "Information Security Program Plan"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-AG-03 analyzer."""
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
        Analyze Python code for FRR-CCM-AG-03 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-AG-03 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-AG-03 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-AG-03 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-AG-03 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-AG-03 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-AG-03 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-AG-03 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-AG-03 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about designating senior officials.
        Agencies SHOULD designate a senior information security official for High impact systems -
        this is a governance/human resources requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Returns Azure Resource Graph and KQL queries for evidence collection.
        
        Note: This is an AGENCY requirement for High impact systems. Evidence focuses
        on agency documentation of senior official designation and participation.
        """
        return [
            # Query 1: Not applicable - this is agency-side HR evidence
            """// NOT APPLICABLE: This requirement applies to agency HR/staffing for High impact
// Agencies must designate senior security officials for High impact system reviews
// Provider evidence: None - this is agency human resources requirement""",
            
            # Query 2: Optional - track High impact customer engagement
            """// Optional: CSP can track Quarterly Review participation for High impact customers
AppEvents
| where TimeGenerated > ago(90d)
| where Name == 'QuarterlyReview' or Name == 'ReportReview'
| extend ImpactLevel = tostring(Properties.impact_level)
| where ImpactLevel == 'High'
| extend AgencyId = tostring(Properties.agency_id)
| summarize ReviewCount = count() by AgencyId, bin(TimeGenerated, 30d)
| order by TimeGenerated desc""",
            
            # Query 3: Not applicable - agency internal staffing
            """// NOT APPLICABLE: Agency internal designation of senior officials
// Agencies should maintain records of senior official appointments
// Provider evidence: None - this is agency governance requirement"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Agency designation letter for senior security official (High impact systems)",
            "Agency organizational chart showing senior official role",
            "Senior official's resume or credentials documentation",
            "Agency attendance records for Quarterly Reviews (High impact systems)",
            "Senior official's review notes or reports",
            "Agency ATO documentation showing senior official authority",
            "Agency policy on senior official designation requirements",
            "Senior official's delegation of authority documentation",
            "Agency training records for senior officials on continuous monitoring",
            "Communication records between senior official and CSP"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "High Impact Customer Engagement Tracking",
                    "description": "Optional: Track engagement with High impact system agencies",
                    "query": """AppEvents
| where TimeGenerated > ago(90d)
| where Name contains 'QuarterlyReview' or Name contains 'ReportReview'
| extend ImpactLevel = tostring(Properties.impact_level)
| where ImpactLevel == 'High'
| summarize count() by bin(TimeGenerated, 7d)
| order by TimeGenerated desc""",
                    "schedule": "Quarterly",
                    "note": "CSP can track but cannot enforce agency senior official designation"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Senior Official Designation Letter",
                    "description": "Agency letter designating senior official for High impact reviews",
                    "location": "Agency-provided documentation / external",
                    "note": "Provider cannot generate this - agency-owned artifact"
                },
                {
                    "name": "Quarterly Review Attendance",
                    "description": "Records showing senior official participation",
                    "location": "Meeting minutes / attendance records",
                    "note": "CSP can document who attended from agency side"
                }
            ],
            "implementation_notes": [
                "This is an AGENCY requirement for High impact systems ONLY",
                "Applies when: Agency system includes CSO with High security category",
                "Provider responsibility: None - this is internal agency HR/governance",
                "Agency responsibility: Designate senior information security official",
                "Senior official duties: Review Ongoing Authorization Reports for High impact",
                "Senior official duties: Represent agency at Quarterly Reviews for High impact",
                "'Senior' indicates appropriate authority and experience level",
                "Provider can support: Coordinate with designated senior officials",
                "Provider can support: Provide clear contact information to senior officials",
                "Provider can support: Track participation in Quarterly Reviews",
                "Evidence source: Agency HR documentation and meeting records",
                "Not required for Low or Moderate impact systems (AG-03 is High only)"
            ]
        }
