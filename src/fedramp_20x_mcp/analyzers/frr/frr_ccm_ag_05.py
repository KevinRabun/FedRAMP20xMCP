"""
FRR-CCM-AG-05: Notify FedRAMP of Concerns

Agencies MUST notify FedRAMP by sending a notification to info@fedramp.gov if the information presented in an _Ongoing Authorization Report_, _Quarterly Review_, or other ongoing _authorization data_ causes significant concerns that may lead the _agency_ to stop operation of the _cloud service offering_.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_AG_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-AG-05: Notify FedRAMP of Concerns
    
    **Official Statement:**
    Agencies MUST notify FedRAMP by sending a notification to info@fedramp.gov if the information presented in an _Ongoing Authorization Report_, _Quarterly Review_, or other ongoing _authorization data_ causes significant concerns that may lead the _agency_ to stop operation of the _cloud service offering_.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
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
    
    FRR_ID = "FRR-CCM-AG-05"
    FRR_NAME = "Notify FedRAMP of Concerns"
    FRR_STATEMENT = """Agencies MUST notify FedRAMP by sending a notification to info@fedramp.gov if the information presented in an _Ongoing Authorization Report_, _Quarterly Review_, or other ongoing _authorization data_ causes significant concerns that may lead the _agency_ to stop operation of the _cloud service offering_."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("IR-6", "Incident Reporting"),
        ("PM-15", "Contacts with Security Groups and Associations"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-AG-05 analyzer."""
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
        Analyze Python code for FRR-CCM-AG-05 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-AG-05 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-AG-05 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-AG-05 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-AG-05 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-AG-05 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-AG-05 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-AG-05 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-AG-05 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying FedRAMP.
        Agencies MUST notify FedRAMP at info@fedramp.gov of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation requirement
        for cloud service providers.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Returns Azure Resource Graph and KQL queries for evidence collection.
        
        Note: This is an AGENCY requirement. Evidence focuses on agency documentation
        of notifications sent to FedRAMP about significant concerns.
        """
        return [
            # Query 1: Not applicable - this is agency-to-FedRAMP communication
            """// NOT APPLICABLE: This requirement applies to agency communication with FedRAMP
// Agencies must notify FedRAMP at info@fedramp.gov of significant concerns
// Provider evidence: None - this is agency-to-FedRAMP reporting requirement""",
            
            # Query 2: Not applicable - FedRAMP notification tracking
            """// NOT APPLICABLE: FedRAMP tracks notifications from agencies
// Agencies must send notifications to info@fedramp.gov
// Provider evidence: None - CSP is not party to this communication""",
            
            # Query 3: Optional - CSP may be copied on notifications
            """// Optional: CSP may track if copied on agency notifications to FedRAMP
// Note: CSP is typically not the primary recipient
// This is agency compliance, not CSP compliance"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Agency email notifications sent to info@fedramp.gov",
            "Agency escalation procedures for FedRAMP notification",
            "Agency documentation of significant concerns triggering notification",
            "FedRAMP receipt acknowledgments (if provided)",
            "Agency communication logs showing FedRAMP notifications",
            "Agency policy requiring FedRAMP notification for concerns",
            "Agency decision records on stopping CSO operation",
            "Copy of notifications sent to info@fedramp.gov (if CSP copied)",
            "Agency risk assessment leading to FedRAMP notification",
            "FedRAMP guidance on notification requirements"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "Not Applicable - Agency Requirement",
                    "description": "This is an agency requirement to notify FedRAMP",
                    "query": """// NOT APPLICABLE: Agencies must notify FedRAMP, not CSP
// No CSP-side automation available for agency-to-FedRAMP communication""",
                    "schedule": "N/A",
                    "note": "CSP cannot automate agency notification to FedRAMP"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Agency Notification to FedRAMP",
                    "description": "Email sent to info@fedramp.gov by agency",
                    "location": "Agency email records / external",
                    "note": "Provider cannot generate this - agency-owned artifact"
                },
                {
                    "name": "FedRAMP Receipt Acknowledgment",
                    "description": "FedRAMP confirmation of agency notification receipt",
                    "location": "FedRAMP systems / agency email",
                    "note": "FedRAMP-generated, agency receives"
                }
            ],
            "implementation_notes": [
                "This is an AGENCY requirement - agencies MUST notify FedRAMP",
                "Applies when: Agency has significant concerns that may lead to stopping CSO",
                "Notification recipient: info@fedramp.gov (FedRAMP official email)",
                "Provider responsibility: None - this is agency-to-FedRAMP communication",
                "Agency responsibility: Send notification to FedRAMP about concerns",
                "Significant concerns: Issues that may lead agency to stop CSO operation",
                "'MUST' indicates mandatory notification requirement for agencies",
                "Notification triggers: Ongoing Authorization Report issues, Quarterly Review findings",
                "Provider may be: Copied on notification or informed by agency/FedRAMP",
                "Provider should: Respond to any concerns raised by agency or FedRAMP",
                "FedRAMP role: Central oversight of agency concerns across marketplace",
                "Evidence source: Agency email records and FedRAMP correspondence",
                "This enables FedRAMP to track systemic issues across agency users"
            ]
        }
