"""
FRR-CCM-QR-03: Review Scheduling Window

Providers SHOULD regularly schedule _Quarterly Reviews_ to occur at least 3 business days after releasing an _Ongoing Authorization Report_ AND within 10 business days of such release.

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


class FRR_CCM_QR_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-QR-03: Review Scheduling Window
    
    **Official Statement:**
    Providers SHOULD regularly schedule _Quarterly Reviews_ to occur at least 3 business days after releasing an _Ongoing Authorization Report_ AND within 10 business days of such release.
    
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
    
    FRR_ID = "FRR-CCM-QR-03"
    FRR_NAME = "Review Scheduling Window"
    FRR_STATEMENT = """Providers SHOULD regularly schedule _Quarterly Reviews_ to occur at least 3 business days after releasing an _Ongoing Authorization Report_ AND within 10 business days of such release."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-QR-03 analyzer."""
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
        Analyze Python code for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: This requirement specifies the scheduling window for
        quarterly reviews - at least 3 business days after releasing an Ongoing
        Authorization Report AND within 10 business days of such release. It's
        a scheduling/timing requirement, not a code implementation requirement.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing (3-10 business days after report release). Not detectable in code.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing (3-10 business days after report release). Not detectable in code.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing (3-10 business days after report release). Not detectable in code.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing. Not detectable in infrastructure.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing. Not detectable in infrastructure.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing. Not detectable in CI/CD.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing. Not detectable in CI/CD.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-QR-03 compliance.
        
        NOT APPLICABLE: Provider scheduling requirement for quarterly review
        timing. Not detectable in CI/CD.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[Dict[str, Any]]:
        """
        Get automated queries for evidence collection.
        
        Returns queries that can be executed against cloud platforms,
        logging systems, or configuration management tools.
        """
        return [
            {
                "query_type": "Document Repository Query",
                "platform": "SharePoint, Confluence, etc.",
                "query": "Find Ongoing Authorization Report release dates to establish baseline for scheduling window",
                "description": "Identify when each Ongoing Authorization Report was released to calculate proper QR scheduling window"
            },
            {
                "query_type": "Calendar Analysis",
                "platform": "Calendar system",
                "query": "Compare Quarterly Review meeting dates against Ongoing Authorization Report release dates to verify 3-10 business day window",
                "description": "Verify QRs are scheduled at least 3 business days after and within 10 business days of report release"
            },
            {
                "query_type": "Business Days Calculator",
                "platform": "Custom script or compliance tool",
                "query": "Calculate business days between report release and QR meeting (excluding weekends/holidays)",
                "description": "Ensure timing window calculation uses business days, not calendar days"
            }
        ]
    
    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get list of evidence artifacts to collect.
        
        Returns specific files, logs, configurations, or documentation
        that demonstrate compliance.
        """
        return [
            {
                "artifact_type": "Ongoing Authorization Report Release Dates",
                "location": "Document repository",
                "description": "Log or metadata showing when each Ongoing Authorization Report was released to agencies/necessary parties",
                "collection_method": "Export from document management system"
            },
            {
                "artifact_type": "Quarterly Review Meeting Dates",
                "location": "Calendar system",
                "description": "Calendar entries showing when Quarterly Reviews were scheduled and held",
                "collection_method": "Export from calendar system"
            },
            {
                "artifact_type": "Scheduling Window Compliance Report",
                "location": "Compliance tracking system",
                "description": "Report showing for each QR: (1) Report release date, (2) QR meeting date, (3) Business days between, (4) Compliance status (3-10 day window)",
                "collection_method": "Generate from compliance tool"
            },
            {
                "artifact_type": "Business Days Calendar",
                "location": "HR or compliance system",
                "description": "Organization's business days calendar showing weekends, holidays, and non-business days used for calculations",
                "collection_method": "Export from HR/compliance system"
            },
            {
                "artifact_type": "Scheduling Policy Documentation",
                "location": "Policy repository",
                "description": "Provider's documented policy for scheduling Quarterly Reviews within the 3-10 business day window",
                "collection_method": "Manual - Collect from policy documentation"
            },
            {
                "artifact_type": "Exception Documentation (If Any)",
                "location": "Compliance records",
                "description": "Documentation of any instances where QR was scheduled outside the 3-10 day window with justification",
                "collection_method": "Manual - Collect from compliance records"
            },
            {
                "artifact_type": "Quarterly Review Invitations",
                "location": "Calendar system",
                "description": "Meeting invitations showing scheduled dates relative to report release dates",
                "collection_method": "Export from calendar system"
            },
            {
                "artifact_type": "Report Distribution Confirmation",
                "location": "Email or document system",
                "description": "Confirmation that Ongoing Authorization Report was distributed before scheduling the Quarterly Review",
                "collection_method": "Email receipts or system logs"
            },
            {
                "artifact_type": "Scheduling Timeline Documentation",
                "location": "Project management system",
                "description": "Timeline showing the sequence: (1) Report completion, (2) Report release, (3) QR scheduling (at least 3 days later), (4) QR meeting (within 10 days)",
                "collection_method": "Export from project tracking"
            },
            {
                "artifact_type": "Automated Scheduling System Configuration",
                "location": "Scheduling tool",
                "description": "If using automated scheduling: Configuration showing 3-10 business day window is enforced",
                "collection_method": "Export configuration from scheduling tool"
            }
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection.
        """
        return {
            "automated_queries": self.get_evidence_collection_queries(),
            "evidence_artifacts": self.get_evidence_artifacts(),
            "implementation_notes": [
                "NOT APPLICABLE for code analysis - This is a provider scheduling/timing requirement",
                "Requirement: Providers SHOULD regularly schedule Quarterly Reviews to occur at least 3 business days after releasing Ongoing Authorization Report AND within 10 business days of release",
                "Minimum Delay: At least 3 business days after report release",
                "Maximum Delay: Within 10 business days of report release",
                "Day Type: Business days (not calendar days) - excludes weekends and holidays",
                "Both Conditions Required: Must satisfy BOTH the 3-day minimum AND 10-day maximum (window is 3-10 business days)",
                "Impact Levels: All (Low, Moderate, High)",
                "Primary Keyword: SHOULD (recommended practice, not mandatory)",
                "Purpose: Gives agencies time to review the Ongoing Authorization Report (3 days) while keeping discussion timely (within 10 days)",
                "Key Evidence: Report release dates, QR meeting dates, business days calculation showing compliance with window",
                "Calculation Challenge: Must correctly calculate business days (exclude weekends/holidays)",
                "Automation Opportunity: Can automate tracking of report release dates and QR meeting dates to verify window compliance",
                "Related Requirements: FRR-CCM-QR-01 (SHOULD host QRs for Low), FRR-CCM-QR-02 (MUST host QRs for Moderate/High)",
                "Regularly: Word 'regularly' implies consistent pattern of scheduling within this window",
                "Monitoring: Track all QRs to verify they fall within 3-10 business day window after each report release"
            ]
        }
