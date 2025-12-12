"""
FRR-CCM-QR-02: Quarterly Review

Providers MUST host a synchronous _Quarterly Review_ every 3 months, open to _all necessary parties_, to review aspects of the most recent _Ongoing Authorization Reports_ that the provider determines are of the most relevance to _agencies_.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: MUST
Impact Levels: Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_QR_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-QR-02: Quarterly Review
    
    **Official Statement:**
    Providers MUST host a synchronous _Quarterly Review_ every 3 months, open to _all necessary parties_, to review aspects of the most recent _Ongoing Authorization Reports_ that the provider determines are of the most relevance to _agencies_.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: No
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
    
    FRR_ID = "FRR-CCM-QR-02"
    FRR_NAME = "Quarterly Review"
    FRR_STATEMENT = """Providers MUST host a synchronous _Quarterly Review_ every 3 months, open to _all necessary parties_, to review aspects of the most recent _Ongoing Authorization Reports_ that the provider determines are of the most relevance to _agencies_."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-QR-02 analyzer."""
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
        Analyze Python code for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: This requirement mandates that providers MUST host
        synchronous quarterly review meetings for Moderate/High impact systems.
        It's a process/meeting requirement, not a code implementation requirement.
        This is the mandatory version of FRR-CCM-QR-01 (which is SHOULD for Low).
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings (Moderate/High - mandatory). Not detectable in code.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings (Moderate/High - mandatory). Not detectable in code.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings (Moderate/High - mandatory). Not detectable in code.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings. Not detectable in infrastructure.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings. Not detectable in infrastructure.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings. Not detectable in CI/CD.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings. Not detectable in CI/CD.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-QR-02 compliance.
        
        NOT APPLICABLE: Provider process requirement for hosting quarterly
        review meetings. Not detectable in CI/CD.
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
                "query_type": "Calendar/Meeting System",
                "platform": "Microsoft 365, Google Calendar, etc.",
                "query": "Search for recurring meetings with 'Quarterly Review' or 'QR' in title every 3 months",
                "description": "Verify provider hosts quarterly review meetings at 3-month intervals (MUST for Moderate/High)"
            },
            {
                "query_type": "Meeting Attendance Records",
                "platform": "Meeting system, ticketing system",
                "query": "List attendees for Quarterly Review meetings to verify 'all necessary parties' are invited",
                "description": "Confirm agencies and other necessary parties have access to quarterly reviews"
            },
            {
                "query_type": "Compliance Tracking",
                "platform": "Compliance management system",
                "query": "Verify quarterly review schedule maintained for all Moderate/High impact systems",
                "description": "Ensure MUST requirement is met for Moderate/High (unlike SHOULD for Low in QR-01)"
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
                "artifact_type": "Quarterly Review Meeting Invitations",
                "location": "Calendar system",
                "description": "Calendar invitations for quarterly review meetings every 3 months, showing 'all necessary parties' invited (MANDATORY for Moderate/High)",
                "collection_method": "Export from calendar system"
            },
            {
                "artifact_type": "Quarterly Review Meeting Minutes",
                "location": "Document repository",
                "description": "Minutes/notes from quarterly review meetings showing discussions of relevant Ongoing Authorization Report aspects",
                "collection_method": "Manual - Collect from document storage"
            },
            {
                "artifact_type": "Quarterly Review Attendance Records",
                "location": "Meeting system",
                "description": "Attendance records showing which agencies and necessary parties participated in quarterly reviews",
                "collection_method": "Export from meeting system"
            },
            {
                "artifact_type": "Quarterly Review Schedule",
                "location": "Project management system",
                "description": "Schedule showing quarterly review meetings planned at 3-month intervals throughout the year (mandatory compliance)",
                "collection_method": "Manual - Export from project tracking"
            },
            {
                "artifact_type": "Quarterly Review Agendas",
                "location": "Document repository",
                "description": "Agendas for quarterly reviews showing topics from Ongoing Authorization Reports determined most relevant to agencies",
                "collection_method": "Manual - Collect from document storage"
            },
            {
                "artifact_type": "Meeting Recordings (Optional)",
                "location": "Video conferencing system",
                "description": "Recordings of quarterly review meetings demonstrating synchronous nature and agency participation",
                "collection_method": "Export from video platform"
            },
            {
                "artifact_type": "Necessary Parties List",
                "location": "Compliance documentation",
                "description": "Documentation defining who 'all necessary parties' are for quarterly reviews (agencies, FedRAMP, etc.)",
                "collection_method": "Manual - Collect from compliance records"
            },
            {
                "artifact_type": "Ongoing Authorization Report References",
                "location": "Quarterly review materials",
                "description": "References showing which aspects of Ongoing Authorization Reports were reviewed in each quarterly meeting",
                "collection_method": "Manual - Extract from meeting materials"
            },
            {
                "artifact_type": "Agency Feedback Records",
                "location": "Email, ticketing system",
                "description": "Agency feedback on quarterly reviews showing engagement and value",
                "collection_method": "Manual - Email/ticket archives"
            },
            {
                "artifact_type": "Compliance Attestation",
                "location": "Compliance documentation",
                "description": "Attestation that provider hosts quarterly reviews as required for Moderate/High systems (MUST requirement)",
                "collection_method": "Manual - Compliance team creates"
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
                "NOT APPLICABLE for code analysis - This is a provider meeting/process requirement (Moderate/High - MANDATORY)",
                "Requirement: Providers MUST host synchronous Quarterly Reviews every 3 months with all necessary parties",
                "Frequency: Every 3 months (quarterly)",
                "Format: Synchronous (real-time meeting, not asynchronous)",
                "Attendees: Open to 'all necessary parties' (agencies using the service, potentially FedRAMP)",
                "Content: Review aspects of recent Ongoing Authorization Reports most relevant to agencies",
                "Impact Levels: Moderate and High ONLY (MUST requirement)",
                "Difference from QR-01: QR-01 is SHOULD for Low impact; QR-02 is MUST for Moderate/High",
                "No Opt-Out: Unlike QR-01, there is no option to document decision not to host (MUST is mandatory)",
                "Key Evidence: Meeting invitations/schedules at 3-month intervals, attendance records, meeting minutes, agendas",
                "Automation Level: Partial - Can query calendar systems and document repositories for meeting artifacts",
                "Related Requirements: FRR-CCM-QR-01 (Low impact SHOULD version), FRR-ADS-06/07 (authorization data)",
                "Provider Determines: Which aspects of Ongoing Authorization Reports are most relevant to agencies for review",
                "Compliance Critical: This is mandatory for Moderate/High - failure to host quarterly reviews is non-compliance",
                "Monitoring: Track quarterly review schedule, attendance patterns, agency participation rates"
            ]
        }
