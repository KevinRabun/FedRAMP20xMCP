"""
FRR-CCM-QR-05: Meeting Registration Info

Providers MUST include either a registration link or a downloadable calendar file with meeting information for _Quarterly Reviews_ in the _authorization data_ available to all _necessary parties_ required by FRR-ADS-06 and FRR-ADS-07.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import Dict, List, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_QR_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-QR-05: Meeting Registration Info
    
    **Official Statement:**
    Providers MUST include either a registration link or a downloadable calendar file with meeting information for _Quarterly Reviews_ in the _authorization data_ available to all _necessary parties_ required by FRR-ADS-06 and FRR-ADS-07.
    
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
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-CCM-QR-05"
    FRR_NAME = "Meeting Registration Info"
    FRR_STATEMENT = """Providers MUST include either a registration link or a downloadable calendar file with meeting information for _Quarterly Reviews_ in the _authorization data_ available to all _necessary parties_ required by FRR-ADS-06 and FRR-ADS-07."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
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
        """Initialize FRR-CCM-QR-05 analyzer."""
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
        Analyze Python code for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data (metadata/content requirement).
        It governs what information must be made available to necessary parties, not
        how CSP application code is written.
        
        **Detection Strategy:** N/A - Data availability requirement about authorization
        data content (FRR-ADS-06/07 context), not code implementation.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. It's a data/content requirement
        about what must be available to necessary parties, not C# code implementation.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. It's a data/content requirement,
        not Java code implementation.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. It's a data/content requirement,
        not TypeScript/JavaScript code implementation.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. Infrastructure code doesn't
        control authorization data content.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. Infrastructure code doesn't
        control authorization data content.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. CI/CD pipelines don't control
        authorization data content.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. CI/CD pipelines don't control
        authorization data content.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. CI/CD pipelines don't control
        authorization data content.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Get automated queries for collecting evidence of FRR-CCM-QR-05 compliance.
        
        **NOT APPLICABLE:** This requirement mandates that providers include registration
        links or calendar files in authorization data. Evidence collection verifies
        that meeting information is available in required locations.
        """
        return [
            "# Note: This is a data availability requirement - verify authorization data sources"
        ]
    
    def get_evidence_artifacts(self) -> List[Dict[str, Any]]:
        """
        Get list of evidence artifacts to collect for FRR-CCM-QR-05 compliance.
        
        Returns evidence related to meeting registration information availability.
        """
        return [
            {
                "artifact_name": "Authorization Data Portal Screenshot",
                "description": "Screenshot showing registration link or calendar file visible in authorization data portal per FRR-ADS-06/07",
                "collection_method": "Manual capture from portal",
                "frequency": "Quarterly before each QR"
            },
            {
                "artifact_name": "Meeting Registration Link",
                "description": "Copy of registration URL included in authorization data",
                "collection_method": "Extract from portal metadata",
                "frequency": "Quarterly before each QR"
            },
            {
                "artifact_name": "Calendar File (.ics)",
                "description": "Downloadable calendar file with meeting information (if link not provided)",
                "collection_method": "Download from portal",
                "frequency": "Quarterly before each QR"
            },
            {
                "artifact_name": "Necessary Parties Access Log",
                "description": "Logs showing all necessary parties (per FRR-ADS-06/07) have access to meeting information",
                "collection_method": "Query authorization portal access logs",
                "frequency": "Quarterly"
            },
            {
                "artifact_name": "Meeting Information Content",
                "description": "Verification that registration/calendar contains required meeting details (date, time, connection info)",
                "collection_method": "Manual review of link/file content",
                "frequency": "Quarterly before each QR"
            },
            {
                "artifact_name": "Authorization Data Update Records",
                "description": "Change logs showing when meeting information was added/updated in authorization data",
                "collection_method": "Query portal change management system",
                "frequency": "Quarterly"
            },
            {
                "artifact_name": "Necessary Parties Notification Records",
                "description": "Evidence that all necessary parties were notified of meeting information availability",
                "collection_method": "Email logs or notification system records",
                "frequency": "Quarterly before each QR"
            },
            {
                "artifact_name": "Registration Link Accessibility Test",
                "description": "Test results confirming registration link is accessible to all necessary parties",
                "collection_method": "Automated link testing or manual verification",
                "frequency": "Quarterly before each QR"
            },
            {
                "artifact_name": "Calendar File Validity Check",
                "description": "Verification that calendar file can be imported into standard calendar applications",
                "collection_method": "Manual test import into Outlook/Google Calendar",
                "frequency": "Quarterly before each QR"
            },
            {
                "artifact_name": "Compliance Attestation",
                "description": "Provider attestation that meeting registration info is available in authorization data per requirement",
                "collection_method": "Signed attestation document",
                "frequency": "Quarterly"
            }
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for FRR-CCM-QR-05.
        
        Provides guidance on verifying meeting registration information availability.
        """
        return {
            "automated_queries": self.get_evidence_collection_queries(),
            "evidence_artifacts": self.get_evidence_artifacts(),
            "implementation_notes": (
                "FRR-CCM-QR-05 requires providers to include registration links or calendar files "
                "for Quarterly Reviews in authorization data (per FRR-ADS-06/07). This is NOT a code "
                "requirement - it mandates data availability. Evidence collection focuses on: "
                "(1) Verifying meeting information exists in authorization data portal, "
                "(2) Confirming registration link or calendar file is accessible, "
                "(3) Validating all necessary parties have access per FRR-ADS-06/07, "
                "(4) Testing that link works or calendar file imports correctly. "
                "Automate by: Querying authorization portal APIs for meeting metadata presence, "
                "testing registration link accessibility, verifying access logs show necessary parties, "
                "and validating calendar file format (.ics standard). Related to FRR-ADS-06 (access for "
                "necessary parties) and FRR-ADS-07 (authorization data structure)."
            )
        }
