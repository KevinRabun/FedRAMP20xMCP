"""
FRR-CCM-AG-07: Notify FedRAMP After Requests

Agencies MUST inform FedRAMP after requesting any additional information or materials from a cloud service provider beyond those FedRAMP requires by sending a notification to info@fedramp.gov.

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


class FRR_CCM_AG_07_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-AG-07: Notify FedRAMP After Requests
    
    **Official Statement:**
    Agencies MUST inform FedRAMP after requesting any additional information or materials from a cloud service provider beyond those FedRAMP requires by sending a notification to info@fedramp.gov.
    
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
    
    FRR_ID = "FRR-CCM-AG-07"
    FRR_NAME = "Notify FedRAMP After Requests"
    FRR_STATEMENT = """Agencies MUST inform FedRAMP after requesting any additional information or materials from a cloud service provider beyond those FedRAMP requires by sending a notification to info@fedramp.gov."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SA-9", "External System Services"),
        ("PM-15", "Contacts with Security Groups and Associations"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-CCM-AG-07 analyzer."""
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
        Analyze Python code for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: This requirement mandates that agencies inform FedRAMP
        (at info@fedramp.gov) after requesting additional information from CSPs.
        It addresses agency notification obligations to FedRAMP, not CSP code
        implementation. CSP role is passive: respond to agency requests and
        potentially be copied on agency notifications to FedRAMP.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information from CSPs. Not detectable in CSP code.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information from CSPs. Not detectable in CSP code.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information from CSPs. Not detectable in CSP code.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information. Not detectable in CSP infrastructure.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information. Not detectable in CSP infrastructure.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information. Not detectable in CSP CI/CD.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information. Not detectable in CSP CI/CD.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-AG-07 compliance.
        
        NOT APPLICABLE: Agency notification requirement to FedRAMP after
        requesting additional information. Not detectable in CSP CI/CD.
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
                "query_type": "N/A",
                "platform": "N/A",
                "query": "N/A - Agency notification requirement to FedRAMP, not CSP implementation",
                "description": "This requirement mandates agency notifications to FedRAMP after requesting additional information from CSPs"
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
                "artifact_type": "Agency Email to FedRAMP",
                "location": "Agency email records",
                "description": "Email notifications from agency to info@fedramp.gov informing of additional information requests to CSP",
                "collection_method": "Manual - Request from agency"
            },
            {
                "artifact_type": "Agency Information Request to CSP",
                "location": "Agency or CSP records",
                "description": "Original agency request to CSP for additional information beyond FedRAMP requirements",
                "collection_method": "Manual - Email/ticket archives"
            },
            {
                "artifact_type": "CSP Response to Agency Request",
                "location": "CSP files",
                "description": "CSP's response to agency request for additional information",
                "collection_method": "Manual - CSP creates and maintains"
            },
            {
                "artifact_type": "FedRAMP Acknowledgement",
                "location": "Agency email records",
                "description": "FedRAMP acknowledgement of agency notification (if received)",
                "collection_method": "Manual - Request from agency"
            },
            {
                "artifact_type": "Agency Notification Log",
                "location": "Agency tracking system",
                "description": "Agency log tracking when notifications to FedRAMP were sent per FRR-CCM-AG-07",
                "collection_method": "Manual - Request from agency"
            },
            {
                "artifact_type": "Request Justification Documentation",
                "location": "Agency files",
                "description": "Agency documentation explaining why additional information was needed beyond FedRAMP requirements",
                "collection_method": "Manual - Request from agency"
            },
            {
                "artifact_type": "CSP Communication Records",
                "location": "CSP ticketing/email system",
                "description": "CSP records showing receipt of agency requests and responses provided",
                "collection_method": "Manual - CSP archives"
            },
            {
                "artifact_type": "FedRAMP Baseline Comparison",
                "location": "Agency or CSP files",
                "description": "Comparison showing how requested information goes beyond FedRAMP baseline requirements",
                "collection_method": "Manual - Agency or CSP creates"
            },
            {
                "artifact_type": "Agency Process Documentation",
                "location": "Agency policy repository",
                "description": "Agency procedures for notifying FedRAMP when requesting additional CSP information",
                "collection_method": "Manual - Request from agency"
            },
            {
                "artifact_type": "Notification Timeline",
                "location": "Agency tracking system",
                "description": "Timeline showing when agency requested information from CSP and when FedRAMP was notified",
                "collection_method": "Manual - Agency creates"
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
                "NOT APPLICABLE for CSP code analysis - This is an agency notification requirement",
                "Requirement: Agencies MUST inform FedRAMP (info@fedramp.gov) AFTER requesting additional information from CSPs beyond FedRAMP requirements",
                "Trigger: Agency requests additional information/materials from CSP beyond FedRAMP baseline",
                "Action: Agency sends notification to info@fedramp.gov",
                "Timing: AFTER requesting additional information (not before)",
                "CSP Role: Passive - Receive and respond to agency requests, may be copied on FedRAMP notifications",
                "Key Evidence: Agency emails to info@fedramp.gov, original agency requests to CSP, notification logs",
                "Difference from CCM-AG-06: CCM-AG-06 limits when agencies CAN impose requirements; CCM-AG-07 requires notification AFTER requesting additional info",
                "Automation Level: Minimal - This is primarily an agency communication obligation, not CSP implementation",
                "Primary Responsibility: Agency (notifies FedRAMP after making requests)",
                "CSP Responsibility: Track agency requests for additional information, respond appropriately, maintain records",
                "Monitoring: CSPs should log all agency information requests to identify patterns and ensure proper channels"
            ]
        }
