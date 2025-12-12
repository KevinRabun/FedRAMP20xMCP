"""
FRR-PVA-16: Verify Procedure Adherence

Assessors MUST assess whether or not procedures are consistently followed, including the processes in place to ensure this occurs, without relying solely on the existence of a procedure document for assessing if appropriate processes and procedures are in place.

Official FedRAMP 20x Requirement
Source: FRR-PVA (PVA) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_PVA_16_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-PVA-16: Verify Procedure Adherence
    
    **Official Statement:**
    Assessors MUST assess whether or not procedures are consistently followed, including the processes in place to ensure this occurs, without relying solely on the existence of a procedure document for assessing if appropriate processes and procedures are in place.
    
    **Family:** PVA - PVA
    
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
    
    FRR_ID = "FRR-PVA-16"
    FRR_NAME = "Verify Procedure Adherence"
    FRR_STATEMENT = """Assessors MUST assess whether or not procedures are consistently followed, including the processes in place to ensure this occurs, without relying solely on the existence of a procedure document for assessing if appropriate processes and procedures are in place."""
    FAMILY = "PVA"
    FAMILY_NAME = "PVA"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-2", "Control Assessments"),
        ("CA-7", "Continuous Monitoring"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Procedure adherence verification
    ]
    
    def __init__(self):
        """Initialize FRR-PVA-16 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Python code for FRR-PVA-16 compliance.
        
        PVA-16 NOT code-detectable: Assessor procedure adherence verification is operational.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# code for FRR-PVA-16 compliance.
        
        PVA-16 NOT code-detectable: Assessor procedure adherence verification is operational.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code for FRR-PVA-16 compliance.
        
        PVA-16 NOT code-detectable: Assessor procedure adherence verification is operational.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript/JavaScript code for FRR-PVA-16 compliance.
        
        PVA-16 NOT code-detectable: Assessor procedure adherence verification is operational.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-PVA-16 compliance.
        
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
        """Analyze Terraform infrastructure code for FRR-PVA-16 compliance.
        
        Assessor procedure adherence verification is operational.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions workflow for FRR-PVA-16 compliance.
        
        Assessor procedure adherence verification is operational.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines YAML for FRR-PVA-16 compliance.
        
        Assessor procedure adherence verification is operational.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI YAML for FRR-PVA-16 compliance.
        
        Assessor procedure adherence verification is operational.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    # ============================================================================
    # EVIDENCE COLLECTION METHODS
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get KQL queries for collecting evidence of procedure adherence assessment.
        
        Returns queries to detect procedure adherence verification activities.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'automated_queries': [
                # Resources with procedure-adherence tags
                "Resources | where tags contains 'procedure-adherence' | project name, type, tags, location",
                
                # Assessment activities verifying procedure adherence
                "AzureActivity | where OperationNameValue contains 'Assessment' and Properties contains 'procedure-adherence' | project TimeGenerated, Caller, OperationNameValue, Properties",
                
                # Resources with adherence-verification and procedure-enforcement metadata
                "Resources | where tags contains 'adherence-verification' or tags contains 'procedure-enforcement' | project name, type, tags['adherence-verification'], tags['procedure-enforcement']"
            ]
        }
    
    def get_evidence_artifacts(self) -> dict:
        """
        Get list of evidence artifacts for demonstrating procedure adherence assessment.
        
        Returns documentation and records demonstrating adherence verification.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'evidence_artifacts': [
                "Procedure adherence assessment documentation and methodology",
                "Procedure execution evidence and audit trails",
                "Process enforcement mechanisms and controls",
                "Adherence verification findings and reports",
                "Procedure effectiveness assessment and consistency evaluation",
                "Non-adherence detection and remediation documentation",
                "Procedure enforcement automation and monitoring",
                "Assessment methodology prohibiting document-only verification"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for implementing procedure adherence verification.
        
        Returns implementation notes for adherence assessment and enforcement.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'implementation_notes': [
                "Define assessor procedures for verifying procedure adherence (beyond document existence)",
                "Tag Azure resources with 'procedure-adherence', 'adherence-verification', and 'procedure-enforcement' metadata",
                "Document procedure execution evidence and enforcement mechanisms",
                "Track assessor adherence verification activities and findings",
                "Maintain audit trails demonstrating consistent procedure following",
                "Provide assessors with adherence evidence and enforcement documentation",
                "Review procedure adherence assessment methodology and enforcement effectiveness quarterly"
            ]
        }
