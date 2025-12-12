"""
FRR-MAS-EX-01: Supplemental Information

Providers MAY include documentation of _information resources_ beyond the _cloud service offering_, or even entirely outside the scope of FedRAMP, in a FedRAMP assessment and _authorization package_ supplement; these resources will not be FedRAMP authorized and MUST be clearly marked and separated from the _cloud service offering_.

Official FedRAMP 20x Requirement
Source: FRR-MAS (MAS) family
Primary Keyword: MAY
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_MAS_EX_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-MAS-EX-01: Supplemental Information
    
    **Official Statement:**
    Providers MAY include documentation of _information resources_ beyond the _cloud service offering_, or even entirely outside the scope of FedRAMP, in a FedRAMP assessment and _authorization package_ supplement; these resources will not be FedRAMP authorized and MUST be clearly marked and separated from the _cloud service offering_.
    
    **Family:** MAS - MAS
    
    **Primary Keyword:** MAY
    
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
    
    FRR_ID = "FRR-MAS-EX-01"
    FRR_NAME = "Supplemental Information"
    FRR_STATEMENT = """Providers MAY include documentation of _information resources_ beyond the _cloud service offering_, or even entirely outside the scope of FedRAMP, in a FedRAMP assessment and _authorization package_ supplement; these resources will not be FedRAMP authorized and MUST be clearly marked and separated from the _cloud service offering_."""
    FAMILY = "MAS"
    FAMILY_NAME = "MAS"
    PRIMARY_KEYWORD = "MAY"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PM-5", "System Inventory"),
        ("CM-8", "System Component Inventory"),
        ("SA-4", "Acquisition Process"),
        ("PL-2", "System Security Plan"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Assessment documentation
    ]
    
    def __init__(self):
        """Initialize FRR-MAS-EX-01 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-EX-01 NOT code-detectable: Supplemental documentation is operational."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-EX-01 NOT code-detectable: Supplemental documentation is operational."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-EX-01 NOT code-detectable: Supplemental documentation is operational."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-EX-01 NOT code-detectable: Supplemental documentation is operational."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Supplemental documentation is operational."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Supplemental documentation is operational."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Supplemental documentation is operational."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Supplemental documentation is operational."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Supplemental documentation is operational."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """Get Azure Resource Graph / KQL queries for evidence collection."""
        return {
            'automated_queries': [
                "Resources | where tags['scope'] == 'supplemental' or tags['fedramp-supplemental'] == 'true' | project name, type, resourceGroup, tags",
                "Resources | where tags['authorization-status'] != 'in-scope' | project name, type, location, tags['authorization-status']",
                "Resources | summarize SupplementalCount=countif(tags['fedramp-supplemental'] == 'true'), InScopeCount=countif(tags['fedramp-supplemental'] != 'true') by resourceGroup"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Get list of evidence artifacts to collect."""
        return {
            'evidence_artifacts': [
                "Supplemental information documentation clearly marked as 'Not FedRAMP Authorized'",
                "Authorization package appendix showing supplemental resources separated from CSO",
                "Marking and separation procedures documentation",
                "Out-of-scope resource inventory with clear labels",
                "Visual distinction mechanisms (headers, watermarks, labels) for supplemental docs",
                "System Security Plan (SSP) appendix for supplemental resources",
                "Documentation of excluded resources with rationale",
                "Review procedures for supplemental information classification"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Get recommendations for implementing automated evidence collection."""
        return {
            'implementation_notes': [
                "Clearly mark all supplemental information as 'Not FedRAMP Authorized'",
                "Separate supplemental resources from CSO in authorization package structure",
                "Document supplemental resources in SSP appendix with clear separation",
                "Maintain out-of-scope resource inventory with supplemental tag",
                "Use visual distinctions (headers, watermarks, labels) for supplemental documentation",
                "Document supplemental resources in authorization materials with clear marking",
                "Review supplemental information classification quarterly"
            ]
        }
