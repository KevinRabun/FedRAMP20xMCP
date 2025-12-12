"""
FRR-MAS-AY-03: Exclusion of Non-Impacting Information Resources

_Information resources_ (including _third-party information resources_) that do not meet the conditions in FRR-MAS-01 are not included in the _cloud service offering_ for FedRAMP (_FRR-MAS-02_).

Official FedRAMP 20x Requirement
Source: FRR-MAS (MAS) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_MAS_AY_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-MAS-AY-03: Exclusion of Non-Impacting Information Resources
    
    **Official Statement:**
    _Information resources_ (including _third-party information resources_) that do not meet the conditions in FRR-MAS-01 are not included in the _cloud service offering_ for FedRAMP (_FRR-MAS-02_).
    
    **Family:** MAS - MAS
    
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
    
    FRR_ID = "FRR-MAS-AY-03"
    FRR_NAME = "Exclusion of Non-Impacting Information Resources"
    FRR_STATEMENT = """_Information resources_ (including _third-party information resources_) that do not meet the conditions in FRR-MAS-01 are not included in the _cloud service offering_ for FedRAMP (_FRR-MAS-02_)."""
    FAMILY = "MAS"
    FAMILY_NAME = "MAS"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PM-5", "System Inventory"),
        ("CM-8", "System Component Inventory"),
        ("SA-4", "Acquisition Process"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Assessment scope determination
    ]
    
    def __init__(self):
        """Initialize FRR-MAS-AY-03 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-03 NOT code-detectable: Resource exclusion is scope determination."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-03 NOT code-detectable: Resource exclusion is scope determination."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-03 NOT code-detectable: Resource exclusion is scope determination."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-03 NOT code-detectable: Resource exclusion is scope determination."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Resource exclusion is scope determination."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Resource exclusion is scope determination."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Resource exclusion is scope determination."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Resource exclusion is scope determination."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Resource exclusion is scope determination."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """KQL queries for non-impacting resource exclusion documentation."""
        from typing import Dict, Any
        return {
            "automated_queries": [
                "# Query 1: Resources with scope/impact metadata\nResources\n| extend ScopeStatus = tostring(tags.scopeStatus)\n| extend ImpactLevel = tostring(tags.impactLevel)\n| project name, type, ScopeStatus, ImpactLevel, tags",
                "# Query 2: Resources excluded from FedRAMP scope\nResources\n| where tags contains 'excluded' or tags contains 'outOfScope'\n| project name, type, tags",
                "# Query 3: Resources not meeting MAS-01 conditions\nResources\n| where tags.fedRAMPIncluded != 'true'\n| project name, type, tags"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Required evidence artifacts for FRR-MAS-AY-03."""
        from typing import Dict, Any
        return {
            "evidence_artifacts": [
                "Resource exclusion documentation",
                "Scope determination analysis per FRR-MAS-01",
                "Non-impacting resource inventory",
                "Exclusion justifications with MAS-01 condition references",
                "Authorization boundary documentation showing excluded resources",
                "Impact assessment for excluded resources",
                "Third-party resource exclusion documentation",
                "Scope change log with exclusion rationale"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Implementation recommendations for FRR-MAS-AY-03."""
        from typing import Dict, Any
        return {
            "implementation_notes": [
                "Review all resources against FRR-MAS-01 conditions for inclusion criteria",
                "Document resources that do not meet MAS-01 conditions",
                "Maintain clear exclusion justifications referencing MAS-01",
                "Tag excluded resources with scope status metadata",
                "Update authorization boundary documentation to show exclusions",
                "Conduct impact assessment for excluded resources",
                "Review exclusions quarterly or when infrastructure changes"
            ]
        }
