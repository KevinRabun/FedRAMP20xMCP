"""
FRR-MAS-04: Metadata Inclusion

Providers MUST include metadata (including metadata about _federal customer data_), ONLY IF _FRR-MAS-01_ APPLIES.

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


class FRR_MAS_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-MAS-04: Metadata Inclusion
    
    **Official Statement:**
    Providers MUST include metadata (including metadata about _federal customer data_), ONLY IF _FRR-MAS-01_ APPLIES.
    
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
    
    FRR_ID = "FRR-MAS-04"
    FRR_NAME = "Metadata Inclusion"
    FRR_STATEMENT = """Providers MUST include metadata (including metadata about _federal customer data_), ONLY IF _FRR-MAS-01_ APPLIES."""
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
        ("SC-28", "Protection of Information at Rest"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-CED-01",  # Data classification and handling
    ]
    
    def __init__(self):
        """Initialize FRR-MAS-04 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-04 NOT code-detectable: Metadata documentation is operational."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """KQL queries for metadata documentation."""
        from typing import Dict, Any
        return {
            "automated_queries": [
                "# Query 1: Resources with metadata tags\nResources\n| extend Metadata = tostring(tags)\n| extend DataClassification = tostring(tags.dataClassification)\n| extend Owner = tostring(tags.owner)\n| project name, type, location, DataClassification, Owner, Metadata",
                "# Query 2: Resource Groups with metadata\nResourceContainers\n| where type == 'microsoft.resources/subscriptions/resourcegroups'\n| extend Tags = tostring(tags)\n| project name, location, Tags",
                "# Query 3: Resources handling federal data\nResources\n| where tags contains 'federalData' or tags contains 'pii'\n| project name, type, tags"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Required evidence artifacts for FRR-MAS-04."""
        from typing import Dict, Any
        return {
            "evidence_artifacts": [
                "Resource metadata documentation (tags, labels, annotations)",
                "Data classification metadata for federal customer data",
                "Resource ownership and responsibility metadata",
                "Data lifecycle metadata (retention, disposal)",
                "Security classification metadata",
                "Compliance scope metadata",
                "Metadata schema definition and standards",
                "Metadata validation procedures and evidence"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Implementation recommendations for FRR-MAS-04."""
        from typing import Dict, Any
        return {
            "implementation_notes": [
                "Implement consistent resource tagging strategy with metadata standards",
                "Include data classification metadata for federal customer data",
                "Document resource ownership and responsibility in metadata",
                "Use Azure Policy to enforce required metadata tags",
                "Implement metadata validation in deployment pipelines",
                "Maintain metadata schema documentation",
                "Review and update metadata quarterly for accuracy"
            ]
        }
