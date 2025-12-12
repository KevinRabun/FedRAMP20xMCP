"""
FRR-MAS-02: Third-Party Information Resources

Providers MUST include the configuration and usage of _third-party information resources_, ONLY IF _FRR-MAS-01_ APPLIES.

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


class FRR_MAS_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-MAS-02: Third-Party Information Resources
    
    **Official Statement:**
    Providers MUST include the configuration and usage of _third-party information resources_, ONLY IF _FRR-MAS-01_ APPLIES.
    
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
    
    FRR_ID = "FRR-MAS-02"
    FRR_NAME = "Third-Party Information Resources"
    FRR_STATEMENT = """Providers MUST include the configuration and usage of _third-party information resources_, ONLY IF _FRR-MAS-01_ APPLIES."""
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
        "KSI-AFR-01",  # Third-party assessment and authorization
    ]
    
    def __init__(self):
        """Initialize FRR-MAS-02 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-02 NOT code-detectable: Third-party resources inventory is operational documentation."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """KQL queries for third-party resources inventory."""
        from typing import Dict, Any
        return {
            "automated_queries": [
                "# Query 1: Third-party SaaS integrations\nResources\n| where tags contains 'thirdParty' or tags contains 'saas'\n| project name, type, location, tags",
                "# Query 2: External service connections\nResources\n| where type contains 'connection' or type contains 'integration'\n| project name, type, properties",
                "# Query 3: Marketplace resources\nResources\n| where plan.publisher != 'Microsoft' and plan.publisher != ''\n| project name, type, plan"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Required evidence artifacts for FRR-MAS-02."""
        from typing import Dict, Any
        return {
            "evidence_artifacts": [
                "Third-party service inventory with vendor details",
                "Third-party FedRAMP authorization status documentation",
                "Service-level agreements (SLAs) for third-party services",
                "Third-party security assessment reports",
                "Data sharing agreements with third parties",
                "Third-party integration architecture diagrams",
                "Vendor security questionnaire responses",
                "Third-party dependency change log"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Implementation recommendations for FRR-MAS-02."""
        from typing import Dict, Any
        return {
            "implementation_notes": [
                "Maintain inventory of all third-party services and SaaS integrations",
                "Verify FedRAMP authorization status for each third-party service",
                "Document data flows between system and third-party services",
                "Review and document third-party service configurations",
                "Track third-party service changes and updates",
                "Conduct security assessments for non-FedRAMP third parties",
                "Implement monitoring for third-party service availability and security"
            ]
        }
