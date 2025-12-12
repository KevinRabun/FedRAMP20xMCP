"""
FRR-MAS-03: Non-FedRAMP Authorized Third-Party Information Resources

Providers MUST clearly identify and document the justification, mitigation measures, compensating controls, and potential impact to _federal customer data_ from the configuration and usage of non-FedRAMP authorized _third-party information resources_, ONLY IF _FRR-MAS-01_ APPLIES.

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


class FRR_MAS_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-MAS-03: Non-FedRAMP Authorized Third-Party Information Resources
    
    **Official Statement:**
    Providers MUST clearly identify and document the justification, mitigation measures, compensating controls, and potential impact to _federal customer data_ from the configuration and usage of non-FedRAMP authorized _third-party information resources_, ONLY IF _FRR-MAS-01_ APPLIES.
    
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
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-MAS-03"
    FRR_NAME = "Non-FedRAMP Authorized Third-Party Information Resources"
    FRR_STATEMENT = """Providers MUST clearly identify and document the justification, mitigation measures, compensating controls, and potential impact to _federal customer data_ from the configuration and usage of non-FedRAMP authorized _third-party information resources_, ONLY IF _FRR-MAS-01_ APPLIES."""
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
        ("RA-3", "Risk Assessment"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Third-party assessment and authorization
    ]
    
    def __init__(self):
        """Initialize FRR-MAS-03 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-03 NOT code-detectable: Non-FedRAMP third-party documentation is operational."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """KQL queries for non-FedRAMP third-party resources."""
        from typing import Dict, Any
        return {
            "automated_queries": [
                "# Query 1: Non-FedRAMP third-party resources\nResources\n| where tags contains 'nonFedRAMP' or tags contains 'thirdParty'\n| extend FedRAMPStatus = tostring(tags.fedRAMPStatus)\n| where FedRAMPStatus != 'Authorized'\n| project name, type, location, tags",
                "# Query 2: External marketplace resources\nResources\n| where plan.publisher != 'Microsoft' and plan.publisher != ''\n| extend FedRAMPStatus = tostring(tags.fedRAMPStatus)\n| project name, type, plan, FedRAMPStatus",
                "# Query 3: Third-party service connections\nResources\n| where type contains 'connection' or type contains 'integration'\n| where tags !contains 'fedRAMPAuthorized'\n| project name, type, properties, tags"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Required evidence artifacts for FRR-MAS-03."""
        from typing import Dict, Any
        return {
            "evidence_artifacts": [
                "Non-FedRAMP third-party service inventory with justification",
                "Risk assessment for each non-FedRAMP third-party service",
                "Mitigation measures documentation for non-FedRAMP services",
                "Compensating controls implementation evidence",
                "Impact analysis on federal customer data",
                "Non-FedRAMP third-party security assessment reports",
                "Continuous monitoring plan for non-FedRAMP services",
                "Approval documentation for non-FedRAMP service usage"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Implementation recommendations for FRR-MAS-03."""
        from typing import Dict, Any
        return {
            "implementation_notes": [
                "Document justification for each non-FedRAMP third-party service",
                "Conduct risk assessment identifying potential impact to federal data",
                "Implement mitigation measures and compensating controls",
                "Document data flows and access patterns for non-FedRAMP services",
                "Establish continuous monitoring for non-FedRAMP service security posture",
                "Obtain approval for non-FedRAMP service usage from authorizing official",
                "Review non-FedRAMP third-party justifications quarterly"
            ]
        }
