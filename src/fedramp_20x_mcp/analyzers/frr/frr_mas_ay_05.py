"""
FRR-MAS-AY-05: Review of Best Practices

All parties SHOULD review best practices and technical assistance provided separately by FedRAMP for help with applying the Minimum Assessment Scope as needed.

Official FedRAMP 20x Requirement
Source: FRR-MAS (MAS) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_MAS_AY_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-MAS-AY-05: Review of Best Practices
    
    **Official Statement:**
    All parties SHOULD review best practices and technical assistance provided separately by FedRAMP for help with applying the Minimum Assessment Scope as needed.
    
    **Family:** MAS - MAS
    
    **Primary Keyword:** SHOULD
    
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
    
    FRR_ID = "FRR-MAS-AY-05"
    FRR_NAME = "Review of Best Practices"
    FRR_STATEMENT = """All parties SHOULD review best practices and technical assistance provided separately by FedRAMP for help with applying the Minimum Assessment Scope as needed."""
    FAMILY = "MAS"
    FAMILY_NAME = "MAS"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PM-5", "System Inventory"),
        ("CM-8", "System Component Inventory"),
        ("SA-4", "Acquisition Process"),
        ("SA-15", "Development Process, Standards, and Tools"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Assessment best practices
    ]
    
    def __init__(self):
        """Initialize FRR-MAS-AY-05 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-05 NOT code-detectable: Best practices review is procedural."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-05 NOT code-detectable: Best practices review is procedural."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-05 NOT code-detectable: Best practices review is procedural."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-05 NOT code-detectable: Best practices review is procedural."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Best practices review is procedural."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Best practices review is procedural."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Best practices review is procedural."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Best practices review is procedural."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Best practices review is procedural."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """KQL queries for best practices review documentation."""
        from typing import Dict, Any
        return {
            "automated_queries": [
                "# Query 1: All resources in scope\nResources\n| extend ScopeStatus = tostring(tags.scopeStatus)\n| where ScopeStatus == 'in-scope' or ScopeStatus == ''\n| project name, type, resourceGroup, location",
                "# Query 2: Resources with assessment metadata\nResources\n| extend AssessmentScope = tostring(tags.assessmentScope)\n| extend LastReview = tostring(tags.lastScopeReview)\n| project name, type, AssessmentScope, LastReview",
                "# Query 3: Resource groups by environment\nResourceContainers\n| where type == 'microsoft.resources/subscriptions/resourcegroups'\n| extend Environment = tostring(tags.environment)\n| project name, Environment, location"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Required evidence artifacts for FRR-MAS-AY-05."""
        from typing import Dict, Any
        return {
            "evidence_artifacts": [
                "FedRAMP best practices review documentation",
                "Technical assistance engagement records",
                "Minimum Assessment Scope (MAS) application documentation",
                "Best practices checklist with review dates",
                "FedRAMP guidance references (https://fedramp.gov/resources)",
                "Scope determination methodology documentation",
                "Training records for FedRAMP best practices",
                "Continuous improvement documentation"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Implementation recommendations for FRR-MAS-AY-05."""
        from typing import Dict, Any
        return {
            "implementation_notes": [
                "Review FedRAMP best practices at https://fedramp.gov/resources",
                "Engage FedRAMP technical assistance for scope determination guidance",
                "Document review of FedRAMP Minimum Assessment Scope guidance",
                "Maintain records of best practices review and application",
                "Schedule annual reviews of FedRAMP guidance updates",
                "Document how FedRAMP best practices informed scope decisions",
                "Track continuous improvement based on FedRAMP best practices"
            ]
        }
