"""
FRR-RSC-03: Privileged Accounts Security Settings Guidance

Providers SHOULD create and maintain guidance that explains security-related settings that can be operated only by _privileged accounts_ and their security implications.

Official FedRAMP 20x Requirement
Source: FRR-RSC (Resource Categorization) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_RSC_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-03: Privileged Accounts Security Settings Guidance
    
    **Official Statement:**
    Providers SHOULD create and maintain guidance that explains security-related settings that can be operated only by _privileged accounts_ and their security implications.
    
    **Family:** RSC - Resource Categorization
    
    **Primary Keyword:** SHOULD
    
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
    
    FRR_ID = "FRR-RSC-03"
    FRR_NAME = "Privileged Accounts Security Settings Guidance"
    FRR_STATEMENT = """Providers SHOULD create and maintain guidance that explains security-related settings that can be operated only by _privileged accounts_ and their security implications."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-2", "Account Management"),
        ("AC-6", "Least Privilege"),
        ("CM-6", "Configuration Settings")
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = ["KSI-IAM-01"]
    
    def __init__(self):
        """Initialize FRR-RSC-03 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Delegate to RSC-01 with privileged account focus (SHOULD = lower severity)."""
        from .frr_rsc_01 import FRR_RSC_01_Analyzer
        base_analyzer = FRR_RSC_01_Analyzer()
        findings = base_analyzer.analyze_python(code, file_path)
        
        # Update for RSC-03 (SHOULD requirement, privileged vs top-level admin)
        for finding in findings:
            finding.ksi_id = self.FRR_ID
            finding.requirement_id = self.FRR_ID
            # Reduce severity for SHOULD
            if finding.severity == Severity.CRITICAL:
                finding.severity = Severity.HIGH
            elif finding.severity == Severity.HIGH:
                finding.severity = Severity.MEDIUM
            finding.title = finding.title.replace("admin", "privileged")
            finding.description = finding.description.replace("FRR-RSC-01", "FRR-RSC-03 (SHOULD)").replace("top-level administrative", "privileged")
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Delegate to Python implementation."""
        return self.analyze_python(code, file_path)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Delegate to Python implementation."""
        return self.analyze_python(code, file_path)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Delegate to Python implementation."""
        return self.analyze_python(code, file_path)
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-RSC-03 compliance.
        
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
        """
        Analyze Terraform infrastructure code for FRR-RSC-03 compliance.
        
        TODO: Implement Terraform analysis
        - Detect relevant resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Terraform regex patterns
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-RSC-03 compliance.
        
        TODO: Implement GitHub Actions analysis
        - Check for required steps/actions
        - Verify compliance configuration
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitHub Actions analysis
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-RSC-03 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-RSC-03 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """KQL queries for privileged account security settings documentation evidence."""
        return {
            'automated_queries': [
                "// Query 1: Privileged role assignments and security settings changes\nAzureActivity\n| where TimeGenerated > ago(90d)\n| where OperationNameValue contains 'roleAssignments' or OperationNameValue contains 'SecuritySettings'\n| where Properties contains 'privileged' or Properties contains 'Contributor' or Properties contains 'Owner'\n| project TimeGenerated, Caller, ResourceId, OperationNameValue, Properties\n| order by TimeGenerated desc",
                "// Query 2: Resources tagged with privileged-settings-documented metadata\nResources\n| where tags['privileged-settings-documented'] == 'true'\n| project resourceId, name, type, tags, location",
                "// Query 3: Privileged role definitions (non-admin elevated access)\nAuthorizationManagementResources\n| where type == 'microsoft.authorization/roledefinitions'\n| where properties.roleName contains 'Contributor' or properties.roleName contains 'Operator'\n| where properties.roleName !contains 'Owner'\n| project id, properties"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Documentation artifacts for privileged account security settings guidance."""
        return {
            'evidence_artifacts': [
                "PRIVILEGED-SETTINGS.md or equivalent documentation file",
                "List of privileged-only security settings (non-admin elevated access)",
                "Security impact analysis for privileged settings",
                "Configuration change procedures for privileged accounts",
                "Privileged access security baseline",
                "Privileged role assignment audit logs",
                "Least privilege analysis documentation",
                "Risk assessment for privileged setting changes"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Implementation recommendations for privileged account security settings guidance."""
        return {
            'implementation_notes': [
                "Create PRIVILEGED-SETTINGS.md documenting privileged-only security settings",
                "List each security setting controllable by privileged (non-admin) accounts",
                "Document security implications for privileged settings (CIA triad impact)",
                "Define change procedures and approval workflows for privileged access",
                "Tag resources with privileged-settings-documented metadata",
                "Maintain audit logs of privileged setting changes (90-day retention)",
                "Review and update privileged settings documentation quarterly"
            ]
        }
