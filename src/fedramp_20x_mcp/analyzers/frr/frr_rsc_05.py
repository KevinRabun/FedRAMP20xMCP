"""
FRR-RSC-05: Comparison Capability

Providers SHOULD offer the capability to compare all current settings for _top-level administrative accounts_ and _privileged accounts_ to the recommended secure defaults.

Official FedRAMP 20x Requirement
Source: FRR-RSC (Resource Categorization) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_RSC_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-05: Comparison Capability
    
    **Official Statement:**
    Providers SHOULD offer the capability to compare all current settings for _top-level administrative accounts_ and _privileged accounts_ to the recommended secure defaults.
    
    **Family:** RSC - Resource Categorization
    
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
    
    FRR_ID = "FRR-RSC-05"
    FRR_NAME = "Comparison Capability"
    FRR_STATEMENT = """Providers SHOULD offer the capability to compare all current settings for _top-level administrative accounts_ and _privileged accounts_ to the recommended secure defaults."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CM-6", "Configuration Settings"),
        ("CM-7", "Least Functionality")
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-RSC-05 analyzer."""
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
        Check for comparison/validation APIs for security settings.
        
        Looks for:
        - API endpoints for comparing settings
        - Functions that validate against secure defaults
        - Configuration comparison logic
        """
        findings = []
        lines = code.split('\n')
        
        # Check for comparison functions
        comparison_patterns = [
            r'def.*compare.*settings', r'def.*validate.*config',
            r'def.*check.*defaults', r'compare.*security',
            r'@app\.route.*\/compare', r'@api\.route.*\/validate'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in comparison_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Comparison capability detected - ensure completeness",
                        description=f"Line {i} implements settings comparison. FRR-RSC-05 requires ability to compare ALL current settings for admin/privileged accounts to recommended defaults.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Verify comparison covers: (1) All admin/privileged accounts, (2) All security settings, (3) Current vs recommended defaults, (4) Deviation reporting"
                    ))
                    return findings  # Only report once per file
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Check C# for comparison APIs (similar patterns).""" 
        return self._check_comparison_api(code, file_path)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Check Java for comparison APIs (similar patterns)."""
        return self._check_comparison_api(code, file_path)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Check TypeScript for comparison APIs (similar patterns)."""
        return self._check_comparison_api(code, file_path)
    
    def _check_comparison_api(self, code: str, file_path: str) -> List[Finding]:
        """Shared logic for detecting comparison APIs."""
        findings = []
        patterns = [r'compare.*settings', r'validate.*config', r'/api/compare', r'/api/validate']
        
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Comparison API detected",
                    description="Code implements comparison capability. Ensure it covers all admin/privileged account settings per FRR-RSC-05.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Verify comprehensive coverage of all security settings"
                ))
                break
        return findings
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-RSC-05 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-RSC-05 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-RSC-05 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-RSC-05 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-RSC-05 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-RSC-05.
        
        TODO: Add evidence collection guidance
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Unknown',
            'automation_approach': 'TODO: Fully automated detection through code, IaC, and CI/CD analysis',
            'evidence_artifacts': [
                # TODO: List evidence artifacts to collect
                # Examples:
                # - "Configuration export from service X"
                # - "Access logs showing activity Y"
                # - "Documentation showing policy Z"
            ],
            'collection_queries': [
                # TODO: Add KQL or API queries for evidence
                # Examples for Azure:
                # - "AzureDiagnostics | where Category == 'X' | project TimeGenerated, Property"
                # - "GET https://management.azure.com/subscriptions/{subscriptionId}/..."
            ],
            'manual_validation_steps': [
                # TODO: Add manual validation procedures
                # 1. "Review documentation for X"
                # 2. "Verify configuration setting Y"
                # 3. "Interview stakeholder about Z"
            ],
            'recommended_services': [
                # TODO: List Azure/AWS services that help with this requirement
                # Examples:
                # - "Azure Policy - for configuration validation"
                # - "Azure Monitor - for activity logging"
                # - "Microsoft Defender for Cloud - for security posture"
            ],
            'integration_points': [
                # TODO: List integration with other tools
                # Examples:
                # - "Export to OSCAL format for automated reporting"
                # - "Integrate with ServiceNow for change management"
            ]
        }
