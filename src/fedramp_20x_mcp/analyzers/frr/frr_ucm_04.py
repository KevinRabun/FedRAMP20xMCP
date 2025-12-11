"""
FRR-UCM-04: Update Streams (High)

Providers MUST use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect _federal customer data_.

Official FedRAMP 20x Requirement
Source: FRR-UCM (Using Cryptographic Modules) family
Primary Keyword: MUST
Impact Levels: High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_UCM_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-UCM-04: Update Streams (High)
    
    **Official Statement:**
    Providers MUST use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect _federal customer data_.
    
    **Family:** UCM - Using Cryptographic Modules
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: No
    - Moderate: No
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Yes (Code, IaC)
    
    **Detection Strategy:**
    Same as FRR-UCM-02 but specific to High impact systems:
        1. Application code: Non-FIPS crypto modules, weak algorithms (MD5, SHA1, DES, RC4)
        2. Infrastructure: Azure services without FIPS compliance
        3. Custom crypto implementations instead of validated modules
    
    """
    
    FRR_ID = "FRR-UCM-04"
    FRR_NAME = "Update Streams (High)"
    FRR_STATEMENT = """Providers MUST use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect _federal customer data_."""
    FAMILY = "UCM"
    FAMILY_NAME = "Using Cryptographic Modules"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = False
    IMPACT_MODERATE = False
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SC-13", "Cryptographic Protection"),
        ("SC-12", "Cryptographic Key Establishment and Management"),
        ("IA-7", "Cryptographic Module Authentication"),
    ]
    CODE_DETECTABLE = True  # Detects non-FIPS cryptographic modules
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-CNA-05",  # Encryption in transit
        "KSI-IAM-03",  # Multi-factor authentication
        "KSI-CED-03",  # Encryption at rest
    ]
    
    def __init__(self):
        """Initialize FRR-UCM-04 analyzer."""
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
        Analyze Python code for FRR-UCM-04 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer (identical logic, High impact only).
        Detects weak crypto: MD5, SHA1, DES, RC4, custom implementations.
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        # Delegate to UCM-02 analyzer (same detection logic)
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_python(code, file_path)
        
        # Update FRR ID to UCM-04
        for finding in findings:
            finding.frr_id = self.FRR_ID
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-UCM-04 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer (identical logic, High impact only).
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_csharp(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-UCM-04 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer (identical logic, High impact only).
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_java(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-UCM-04 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer (identical logic, High impact only).
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_typescript(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for FRR-UCM-04 compliance.
        
        Delegates to FRR-UCM-02 analyzer (identical logic, High impact only).
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_bicep(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
        
        return findings
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """GitHub Actions not applicable for cryptographic module validation."""
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-UCM-04 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-UCM-04 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-UCM-04 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-UCM-04 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-UCM-04 compliance.
        
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
        Get recommendations for automating evidence collection for FRR-UCM-04.
        
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
