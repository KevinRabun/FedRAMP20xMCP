"""
FRR-UCM-03: Update Streams (Moderate)

Providers SHOULD use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect _federal customer data_.

Official FedRAMP 20x Requirement
Source: FRR-UCM (Using Cryptographic Modules) family
Primary Keyword: SHOULD
Impact Levels: Moderate
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_UCM_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-UCM-03: Update Streams (Moderate)
    
    **Official Statement:**
    Providers SHOULD use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect _federal customer data_.
    
    **Family:** UCM - Using Cryptographic Modules
    
    **Primary Keyword:** SHOULD
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    - High: No
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Yes (Code, IaC)
    
    **Detection Strategy:**
    Same as FRR-UCM-02 but for Moderate impact (SHOULD = lower severity):
        1. Application code: Non-FIPS crypto modules, weak algorithms
        2. Infrastructure: Azure services without FIPS compliance
        3. Custom crypto implementations
    
    """
    
    FRR_ID = "FRR-UCM-03"
    FRR_NAME = "Update Streams (Moderate)"
    FRR_STATEMENT = """Providers SHOULD use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect _federal customer data_."""
    FAMILY = "UCM"
    FAMILY_NAME = "Using Cryptographic Modules"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    IMPACT_HIGH = False
    NIST_CONTROLS = [
        ("SC-13", "Cryptographic Protection"),
        ("SC-12", "Cryptographic Key Establishment and Management"),
        ("IA-7", "Cryptographic Module Authentication"),
    ]
    CODE_DETECTABLE = "Yes"  # Detects non-FIPS cryptographic modules (SHOULD = recommendation)
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-CNA-05",  # Encryption in transit
        "KSI-CED-03",  # Encryption at rest
    ]
    
    def __init__(self):
        """Initialize FRR-UCM-03 analyzer."""
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
        Analyze Python code for FRR-UCM-03 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer (identical logic, Moderate impact, SHOULD keyword).
        Detects weak crypto: MD5, SHA1, DES, RC4, custom implementations.
        Uses LOWER severity since SHOULD vs MUST.
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        # Delegate to UCM-02 analyzer
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_python(code, file_path)
        
        # Update FRR ID and reduce severity (SHOULD vs MUST)
        for finding in findings:
            finding.frr_id = self.FRR_ID
            # Reduce severity by one level for SHOULD requirements
            if finding.severity == Severity.CRITICAL:
                finding.severity = Severity.HIGH
            elif finding.severity == Severity.HIGH:
                finding.severity = Severity.MEDIUM
            elif finding.severity == Severity.MEDIUM:
                finding.severity = Severity.LOW
        
        return findings
        # Example from FRR-VDR-08:
        # try:
        #     parser = ASTParser(CodeLanguage.PYTHON)
        #     tree = parser.parse(code)
        #     code_bytes = code.encode('utf8')
        #     
        #     if tree and tree.root_node:
        #         # Find relevant nodes
        #         nodes = parser.find_nodes_by_type(tree.root_node, 'node_type')
        #         for node in nodes:
        #             node_text = parser.get_node_text(node, code_bytes)
        #             # Check for violations
        #         
        #         return findings
        # except Exception:
        #     pass
        
        # TODO: Implement regex fallback
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-UCM-03 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer with reduced severity.
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_csharp(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
            if finding.severity == Severity.CRITICAL:
                finding.severity = Severity.HIGH
            elif finding.severity == Severity.HIGH:
                finding.severity = Severity.MEDIUM
            elif finding.severity == Severity.MEDIUM:
                finding.severity = Severity.LOW
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-UCM-03 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer with reduced severity.
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_java(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
            if finding.severity == Severity.CRITICAL:
                finding.severity = Severity.HIGH
            elif finding.severity == Severity.HIGH:
                finding.severity = Severity.MEDIUM
            elif finding.severity == Severity.MEDIUM:
                finding.severity = Severity.LOW
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-UCM-03 compliance using AST.
        
        Delegates to FRR-UCM-02 analyzer with reduced severity.
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_typescript(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
            if finding.severity == Severity.CRITICAL:
                finding.severity = Severity.HIGH
            elif finding.severity == Severity.HIGH:
                finding.severity = Severity.MEDIUM
            elif finding.severity == Severity.MEDIUM:
                finding.severity = Severity.LOW
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for FRR-UCM-03 compliance.
        
        Delegates to FRR-UCM-02 analyzer with reduced severity.
        """
        from .frr_ucm_02 import FRR_UCM_02_Analyzer
        
        ucm_02 = FRR_UCM_02_Analyzer()
        findings = ucm_02.analyze_bicep(code, file_path)
        
        for finding in findings:
            finding.frr_id = self.FRR_ID
            if finding.severity == Severity.CRITICAL:
                finding.severity = Severity.HIGH
            elif finding.severity == Severity.HIGH:
                finding.severity = Severity.MEDIUM
            elif finding.severity == Severity.MEDIUM:
                finding.severity = Severity.LOW
        
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
        Analyze Bicep infrastructure code for FRR-UCM-03 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-UCM-03 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-UCM-03 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-UCM-03 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-UCM-03 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, List[str]]:
        """
        Provides queries for collecting evidence of FRR-UCM-03 compliance.
        
        Returns:
            Dict containing query strings for various platforms
        """
        return {
            "azure_resource_graph": [
                "Resources | where type =~ 'microsoft.keyvault/vaults' | extend skuName = tostring(properties.sku.name) | project id, name, skuName, location",
                "Resources | where type =~ 'microsoft.storage/storageaccounts' | extend infraEncryption = tostring(properties.encryption.requireInfrastructureEncryption) | project id, name, infraEncryption"
            ],
            "azure_cli": [
                "az keyvault list --query '[].{Name:name, SKU:properties.sku.name}'",
                "az storage account list --query '[].{Name:name, Encryption:properties.encryption}'"
            ]
        }
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Lists artifacts to collect as evidence of FRR-UCM-03 compliance.
        
        Returns:
            List of artifact descriptions
        """
        return [
            "Cryptographic module inventory with NIST CMVP validation status (Moderate impact)",
            "Azure Key Vault configuration for Moderate impact systems",
            "Code scan results for Moderate impact applications",
            "Documentation of FIPS-validated modules used for federal data protection",
            "Storage encryption configuration for Moderate impact data"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, str]:
        """
        Provides recommendations for automating evidence collection for FRR-UCM-03.
        
        Returns:
            Dict mapping automation areas to implementation guidance
        """
        return {
            "policy_enforcement": "Deploy Azure Policy for Moderate impact systems (SHOULD = recommendation)",
            "code_scanning": "Implement SAST for Moderate impact applications to detect weak crypto",
            "inventory_tracking": "Maintain separate crypto inventory for Moderate impact services"
        }
