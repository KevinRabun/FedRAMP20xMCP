"""
FRR-ICP-06: Responsible Disclosure

Providers MUST NOT irresponsibly disclose specific sensitive information about _incidents_ that would _likely_ increase the impact of the _incident_, but MUST disclose sufficient information for informed risk-based decision-making to _all necessary parties_.

Official FedRAMP 20x Requirement
Source: FRR-ICP (ICP) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import Dict, List, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ICP_06_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-06: Responsible Disclosure
    
    **Official Statement:**
    Providers MUST NOT irresponsibly disclose specific sensitive information about _incidents_ that would _likely_ increase the impact of the _incident_, but MUST disclose sufficient information for informed risk-based decision-making to _all necessary parties_.
    
    **Family:** ICP - ICP
    
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
    
    FRR_ID = "FRR-ICP-06"
    FRR_NAME = "Responsible Disclosure"
    FRR_STATEMENT = """Providers MUST NOT irresponsibly disclose specific sensitive information about _incidents_ that would _likely_ increase the impact of the _incident_, but MUST disclose sufficient information for informed risk-based decision-making to _all necessary parties_."""
    FAMILY = "ICP"
    FAMILY_NAME = "ICP"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("IR-4", "Incident Handling"),
        ("IR-6", "Incident Reporting"),
        ("IR-5", "Incident Monitoring"),
        ("IR-8", "Incident Response Plan"),
    ]
    CODE_DETECTABLE = True  # Detects data redaction and sensitive info handling mechanisms
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-06 analyzer."""
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
        Analyze Python code for FRR-ICP-06 compliance using AST.
        
        Detects:
        - Data redaction mechanisms
        - PII filtering
        - Sensitive information handling
        """
        findings = []
        
        # Check for redaction/sanitization
        has_redaction = bool(re.search(
            r'redact|sanitize|mask|scrub|filter.*sensitive|remove.*pii',
            code, re.IGNORECASE
        ))
        
        # Check for PII handling
        has_pii_handling = bool(re.search(
            r'pii|personal.*identifiable|sensitive.*data|confidential',
            code, re.IGNORECASE
        ))
        
        # Check for classification
        has_classification = bool(re.search(
            r'classify|classification|sensitivity.*level|data.*category',
            code, re.IGNORECASE
        ))
        
        if not has_redaction:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.HIGH,
                message="No data redaction mechanism detected",
                details=(
                    "FRR-ICP-06 requires responsible disclosure with sensitive info removed. "
                    "Implement data redaction before sharing incident information."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement data redaction for incident reports."
            ))
        
        if not has_pii_handling:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.MEDIUM,
                message="No PII handling detected",
                details=(
                    "FRR-ICP-06 requires protecting sensitive information. "
                    "Implement PII detection and filtering."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement PII detection and filtering mechanisms."
            ))
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
        """Analyze C# for data redaction/PII handling."""
        findings = []
        has_redaction = bool(re.search(r'(Redact|Sanitize|Mask|Scrub)', code, re.IGNORECASE))
        if not has_redaction:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No redaction mechanism", description=f"FRR-ICP-06 requires data redaction for responsible disclosure.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement data redaction mechanisms before sharing incident info"
            ))
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java for data redaction/PII handling."""
        findings = []
        has_redaction = bool(re.search(r'(redact|sanitize|mask|scrub)', code, re.IGNORECASE))
        if not has_redaction:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No redaction mechanism", description=f"FRR-ICP-06 requires data redaction for responsible disclosure.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement data redaction mechanisms before sharing incident info"
            ))
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript for data redaction/PII handling."""
        findings = []
        has_redaction = bool(re.search(r'(redact|sanitize|mask|scrub)', code, re.IGNORECASE))
        if not has_redaction:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No redaction mechanism", description=f"FRR-ICP-06 requires data redaction for responsible disclosure.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement data redaction mechanisms before sharing incident info"
            ))
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep for redaction services."""
        return []  # Data redaction is runtime application logic
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for redaction services."""
        return []  # Data redaction is runtime application logic
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for redaction steps."""
        return []  # Data redaction is runtime operational
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for redaction steps."""
        return []  # Data redaction is runtime operational
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for redaction steps."""
        return []  # Data redaction is runtime operational
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """Get automated queries for FRR-ICP-06 evidence (responsible disclosure/redaction)."""
        return {
            'automated_queries': [
                "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.COGNITIVESERVICES' and Category == 'TextAnalytics' | project TimeGenerated, OperationName",
                "Resources | where type contains 'cognitiveservices' or tags contains 'pii-detection' | project name, type, resourceGroup",
                "AzureActivity | where OperationNameValue contains 'redact' or OperationNameValue contains 'sanitize' | summarize by ResourceId"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Get evidence artifacts for FRR-ICP-06 (responsible disclosure/redaction)."""
        return {
            'evidence_artifacts': [
                "Data classification policy and procedures",
                "Redaction mechanism implementation documentation",
                "PII detection and filtering configuration",
                "Sensitive information handling procedures (section of IRP)",
                "Historical incident reports showing redacted content",
                "Data sanitization testing evidence",
                "Staff training records on responsible disclosure",
                "Incident disclosure approval workflows"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Get automation recommendations for FRR-ICP-06 (responsible disclosure/redaction)."""
        return {
            'implementation_notes': [
                "Implement automated data redaction mechanisms (pattern matching, entity recognition)",
                "Configure PII detection services (Azure Text Analytics, AWS Comprehend)",
                "Establish data classification framework for incident information",
                "Implement approval workflows for incident disclosure",
                "Test redaction mechanisms with sample incident data",
                "Train staff on identifying sensitive information to redact",
                "Monitor redacted disclosures for accidental exposure"
            ]
        }
