"""
FRR-ICP-09: Human-Readable and Machine-Readable Formats

Providers SHOULD make _incident_ report information available in consistent human-readable and _machine-readable_ formats.

Official FedRAMP 20x Requirement
Source: FRR-ICP (ICP) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ICP_09_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-09: Human-Readable and Machine-Readable Formats
    
    **Official Statement:**
    Providers SHOULD make _incident_ report information available in consistent human-readable and _machine-readable_ formats.
    
    **Family:** ICP - ICP
    
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
    
    FRR_ID = "FRR-ICP-09"
    FRR_NAME = "Human-Readable and Machine-Readable Formats"
    FRR_STATEMENT = """Providers SHOULD make _incident_ report information available in consistent human-readable and _machine-readable_ formats."""
    FAMILY = "ICP"
    FAMILY_NAME = "ICP"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("IR-4", "Incident Handling"),
        ("IR-6", "Incident Reporting"),
        ("IR-5", "Incident Monitoring"),
        ("IR-8", "Incident Response Plan"),
    ]
    CODE_DETECTABLE = True  # Detects machine-readable format generation and API endpoints
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-09 analyzer."""
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
        Analyze Python code for FRR-ICP-09 compliance using AST.
        
        Detects:
        - JSON/XML export functionality
        - Structured data APIs
        - Machine-readable format generation
        """
        findings = []
        
        # Check for JSON/XML generation
        has_json = bool(re.search(r'json\.dumps|jsonify|to_json|JSONEncoder', code))
        has_xml = bool(re.search(r'xml|ElementTree|lxml|tostring', code, re.IGNORECASE))
        
        # Check for API endpoints
        has_api = bool(re.search(
            r'@app\.route|@api\.|FastAPI|Flask|endpoint|api.*handler',
            code
        ))
        
        # Check for structured schemas
        has_schema = bool(re.search(
            r'pydantic|marshmallow|schema|dataclass|TypedDict',
            code, re.IGNORECASE
        ))
        
        if not (has_json or has_xml):
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="No machine-readable format generation detected",
                details=(
                    "FRR-ICP-09 recommends machine-readable incident reports. "
                    "Consider implementing JSON or XML export."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Consider implementing JSON/XML export for incident reports."
            ))
        
        if not has_api:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="No API endpoints detected",
                details=(
                    "FRR-ICP-09 recommends machine-readable access. "
                    "Consider implementing API endpoints for incident data."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Consider implementing API endpoints for incident data access."
            ))
        
        if (has_json or has_api) and not has_schema:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="Structured data without schema validation",
                details=(
                    "FRR-ICP-09 recommends consistent formats. "
                    "Consider using Pydantic or Marshmallow for schema validation."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Consider implementing schema validation (Pydantic, Marshmallow)."
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
        """
        Analyze C# code for FRR-ICP-09 compliance using AST.
        
        TODO: Implement C# analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for C#
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ICP-09 compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ICP-09 compliance using AST.
        
        TODO: Implement TypeScript analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ICP-09 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-ICP-09 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-ICP-09 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-ICP-09 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ICP-09 compliance.
        
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
        Get recommendations for automating evidence collection for FRR-ICP-09.
        
        This requirement is not directly code-detectable. Provides manual validation guidance.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'No',
            'automation_approach': 'Manual validation required - use evidence collection queries and documentation review',
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
