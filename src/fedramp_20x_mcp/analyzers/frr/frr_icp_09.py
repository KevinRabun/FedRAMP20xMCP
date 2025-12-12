"""
FRR-ICP-09: Human-Readable and Machine-Readable Formats

Providers SHOULD make _incident_ report information available in consistent human-readable and _machine-readable_ formats.

Official FedRAMP 20x Requirement
Source: FRR-ICP (ICP) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import Dict, List, Any
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
        """Analyze C# for machine-readable format generation."""
        findings = []
        has_format = bool(re.search(r'(JsonSerializer|XmlSerializer|JsonConvert|ToJson|ToXml)', code))
        if not has_format:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="No machine-readable format generation detected",
                details="FRR-ICP-09 recommends machine-readable incident reports. Consider implementing JSON/XML serialization.",
                file_path=file_path,
                line_number=1,
                recommendation="Consider implementing JSON/XML serialization: System.Text.Json or Newtonsoft.Json"
            ))
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java for machine-readable format generation."""
        findings = []
        has_format = bool(re.search(r'(ObjectMapper|Gson|Jackson|XmlMapper)', code))
        if not has_format:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="No machine-readable format generation detected",
                details="FRR-ICP-09 recommends machine-readable incident reports. Consider implementing JSON/XML serialization.",
                file_path=file_path,
                line_number=1,
                recommendation="Consider implementing JSON/XML serialization: Jackson, Gson, or JAXB"
            ))
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript for machine-readable format generation."""
        findings = []
        has_format = bool(re.search(r'(JSON\.stringify|toJSON|xml2js|fast-xml-parser)', code, re.IGNORECASE))
        if not has_format:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="No machine-readable format generation detected",
                details="FRR-ICP-09 recommends machine-readable incident reports. Consider implementing JSON/XML serialization.",
                file_path=file_path,
                line_number=1,
                recommendation="Consider implementing JSON/XML serialization: JSON.stringify or xml2js"
            ))
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep for API/data services."""
        return []  # Machine-readable format generation is application logic
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for API/data services."""
        return []  # Machine-readable format generation is application logic
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for data export."""
        return []  # Machine-readable format generation is runtime operational
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for data export."""
        return []  # Machine-readable format generation is runtime operational
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for data export."""
        return []  # Machine-readable format generation is runtime operational
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """KQL queries for machine-readable format evidence."""
        return {
            "automated_queries": [
                "# Query 1: API Management and Function Apps\nResources\n| where type =~ 'microsoft.apimanagement/service' or type =~ 'microsoft.web/sites'\n| where kind contains 'function' or name contains 'api'\n| extend Format = tostring(properties.format)\n| project name, type, location, Format, tags",
                "# Query 2: Storage accounts for structured data\nResources\n| where type =~ 'microsoft.storage/storageaccounts'\n| where tags contains 'incident' or tags contains 'report'\n| project name, type, location, kind, tags",
                "# Query 3: Data Factory for format pipelines\nResources\n| where type =~ 'microsoft.datafactory/factories'\n| project name, location, tags"
            ]
        }

    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Required evidence artifacts for FRR-ICP-09."""
        return {
            "evidence_artifacts": [
                "Machine-readable format specification (JSON/XML schema)",
                "API endpoint documentation for incident reports",
                "Sample machine-readable incident reports",
                "Format validation test results",
                "Serialization library configuration",
                "API integration documentation",
                "Machine-readable format conversion logs",
                "Format compliance test evidence"
            ]
        }

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Implementation recommendations for FRR-ICP-09."""
        return {
            "implementation_notes": [
                "Implement JSON/XML serialization in incident reporting system",
                "Create API endpoints exposing machine-readable incident reports",
                "Define schema for machine-readable incident report format",
                "Validate machine-readable output against schema",
                "Test format compatibility with FedRAMP tools/consumers",
                "Document machine-readable format structure and access methods",
                "Implement automated format conversion for existing reports"
            ]
        }
