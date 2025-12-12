"""
FRR-ADS-TC-02: Human and Machine-Readable

_Trust centers_ SHOULD make _authorization data_ available to view and download in both human-readable and _machine-readable_ formats

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_TC_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-TC-02: Human and Machine-Readable
    
    **Official Statement:**
    _Trust centers_ SHOULD make _authorization data_ available to view and download in both human-readable and _machine-readable_ formats
    
    **Family:** ADS - Authorization Data Sharing
    
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
    
    FRR_ID = "FRR-ADS-TC-02"
    FRR_NAME = "Human and Machine-Readable"
    FRR_STATEMENT = """_Trust centers_ SHOULD make _authorization data_ available to view and download in both human-readable and _machine-readable_ formats"""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SA-9", "External System Services"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-TC-02 analyzer."""
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
        Analyze Python code for FRR-ADS-TC-02 compliance using AST.
        
        Detects human and machine-readable format support:
        - Format conversion functions (PDF, HTML, JSON, XML)
        - Download endpoints with format options
        - Content-Type headers for different formats
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function definitions for format conversion
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in function_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    # Check for format conversion or export functions
                    if any(keyword in func_name_lower for keyword in ['convert_to_json', 'convert_to_xml', 'convert_to_pdf', 'convert_to_html', 'export_format', 'generate_pdf', 'generate_html', 'to_json', 'to_xml']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format conversion function detected",
                            description="Found function for converting authorization data to human/machine-readable format",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure both human-readable (PDF/HTML) and machine-readable (JSON/XML) formats supported."
                        ))
                
                # Check string literals for Content-Type headers
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in string_literals:
                    string_text = parser.get_node_text(string_node, code_bytes).lower()
                    if 'content-type' in string_text and any(fmt in string_text for fmt in ['json', 'xml', 'pdf', 'html']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format-specific Content-Type detected",
                            description="Found Content-Type header for human/machine-readable format",
                            severity=Severity.INFO,
                            line_number=string_node.start_point[0] + 1,
                            code_snippet=string_text[:100],
                            recommendation="Verify trust center supports both format types."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        format_patterns = [
            r'(pdf|html|json|xml).*format',
            r'export.*(?:pdf|html|json|xml)',
            r'download.*(?:pdf|html|json|xml)',
            r'content[-_]type.*(?:json|xml|pdf|html)',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in format_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Format support pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure trust center provides authorization data in both human-readable and machine-readable formats."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-TC-02 compliance using AST.
        
        Detects format conversion in C# applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['convertto', 'exportto', 'generatepdf', 'generatehtml', 'tojson', 'toxml', 'formatconverter']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format conversion method detected",
                            description="Found method for format conversion",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure both human-readable and machine-readable formats supported."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:ConvertTo|ExportTo|Generate)(?:Pdf|Html|Json|Xml)|ContentType.*(?:json|xml|pdf|html)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Format conversion detected",
                    description="Found format conversion reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify trust center provides both format types."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-TC-02 compliance using AST.
        
        Detects format conversion in Java applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['convertto', 'exportto', 'generatepdf', 'generatehtml', 'tojson', 'toxml', 'formatconverter']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format conversion method detected",
                            description="Found method for format conversion",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure both human-readable and machine-readable formats supported."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:convertTo|exportTo|generate)(?:Pdf|Html|Json|Xml)|contentType.*(?:json|xml|pdf|html)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Format conversion detected",
                    description="Found format conversion reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify trust center provides both format types."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-TC-02 compliance using AST.
        
        Detects format conversion in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function declarations
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    if any(keyword in func_name_lower for keyword in ['convertto', 'exportto', 'generatepdf', 'generatehtml', 'tojson', 'toxml', 'formatconverter']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format conversion function detected",
                            description="Found function for format conversion",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure both human-readable and machine-readable formats supported."
                        ))
                
                # Check arrow functions
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['json', 'xml', 'pdf', 'html', 'format']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format handler detected",
                            description="Found format conversion handler",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify both format types supported."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:convertTo|exportTo|generate)(?:Pdf|Html|Json|Xml)|contentType.*(?:json|xml|pdf|html)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Format conversion detected",
                    description="Found format conversion reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify trust center provides both format types."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-TC-02 compliance.
        
        NOT APPLICABLE: Format support (human-readable vs machine-readable) is an
        application-level feature implemented in application code, not infrastructure
        configuration. The requirement mandates that trust centers provide authorization
        data in both PDF/HTML (human-readable) and JSON/XML (machine-readable) formats.
        
        This is implemented through:
        1. Application code that generates/converts formats
        2. Web framework route handlers that serve different Content-Types
        3. Document generation libraries (PDF, HTML rendering)
        4. Serialization libraries (JSON, XML generation)
        
        These are application concerns, not infrastructure concerns.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-TC-02 compliance.
        
        NOT APPLICABLE: Format support (human-readable vs machine-readable) is an
        application-level feature implemented in application code, not infrastructure
        configuration. The requirement mandates that trust centers provide authorization
        data in both PDF/HTML (human-readable) and JSON/XML (machine-readable) formats.
        
        This is implemented through:
        1. Application code that generates/converts formats
        2. Web framework route handlers that serve different Content-Types
        3. Document generation libraries (PDF, HTML rendering)
        4. Serialization libraries (JSON, XML generation)
        
        These are application concerns, not infrastructure concerns.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-TC-02 compliance.
        
        NOT APPLICABLE: Format support (human-readable vs machine-readable) is an
        application feature concern, not a CI/CD pipeline concern. The requirement
        mandates that the trust center application provides data in multiple formats,
        which is an application design decision, not a build or deployment concern.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-TC-02 compliance.
        
        NOT APPLICABLE: Format support (human-readable vs machine-readable) is an
        application feature concern, not a CI/CD pipeline concern. The requirement
        mandates that the trust center application provides data in multiple formats,
        which is an application design decision, not a build or deployment concern.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-TC-02 compliance.
        
        NOT APPLICABLE: Format support (human-readable vs machine-readable) is an
        application feature concern, not a CI/CD pipeline concern. The requirement
        mandates that the trust center application provides data in multiple formats,
        which is an application design decision, not a build or deployment concern.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-TC-02.
        
        Partially code-detectable (can find format conversion functions), but requires manual verification.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Medium - can detect format conversion code, but requires manual testing and validation',
            'automation_approach': 'Hybrid - automated code detection + manual format verification',
            'recommended_services': [
                'Azure API Management - Expose authorization data in multiple formats through API policies',
                'Azure Functions - Implement serverless format conversion endpoints',
                'Azure Storage Blob - Store and serve pre-generated PDF/HTML versions',
                'Azure Front Door - Content negotiation and routing based on Accept headers',
                'Azure App Service - Host trust center with format export capabilities',
            ],
            'collection_methods': [
                'Code review of format conversion functions',
                'API testing with different Accept headers',
                'Download testing for each format type',
                'Content-Type header verification in HTTP responses',
                'Trust center UI testing for export buttons',
                'Automated format validation',
            ],
            'implementation_steps': [
                '1. Implement format conversion libraries',
                '2. Create API endpoints that support Content-Type negotiation',
                '3. Add download buttons in trust center UI for each format',
                '4. Configure response headers properly',
                '5. Test format accessibility with different client tools',
                '6. Document supported formats in API documentation',
                '7. Implement format validation and integrity checks',
                '8. Monitor download metrics by format type',
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get automated queries for collecting evidence of FRR-ADS-TC-02 compliance.
        
        Returns queries for verifying format support.
        """
        return [
            {
                'query_name': 'Trust Center Download Requests by Format',
                'query_type': 'KQL',
                'query': '''AppRequests
| where Url contains "trust-center" or Url contains "authorization-data"
| where Url contains "download" or Url contains "export"
| extend Format = case(
    Url contains ".pdf", "PDF",
    Url contains ".html", "HTML",
    Url contains ".json", "JSON",
    Url contains ".xml", "XML",
    "Unknown"
)
| summarize DownloadCount = count() by Format, bin(TimeGenerated, 1d)
| order by TimeGenerated desc''',
                'data_source': 'Application Insights',
                'evidence_type': 'Download activity by format showing both human and machine-readable usage',
            },
            {
                'query_name': 'API Responses by Content-Type',
                'query_type': 'KQL',
                'query': '''AppRequests
| where Url contains "trust-center"
| where isnotempty(Properties["Content-Type"])
| summarize RequestCount = count() by ContentType = tostring(Properties["Content-Type"])
| order by RequestCount desc''',
                'data_source': 'Application Insights',
                'evidence_type': 'Content-Type header distribution showing format variety',
            },
            {
                'query_name': 'Format Conversion Function Testing',
                'query_type': 'Manual',
                'query': 'Test each format conversion endpoint with sample authorization data',
                'data_source': 'Manual API testing',
                'evidence_type': 'Functional testing evidence showing format conversion works',
            },
            {
                'query_name': 'Trust Center UI Format Options',
                'query_type': 'Manual',
                'query': 'Review trust center UI to confirm download buttons for all formats',
                'data_source': 'Trust center web application',
                'evidence_type': 'Screenshot evidence of format selection options',
            },
            {
                'query_name': 'API Documentation Review',
                'query_type': 'Manual',
                'query': 'Review API documentation to confirm supported formats are documented',
                'data_source': 'API documentation portal',
                'evidence_type': 'Documentation evidence showing format support',
            },
            {
                'query_name': 'Content Negotiation Testing',
                'query_type': 'Manual',
                'query': 'Send requests with different Accept headers and verify correct format returned',
                'data_source': 'HTTP client testing',
                'evidence_type': 'Content negotiation test results showing proper format routing',
            },
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts for FRR-ADS-TC-02 compliance.
        
        Returns specific documents needed to demonstrate format support.
        """
        return [
            'Sample authorization data exports in PDF format (human-readable)',
            'Sample authorization data exports in HTML format (human-readable)',
            'Sample authorization data exports in JSON format (machine-readable)',
            'Sample authorization data exports in XML format (machine-readable)',
            'Screenshots of trust center UI showing format download options',
            'API documentation showing supported Content-Type values',
            'HTTP response headers showing Content-Type for each format',
            'Content negotiation test results with different Accept headers',
            'Format validation reports (JSON schema, XML validation, PDF integrity)',
            'Download metrics showing usage of both human and machine-readable formats',
        ]
