"""
FRR-ADS-02: Consistency Between Formats

Providers MUST use automation to ensure information remains consistent between human-readable and _machine-readable_ formats when _authorization data_ is provided in both formats; Providers SHOULD generate human-readable and _machine-readable_ data from the same source at the same time OR generate human-readable formats directly from _machine-readable_ data.

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-02: Consistency Between Formats
    
    **Official Statement:**
    Providers MUST use automation to ensure information remains consistent between human-readable and _machine-readable_ formats when _authorization data_ is provided in both formats; Providers SHOULD generate human-readable and _machine-readable_ data from the same source at the same time OR generate human-readable formats directly from _machine-readable_ data.
    
    **Family:** ADS - Authorization Data Sharing
    
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
    
    FRR_ID = "FRR-ADS-02"
    FRR_NAME = "Consistency Between Formats"
    FRR_STATEMENT = """Providers MUST use automation to ensure information remains consistent between human-readable and _machine-readable_ formats when _authorization data_ is provided in both formats; Providers SHOULD generate human-readable and _machine-readable_ data from the same source at the same time OR generate human-readable formats directly from _machine-readable_ data."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PM-9", "Risk Management Strategy"),
        ("PL-2", "System Security Plan"),
        ("SA-4", "Acquisition Process"),
        ("SA-9", "External System Services"),
        ("CM-2", "Baseline Configuration"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Automated FedRAMP Data Publication
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-02 analyzer."""
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
        Analyze Python code for FRR-ADS-02 compliance using AST.
        
        Detects automation for format consistency:
        - Document generation from single source
        - JSON/OSCAL to HTML/MD converters
        - Automated format synchronization
        """
        findings = []
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for document generation functions
                function_calls = parser.find_function_calls(tree, "")
                for call_node in function_calls:
                    call_text = parser.get_node_text(call_node, code_bytes).decode('utf8')
                    
                    # Detect format conversion/generation patterns
                    if any(pattern in call_text.lower() for pattern in [
                        'oscal_to_html', 'json_to_markdown', 'render_template',
                        'generate_docs', 'to_html', 'to_markdown'
                    ]):
                        line_num = call_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Automated format generation detected",
                            description=f"Found automated conversion: {call_text[:80]}",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text[:100],
                            recommendation="Ensure this automation maintains consistency between human-readable and machine-readable formats."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Fallback to regex
        lines = code.split('\n')
        conversion_patterns = [
            r'oscal.*to.*html',
            r'json.*to.*markdown',
            r'generate.*from.*json',
            r'render.*template',
            r'export.*to.*(html|md|markdown)',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in conversion_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Format conversion detected",
                        description=f"Found conversion pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify automation ensures consistency between formats."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-02 compliance using AST.
        
        Detects format consistency automation in C#.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                invocations = parser.find_nodes_by_type(tree.root_node, 'invocation_expression')
                for inv in invocations:
                    inv_text = parser.get_node_text(inv, code_bytes).decode('utf8')
                    if any(p in inv_text.lower() for p in ['jsonserializer', 'tohtml', 'tomarkdown', 'renderdocument']):
                        line_num = inv.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format conversion detected (C#)",
                            description=f"Found: {inv_text[:80]}",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=inv_text[:100],
                            recommendation="Verify automation ensures consistency."
                        ))
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(JsonSerializer|ToHtml|ToMarkdown|RenderDocument)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Format conversion detected (C#)",
                    description="Found format conversion",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify consistency automation."
                ))
                break
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-02 compliance using AST.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                method_invocations = parser.find_nodes_by_type(tree.root_node, 'method_invocation')
                for inv in method_invocations:
                    inv_text = parser.get_node_text(inv, code_bytes).decode('utf8')
                    if any(p in inv_text.lower() for p in ['objectmapper', 'tohtml', 'tomarkdown']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format conversion detected (Java)",
                            description=f"Found: {inv_text[:80]}",
                            severity=Severity.INFO,
                            line_number=inv.start_point[0] + 1,
                            code_snippet=inv_text[:100],
                            recommendation="Verify consistency."
                        ))
                return findings
        except Exception:
            pass
        
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(ObjectMapper|toHtml|toMarkdown)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Format conversion (Java)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-02 compliance using AST.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                calls = parser.find_function_calls(tree, "")
                for call in calls:
                    call_text = parser.get_node_text(call, code_bytes).decode('utf8')
                    if any(p in call_text.lower() for p in ['json.stringify', 'tohtml', 'tomarkdown', 'render']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Format conversion detected (TS)",
                            description=f"Found: {call_text[:80]}",
                            severity=Severity.INFO,
                            line_number=call.start_point[0] + 1,
                            code_snippet=call_text[:100],
                            recommendation="Verify consistency."
                        ))
                return findings
        except Exception:
            pass
        
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(JSON\.stringify|toHtml|toMarkdown|render)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Format conversion (TS)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-02 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-ADS-02 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-ADS-02 compliance.
        
        Detects documentation generation automation.
        """
        findings = []
        lines = code.split('\n')
        
        # Detect documentation generation steps
        doc_gen_patterns = [
            r'mkdocs.*build',
            r'sphinx-build',
            r'docusaurus.*build',
            r'generate.*docs',
            r'oscal.*convert',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in doc_gen_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Documentation generation automation detected",
                        description=f"Found doc generation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure automation generates both human-readable and machine-readable formats from same source."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-02 compliance.
        """
        findings = []
        lines = code.split('\n')
        
        doc_gen_patterns = [
            r'mkdocs.*build',
            r'sphinx-build',
            r'generate.*docs',
            r'oscal.*convert',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in doc_gen_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Doc generation detected (Azure Pipelines)",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify consistency automation."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-02 compliance.
        """
        findings = []
        lines = code.split('\n')
        
        doc_gen_patterns = [
            r'mkdocs.*build',
            r'sphinx-build',
            r'generate.*docs',
            r'oscal.*convert',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in doc_gen_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Doc generation detected (GitLab CI)",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify consistency."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-02.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Yes',
            'automation_approach': 'Automated detection of format consistency automation through code analysis (document generators, converters) and CI/CD pipeline scanning',
            'evidence_artifacts': [
                'Source code with format conversion functions',
                'CI/CD pipeline YAML with documentation generation steps',
                'Build logs showing documentation generation',
                'Git repository showing single source of truth',
                'Generated documentation in multiple formats (HTML + JSON)',
                'OSCAL files and corresponding human-readable docs'
            ],
            'collection_queries': [
                'Git log: Show commits to documentation source files',
                'CI/CD history: GET /repos/{owner}/{repo}/actions/runs',
                'File comparison: Verify HTML and JSON generated from same source',
                'Build artifacts: List generated documentation files',
                'Version control: Check for single source documentation strategy'
            ],
            'manual_validation_steps': [
                '1. Review source code for automated document generation',
                '2. Verify CI/CD pipeline generates both formats',
                '3. Compare human-readable and machine-readable output for consistency',
                '4. Check timestamps to ensure simultaneous generation',
                '5. Validate single source of truth approach',
                '6. Test format conversion automation'
            ],
            'recommended_services': [
                'Static site generators (MkDocs, Sphinx, Docusaurus)',
                'OSCAL tools for format conversion',
                'GitHub Actions / Azure Pipelines for automation',
                'Azure Static Web Apps for documentation hosting',
                'Git for version control and single source'
            ],
            'integration_points': [
                'CI/CD automation for consistent generation',
                'OSCAL format export for compliance reporting',
                'Version control integration for change tracking',
                'Automated testing of format consistency',
                'Documentation as code practices'
            ]
        }
