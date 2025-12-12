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
        
        FRR-ADS-02 requires automation to ensure consistency between human-readable
        and machine-readable authorization data formats. Infrastructure code analysis
        is not directly applicable since this requirement focuses on documentation
        generation automation, not infrastructure resources.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-02 compliance.
        
        FRR-ADS-02 requires automation to ensure consistency between human-readable
        and machine-readable authorization data formats. Infrastructure code analysis
        is not directly applicable since this requirement focuses on documentation
        generation automation, not infrastructure resources.
        """
        return []
    
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
            'automation_feasibility': 'High - Can automate detection of format conversion functions, CI/CD pipeline analysis, build artifact comparison, and consistency verification',
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
            'azure_services': [
                'Azure DevOps (CI/CD pipelines for automated doc generation)',
                'Azure Static Web Apps (hosting generated documentation)',
                'Azure Storage (storing build artifacts and generated formats)',
                'Azure Repos (version control for single source of truth)',
                'Azure Pipelines (build automation for format consistency)'
            ],
            'collection_methods': [
                'Static code analysis to detect format conversion functions',
                'CI/CD pipeline configuration scanning',
                'Build artifact comparison (timestamp and content analysis)',
                'Git repository analysis for single-source documentation',
                'Automated format consistency validation',
                'Build log analysis for generation process verification'
            ],
            'implementation_steps': [
                '1. Scan codebase for format conversion/generation functions (oscal_to_html, json_to_markdown, etc.)',
                '2. Analyze CI/CD pipelines for documentation generation automation',
                '3. Compare generated artifacts (HTML vs JSON) for content consistency',
                '4. Verify timestamps show simultaneous generation from same source',
                '5. Check Git history confirms single source of truth for documentation',
                '6. Review build logs to confirm automated generation process',
                '7. Test format conversion automation with sample inputs'
            ],
            'integration_points': [
                'CI/CD automation for consistent generation',
                'OSCAL format export for compliance reporting',
                'Version control integration for change tracking',
                'Automated testing of format consistency',
                'Documentation as code practices'
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get specific queries for collecting FRR-ADS-02 evidence.
        
        Returns:
            List of evidence collection queries specific to format consistency verification
        """
        return [
            {
                'method_type': 'Code Analysis',
                'name': 'Format Conversion Function Detection',
                'description': 'Scan source code repositories for format conversion and document generation functions',
                'command': 'grep -r -E "(oscal_to_html|json_to_markdown|render_template|generate_docs|to_html|to_markdown|ObjectMapper|JsonSerializer)" src/ --include="*.py" --include="*.cs" --include="*.java" --include="*.ts"',
                'purpose': 'Identify automated format conversion functions that ensure consistency between human-readable and machine-readable formats',
                'evidence_type': 'Source code with format conversion automation',
                'validation_checks': [
                    'Verify functions convert from single source to multiple formats',
                    'Check for bidirectional consistency (HTML ↔ JSON)',
                    'Confirm error handling for format conversion failures',
                    'Validate input validation before conversion'
                ],
                'storage_location': 'Evidence/ADS-02/code-analysis-reports/'
            },
            {
                'method_type': 'CI/CD Pipeline Scan',
                'name': 'Documentation Generation Pipeline Analysis',
                'description': 'Analyze CI/CD pipeline configurations for automated documentation generation',
                'command': 'find .github/workflows/ .azure-pipelines/ .gitlab-ci.yml -type f -exec grep -l -E "(mkdocs|sphinx-build|docusaurus|generate.*docs|oscal.*convert)" {} \\;',
                'purpose': 'Verify CI/CD pipelines automatically generate both human-readable and machine-readable formats from single source',
                'evidence_type': 'CI/CD pipeline configuration files',
                'validation_checks': [
                    'Pipeline generates both HTML and JSON/OSCAL formats',
                    'Generation happens in same build step from same source',
                    'Build fails if formats are inconsistent',
                    'Artifacts are stored with matching timestamps'
                ],
                'storage_location': 'Evidence/ADS-02/pipeline-configurations/'
            },
            {
                'method_type': 'Build Artifact Comparison',
                'name': 'Format Consistency Verification',
                'description': 'Compare generated human-readable and machine-readable formats for content consistency',
                'command': 'python scripts/compare_formats.py --html docs/output.html --json docs/output.json --report evidence/consistency-report.json',
                'purpose': 'Validate that human-readable HTML and machine-readable JSON contain identical information',
                'evidence_type': 'Format consistency comparison report',
                'validation_checks': [
                    'All data fields present in both formats',
                    'Values match exactly between formats',
                    'Timestamps indicate simultaneous generation',
                    'No data loss or transformation errors'
                ],
                'storage_location': 'Evidence/ADS-02/consistency-reports/'
            },
            {
                'method_type': 'Git Repository Analysis',
                'name': 'Single Source Documentation Verification',
                'description': 'Analyze Git repository to confirm single source of truth for documentation',
                'command': 'git log --all --oneline --name-only -- docs/source/ | grep -E "(README|docs/source/)" | head -100',
                'purpose': 'Verify documentation is maintained in single source location and generated formats are derived, not manually edited',
                'evidence_type': 'Git commit history showing documentation source management',
                'validation_checks': [
                    'Changes only occur in source directory (e.g., docs/source/)',
                    'Generated formats (HTML/JSON) are not manually edited',
                    'Build automation regenerates outputs on source changes',
                    'No direct commits to generated format directories'
                ],
                'storage_location': 'Evidence/ADS-02/git-analysis/'
            },
            {
                'method_type': 'Build Log Analysis',
                'name': 'Automated Generation Process Verification',
                'description': 'Review CI/CD build logs to confirm automated format generation',
                'command': 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/{owner}/{repo}/actions/runs?event=push | jq ".workflow_runs[0].logs_url"',
                'purpose': 'Confirm automation successfully generates both formats from single source during builds',
                'evidence_type': 'CI/CD build logs showing format generation',
                'validation_checks': [
                    'Build logs show execution of format conversion commands',
                    'Both HTML and JSON generation completed successfully',
                    'No manual intervention during generation process',
                    'Timestamps show sequential generation within same build'
                ],
                'storage_location': 'Evidence/ADS-02/build-logs/'
            },
            {
                'method_type': 'OSCAL Validation',
                'name': 'Machine-Readable Format Compliance',
                'description': 'Validate generated OSCAL JSON files comply with FedRAMP schema requirements',
                'command': 'oscal-cli validate --schema https://pages.nist.gov/OSCAL/schema/json/oscal-ssp-schema.json --file system-security-plan.json',
                'purpose': 'Ensure machine-readable OSCAL format is valid and equivalent to human-readable documentation',
                'evidence_type': 'OSCAL validation report',
                'validation_checks': [
                    'OSCAL JSON validates against official schema',
                    'All required FedRAMP fields are present',
                    'Content matches corresponding HTML documentation',
                    'No schema validation errors or warnings'
                ],
                'storage_location': 'Evidence/ADS-02/oscal-validation/'
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts for FRR-ADS-02 compliance.
        
        Returns:
            List of evidence artifacts specific to format consistency verification
        """
        return [
            {
                'artifact_name': 'Source Code Analysis Report',
                'artifact_type': 'Code Scan Results',
                'description': 'Report identifying all format conversion and document generation functions in source code',
                'collection_method': 'Automated static code analysis using grep/AST parsers to detect conversion functions',
                'validation_checks': [
                    'Report lists all conversion functions (Python, C#, Java, TypeScript)',
                    'Functions documented with input/output format specifications',
                    'Error handling verified for conversion failures',
                    'Code review confirms single-source-to-multiple-formats pattern'
                ],
                'storage_location': 'Evidence/ADS-02/code-analysis/source-code-report.json',
                'retention_period': '7 years per FedRAMP requirements'
            },
            {
                'artifact_name': 'CI/CD Pipeline Configuration',
                'artifact_type': 'Pipeline YAML Files',
                'description': 'GitHub Actions, Azure Pipelines, or GitLab CI configurations showing automated documentation generation',
                'collection_method': 'Extract pipeline YAML files from repository and analyze for doc generation steps',
                'validation_checks': [
                    'Pipeline includes steps for both HTML and JSON generation',
                    'Generation uses same source input for both formats',
                    'Build fails if consistency checks fail',
                    'Artifacts published include both formats with matching timestamps'
                ],
                'storage_location': 'Evidence/ADS-02/pipelines/workflow-configs/',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Generated Format Samples',
                'artifact_type': 'Documentation Artifacts',
                'description': 'Sample outputs in both human-readable (HTML/Markdown) and machine-readable (JSON/OSCAL) formats from same source',
                'collection_method': 'Capture build artifacts from recent pipeline runs showing both format outputs',
                'validation_checks': [
                    'HTML and JSON files generated from same CI/CD run',
                    'Timestamps match (generated within same minute)',
                    'Content comparison shows data consistency',
                    'File sizes reasonable for complete documentation'
                ],
                'storage_location': 'Evidence/ADS-02/generated-formats/',
                'retention_period': '7 years (retain quarterly samples)'
            },
            {
                'artifact_name': 'Build Logs - Format Generation',
                'artifact_type': 'CI/CD Execution Logs',
                'description': 'Build logs showing automated execution of format conversion and documentation generation',
                'collection_method': 'Download logs from CI/CD platform API (GitHub Actions, Azure DevOps, GitLab)',
                'validation_checks': [
                    'Logs show successful execution of generation commands',
                    'Both format generation steps completed without errors',
                    'Timestamps confirm sequential generation in same build',
                    'No manual intervention logged during generation'
                ],
                'storage_location': 'Evidence/ADS-02/build-logs/',
                'retention_period': '7 years (retain monthly samples)'
            },
            {
                'artifact_name': 'Format Consistency Report',
                'artifact_type': 'Validation Report',
                'description': 'Automated comparison report verifying consistency between human-readable and machine-readable formats',
                'collection_method': 'Run automated comparison script that parses both formats and validates data equivalence',
                'validation_checks': [
                    'All data fields present in both HTML and JSON',
                    'Field values match exactly (no data loss or transformation)',
                    'Structural consistency (sections, controls, parameters)',
                    'No discrepancies identified between formats'
                ],
                'storage_location': 'Evidence/ADS-02/consistency-reports/',
                'retention_period': '7 years (generate and retain monthly)'
            },
            {
                'artifact_name': 'Git Repository Documentation Source History',
                'artifact_type': 'Version Control Analysis',
                'description': 'Git history showing single source of truth for documentation with no direct edits to generated formats',
                'collection_method': 'Extract git log for documentation directories, analyze commit patterns to verify single-source approach',
                'validation_checks': [
                    'Source files (e.g., docs/source/) have commit history',
                    'Generated format directories (e.g., docs/build/) excluded from version control or generated via CI/CD',
                    'No manual commits editing HTML or JSON outputs directly',
                    'All documentation changes flow through source → automation → formats'
                ],
                'storage_location': 'Evidence/ADS-02/git-analysis/',
                'retention_period': '7 years (quarterly snapshots)'
            }
        ]
