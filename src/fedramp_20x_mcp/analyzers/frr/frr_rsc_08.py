"""
FRR-RSC-08: Machine-Readable Guidance

Providers SHOULD provide recommended secure configuration guidance in a _machine-readable_ format that can be used by customers or third-party tools to compare against current settings.

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


class FRR_RSC_08_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-08: Machine-Readable Guidance
    
    **Official Statement:**
    Providers SHOULD provide recommended secure configuration guidance in a _machine-readable_ format that can be used by customers or third-party tools to compare against current settings.
    
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
    
    FRR_ID = "FRR-RSC-08"
    FRR_NAME = "Machine-Readable Guidance"
    FRR_STATEMENT = """Providers SHOULD provide recommended secure configuration guidance in a _machine-readable_ format that can be used by customers or third-party tools to compare against current settings."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CM-6", "Configuration Settings"),
        ("CM-2", "Baseline Configuration")
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-RSC-08 analyzer."""
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
        Check for machine-readable configuration guidance generation.
        
        Looks for:
        - JSON/YAML/XML schema generation
        - Configuration export to structured formats
        - Documentation generation with machine-readable output
        """
        findings = []
        lines = code.split('\n')
        
        patterns = [
            r'json\.dump.*config', r'yaml\.dump.*guidance',
            r'generate.*schema', r'export.*json.*settings',
            r'create.*machine.*readable', r'jsonschema',
            r'xml\.etree.*config'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Machine-readable config guidance detected",
                        description=f"Line {i} exports configuration in machine-readable format. FRR-RSC-08 requires secure configuration guidance in machine-readable format.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Ensure output includes: (1) Secure default recommendations, (2) Security setting descriptions, (3) Schema/validation rules, (4) Version information"
                    ))
                    return findings
        
        return findings
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
        Analyze C# code for FRR-RSC-08 compliance using AST.
        
        TODO: Implement C# analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for C#
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-RSC-08 compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-RSC-08 compliance using AST.
        
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
        Analyze Bicep infrastructure code for FRR-RSC-08 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-RSC-08 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-RSC-08 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-RSC-08 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-RSC-08 compliance.
        
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
        """
        Get KQL queries and API endpoints for collecting FRR-RSC-08 evidence.
        
        Returns automated queries to collect evidence of machine-readable
        configuration guidance (JSON/YAML/XML schemas) for secure settings.
        """
        return {
            "automated_queries": [
                # Azure Blob Storage: Configuration guidance files
                """Resources
                | where type =~ 'microsoft.storage/storageaccounts'
                | extend hasConfigDocs = properties contains 'config' or properties contains 'schema' or properties contains 'guidance'
                | where hasConfigDocs == true
                | project name, type, resourceGroup, subscriptionId, properties""",
                
                # Azure Monitor: Downloads of configuration guidance (last 90 days)
                """AzureDiagnostics
                | where Category == 'StorageRead' and TimeGenerated > ago(90d)
                | where Uri_s contains 'secure-config' or Uri_s contains 'schema.json' or Uri_s contains 'baseline.yaml'
                | summarize DownloadCount=count() by Uri_s, bin(TimeGenerated, 1d)
                | order by TimeGenerated desc""",
                
                # Azure DevOps: Configuration guidance repositories
                """Resources
                | where type =~ 'microsoft.devops/repository'
                | where name contains 'config' or name contains 'baseline' or name contains 'guidance'
                | project name, type, resourceGroup, subscriptionId"""
            ],
            "manual_queries": [
                "Review documentation for published configuration guidance files",
                "Check DevOps repositories for baseline configuration schemas (JSON/YAML)",
                "Verify customer-facing documentation includes machine-readable format downloads"
            ]
        }
    
    def get_evidence_artifacts(self) -> dict:
        """
        Get list of evidence artifacts for FRR-RSC-08 compliance.
        
        Returns documentation and sample machine-readable configuration guidance
        files (JSON/YAML/XML schemas) for secure settings.
        """
        return {
            "evidence_artifacts": [
                "CONFIG-GUIDANCE.md - Documentation explaining machine-readable guidance",
                "schemas/secure-baseline.json - JSON schema for secure configuration",
                "schemas/secure-baseline.yaml - YAML version of secure configuration",
                "schemas/config-schema.xsd - XML schema definition for validation",
                "CUSTOMER-GUIDE.md - Instructions for customers to use guidance files",
                "TOOL-INTEGRATION.md - How third-party tools can consume guidance",
                "VERSION-HISTORY.md - Changelog for baseline configuration versions"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating FRR-RSC-08 evidence collection.
        
        Returns guidance for creating and publishing machine-readable secure
        configuration guidance for customers and third-party tools.
        """
        return {
            "implementation_notes": [
                "1. Create machine-readable guidance files",
                "   - Generate JSON/YAML/XML schemas for secure configuration baselines",
                "   - Include: all security settings, recommended values, rationale, NIST control mappings",
                "   - Document schema structure and validation rules",
                "   - Example: schemas/secure-baseline.json with all admin/privileged account settings",
                "",
                "2. Publish guidance for customer access",
                "   - Host guidance files in Azure Blob Storage or GitHub repository",
                "   - Make files publicly accessible or accessible to customers",
                "   - Provide download links in customer documentation",
                "   - Version guidance files (e.g., v1.0.0, v1.1.0) for tracking",
                "",
                "3. Document usage instructions",
                "   - Create CUSTOMER-GUIDE.md explaining how to use guidance files",
                "   - Provide code examples for parsing JSON/YAML/XML",
                "   - Explain how to compare current settings against baseline",
                "   - Include integration instructions for popular tools (Terraform, Ansible, PowerShell DSC)",
                "",
                "4. Automate guidance generation",
                "   - Create CI/CD pipeline to generate updated guidance from IaC templates",
                "   - Auto-publish new versions when baseline changes",
                "   - Track guidance usage via download logs",
                "   - Example: GitHub Actions workflow to export secure baselines to JSON/YAML",
                "",
                "5. Enable third-party tool integration",
                "   - Provide REST API for programmatic access to guidance",
                "   - Support standard formats (JSON Schema, OpenAPI, YAML)",
                "   - Document API endpoints and authentication",
                "   - Example: GET /api/config/baseline returns JSON with secure settings"
            ]
        }
