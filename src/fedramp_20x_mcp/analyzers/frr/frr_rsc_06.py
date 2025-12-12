"""
FRR-RSC-06: Export Capability

Providers SHOULD offer the capability to export all security settings in a _machine-readable_ format.

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


class FRR_RSC_06_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-06: Export Capability
    
    **Official Statement:**
    Providers SHOULD offer the capability to export all security settings in a _machine-readable_ format.
    
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
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-RSC-06"
    FRR_NAME = "Export Capability"
    FRR_STATEMENT = """Providers SHOULD offer the capability to export all security settings in a _machine-readable_ format."""
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
        """Initialize FRR-RSC-06 analyzer."""
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
        Check for export/serialization capabilities for security settings.
        
        Looks for:
        - JSON/YAML/XML export functions
        - API endpoints for exporting settings
        - Serialization of security configurations
        """
        findings = []
        lines = code.split('\n')
        
        export_patterns = [
            r'def.*export.*settings', r'def.*export.*config',
            r'json\.dump', r'yaml\.dump', r'to_json', r'to_yaml',
            r'@app\.route.*\/export', r'serialize.*config'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in export_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Export capability detected - verify machine-readable format",
                        description=f"Line {i} implements settings export. FRR-RSC-06 requires exporting ALL security settings in machine-readable format (JSON, YAML, XML).",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Ensure export includes: (1) All security settings, (2) Machine-readable format, (3) Schema documentation, (4) Version information"
                    ))
                    return findings
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Check C# for export APIs."""
        patterns = [r'Export.*Settings', r'JsonSerializer\.Serialize', r'\/api\/export']
        return self._check_export(code, file_path, patterns)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Check Java for export APIs."""
        patterns = [r'export.*Config', r'ObjectMapper.*writeValue', r'toJson']
        return self._check_export(code, file_path, patterns)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Check TypeScript for export APIs."""
        patterns = [r'export.*settings', r'JSON\.stringify', r'\/api\/export']
        return self._check_export(code, file_path, patterns)
    
    def _check_export(self, code: str, file_path: str, patterns: List[str]) -> List[Finding]:
        """Shared export detection logic."""
        findings = []
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Export capability found",
                    description="Export functionality detected. Verify machine-readable format per FRR-RSC-06.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Ensure comprehensive export of all security settings"
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
        Analyze Bicep infrastructure code for FRR-RSC-06 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-RSC-06 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-RSC-06 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-RSC-06 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-RSC-06 compliance.
        
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
        Get KQL queries and API endpoints for collecting FRR-RSC-06 evidence.
        
        Returns automated queries to collect evidence of export capabilities
        for security settings in machine-readable formats (JSON, YAML, XML).
        """
        return {
            "automated_queries": [
                # Azure Resource Graph: API endpoints with export logic
                """Resources
                | where type =~ 'microsoft.web/sites' or type =~ 'microsoft.apimanagement/service'
                | extend hasExportEndpoint = properties contains 'export' or properties contains '/api/export' or properties contains 'download'
                | where hasExportEndpoint == true
                | project name, type, resourceGroup, subscriptionId, properties""",
                
                # Azure Monitor: Export API calls (last 90 days)
                """AzureDiagnostics
                | where Category == 'ApplicationInsights' and TimeGenerated > ago(90d)
                | where url_s contains '/api/export' or url_s contains '/api/settings/export' or url_s contains '/download/config'
                | summarize ExportCallCount=count() by url_s, bin(TimeGenerated, 1d)
                | order by TimeGenerated desc""",
                
                # Azure Policy: Custom policies checking export capabilities
                """PolicyResources
                | where type =~ 'microsoft.authorization/policydefinitions'
                | where properties.policyRule contains 'export' or properties.metadata.category == 'Configuration Management'
                | project policyName=name, category=properties.metadata.category, effect=properties.policyRule.then.effect
                | where tags contains 'rsc-06' or tags contains 'export-capability'"""
            ],
            "manual_queries": [
                "Review API documentation for /api/export or /api/settings/download endpoints",
                "Check DevOps repositories for export scripts/tools",
                "Verify Azure Automation runbooks for configuration export"
            ]
        }
    
    def get_evidence_artifacts(self) -> dict:
        """
        Get list of evidence artifacts for FRR-RSC-06 compliance.
        
        Returns documentation and sample exports demonstrating machine-readable
        export capability for security settings.
        """
        return {
            "evidence_artifacts": [
                "EXPORT-CAPABILITY.md - Documentation of export API/tool",
                "API-DOCS.md - Endpoints for exporting security settings",
                "exports/sample-settings.json - Sample JSON export of security settings",
                "exports/sample-config.yaml - Sample YAML export of configuration",
                "scripts/export-settings.py - Automation script for settings export",
                "audit-logs/ - Logs showing regular use of export capability",
                "EXPORT-FORMATS.md - Documentation of supported export formats (JSON/YAML/XML)"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating FRR-RSC-06 evidence collection.
        
        Returns guidance for implementing and documenting machine-readable
        export capabilities for all security settings.
        """
        return {
            "implementation_notes": [
                "1. Implement export API/tool",
                "   - Create REST API or CLI tool to export all security settings",
                "   - Support machine-readable formats: JSON, YAML, XML",
                "   - Include all security settings (auth, authorization, encryption, audit, network)",
                "   - Example: GET /api/settings/export returns JSON with all settings",
                "",
                "2. Define export schema",
                "   - Document export format in schemas/settings-export.json",
                "   - Include: setting name, value, default, last modified, compliance status",
                "   - Version control schema to track changes",
                "   - Support multiple export formats (JSON/YAML/XML)",
                "",
                "3. Tag export resources",
                "   - Tag export APIs with 'rsc-06:export-capability'",
                "   - Tag Azure Functions/Automation implementing export with 'fedramp:rsc-06'",
                "   - Enable KQL queries to identify export tools",
                "",
                "4. Automate regular exports",
                "   - Schedule Azure Automation runbook to export settings weekly",
                "   - Store exports in Azure Blob Storage with versioning",
                "   - Track export history for compliance auditing",
                "   - Example: Weekly cron job running export-settings.py",
                "",
                "5. Log export activity",
                "   - Enable Application Insights for export API calls",
                "   - Retain logs for 90 days minimum",
                "   - Track: who exported, what settings, which format, timestamp"
            ]
        }
