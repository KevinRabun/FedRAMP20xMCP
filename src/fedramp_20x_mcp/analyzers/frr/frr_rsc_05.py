"""
FRR-RSC-05: Comparison Capability

Providers SHOULD offer the capability to compare all current settings for _top-level administrative accounts_ and _privileged accounts_ to the recommended secure defaults.

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


class FRR_RSC_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-05: Comparison Capability
    
    **Official Statement:**
    Providers SHOULD offer the capability to compare all current settings for _top-level administrative accounts_ and _privileged accounts_ to the recommended secure defaults.
    
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
    
    FRR_ID = "FRR-RSC-05"
    FRR_NAME = "Comparison Capability"
    FRR_STATEMENT = """Providers SHOULD offer the capability to compare all current settings for _top-level administrative accounts_ and _privileged accounts_ to the recommended secure defaults."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CM-6", "Configuration Settings"),
        ("CM-7", "Least Functionality")
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-RSC-05 analyzer."""
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
        Check for comparison/validation APIs for security settings.
        
        Looks for:
        - API endpoints for comparing settings
        - Functions that validate against secure defaults
        - Configuration comparison logic
        """
        findings = []
        lines = code.split('\n')
        
        # Check for comparison functions
        comparison_patterns = [
            r'def.*compare.*settings', r'def.*validate.*config',
            r'def.*check.*defaults', r'compare.*security',
            r'@app\.route.*\/compare', r'@api\.route.*\/validate'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in comparison_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Comparison capability detected - ensure completeness",
                        description=f"Line {i} implements settings comparison. FRR-RSC-05 requires ability to compare ALL current settings for admin/privileged accounts to recommended defaults.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Verify comparison covers: (1) All admin/privileged accounts, (2) All security settings, (3) Current vs recommended defaults, (4) Deviation reporting"
                    ))
                    return findings  # Only report once per file
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Check C# for comparison APIs (similar patterns).""" 
        return self._check_comparison_api(code, file_path)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Check Java for comparison APIs (similar patterns)."""
        return self._check_comparison_api(code, file_path)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Check TypeScript for comparison APIs (similar patterns)."""
        return self._check_comparison_api(code, file_path)
    
    def _check_comparison_api(self, code: str, file_path: str) -> List[Finding]:
        """Shared logic for detecting comparison APIs."""
        findings = []
        patterns = [r'compare.*settings', r'validate.*config', r'/api/compare', r'/api/validate']
        
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Comparison API detected",
                    description="Code implements comparison capability. Ensure it covers all admin/privileged account settings per FRR-RSC-05.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Verify comprehensive coverage of all security settings"
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
        Analyze Bicep infrastructure code for FRR-RSC-05 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-RSC-05 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-RSC-05 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-RSC-05 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-RSC-05 compliance.
        
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
        Get KQL queries and API endpoints for collecting FRR-RSC-05 evidence.
        
        Returns automated queries to collect evidence of comparison capabilities
        for validating admin/privileged account settings against secure defaults.
        """
        return {
            "automated_queries": [
                # Azure Resource Graph: API endpoints with comparison logic
                """Resources
                | where type =~ 'microsoft.web/sites' or type =~ 'microsoft.apimanagement/service'
                | extend hasComparisonEndpoint = properties contains 'compare' or properties contains 'validate'
                | where hasComparisonEndpoint == true
                | project name, type, resourceGroup, subscriptionId, properties""",
                
                # Azure Monitor: API calls to comparison endpoints (last 90 days)
                """AzureDiagnostics
                | where Category == 'ApplicationInsights' and TimeGenerated > ago(90d)
                | where url_s contains '/api/compare' or url_s contains '/api/validate' or url_s contains '/settings/compare'
                | summarize ComparisonCallCount=count() by url_s, bin(TimeGenerated, 1d)
                | order by TimeGenerated desc""",
                
                # Azure Policy: Custom policies checking settings compliance
                """PolicyResources
                | where type =~ 'microsoft.authorization/policydefinitions'
                | where properties.policyRule contains 'compare' or properties.metadata.category == 'Security Settings'
                | project policyName=name, category=properties.metadata.category, effect=properties.policyRule.then.effect
                | where tags contains 'rsc-05' or tags contains 'comparison-capability'"""
            ],
            "manual_queries": [
                "Review API documentation for /api/admin/compare-settings endpoints",
                "Check DevOps repositories for settings comparison scripts/tools",
                "Verify Azure Automation runbooks for configuration validation"
            ]
        }
    
    def get_evidence_artifacts(self) -> dict:
        """
        Get list of evidence artifacts for FRR-RSC-05 compliance.
        
        Returns documentation and configuration files demonstrating comparison
        capability for admin/privileged account settings.
        """
        return {
            "evidence_artifacts": [
                "COMPARISON-CAPABILITY.md - Documentation of comparison tool/API",
                "API-DOCS.md - Endpoints for comparing current vs default settings",
                "COMPARISON-RESULTS/ - Sample comparison reports for admin accounts",
                "scripts/compare-settings.py - Automation script for settings validation",
                "config/secure-defaults.yaml - Reference secure defaults configuration",
                "audit-logs/ - Logs showing regular use of comparison capability",
                "DEVIATION-REPORTS/ - Reports of deviations from secure defaults"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating FRR-RSC-05 evidence collection.
        
        Returns guidance for implementing and documenting comparison capabilities
        to validate admin/privileged account settings against secure defaults.
        """
        return {
            "implementation_notes": [
                "1. Implement comparison API/tool",
                "   - Create REST API or CLI tool to compare current settings vs secure defaults",
                "   - Support comparison for ALL admin/privileged account settings",
                "   - Return deviation report with severity levels",
                "   - Example: GET /api/admin/compare/{accountId} returns JSON with diffs",
                "",
                "2. Define secure defaults baseline",
                "   - Document recommended secure defaults in config/secure-defaults.yaml",
                "   - Include MFA requirements, password policies, least privilege roles",
                "   - Version control baseline configuration",
                "   - Update baseline when requirements change",
                "",
                "3. Tag comparison resources",
                "   - Tag comparison APIs with 'rsc-05:comparison-capability'",
                "   - Tag Azure Automation/Functions implementing comparison with 'fedramp:rsc-05'",
                "   - Enable KQL queries to identify comparison tools",
                "",
                "4. Automate regular comparisons",
                "   - Schedule Azure Automation runbook to compare settings weekly",
                "   - Generate comparison reports in Azure Blob Storage",
                "   - Alert on critical deviations from secure defaults",
                "   - Example: Weekly cron job running compare-settings.py",
                "",
                "5. Log comparison activity",
                "   - Enable Application Insights for comparison API calls",
                "   - Retain logs for 90 days minimum",
                "   - Track: who compared, which accounts, deviations found"
            ]
        }
