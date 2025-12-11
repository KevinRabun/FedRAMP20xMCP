"""
FRR-RSC-07: API Capability

Providers SHOULD offer the capability to view and adjust security settings via an API or similar capability.

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


class FRR_RSC_07_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-07: API Capability
    
    **Official Statement:**
    Providers SHOULD offer the capability to view and adjust security settings via an API or similar capability.
    
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
    
    FRR_ID = "FRR-RSC-07"
    FRR_NAME = "API Capability"
    FRR_STATEMENT = """Providers SHOULD offer the capability to view and adjust security settings via an API or similar capability."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CM-6", "Configuration Settings"),
        ("AC-3", "Access Enforcement")
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-RSC-07 analyzer."""
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
        Check for API endpoints that allow viewing/adjusting security settings.
        
        Looks for:
        - Flask/FastAPI routes for security configuration
        - API decorators with security endpoints
        - Functions that modify security settings via API
        """
        findings = []
        lines = code.split('\n')
        
        api_patterns = [
            r'@app\.route.*\/security', r'@api\.route.*\/settings',
            r'@app\.route.*\/config', r'@app\.put.*\/security',
            r'@app\.patch.*\/settings', r'FastAPI.*security',
            r'def.*update.*security.*settings', r'def.*configure.*security'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in api_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Security settings API detected - verify capabilities",
                        description=f"Line {i} implements API for security settings. FRR-RSC-07 requires ability to VIEW and ADJUST security settings via API.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Ensure API supports: (1) Viewing current settings (GET), (2) Adjusting settings (PUT/PATCH), (3) Authentication/authorization, (4) Audit logging"
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
        """Check C# for security settings APIs (Web API, ASP.NET Core)."""
        patterns = [r'\[Route.*security', r'\[HttpGet.*settings', r'\[ApiController.*Security']
        return self._check_api(code, file_path, patterns)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-RSC-07 compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Check TypeScript for security settings APIs (Express, NestJS)."""
        patterns = [r'router\.get.*\/security', r'router\.put.*\/settings', r'@Controller.*security']
        return self._check_api(code, file_path, patterns)
    
    def _check_api(self, code: str, file_path: str, patterns: List[str]) -> List[Finding]:
        """Shared API detection logic."""
        findings = []
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Security settings API found",
                    description="API for security settings detected. Verify view/adjust capabilities per FRR-RSC-07.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Ensure API supports viewing AND adjusting security settings"
                ))
                break
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Check for API Management resources (Azure API for settings)."""
        findings = []
        
        if re.search(r'Microsoft\.ApiManagement/service', code):
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="API Management resource detected",
                description="API Management service found. Verify it provides security settings API per FRR-RSC-07.",
                severity=Severity.LOW,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Ensure API endpoints for viewing/adjusting security settings are configured"
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Check for API Gateway resources (AWS API for settings)."""
        findings = []
        
        if 'aws_api_gateway' in code or 'azurerm_api_management' in code:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="API Gateway resource detected",
                description="API Gateway found. Verify it provides security settings API per FRR-RSC-07.",
                severity=Severity.LOW,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Configure endpoints for viewing/adjusting security settings"
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-RSC-07 compliance.
        
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
        Analyze Azure Pipelines YAML for FRR-RSC-07 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-RSC-07 compliance.
        
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
        Get recommendations for automating evidence collection for FRR-RSC-07.
        
        TODO: Add evidence collection guidance
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Unknown',
            'automation_approach': 'TODO: Fully automated detection through code, IaC, and CI/CD analysis',
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
