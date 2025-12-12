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
    CODE_DETECTABLE = "Partial"
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
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get KQL queries and API endpoints for collecting FRR-RSC-07 evidence.
        
        Returns automated queries to collect evidence of API capabilities
        for viewing and adjusting security settings.
        """
        return {
            "automated_queries": [
                # Azure Resource Graph: API Management services with settings endpoints
                """Resources
                | where type =~ 'microsoft.apimanagement/service' or type =~ 'microsoft.web/sites'
                | extend hasSettingsAPI = properties contains '/api/settings' or properties contains '/api/config' or properties contains '/api/security'
                | where hasSettingsAPI == true
                | project name, type, resourceGroup, subscriptionId, properties""",
                
                # Azure Monitor: Settings API calls (GET/PUT) (last 90 days)
                """AzureDiagnostics
                | where Category == 'ApplicationInsights' and TimeGenerated > ago(90d)
                | where (url_s contains '/api/settings' or url_s contains '/api/config' or url_s contains '/api/security')
                | where httpMethod_s in ('GET', 'PUT', 'PATCH', 'POST')
                | summarize GetCount=countif(httpMethod_s=='GET'), UpdateCount=countif(httpMethod_s in ('PUT','PATCH','POST')) by url_s, bin(TimeGenerated, 1d)
                | order by TimeGenerated desc""",
                
                # Azure Policy: API access policies
                """PolicyResources
                | where type =~ 'microsoft.authorization/policydefinitions'
                | where properties.policyRule contains 'api' or properties.metadata.category == 'API Management'
                | project policyName=name, category=properties.metadata.category, effect=properties.policyRule.then.effect
                | where tags contains 'rsc-07' or tags contains 'api-capability'"""
            ],
            "manual_queries": [
                "Review API documentation for GET/PUT /api/settings endpoints",
                "Check OpenAPI/Swagger specs for security settings APIs",
                "Verify Azure API Management policies for settings access"
            ]
        }
    
    def get_evidence_artifacts(self) -> dict:
        """
        Get list of evidence artifacts for FRR-RSC-07 compliance.
        
        Returns documentation and API specs demonstrating API capability
        for viewing and adjusting security settings.
        """
        return {
            "evidence_artifacts": [
                "API-CAPABILITY.md - Documentation of settings API",
                "openapi-spec.yaml - OpenAPI/Swagger specification for settings endpoints",
                "ENDPOINTS.md - List of GET/PUT endpoints for security settings",
                "api-examples/ - Sample API requests/responses for settings management",
                "audit-logs/ - Logs showing API usage for viewing/adjusting settings",
                "AUTHENTICATION.md - API authentication/authorization documentation",
                "RATE-LIMITS.md - API rate limiting and throttling policies"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating FRR-RSC-07 evidence collection.
        
        Returns guidance for implementing and documenting API capabilities
        for viewing and adjusting all security settings.
        """
        return {
            "implementation_notes": [
                "1. Implement settings management API",
                "   - Create RESTful API for viewing (GET) and adjusting (PUT/PATCH) security settings",
                "   - Support all security settings (authentication, authorization, encryption, audit, network)",
                "   - Implement proper authentication (OAuth 2.0, API keys) and authorization (RBAC)",
                "   - Example: GET /api/settings, PUT /api/settings/{settingId}",
                "",
                "2. Document API endpoints",
                "   - Create OpenAPI/Swagger specification in openapi-spec.yaml",
                "   - Document all GET/PUT/PATCH endpoints for settings",
                "   - Include request/response schemas, error codes, authentication requirements",
                "   - Host API documentation on developer portal",
                "",
                "3. Tag API resources",
                "   - Tag API Management/Azure Functions with 'rsc-07:api-capability'",
                "   - Tag endpoints with 'fedramp:settings-api' for KQL queries",
                "   - Enable Application Insights for API monitoring",
                "",
                "4. Implement API security",
                "   - Enforce authentication on all settings endpoints",
                "   - Implement rate limiting (e.g., 100 requests/minute)",
                "   - Log all GET/PUT operations with user identity, timestamp, setting changed",
                "   - Validate input on PUT/PATCH to prevent injection attacks",
                "",
                "5. Monitor API usage",
                "   - Enable Application Insights for all settings API calls",
                "   - Retain logs for 90 days minimum",
                "   - Track: who accessed, which settings, read vs write operations",
                "   - Alert on suspicious activity (excessive PUTs, unauthorized access)"
            ]
        }
