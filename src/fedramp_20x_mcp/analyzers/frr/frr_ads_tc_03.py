"""
FRR-ADS-TC-03: Programmatic Access

_Trust centers_ MUST provide documented programmatic access to all _authorization data_, including programmatic access to human-readable materials.

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


class FRR_ADS_TC_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-TC-03: Programmatic Access
    
    **Official Statement:**
    _Trust centers_ MUST provide documented programmatic access to all _authorization data_, including programmatic access to human-readable materials.
    
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
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-ADS-TC-03"
    FRR_NAME = "Programmatic Access"
    FRR_STATEMENT = """_Trust centers_ MUST provide documented programmatic access to all _authorization data_, including programmatic access to human-readable materials."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-2", "Account Management"),
        ("AC-3", "Access Enforcement"),
        ("SA-9", "External System Services"),
        ("SC-8", "Transmission Confidentiality and Integrity"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-TC-03 analyzer."""
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
        Analyze Python code for FRR-ADS-TC-03 compliance using AST.
        
        Detects programmatic access mechanisms:
        - API endpoints (Flask routes, FastAPI endpoints)
        - API documentation (Swagger/OpenAPI decorators)
        - REST/GraphQL patterns
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect decorators for API routes
                decorators = parser.find_nodes_by_type(tree.root_node, 'decorator')
                for decorator in decorators:
                    decorator_text = parser.get_node_text(decorator, code_bytes).lower()
                    if any(keyword in decorator_text for keyword in ['@app.route', '@app.get', '@app.post', '@api', '@router', '@bp.route']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="API endpoint decorator detected",
                            description="Found API route/endpoint decorator for programmatic access",
                            severity=Severity.INFO,
                            line_number=decorator.start_point[0] + 1,
                            code_snippet=decorator_text.split('\n')[0],
                            recommendation="Ensure API endpoint is documented and provides access to authorization data."
                        ))
                
                # Detect API/documentation functions
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in function_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    if any(keyword in func_name_lower for keyword in ['api', 'get_authorization_data', 'swagger', 'openapi', 'graphql', 'rest_endpoint']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Programmatic access function detected",
                            description="Found function for API or programmatic access",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify function provides documented programmatic access to authorization data."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        api_patterns = [
            r'@(?:app|api|router|bp)\.(?:route|get|post|put|delete)',
            r'/api/.*authorization',
            r'swagger|openapi',
            r'graphql.*schema',
            r'programmatic.*access',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in api_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="API pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure documented programmatic access to all authorization data."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-TC-03 compliance using AST.
        
        Detects programmatic access in C# applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations with API attributes
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['[httpget]', '[httppost]', '[route', '[apicontroller]', 'api', 'swagger']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="API endpoint method detected",
                            description="Found API method for programmatic access",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure API method is documented and provides access to authorization data."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'\[Http(?:Get|Post|Put|Delete)\]|\[Route\(|\[ApiController\]|swagger|Swashbuckle', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="API endpoint detected",
                    description="Found API endpoint or documentation attribute",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify documented programmatic access to authorization data."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-TC-03 compliance using AST.
        
        Detects programmatic access in Java applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations with Spring annotations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['@getmapping', '@postmapping', '@requestmapping', '@restcontroller', 'swagger', 'openapi']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="API endpoint method detected",
                            description="Found Spring REST API endpoint",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure API endpoint is documented and provides access to authorization data."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)|@RestController|@Api|swagger', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="API endpoint detected",
                    description="Found Spring REST API annotation",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify documented programmatic access to authorization data."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-TC-03 compliance using AST.
        
        Detects programmatic access in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function declarations for API routes
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['app.get', 'app.post', 'router.get', 'router.post', '@get(', '@post(', 'swagger']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="API endpoint function detected",
                            description="Found API route handler",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure API endpoint is documented and provides access to authorization data."
                        ))
                
                # Check arrow functions for route handlers
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['app.get', 'app.post', 'router', 'api']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="API route handler detected",
                            description="Found arrow function route handler",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify documented programmatic access."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:app|router)\.(?:get|post|put|delete)|@(?:Get|Post)\(|swagger|openapi', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="API endpoint detected",
                    description="Found API route pattern",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify documented programmatic access to authorization data."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-TC-03 compliance.
        
        NOT APPLICABLE: Programmatic access (API endpoints and documentation) is an
        application-level feature, not an infrastructure configuration. The requirement
        mandates that trust centers provide documented programmatic access to authorization
        data, which is implemented through:
        
        1. Application code (REST APIs, GraphQL endpoints)
        2. API documentation tools (Swagger/OpenAPI, API specifications)
        3. API gateway configuration (which could be in IaC, but the documentation
           requirement is application-level)
        4. Authentication/authorization for API access (implemented in app code)
        
        While API Management resources could be deployed via Bicep, the core requirement
        of providing and documenting API access is an application design concern.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-TC-03 compliance.
        
        NOT APPLICABLE: Programmatic access (API endpoints and documentation) is an
        application-level feature, not an infrastructure configuration. The requirement
        mandates that trust centers provide documented programmatic access to authorization
        data, which is implemented through:
        
        1. Application code (REST APIs, GraphQL endpoints)
        2. API documentation tools (Swagger/OpenAPI, API specifications)
        3. API gateway configuration (which could be in IaC, but the documentation
           requirement is application-level)
        4. Authentication/authorization for API access (implemented in app code)
        
        While API Gateway resources could be deployed via Terraform, the core requirement
        of providing and documenting API access is an application design concern.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-TC-03 compliance.
        
        NOT APPLICABLE: Programmatic access (API endpoints and documentation) is an
        application feature requirement, not a CI/CD pipeline concern. The requirement
        mandates that the trust center application provides documented API access, which
        is an application design decision, not a build or deployment automation concern.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-TC-03 compliance.
        
        NOT APPLICABLE: Programmatic access (API endpoints and documentation) is an
        application feature requirement, not a CI/CD pipeline concern. The requirement
        mandates that the trust center application provides documented API access, which
        is an application design decision, not a build or deployment automation concern.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-TC-03 compliance.
        
        NOT APPLICABLE: Programmatic access (API endpoints and documentation) is an
        application feature requirement, not a CI/CD pipeline concern. The requirement
        mandates that the trust center application provides documented API access, which
        is an application design decision, not a build or deployment automation concern.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-TC-03.
        
        Partially code-detectable (can find API endpoints), requires documentation review.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Medium - can detect API endpoints but requires documentation verification',
            'automation_approach': 'Hybrid - automated endpoint detection + manual documentation review',
            'recommended_services': [
                'Azure API Management - Centralized API gateway with built-in documentation portal',
                'Azure App Service - Host trust center API with automatic Swagger generation',
                'Azure Functions - Serverless API endpoints with OpenAPI extension',
                'Azure Front Door - Global API routing and protection',
                'Azure AD B2C - Programmatic access authentication and authorization',
            ],
            'collection_methods': [
                'Code review of API endpoint definitions',
                'API documentation portal review (Swagger UI, ReDoc)',
                'API specification file review (OpenAPI/Swagger JSON/YAML)',
                'API authentication testing (verify programmatic access works)',
                'API endpoint accessibility testing from external systems',
                'Rate limiting and throttling verification',
            ],
            'implementation_steps': [
                '1. Implement REST API endpoints for all authorization data',
                '2. Generate API documentation using Swagger/OpenAPI',
                '3. Deploy API documentation portal (Swagger UI)',
                '4. Implement API authentication (API keys, OAuth2, JWT)',
                '5. Configure CORS for cross-origin programmatic access',
                '6. Test API accessibility from external systems',
                '7. Document API endpoints in trust center documentation',
                '8. Monitor API usage and access logs',
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get automated queries for collecting evidence of FRR-ADS-TC-03 compliance.
        
        Returns queries for verifying programmatic access.
        """
        return [
            {
                'query_name': 'API Requests to Trust Center',
                'query_type': 'KQL',
                'query': '''AppRequests
| where Url contains "/api/" and (Url contains "trust-center" or Url contains "authorization-data")
| summarize RequestCount = count(), UniqueClients = dcount(ClientIP) by bin(TimeGenerated, 1d), Url
| order by TimeGenerated desc''',
                'data_source': 'Application Insights',
                'evidence_type': 'API usage logs showing programmatic access to authorization data',
            },
            {
                'query_name': 'API Management Gateway Logs',
                'query_type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceType == "APIMANAGEMENT"
| where Category == "GatewayLogs"
| where url_s contains "authorization" or url_s contains "trust-center"
| summarize RequestCount = count() by bin(TimeGenerated, 1h), url_s, responseCode_d
| order by TimeGenerated desc''',
                'data_source': 'Azure API Management Logs',
                'evidence_type': 'API Management gateway logs showing API access patterns',
            },
            {
                'query_name': 'API Documentation Accessibility',
                'query_type': 'Manual',
                'query': 'Access trust center Swagger/OpenAPI documentation portal and verify all authorization data endpoints are documented',
                'data_source': 'Swagger UI / API documentation portal',
                'evidence_type': 'Screenshot of API documentation showing all endpoints',
            },
            {
                'query_name': 'OpenAPI Specification Review',
                'query_type': 'Manual',
                'query': 'Review OpenAPI/Swagger JSON/YAML file to confirm all authorization data endpoints are specified',
                'data_source': 'OpenAPI specification file (swagger.json, openapi.yaml)',
                'evidence_type': 'OpenAPI specification file showing endpoint definitions',
            },
            {
                'query_name': 'Programmatic Access Testing',
                'query_type': 'Manual',
                'query': 'Test API endpoints programmatically using curl, Postman, or API client to verify access works',
                'data_source': 'API testing tool (curl, Postman, REST client)',
                'evidence_type': 'API test results showing successful programmatic access',
            },
            {
                'query_name': 'API Authentication Methods',
                'query_type': 'Manual',
                'query': 'Document authentication methods available for programmatic access (API keys, OAuth2, JWT)',
                'data_source': 'API authentication documentation',
                'evidence_type': 'Documentation of API authentication mechanisms',
            },
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts for FRR-ADS-TC-03 compliance.
        
        Returns specific documents needed to demonstrate programmatic access.
        """
        return [
            'OpenAPI/Swagger specification file (swagger.json or openapi.yaml)',
            'API documentation portal screenshots (Swagger UI, ReDoc)',
            'API endpoint inventory listing all authorization data endpoints',
            'API authentication documentation (API keys, OAuth2, JWT setup)',
            'API usage logs showing programmatic access requests',
            'API testing results (Postman collections, curl commands, responses)',
            'API client code examples (Python, JavaScript, C#, Java)',
            'API rate limiting and throttling documentation',
            'CORS configuration showing cross-origin programmatic access allowed',
            'API gateway configuration (Azure API Management, AWS API Gateway)',
        ]
