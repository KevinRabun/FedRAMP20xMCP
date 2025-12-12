"""
FRR-ADS-AC-01: Public Guidance

Providers MUST publicly provide plain-language policies and guidance for all necessary parties that explains how they can obtain and manage access to _authorization data_ stored in the _trust center_.

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


class FRR_ADS_AC_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-AC-01: Public Guidance
    
    **Official Statement:**
    Providers MUST publicly provide plain-language policies and guidance for all necessary parties that explains how they can obtain and manage access to _authorization data_ stored in the _trust center_.
    
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
    
    FRR_ID = "FRR-ADS-AC-01"
    FRR_NAME = "Public Guidance"
    FRR_STATEMENT = """Providers MUST publicly provide plain-language policies and guidance for all necessary parties that explains how they can obtain and manage access to _authorization data_ stored in the _trust center_."""
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
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-AC-01 analyzer."""
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
        Analyze Python code for FRR-ADS-AC-01 compliance using AST.
        
        Detects public guidance and documentation mechanisms:
        - Public documentation endpoints (Flask, FastAPI routes)
        - Access policy documentation functions
        - Plain-language guidance systems
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect Flask/FastAPI routes for documentation
                route_decorators = parser.find_nodes_by_type(tree.root_node, 'decorator')
                for decorator in route_decorators:
                    decorator_text = parser.get_node_text(decorator, code_bytes)
                    if any(pattern in decorator_text.lower() for pattern in ['@app.route', '@router.get', '/docs', '/help', '/guide', '/policy']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public documentation endpoint detected",
                            description=f"Found public documentation route: {decorator_text}",
                            severity=Severity.INFO,
                            line_number=decorator.start_point[0] + 1,
                            code_snippet=decorator_text,
                            recommendation="Ensure endpoint provides plain-language guidance for accessing authorization data in trust center."
                        ))
                
                # Detect function definitions for guidance/documentation
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in function_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_name_lower = func_text.lower()
                    if any(keyword in func_name_lower for keyword in ['guidance', 'documentation', 'help', 'policy', 'access_instructions']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public guidance function detected",
                            description=f"Found guidance/documentation function",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify function provides plain-language guidance for authorization data access."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        guidance_patterns = [
            r'public.*guidance',
            r'access.*policy.*public',
            r'documentation.*endpoint',
            r'/docs',
            r'/help',
            r'/guide',
            r'plain.*language',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in guidance_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Public guidance pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure plain-language guidance provided for trust center access."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-AC-01 compliance using AST.
        
        Detects public guidance mechanisms in ASP.NET:
        - Controller actions for documentation
        - Public API endpoints for help/guidance
        - Plain-language policy methods
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect HTTP route attributes
                attributes = parser.find_nodes_by_type(tree.root_node, 'attribute')
                for attr in attributes:
                    attr_text = parser.get_node_text(attr, code_bytes)
                    if any(pattern in attr_text.lower() for pattern in ['[httpget', '[route', '/docs', '/help', '/guide', '/policy']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public documentation endpoint detected",
                            description=f"Found documentation route: {attr_text}",
                            severity=Severity.INFO,
                            line_number=attr.start_point[0] + 1,
                            code_snippet=attr_text,
                            recommendation="Ensure endpoint provides plain-language guidance for trust center access."
                        ))
                
                # Detect method declarations for guidance
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    if any(keyword in method_text.lower() for keyword in ['guidance', 'documentation', 'help', 'policy']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public guidance method detected",
                            description="Found guidance/documentation method",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify method provides plain-language authorization data access guidance."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'\[HttpGet\(.*(?:docs|help|guide|policy)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Documentation endpoint detected",
                    description="Found HTTP GET endpoint for documentation",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure plain-language guidance for trust center access."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-AC-01 compliance using AST.
        
        Detects public guidance mechanisms in Spring Boot:
        - @GetMapping/@RequestMapping for documentation endpoints
        - Public API methods for help/guidance
        - Plain-language policy methods
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect Spring annotations for routes
                annotations = parser.find_nodes_by_type(tree.root_node, 'annotation')
                for annotation in annotations:
                    annotation_text = parser.get_node_text(annotation, code_bytes)
                    if any(pattern in annotation_text.lower() for pattern in ['@getmapping', '@requestmapping', '/docs', '/help', '/guide', '/policy']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public documentation endpoint detected",
                            description=f"Found documentation route: {annotation_text}",
                            severity=Severity.INFO,
                            line_number=annotation.start_point[0] + 1,
                            code_snippet=annotation_text,
                            recommendation="Ensure endpoint provides plain-language guidance for trust center access."
                        ))
                
                # Detect method declarations for guidance
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    if any(keyword in method_text.lower() for keyword in ['guidance', 'documentation', 'help', 'policy']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public guidance method detected",
                            description="Found guidance/documentation method",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify method provides plain-language authorization data access guidance."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'@(?:Get|Request)Mapping.*(?:docs|help|guide|policy)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Documentation endpoint detected",
                    description="Found Spring mapping for documentation",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure plain-language guidance for trust center access."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-AC-01 compliance using AST.
        
        Detects public guidance mechanisms in Express/NestJS:
        - API route definitions for documentation
        - Public endpoints for help/guidance
        - Plain-language policy functions
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect Express/NestJS route definitions
                call_expressions = parser.find_nodes_by_type(tree.root_node, 'call_expression')
                for call_expr in call_expressions:
                    call_text = parser.get_node_text(call_expr, code_bytes)
                    if any(pattern in call_text.lower() for pattern in ['app.get', 'router.get', '/docs', '/help', '/guide', '/policy']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public documentation endpoint detected",
                            description=f"Found documentation route",
                            severity=Severity.INFO,
                            line_number=call_expr.start_point[0] + 1,
                            code_snippet=call_text.split('\n')[0],
                            recommendation="Ensure endpoint provides plain-language guidance for trust center access."
                        ))
                
                # Detect decorator definitions (NestJS)
                decorators = parser.find_nodes_by_type(tree.root_node, 'decorator')
                for decorator in decorators:
                    decorator_text = parser.get_node_text(decorator, code_bytes)
                    if any(pattern in decorator_text.lower() for pattern in ['@get', '@controller', '/docs', '/help', '/guide']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Documentation endpoint detected",
                            description=f"Found NestJS route decorator",
                            severity=Severity.INFO,
                            line_number=decorator.start_point[0] + 1,
                            code_snippet=decorator_text,
                            recommendation="Verify plain-language guidance provided for authorization data access."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:app|router)\.get\(.*(?:docs|help|guide|policy)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Documentation endpoint detected",
                    description="Found Express/NestJS documentation route",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure plain-language guidance for trust center access."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-AC-01 compliance.
        
        NOT APPLICABLE: Public guidance provision is a documentation and web content
        requirement, not an infrastructure configuration requirement. The requirement
        mandates publicly available plain-language policies and guidance documents,
        which are delivered through web applications or documentation systems,
        not through Azure infrastructure definitions.
        
        Infrastructure may host the documentation (e.g., Azure Static Web Apps,
        Azure App Service), but the actual guidance content and its public
        availability are managed at the application and content management level.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-AC-01 compliance.
        
        NOT APPLICABLE: Public guidance provision is a documentation and web content
        requirement, not an infrastructure configuration requirement. The requirement
        mandates publicly available plain-language policies and guidance documents,
        which are delivered through web applications or documentation systems,
        not through cloud infrastructure definitions.
        
        Infrastructure may host the documentation (e.g., AWS S3 static sites,
        CloudFront), but the actual guidance content and its public availability
        are managed at the application and content management level.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-AC-01 compliance.
        
        NOT APPLICABLE: Public guidance provision is a documentation and web content
        requirement, not a CI/CD pipeline requirement. The requirement mandates
        publicly available plain-language policies and guidance, which are content
        and accessibility concerns rather than build/deployment pipeline concerns.
        
        CI/CD pipelines may deploy documentation sites, but the actual guidance
        content, its plain-language nature, and public availability are managed
        at the application/content level, not in the deployment automation.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-AC-01 compliance.
        
        NOT APPLICABLE: Public guidance provision is a documentation and web content
        requirement, not a CI/CD pipeline requirement. The requirement mandates
        publicly available plain-language policies and guidance, which are content
        and accessibility concerns rather than build/deployment pipeline concerns.
        
        CI/CD pipelines may deploy documentation sites, but the actual guidance
        content, its plain-language nature, and public availability are managed
        at the application/content level, not in the deployment automation.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-AC-01 compliance.
        
        NOT APPLICABLE: Public guidance provision is a documentation and web content
        requirement, not a CI/CD pipeline requirement. The requirement mandates
        publicly available plain-language policies and guidance, which are content
        and accessibility concerns rather than build/deployment pipeline concerns.
        
        CI/CD pipelines may deploy documentation sites, but the actual guidance
        content, its plain-language nature, and public availability are managed
        at the application/content level, not in the deployment automation.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-AC-01.
        
        This requirement is partially code-detectable (endpoints/routes can be detected).
        Complete validation requires documentation review.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Medium - can detect documentation endpoints, but content quality requires manual review',
            'automation_approach': 'Hybrid - automated endpoint detection + manual documentation review',
            'recommended_services': [
                'Azure Static Web Apps - Host public documentation and guidance',
                'Azure App Service - Deploy web applications with documentation endpoints',
                'Azure Content Delivery Network (CDN) - Global distribution of documentation',
                'Azure API Management - Document APIs with plain-language guidance',
                'Azure Monitor Application Insights - Track documentation access patterns',
            ],
            'collection_methods': [
                'Web application scanning for documentation endpoints',
                'API route enumeration and documentation detection',
                'Content accessibility testing (plain language, public access)',
                'Trust center portal review',
                'User access log analysis',
                'Documentation version control review',
            ],
            'implementation_steps': [
                '1. Create public documentation portal with plain-language access guides',
                '2. Implement /docs, /help, or /guide endpoints in web applications',
                '3. Publish policies for obtaining and managing authorization data access',
                '4. Ensure documentation is publicly accessible (no authentication required)',
                '5. Use clear, plain-language (non-technical) explanations',
                '6. Include step-by-step instructions for all necessary parties',
                '7. Implement analytics to track documentation usage and effectiveness',
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get automated queries for collecting evidence of FRR-ADS-AC-01 compliance.
        
        Returns KQL queries and API calls for Azure services.
        """
        return [
            {
                'query_name': 'Public Documentation Access Logs',
                'query_type': 'KQL',
                'query': '''AppRequests
| where Url contains "/docs" or Url contains "/help" or Url contains "/guide" or Url contains "/policy"
| where ResultCode == "200"
| summarize AccessCount = count(), UniqueUsers = dcount(ClientIP) by Url, bin(TimeGenerated, 1d)
| order by TimeGenerated desc''',
                'data_source': 'Azure Application Insights',
                'evidence_type': 'Public documentation endpoint access patterns',
            },
            {
                'query_name': 'Static Web App Content Deployment',
                'query_type': 'Azure CLI',
                'query': 'az staticwebapp show --name <webapp-name> --resource-group <rg-name> --query "{name:name, defaultHostname:defaultHostname, customDomains:customDomains}"',
                'data_source': 'Azure Static Web Apps',
                'evidence_type': 'Public documentation hosting configuration',
            },
            {
                'query_name': 'CDN Endpoint Configuration',
                'query_type': 'Azure CLI',
                'query': 'az cdn endpoint list --profile-name <profile-name> --resource-group <rg-name> --query "[].{name:name, hostName:hostName, isHttpAllowed:isHttpAllowed, isHttpsAllowed:isHttpsAllowed}"',
                'data_source': 'Azure CDN',
                'evidence_type': 'Global documentation distribution configuration',
            },
            {
                'query_name': 'API Management Documentation Access',
                'query_type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceType == "APIMANAGEMENT"
| where OperationName == "Microsoft.ApiManagement/GatewayLogs"
| where url_s contains "/docs" or url_s contains "/api-docs" or url_s contains "/swagger"
| summarize AccessCount = count() by url_s, bin(TimeGenerated, 1h)
| order by TimeGenerated desc''',
                'data_source': 'Azure API Management',
                'evidence_type': 'API documentation access logs',
            },
            {
                'query_name': 'App Service Deployment Logs',
                'query_type': 'KQL',
                'query': '''AppServiceConsoleLogs
| where ResultDescription contains "documentation" or ResultDescription contains "guidance"
| project TimeGenerated, ResultDescription, Level
| order by TimeGenerated desc
| take 100''',
                'data_source': 'Azure App Service',
                'evidence_type': 'Documentation deployment and update logs',
            },
            {
                'query_name': 'Public Endpoint Anonymous Access Verification',
                'query_type': 'KQL',
                'query': '''AppRequests
| where Url contains "/docs" or Url contains "/help" or Url contains "/guide"
| where ResultCode == "401" or ResultCode == "403"
| summarize BlockedAccessCount = count() by Url, ResultCode, bin(TimeGenerated, 1d)
| order by TimeGenerated desc''',
                'data_source': 'Azure Application Insights',
                'evidence_type': 'Authentication failures on documentation endpoints (should be zero for public docs)',
            },
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts that should be collected for FRR-ADS-AC-01.
        
        Returns specific documents and exports needed to demonstrate compliance.
        """
        return [
            'Public documentation portal screenshot showing plain-language guidance for trust center access',
            'URL and accessibility report for public documentation (no authentication required)',
            'Plain-language access policy document (PDF or HTML) for authorization data',
            'Step-by-step guide for necessary parties to obtain and manage trust center access',
            'Documentation analytics report showing public access patterns and usage',
            'Content readability analysis report (Flesch Reading Ease, grade level)',
            'Trust center integration documentation (APIs, access methods, authentication flows)',
            'User feedback or usability testing results for documentation clarity',
            'Documentation version control history (Git commits, change logs)',
            'Web application route configuration showing public documentation endpoints',
        ]
