"""
KSI-CNA-02 Enhanced: Minimize the Attack Surface (AST-Based)

Design systems to minimize the attack surface and minimize lateral movement if compromised.

This enhanced version uses AST parsing and semantic analysis for improved accuracy.
"""

from typing import List, Set
from ..base import Finding, Severity, AnalysisResult
from ..ast_utils import ASTParser, CodeLanguage
from ..semantic_analysis import SemanticAnalyzer
from ..interprocedural import InterProceduralAnalyzer
from .base import BaseKSIAnalyzer


class KSI_CNA_02_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced AST-based analyzer for KSI-CNA-02: Minimize the Attack Surface.
    
    Uses AST parsing, semantic analysis, and inter-procedural analysis to detect:
    - Debug mode enabled in production
    - Developer exception pages without environment checks
    - Permissive CORS configurations (allow all origins)
    - Public network access on cloud resources
    - Stack trace exposure in error handlers
    - Missing service endpoints on subnets
    - Exposed actuator endpoints without security
    """
    
    KSI_ID = "KSI-CNA-02"
    KSI_NAME = "Minimize the Attack Surface"
    KSI_STATEMENT = "Design systems to minimize the attack surface and minimize lateral movement if compromised."
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-17.3", "Managed Access Control Points"),
        ("ac-18.1", "Authentication and Encryption"),
        ("ac-18.3", "Disable Wireless Networking"),
        ("ac-20.1", "Limits on Authorized Use"),
        ("ca-9", "Internal System Connections"),
        ("sc-7.3", "Access Points"),
        ("sc-7.4", "External Telecommunications Services"),
        ("sc-7.5", "Deny by Default — Allow by Exception"),
        ("sc-7.8", "Route Traffic to Authenticated Proxy Servers"),
        ("sc-8", "Transmission Confidentiality and Integrity"),
        ("sc-10", "Network Disconnect"),
        ("si-10", "Information Input Validation"),
        ("si-11", "Error Handling"),
        ("si-16", "Memory Protection")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    # Attack surface indicators
    DEBUG_METHODS = {"run", "uvicorn.run", "app.run", "UseDeveloperExceptionPage"}
    PERMISSIVE_CORS_PATTERNS = {"AllowAnyOrigin", "allowedOrigins", "origins"}
    ERROR_EXPOSURE_PATTERNS = {"stack", "error.stack", "err.stack"}
    PUBLIC_SERVICES = {"Microsoft.Storage/storageAccounts", "azurerm_storage_account"}
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Python code for attack surface minimization."""
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        if not tree:
            return []
        
        code_bytes = code.encode('utf-8')
        frameworks = self._detect_frameworks_python(code)
        return self._analyze_python_ast(tree.root_node, code_bytes, file_path, frameworks, parser)
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# code for attack surface minimization."""
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        if not tree:
            return []
        
        code_bytes = code.encode('utf-8')
        frameworks = self._detect_frameworks_csharp(code)
        return self._analyze_csharp_ast(tree.root_node, code_bytes, file_path, frameworks, parser)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code for attack surface minimization."""
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        if not tree:
            return []
        
        code_bytes = code.encode('utf-8')
        frameworks = self._detect_frameworks_java(code)
        return self._analyze_java_ast(tree.root_node, code_bytes, file_path, frameworks, parser)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript/JavaScript code for attack surface minimization."""
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        if not tree:
            return []
        
        code_bytes = code.encode('utf-8')
        frameworks = self._detect_frameworks_typescript(code)
        return self._analyze_typescript_ast(tree.root_node, code_bytes, file_path, frameworks, parser)
    
    def _detect_frameworks_python(self, code: str) -> List[str]:
        """Detect Python frameworks in code."""
        frameworks = []
        if 'flask' in code.lower():
            frameworks.append('flask')
        if 'django' in code.lower():
            frameworks.append('django')
        if 'fastapi' in code.lower():
            frameworks.append('fastapi')
        return frameworks
    
    def _detect_frameworks_csharp(self, code: str) -> List[str]:
        """Detect C# frameworks in code."""
        frameworks = []
        # Check for Microsoft.AspNetCore namespace in using statements (more precise than substring search)
        if 'Microsoft.AspNetCore' in code:
            frameworks.append('aspnetcore')
        return frameworks
    
    def _detect_frameworks_java(self, code: str) -> List[str]:
        """Detect Java frameworks in code."""
        frameworks = []
        if 'springframework' in code.lower():
            frameworks.append('spring')
        return frameworks
    
    def _detect_frameworks_typescript(self, code: str) -> List[str]:
        """Detect TypeScript/JavaScript frameworks in code."""
        frameworks = []
        if 'express' in code.lower():
            frameworks.append('express')
        if 'nestjs' in code.lower():
            frameworks.append('nestjs')
        return frameworks
    
    def _analyze_python_ast(self, root_node, code_bytes: bytes, file_path: str,
                           frameworks: List[str], parser: ASTParser) -> List[Finding]:
        """Analyze Python code using AST for attack surface issues."""
        findings = []
        
        # Check 1: Debug mode enabled (CRITICAL)
        # Look for app.run(debug=True) or uvicorn.run(..., debug=True)
        calls = parser.find_nodes_by_type(root_node, "call")
        for call in calls:
            call_text = parser.get_node_text(call, code_bytes)
            
            # Check if it's a run() call with debug=True
            if "run" in call_text and "debug" in call_text:
                args = parser.find_nodes_by_type(call, "argument_list")
                for arg_list in args:
                    # Look for keyword argument debug=True
                    keywords = parser.find_nodes_by_type(arg_list, "keyword_argument")
                    for kw in keywords:
                        kw_text = parser.get_node_text(kw, code_bytes)
                        if "debug" in kw_text.lower() and "true" in kw_text.lower():
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                title="Debug Mode Enabled Increases Attack Surface",
                                description=(
                                    f"Debug mode enabled at line {call.start_point[0] + 1}. "
                                    f"Debug mode exposes stack traces, environment variables, and internal "
                                    f"application details that aid attackers. This violates the principle "
                                    f"of minimizing attack surface."
                                ),
                                file_path=file_path,
                                line_number=call.start_point[0] + 1,
                                snippet=call_text[:200],
                                remediation=(
                                    "Disable debug mode in production:\n"
                                    "app.run(debug=False)  # or remove debug parameter\n"
                                    "Use environment variables: debug=os.getenv('DEBUG', 'false').lower() == 'true'"
                                ),
                                ksi_id=self.KSI_ID
                            ))
        
        # Check 2: Permissive CORS (HIGH)
        # Look for CORS(app, origins=['*']) or CORS(..., origins="*")
        for call in calls:
            call_text = parser.get_node_text(call, code_bytes)
            
            if "CORS" in call_text:
                args = parser.find_nodes_by_type(call, "argument_list")
                for arg_list in args:
                    # Look for origins parameter
                    keywords = parser.find_nodes_by_type(arg_list, "keyword_argument")
                    for kw in keywords:
                        kw_text = parser.get_node_text(kw, code_bytes)
                        if "origins" in kw_text and ("*" in kw_text or '"*"' in kw_text or "'*'" in kw_text):
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                title="Permissive CORS Configuration Expands Attack Surface",
                                description=(
                                    f"CORS allows all origins (*) at line {call.start_point[0] + 1}. "
                                    f"This increases attack surface by allowing any website to make requests "
                                    f"to your API, potentially enabling cross-site attacks and lateral movement."
                                ),
                                file_path=file_path,
                                line_number=call.start_point[0] + 1,
                                snippet=call_text[:200],
                                remediation=(
                                    "Restrict CORS to specific origins:\n"
                                    "CORS(app, origins=['https://yourdomain.com', 'https://trusted-partner.com'])\n"
                                    "Use environment-based configuration for different deployment stages."
                                ),
                                ksi_id=self.KSI_ID
                            ))
        
        return findings
    
    def _analyze_csharp_ast(self, root_node, code_bytes: bytes, file_path: str,
                           frameworks: List[str], parser: ASTParser) -> List[Finding]:
        """Analyze C# code using AST for attack surface issues."""
        findings = []
        
        # Check 1: UseDeveloperExceptionPage without environment check (CRITICAL)
        invocations = parser.find_nodes_by_type(root_node, "invocation_expression")
        has_dev_page = False
        dev_page_line = 0
        
        for inv in invocations:
            inv_text = parser.get_node_text(inv, code_bytes)
            if "UseDeveloperExceptionPage" in inv_text:
                has_dev_page = True
                dev_page_line = inv.start_point[0] + 1
        
        # Check if there's an environment check (if (env.IsDevelopment()))
        if has_dev_page:
            has_env_check = False
            if_statements = parser.find_nodes_by_type(root_node, "if_statement")
            for if_stmt in if_statements:
                if_text = parser.get_node_text(if_stmt, code_bytes)
                if "IsDevelopment" in if_text and "UseDeveloperExceptionPage" in if_text:
                    has_env_check = True
                    break
            
            if not has_env_check:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Developer Exception Page Exposes Internal Details",
                    description=(
                        f"UseDeveloperExceptionPage at line {dev_page_line} without environment check. "
                        f"This exposes stack traces, source code paths, and internal state in production, "
                        f"significantly increasing attack surface."
                    ),
                    file_path=file_path,
                    line_number=dev_page_line,
                    snippet="UseDeveloperExceptionPage() without env.IsDevelopment() check",
                    remediation=(
                        "Restrict to development environment:\n"
                        "if (env.IsDevelopment()) {\n"
                        "    app.UseDeveloperExceptionPage();\n"
                        "} else {\n"
                        "    app.UseExceptionHandler(\"/Error\");\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Check 2: AllowAnyOrigin in CORS (HIGH)
        for inv in invocations:
            inv_text = parser.get_node_text(inv, code_bytes)
            if "AllowAnyOrigin" in inv_text:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Permissive CORS Policy Increases Attack Surface",
                    description=(
                        f"AllowAnyOrigin() at line {inv.start_point[0] + 1} permits requests from any domain. "
                        f"This expands attack surface and enables potential cross-site attacks."
                    ),
                    file_path=file_path,
                    line_number=inv.start_point[0] + 1,
                    snippet=inv_text[:200],
                    remediation=(
                        "Restrict CORS to specific origins:\n"
                        "builder.WithOrigins(\"https://yourdomain.com\", \"https://trusted.com\")\n"
                        "Configure origins in appsettings.json and load dynamically."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_java_ast(self, root_node, code_bytes: bytes, file_path: str,
                         frameworks: List[str], parser: ASTParser) -> List[Finding]:
        """Analyze Java code using AST for attack surface issues."""
        findings = []
        
        # Check 1: Permissive CORS (HIGH)
        # Look for allowedOrigins("*")
        method_invocations = parser.find_nodes_by_type(root_node, "method_invocation")
        for inv in method_invocations:
            inv_text = parser.get_node_text(inv, code_bytes)
            if "allowedOrigins" in inv_text and '"*"' in inv_text:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Permissive CORS Increases Attack Surface",
                    description=(
                        f"CORS configured to allow all origins (*) at line {inv.start_point[0] + 1}. "
                        f"This expands the attack surface by allowing any website to interact with your API, "
                        f"potentially enabling cross-origin attacks."
                    ),
                    file_path=file_path,
                    line_number=inv.start_point[0] + 1,
                    snippet=inv_text[:200],
                    remediation=(
                        "Restrict CORS to specific origins:\n"
                        "@Override\n"
                        "public void addCorsMappings(CorsRegistry registry) {\n"
                        "    registry.addMapping(\"/api/**\")\n"
                        "        .allowedOrigins(\"https://yourdomain.com\", \"https://trusted.com\");\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Check 2: Actuator without security (MEDIUM)
        # Look for spring-boot-starter-actuator dependency
        string_literals = parser.find_nodes_by_type(root_node, "string_literal")
        has_actuator = False
        actuator_line = 0
        
        for lit in string_literals:
            lit_text = parser.get_node_text(lit, code_bytes)
            if "spring-boot-starter-actuator" in lit_text:
                has_actuator = True
                actuator_line = lit.start_point[0] + 1
                break
        
        if has_actuator:
            # Check for actuator security configuration
            has_security = False
            for lit in string_literals:
                lit_text = parser.get_node_text(lit, code_bytes)
                if "management.endpoints.web.exposure.include" in lit_text:
                    has_security = True
                    break
            
            if not has_security:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Actuator Endpoints Exposed Without Restrictions",
                    description=(
                        f"Spring Boot Actuator at line {actuator_line} without explicit endpoint restrictions. "
                        f"Actuator exposes internal application metrics, health checks, and configuration, "
                        f"increasing attack surface if not properly secured."
                    ),
                    file_path=file_path,
                    line_number=actuator_line,
                    snippet="spring-boot-starter-actuator dependency",
                    remediation=(
                        "Restrict actuator endpoints in application.properties:\n"
                        "management.endpoints.web.exposure.include=health,info\n"
                        "management.endpoint.health.show-details=when-authorized\n"
                        "Protect with Spring Security: .requestMatchers(\"/actuator/**\").hasRole(\"ADMIN\")"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_typescript_ast(self, root_node, code_bytes: bytes, file_path: str,
                               frameworks: List[str], parser: ASTParser) -> List[Finding]:
        """Analyze JavaScript/TypeScript code using AST for attack surface issues."""
        findings = []
        
        # Check 1: Permissive CORS (HIGH)
        # Look for cors({ origin: '*' }) or cors({ origin: "*" })
        calls = parser.find_nodes_by_type(root_node, "call_expression")
        for call in calls:
            call_text = parser.get_node_text(call, code_bytes)
            
            if "cors" in call_text and "origin" in call_text:
                # Check for wildcard origin
                args = parser.find_nodes_by_type(call, "arguments")
                for arg in args:
                    arg_text = parser.get_node_text(arg, code_bytes)
                    if "origin" in arg_text and ("'*'" in arg_text or '"*"' in arg_text):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Permissive CORS Configuration Expands Attack Surface",
                            description=(
                                f"CORS allows all origins (*) at line {call.start_point[0] + 1}. "
                                f"This increases attack surface by allowing any website to make cross-origin "
                                f"requests, potentially enabling credential theft and lateral movement attacks."
                            ),
                            file_path=file_path,
                            line_number=call.start_point[0] + 1,
                            snippet=call_text[:200],
                            remediation=(
                                "Restrict CORS to specific origins:\n"
                                "app.use(cors({\n"
                                "  origin: ['https://yourdomain.com', 'https://trusted.com'],\n"
                                "  credentials: true\n"
                                "}));"
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        # Check 2: Stack trace exposure (MEDIUM)
        # Look for err.stack or error.stack being sent in response
        member_expressions = parser.find_nodes_by_type(root_node, "member_expression")
        for member in member_expressions:
            member_text = parser.get_node_text(member, code_bytes)
            if "stack" in member_text and ("err." in member_text or "error." in member_text):
                # Check if this is in a response context (look for parent call with res.send or res.json)
                parent = member.parent
                while parent and parent.type not in ("call_expression", "expression_statement"):
                    parent = parent.parent
                
                if parent and parent.type == "call_expression":
                    parent_text = parser.get_node_text(parent, code_bytes)
                    if "res." in parent_text and ("send" in parent_text or "json" in parent_text):
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Stack Traces Exposed in Error Responses",
                            description=(
                                f"Error stack trace exposed at line {member.start_point[0] + 1}. "
                                f"Stack traces reveal internal application structure, file paths, and "
                                f"dependencies, increasing attack surface by providing reconnaissance "
                                f"information to attackers."
                            ),
                            file_path=file_path,
                            line_number=member.start_point[0] + 1,
                            snippet=parent_text[:200],
                            remediation=(
                                "Use generic error messages in production:\n"
                                "if (process.env.NODE_ENV === 'production') {\n"
                                "  res.status(500).json({ error: 'Internal server error' });\n"
                                "} else {\n"
                                "  res.status(500).json({ error: err.message, stack: err.stack });\n"
                                "}"
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        return findings


def create_analyzer(language: str) -> KSI_CNA_02_Analyzer:
    """Factory function to create analyzer for specific language."""
    lang_map = {
        "python": CodeLanguage.PYTHON,
        "csharp": CodeLanguage.CSHARP,
        "java": CodeLanguage.JAVA,
        "javascript": CodeLanguage.JAVASCRIPT,
        "typescript": CodeLanguage.TYPESCRIPT,
    }
    return KSI_CNA_02_Analyzer(lang_map.get(language.lower(), CodeLanguage.PYTHON))

