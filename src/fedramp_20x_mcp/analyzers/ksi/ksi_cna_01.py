"""
KSI-CNA-01: Restrict Network Traffic

Configure all machine-based information resources to limit inbound and outbound network traffic.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_CNA_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CNA-01: Restrict Network Traffic
    
    **Official Statement:**
    Configure all machine-based information resources to limit inbound and outbound network traffic.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-17.3
    - ca-9
    - cm-7.1
    - sc-7.5
    - si-8
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Configure all machine-based information resources to limit inbound and outbound network traffic....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-01"
    KSI_NAME = "Restrict Network Traffic"
    KSI_STATEMENT = """Configure all machine-based information resources to limit inbound and outbound network traffic."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-17.3", "Managed Access Control Points"),
        ("ca-9", "Internal System Connections"),
        ("cm-7.1", "Periodic Review"),
        ("sc-7.5", "Deny by Default — Allow by Exception"),
        ("si-8", "Spam Protection")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-CNA-01 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Unrestricted socket binding (0.0.0.0)
        - Missing IP allowlist/restrictions
        - Open listening ports without filtering
        - Missing network security middleware
        """
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_python_ast(code, file_path, parser, tree)
        else:
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Python code."""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Pattern 1: Check function calls for unrestricted binding
        # Look for app.run(), uvicorn.run(), server.bind() with host='0.0.0.0'
        call_nodes = parser.find_nodes_by_type(tree.root_node, "call")
        
        for call_node in call_nodes:
            call_text = parser.get_node_text(call_node, code_bytes)
            
            # Check if this is a run/bind call with 0.0.0.0
            if any(method in call_text for method in ['app.run', 'uvicorn.run', 'server.bind', '.bind(']):
                if '0.0.0.0' in call_text or (('host' in call_text or 'bind' in call_text) and ('""' in call_text or "''" in call_text)):
                    line_num = code[:call_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Unrestricted Network Binding (0.0.0.0)",
                        description=(
                            f"Application binds to 0.0.0.0 at line {line_num}, accepting connections from all interfaces. "
                            f"FedRAMP requires restricting inbound and outbound network traffic. Consider binding to "
                            f"specific interfaces or using Azure network security groups to limit access."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=call_text[:200],
                        remediation=(
                            "Restrict network binding:\n"
                            "app.run(host='127.0.0.1')  # Localhost only\n"
                            "Or use Azure Application Gateway/Front Door with NSG rules to control traffic. "
                            "Implement IP allowlist middleware if public access is required."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Regex fallback for Python analysis when AST parsing fails.
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Unrestricted binding (HIGH)
        if re.search(r'(app\.run|uvicorn\.run|server\.bind)\s*\([^)]*host\s*=\s*["\']0\.0\.0\.0', code):
            result = self._find_line(lines, r'host\s*=\s*["\']0\.0\.0\.0')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Unrestricted Network Binding (0.0.0.0)",
                description=(
                    f"Application binds to 0.0.0.0 at line {line_num}, accepting connections from all interfaces. "
                    f"FedRAMP requires restricting inbound and outbound network traffic. Consider binding to "
                    f"specific interfaces or using Azure network security groups to limit access."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict network binding:\n"
                    "app.run(host='127.0.0.1')  # Localhost only\n"
                    "Or use Azure Application Gateway/Front Door with NSG rules to control traffic. "
                    "Implement IP allowlist middleware if public access is required."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Socket server without IP restrictions (HIGH)
        if re.search(r'socket\.socket\s*\(', code):
            has_bind_all = re.search(r'bind\s*\(\s*\(\s*["\']0\.0\.0\.0|bind\s*\(\s*\(\s*[""]["\']', code)
            if has_bind_all:
                result = self._find_line(lines, r'bind\s*\(', use_regex=True)

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Socket Server Without Network Restrictions",
                    description=(
                        f"Raw socket binding at line {line_num} without IP filtering. "
                        f"Direct socket programming requires explicit inbound/outbound traffic controls "
                        f"to comply with FedRAMP network security requirements."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Implement IP allowlist:\n"
                        "1. Bind to specific interface: sock.bind(('127.0.0.1', port))\n"
                        "2. Check client IP against allowlist before accepting connections\n"
                        "3. Use Azure NSG rules to restrict traffic at network layer"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-01 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Unrestricted Kestrel/ASP.NET endpoints
        - Missing IP filtering middleware
        - Open listening without allowlist
        - No network restriction configuration
        """
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for C# code."""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Pattern 1: Check for UseUrls with unrestricted binding
        invocation_nodes = parser.find_nodes_by_type(tree.root_node, "invocation_expression")
        
        for inv_node in invocation_nodes:
            inv_text = parser.get_node_text(inv_node, code_bytes)
            
            if "UseUrls" in inv_text and ("http://*:" in inv_text or "http://0.0.0.0" in inv_text):
                line_num = code[:inv_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Unrestricted Kestrel Endpoint Configuration",
                    description=(
                        f"Kestrel configured with unrestricted binding (http://*: or 0.0.0.0) at line {line_num}. "
                        f"FedRAMP requires limiting inbound network traffic. Use Azure Application Gateway with "
                        f"NSG rules or implement IP allowlist middleware."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=inv_text[:200],
                    remediation=(
                        "Restrict endpoint binding:\n"
                        "webBuilder.UseUrls(\"http://localhost:5000\");\n"
                        "Or deploy behind Azure Application Gateway with NSG restrictions. "
                        "Add IP filtering middleware: app.UseMiddleware<IPRestrictionMiddleware>();"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Check for web app without IP restriction middleware
        has_web_app = False
        has_ip_filter = False
        
        for inv_node in invocation_nodes:
            inv_text = parser.get_node_text(inv_node, code_bytes)
            if any(method in inv_text for method in ["WebApplication.Create", ".Run(", "UseRouting"]):
                has_web_app = True
            if any(term in inv_text for term in ["UseMiddleware", "IPRestriction", "UseIpRateLimiting"]):
                has_ip_filter = True
        
        # Also check for IP-related identifiers in the code
        if not has_ip_filter:
            if any(term in code for term in ["IPRestriction", "AllowedIPs", "ClientIpCheck", "UseIpRateLimiting"]):
                has_ip_filter = True
        
        if has_web_app and not has_ip_filter:
            # Find the line where web app is created/run
            for inv_node in invocation_nodes:
                inv_text = parser.get_node_text(inv_node, code_bytes)
                if "WebApplication.Create" in inv_text or ".Run(" in inv_text:
                    line_num = code[:inv_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Missing IP Restriction Middleware",
                        description=(
                            f"ASP.NET Core application at line {line_num} without IP filtering middleware. "
                            f"Application-level IP restrictions provide defense-in-depth alongside Azure NSG rules."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=inv_text[:200],
                        remediation=(
                            "Add IP restriction middleware:\n"
                            "app.UseMiddleware<IPRestrictionMiddleware>();\n"
                            "Configure allowed IPs in appsettings.json: \"AllowedIPs\": [\"10.0.0.0/8\", \"specific-ip\"]"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Regex fallback for C# analysis when AST parsing fails.
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Unrestricted Kestrel endpoint (HIGH)
        if re.search(r'UseUrls\s*\([^)]*http://\*:|UseUrls\s*\([^)]*http://0\.0\.0\.0', code, re.IGNORECASE):
            result = self._find_line(lines, r'UseUrls', use_regex=True)

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Unrestricted Kestrel Endpoint Configuration",
                description=(
                    f"Kestrel configured with unrestricted binding (http://*: or 0.0.0.0) at line {line_num}. "
                    f"FedRAMP requires limiting inbound network traffic. Use Azure Application Gateway with "
                    f"NSG rules or implement IP allowlist middleware."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict endpoint binding:\n"
                    "webBuilder.UseUrls(\"http://localhost:5000\");\n"
                    "Or deploy behind Azure Application Gateway with NSG restrictions. "
                    "Add IP filtering middleware: app.UseMiddleware<IPRestrictionMiddleware>();"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing IP restriction middleware (MEDIUM)
        has_web_app = re.search(r'(WebApplication\.Create|app\.Run|app\.UseRouting)', code, re.IGNORECASE)
        has_ip_filter = re.search(r'(IPRestriction|AllowedIPs|ClientIpCheck|UseIpRateLimiting)', code, re.IGNORECASE)
        
        if has_web_app and not has_ip_filter:
            result = self._find_line(lines, r'WebApplication\.Create|app\.Run', use_regex=True)

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing IP Restriction Middleware",
                description=(
                    f"ASP.NET Core application at line {line_num} without IP filtering middleware. "
                    f"Application-level IP restrictions provide defense-in-depth alongside Azure NSG rules."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add IP restriction middleware:\n"
                    "app.UseMiddleware<IPRestrictionMiddleware>();\n"
                    "Configure allowed IPs in appsettings.json: \"AllowedIPs\": [\"10.0.0.0/8\", \"specific-ip\"]"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-01 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Unrestricted ServerSocket binding
        - Missing Spring Security IP restrictions
        - Open listening ports without filtering
        - No network access control configuration
        """
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Java code."""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Pattern 1: Check for ServerSocket creation
        object_creation_nodes = parser.find_nodes_by_type(tree.root_node, "object_creation_expression")
        
        for obj_node in object_creation_nodes:
            obj_text = parser.get_node_text(obj_node, code_bytes)
            
            if "ServerSocket" in obj_text:
                # Check if only port argument (no IP specified) - binds to all interfaces
                if obj_text.count(',') == 0 and '(' in obj_text and ')' in obj_text:
                    line_num = code[:obj_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Unrestricted ServerSocket Binding",
                        description=(
                            f"ServerSocket at line {line_num} binds to all interfaces (no IP specified). "
                            f"FedRAMP requires restricting inbound network traffic. Bind to specific IP or "
                            f"implement IP filtering with Azure NSG rules."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=obj_text[:200],
                        remediation=(
                            "Restrict ServerSocket binding:\n"
                            "ServerSocket server = new ServerSocket(port, backlog, InetAddress.getLoopbackAddress());\n"
                            "Or deploy behind Azure Application Gateway with NSG restrictions."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Check for Spring Boot without IP restrictions
        has_spring_app = False
        has_ip_filter = False
        
        # Check for Spring annotations
        annotation_nodes = parser.find_nodes_by_type(tree.root_node, "marker_annotation")
        
        for ann_node in annotation_nodes:
            ann_text = parser.get_node_text(ann_node, code_bytes)
            if "SpringBootApplication" in ann_text:
                has_spring_app = True
            elif any(term in ann_text for term in ["Configuration", "Order"]) and "IpFilter" in code:
                has_ip_filter = True
        
        # Check for Spring application run
        method_invocation_nodes = parser.find_nodes_by_type(tree.root_node, "method_invocation")
        for method_node in method_invocation_nodes:
            method_text = parser.get_node_text(method_node, code_bytes)
            if "SpringApplication" in method_text and ".run(" in method_text:
                has_spring_app = True
        
        # Check for IP filter classes/keywords
        if not has_ip_filter and any(term in code for term in ["IpAddressFilter", "ClientIpCheck", "IpFilterSecurityConfig"]):
            has_ip_filter = True
        
        if has_spring_app and not has_ip_filter:
            # Find line with Spring annotation or run method
            for ann_node in annotation_nodes:
                ann_text = parser.get_node_text(ann_node, code_bytes)
                if "SpringBootApplication" in ann_text:
                    line_num = code[:ann_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Spring Boot Missing IP Filtering",
                        description=(
                            f"Spring Boot application at line {line_num} without IP filtering configuration. "
                            f"Implement IP allowlist using Spring Security or server configuration to restrict network traffic."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=ann_text[:200],
                        remediation=(
                            "Add IP filtering with Spring Security:\n"
                            "@Configuration\n"
                            "public class IpSecurityConfig extends WebSecurityConfigurerAdapter {\n"
                            "  protected void configure(HttpSecurity http) {\n"
                            "    http.authorizeRequests().requestMatchers(hasIpAddress(\"allowed-cidr\")).permitAll();\n"
                            "  }\n"
                            "}"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Regex fallback for Java analysis when AST parsing fails.
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Unrestricted ServerSocket (HIGH)
        if re.search(r'new\s+ServerSocket\s*\(', code):
            # Check if bound to all interfaces
            has_unrestricted = re.search(r'new\s+ServerSocket\s*\(\s*\d+\s*\)', code)  # No IP specified = all interfaces
            if has_unrestricted:
                result = self._find_line(lines, r'new\s+ServerSocket', use_regex=True)

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Unrestricted ServerSocket Binding",
                    description=(
                        f"ServerSocket at line {line_num} binds to all interfaces (no IP specified). "
                        f"FedRAMP requires restricting inbound network traffic. Bind to specific IP or "
                        f"implement IP filtering with Azure NSG rules."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Restrict ServerSocket binding:\n"
                        "ServerSocket server = new ServerSocket(port, backlog, InetAddress.getLoopbackAddress());\n"
                        "Or deploy behind Azure Application Gateway with NSG restrictions."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Spring Boot without IP restrictions (MEDIUM)
        has_spring_app = re.search(r'@SpringBootApplication|SpringApplication\.run', code)
        has_ip_filter = re.search(
            r'(IpAddressFilter|ClientIpCheck|@Order.*IpFilterSecurityConfig)',
            code
        )
        
        if has_spring_app and not has_ip_filter:
            result = self._find_line(lines, r'@SpringBootApplication|SpringApplication\.run', use_regex=True)

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Spring Boot Missing IP Filtering",
                description=(
                    f"Spring Boot application at line {line_num} without IP filtering configuration. "
                    f"Implement IP allowlist using Spring Security or server configuration to restrict network traffic."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add IP filtering with Spring Security:\n"
                    "@Configuration\n"
                    "public class IpSecurityConfig extends WebSecurityConfigurerAdapter {\n"
                    "  protected void configure(HttpSecurity http) {\n"
                    "    http.authorizeRequests().requestMatchers(hasIpAddress(\"allowed-cidr\")).permitAll();\n"
                    "  }\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-01 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Express/NestJS listening on 0.0.0.0
        - Missing IP filtering middleware
        - Open HTTP server without restrictions
        - No network access control
        """
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for TypeScript code."""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Pattern 1: Check for listen() calls with 0.0.0.0
        call_nodes = parser.find_nodes_by_type(tree.root_node, "call_expression")
        
        for call_node in call_nodes:
            call_text = parser.get_node_text(call_node, code_bytes)
            
            if ".listen(" in call_text and "0.0.0.0" in call_text:
                line_num = code[:call_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Unrestricted Network Listener (0.0.0.0)",
                    description=(
                        f"Server listening on 0.0.0.0 at line {line_num}, accepting connections from all interfaces. "
                        f"FedRAMP requires limiting inbound traffic. Use Azure Application Gateway with NSG rules "
                        f"or implement IP allowlist middleware."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=call_text[:200],
                    remediation=(
                        "Restrict listening address:\n"
                        "app.listen(port, '127.0.0.1');  // Localhost only\n"
                        "Or deploy behind Azure Front Door with NSG rules. "
                        "Add IP filtering middleware: app.use(ipFilter(allowedIPs));"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Check for Express/NestJS without IP filtering
        has_express = False
        has_ip_filter = False
        
        # Check imports
        import_nodes = parser.find_nodes_by_type(tree.root_node, "import_statement")
        
        for import_node in import_nodes:
            import_text = parser.get_node_text(import_node, code_bytes)
            if "express" in import_text or "@nestjs/common" in import_text:
                has_express = True
            elif any(term in import_text for term in ["express-ipfilter", "ip-filter", "ipware"]):
                has_ip_filter = True
        
        # Check for IP filter keywords in code
        if not has_ip_filter and any(term in code for term in ["ClientIpCheck", "allowedIPs", "ipfilter", "IpFilter"]):
            has_ip_filter = True
        
        if has_express and not has_ip_filter:
            # Find line with Express import or instantiation
            for import_node in import_nodes:
                import_text = parser.get_node_text(import_node, code_bytes)
                if "express" in import_text or "@nestjs/common" in import_text:
                    line_num = code[:import_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Missing IP Filtering Middleware",
                        description=(
                            f"Express/NestJS application at line {line_num} without IP filtering middleware. "
                            f"Application-level IP restrictions complement Azure NSG rules for defense-in-depth."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=import_text[:200],
                        remediation=(
                            "Add IP filtering middleware:\n"
                            "npm install express-ipfilter\n"
                            "const ipfilter = require('express-ipfilter').IpFilter;\n"
                            "app.use(ipfilter(['10.0.0.0/8', 'specific-ip'], {mode: 'allow'}));"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Regex fallback for TypeScript analysis when AST parsing fails.
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Unrestricted Express/HTTP server (HIGH)
        listen_patterns = [
            r'app\.listen\s*\([^)]*["\']0\.0\.0\.0',
            r'listen\s*\(\s*port\s*,\s*["\']0\.0\.0\.0',
            r'createServer.*listen\s*\(\s*port\s*,\s*["\']0\.0\.0\.0',
        ]
        
        for pattern in listen_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Unrestricted Network Listener (0.0.0.0)",
                    description=(
                        f"Server listening on 0.0.0.0 at line {line_num}, accepting connections from all interfaces. "
                        f"FedRAMP requires limiting inbound traffic. Use Azure Application Gateway with NSG rules "
                        f"or implement IP allowlist middleware."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Restrict listening address:\n"
                        "app.listen(port, '127.0.0.1');  // Localhost only\n"
                        "Or deploy behind Azure Front Door with NSG rules. "
                        "Add IP filtering middleware: app.use(ipFilter(allowedIPs));"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Missing IP restriction middleware (MEDIUM)
        has_express = re.search(r'express\(\)|from\s+["\']express["\']|@nestjs/common', code)
        has_ip_filter = re.search(
            r'(express-ipfilter|ip-filter|ipware|ClientIpCheck|allowedIPs)',
            code
        )
        
        if has_express and not has_ip_filter:
            result = self._find_line(lines, r'express\(\)|@nestjs/common', use_regex=True)
            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing IP Filtering Middleware",
                description=(
                    f"Express/NestJS application at line {line_num} without IP filtering middleware. "
                    f"Application-level IP restrictions complement Azure NSG rules for defense-in-depth."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add IP filtering middleware:\n"
                    "npm install express-ipfilter\n"
                    "const ipfilter = require('express-ipfilter').IpFilter;\n"
                    "app.use(ipfilter(['10.0.0.0/8', 'specific-ip'], {mode: 'allow'}));"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-01 compliance.
        
        Note: Using regex - tree-sitter not available for Bicep.
        
        Detects:
        - Missing Network Security Groups (NSG)
        - Overly permissive NSG rules (*, 0.0.0.0/0)
        - Virtual networks without subnets/NSG associations
        - Missing network restrictions on Azure resources
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VNet/Subnet without NSG (CRITICAL)
        has_vnet = re.search(r"resource.*'Microsoft\.Network/virtualNetworks", code)
        has_nsg = re.search(r"resource.*'Microsoft\.Network/networkSecurityGroups", code)
        
        if has_vnet and not has_nsg:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Virtual Network Without Network Security Group",
                description=(
                    "Virtual network defined without Network Security Group. FedRAMP requires "
                    f"restricting inbound and outbound network traffic at the network layer. "
                    f"NSGs provide stateful packet filtering for Azure resources."
                ),
                file_path=file_path,
                line_number=1,
                snippet="VNet defined without NSG",
                remediation=(
                    "Add Network Security Group:\n"
                    "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {\n"
                    "  name: 'nsg-${subnet-name}'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    securityRules: [\n"
                    "      // Define restrictive inbound/outbound rules\n"
                    "    ]\n"
                    "  }\n"
                    "}\n"
                    "Associate NSG with subnet using networkSecurityGroup property."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Overly permissive NSG rules (HIGH)
        permissive_patterns = [
            r'sourceAddressPrefix\s*:\s*["\']\\*["\']',
            r'destinationAddressPrefix\s*:\s*["\']\\*["\']',
            r'sourceAddressPrefix\s*:\s*["\']0\.0\.0\.0/0["\']',
        ]
        
        for pattern in permissive_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Overly Permissive NSG Rule",
                    description=(
                        f"Network Security Group rule at line {line_num} allows traffic from/to * or 0.0.0.0/0. "
                        f"FedRAMP requires limiting network traffic to specific sources/destinations. "
                        f"Use CIDR ranges or service tags instead of wildcards."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Restrict to specific IP ranges or service tags:\n"
                        "sourceAddressPrefix: '10.0.0.0/16'  // Internal network\n"
                        "destinationAddressPrefix: 'VirtualNetwork'  // Service tag\n"
                        "Only allow traffic from known, trusted sources."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-01 compliance.
        
        Note: Using regex - tree-sitter not available for Terraform.
        
        Detects:
        - Missing azurerm_network_security_group
        - Overly permissive security rules (0.0.0.0/0, *)
        - Subnets without NSG associations
        - Missing network restrictions
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VNet/Subnet without NSG (CRITICAL)
        has_vnet = re.search(r'resource\s+"azurerm_virtual_network"', code)
        has_nsg = re.search(r'resource\s+"azurerm_network_security_group"', code)
        
        if has_vnet and not has_nsg:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Virtual Network Without Network Security Group",
                description=(
                    "Virtual network configured without Network Security Group. FedRAMP requires "
                    f"restricting inbound and outbound network traffic. NSGs provide mandatory "
                    f"packet filtering for Azure resources."
                ),
                file_path=file_path,
                line_number=1,
                snippet="azurerm_virtual_network without azurerm_network_security_group",
                remediation=(
                    "Add Network Security Group:\n"
                    "resource \"azurerm_network_security_group\" \"main\" {\n"
                    "  name                = \"nsg-${var.subnet_name}\"\n"
                    "  location            = azurerm_resource_group.main.location\n"
                    "  resource_group_name = azurerm_resource_group.main.name\n"
                    "}\n"
                    "Associate with subnet: azurerm_subnet_network_security_group_association"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Permissive security rules (HIGH)
        permissive_patterns = [
            r'source_address_prefix\s*=\s*"\*"',
            r'destination_address_prefix\s*=\s*"\*"',
            r'source_address_prefix\s*=\s*"0\.0\.0\.0/0"',
        ]
        
        for pattern in permissive_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Overly Permissive NSG Security Rule",
                    description=(
                        f"Security rule at line {line_num} allows traffic from/to * or 0.0.0.0/0. "
                        f"FedRAMP requires limiting network traffic to specific IP ranges. "
                        f"Overly broad rules violate principle of least privilege for network access."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Restrict to specific CIDR ranges or service tags:\n"
                        "source_address_prefix      = \"10.0.0.0/16\"\n"
                        "destination_address_prefix = \"VirtualNetwork\"\n"
                        "Only allow necessary traffic from trusted sources."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-01 compliance.
        
        Note: Using regex - tree-sitter not available for GitHub Actions YAML.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-01 compliance.
        
        Note: Using regex - tree-sitter not available for Azure Pipelines YAML.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-01 compliance.
        
        Note: Using regex - tree-sitter not available for GitLab CI YAML.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
