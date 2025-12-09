"""
KSI-SVC-02: Network Encryption

Encrypt or otherwise secure network traffic.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
import ast
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_SVC_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-02: Network Encryption
    
    **Official Statement:**
    Encrypt or otherwise secure network traffic.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-1
    - ac-17.2
    - cp-9.8
    - sc-8
    - sc-8.1
    - sc-13
    - sc-20
    - sc-21
    - sc-22
    - sc-23
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Encrypt or otherwise secure network traffic....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-02"
    KSI_NAME = "Network Encryption"
    KSI_STATEMENT = """Encrypt or otherwise secure network traffic."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-1", "Policy and Procedures"),
        ("ac-17.2", "Protection of Confidentiality and Integrity Using Encryption"),
        ("cp-9.8", "Cryptographic Protection"),
        ("sc-8", "Transmission Confidentiality and Integrity"),
        ("sc-8.1", "Cryptographic Protection"),
        ("sc-13", "Cryptographic Protection"),
        ("sc-20", "Secure Name/Address Resolution Service (Authoritative Source)"),
        ("sc-21", "Secure Name/Address Resolution Service (Recursive or Caching Resolver)"),
        ("sc-22", "Architecture and Provisioning for Name/Address Resolution Service"),
        ("sc-23", "Session Authenticity")
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
        Analyze Python code for KSI-SVC-02 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - HTTP instead of HTTPS in URLs (ast.Call with string literals)
        - SSL verification disabled (ast.keyword verify=False)
        - Weak TLS versions (ast.Attribute for ssl.PROTOCOL_*)
        - Insecure connection configurations
        """
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fall back to regex if syntax errors
            return self._python_regex_fallback(code, file_path)
        
        # Pattern 1: HTTP URLs in function calls (CRITICAL)
        # Detects requests.get('http://...'), urllib.request.urlopen('http://...'), etc.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for requests.get/post/put/delete/patch with HTTP URL
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if func_name in ['get', 'post', 'put', 'delete', 'patch', 'request']:
                        # Check if module is requests/httpx
                        if isinstance(node.func.value, ast.Name) and node.func.value.id in ['requests', 'httpx']:
                            # Check first argument (URL)
                            if node.args and isinstance(node.args[0], ast.Constant):
                                url_value = node.args[0].value
                                if isinstance(url_value, str) and url_value.startswith('http://'):
                                    # Exclude localhost/127.0.0.1
                                    if not any(x in url_value for x in ['localhost', '127.0.0.1']):
                                        line_num = node.lineno
                                        findings.append(Finding(
                                            severity=Severity.CRITICAL,
                                            title="Unencrypted HTTP Connection",
                                            description=(
                                                f"HTTP connection detected in {node.func.value.id}.{func_name}() call. "
                                                f"KSI-SVC-02 requires encrypting network traffic (SC-8, SC-8.1) - "
                                                f"HTTP transmits data in plaintext, exposing sensitive information to interception."
                                            ),
                                            file_path=file_path,
                                            line_number=line_num,
                                            snippet=self._get_snippet(lines, line_num),
                                            remediation=(
                                                "Replace HTTP with HTTPS:\n"
                                                f"{node.func.value.id}.{func_name}('https://api.example.com/data')\n\n"
                                                "Ensure:\n"
                                                "- Server supports TLS 1.2 or higher\n"
                                                "- Valid SSL certificate is installed\n"
                                                "- Certificate validation is enabled (verify=True, default)\n\n"
                                                "Ref: Python Requests Security (https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)"
                                            ),
                                            ksi_id=self.KSI_ID
                                        ))
                
                # Check for urllib.request.urlopen('http://...')
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'urlopen':
                    # Check if it's urllib.request.urlopen or just urlopen
                    if isinstance(node.func.value, ast.Attribute):
                        if node.func.value.attr == 'request' and isinstance(node.func.value.value, ast.Name):
                            if node.func.value.value.id == 'urllib':
                                if node.args and isinstance(node.args[0], ast.Constant):
                                    url_value = node.args[0].value
                                    if isinstance(url_value, str) and url_value.startswith('http://'):
                                        if not any(x in url_value for x in ['localhost', '127.0.0.1']):
                                            line_num = node.lineno
                                            findings.append(Finding(
                                                severity=Severity.CRITICAL,
                                                title="Unencrypted HTTP Connection",
                                                description=(
                                                    f"HTTP connection detected in urllib.request.urlopen() call. "
                                                    f"KSI-SVC-02 requires encrypting network traffic - "
                                                    f"unencrypted HTTP exposes data to interception."
                                                ),
                                                file_path=file_path,
                                                line_number=line_num,
                                                snippet=self._get_snippet(lines, line_num),
                                                remediation=(
                                                    "Use HTTPS:\n"
                                                    "urllib.request.urlopen('https://api.example.com/data')\n\n"
                                                    "Ref: urllib Security (https://docs.python.org/3/library/urllib.request.html)"
                                                ),
                                                ksi_id=self.KSI_ID
                                            ))
        
        # Pattern 2: HTTP URLs in variable assignments (CRITICAL)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check if assigning HTTP URL to url/endpoint/api_url variables
                if any(isinstance(target, ast.Name) and 'url' in target.id.lower() for target in node.targets):
                    if isinstance(node.value, ast.Constant):
                        url_value = node.value.value
                        if isinstance(url_value, str) and url_value.startswith('http://'):
                            if not any(x in url_value for x in ['localhost', '127.0.0.1']):
                                line_num = node.lineno
                                findings.append(Finding(
                                    severity=Severity.CRITICAL,
                                    title="Unencrypted HTTP URL Configuration",
                                    description=(
                                        f"HTTP URL assigned to variable. "
                                        f"KSI-SVC-02 requires encrypting network traffic - "
                                        f"HTTP URLs should be replaced with HTTPS."
                                    ),
                                    file_path=file_path,
                                    line_number=line_num,
                                    snippet=self._get_snippet(lines, line_num),
                                    remediation=(
                                        "Use HTTPS URL:\n"
                                        "url = 'https://api.example.com/endpoint'\n"
                                    ),
                                    ksi_id=self.KSI_ID
                                ))
        
        # Pattern 3: SSL verification disabled (CRITICAL)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for verify=False keyword argument
                for keyword in node.keywords:
                    if keyword.arg == 'verify':
                        if isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                            line_num = node.lineno
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                title="SSL Certificate Verification Disabled",
                                description=(
                                    f"SSL verification explicitly disabled (verify=False). "
                                    f"KSI-SVC-02 requires secure network traffic (SC-8.1, SC-13) - "
                                    f"disabling certificate validation bypasses TLS security, "
                                    f"making connections vulnerable to man-in-the-middle attacks."
                                ),
                                file_path=file_path,
                                line_number=line_num,
                                snippet=self._get_snippet(lines, line_num),
                                remediation=(
                                    "Enable SSL verification (default behavior):\n"
                                    "# Option 1: Use default (verify=True)\n"
                                    "requests.get(url)  # verify=True by default\n\n"
                                    "# Option 2: Use custom CA bundle for self-signed certs (dev only)\n"
                                    "requests.get(url, verify='/path/to/ca-bundle.crt')\n\n"
                                    "# Option 3: Use certifi for system certificates\n"
                                    "import certifi\n"
                                    "requests.get(url, verify=certifi.where())\n\n"
                                    "NEVER disable verify in production!\n\n"
                                    "Ref: Requests SSL Verification (https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)"
                                ),
                                ksi_id=self.KSI_ID
                            ))
        
        # Pattern 4: Weak SSL/TLS protocols (HIGH)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                # Check for ssl.PROTOCOL_SSLv2, ssl.PROTOCOL_SSLv3, ssl.PROTOCOL_TLSv1
                if isinstance(node.value, ast.Name) and node.value.id == 'ssl':
                    weak_protocols = ['PROTOCOL_SSLv2', 'PROTOCOL_SSLv3', 'PROTOCOL_TLSv1', 'PROTOCOL_TLSv1_1']
                    if node.attr in weak_protocols:
                        line_num = node.lineno
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Weak TLS Protocol Version",
                            description=(
                                f"Weak SSL/TLS protocol detected: ssl.{node.attr}. "
                                f"KSI-SVC-02 requires strong encryption (SC-13) - "
                                f"SSLv2, SSLv3, TLSv1.0, and TLSv1.1 have known vulnerabilities. "
                                f"Minimum TLS 1.2 is required for FedRAMP compliance."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num),
                            remediation=(
                                "Use TLS 1.2 or higher:\n"
                                "import ssl\n\n"
                                "# Option 1: Use default context (TLS 1.2+ by default)\n"
                                "context = ssl.create_default_context()\n\n"
                                "# Option 2: Explicitly set minimum TLS version\n"
                                "context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
                                "context.minimum_version = ssl.TLSVersion.TLSv1_2\n\n"
                                "# Use with requests\n"
                                "session = requests.Session()\n"
                                "session.mount('https://', requests.adapters.HTTPAdapter())\n\n"
                                "Ref: Python SSL Module (https://docs.python.org/3/library/ssl.html#ssl-security)"
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback for Python when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs (CRITICAL)
        http_patterns = [
            r'requests\.(get|post|put|delete|patch)\s*\(\s*["\']http://',
            r'urllib\.request\.urlopen\s*\(\s*["\']http://',
            r'httpx\.(get|post|put|delete)\s*\(\s*["\']http://',
            r'url\s*=\s*["\']http://(?!localhost|127\.0\.0\.1)',
        ]
        
        for pattern in http_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num > 0:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Unencrypted HTTP Connection (Regex Fallback)",
                    description="HTTP connection detected. Use HTTPS for encrypted communication.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Replace HTTP with HTTPS URLs.",
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: SSL verification disabled (CRITICAL)
        if re.search(r'verify\s*=\s*False', code):
            line_num = self._find_line(lines, r'verify\s*=\s*False')
            if line_num > 0:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="SSL Verification Disabled (Regex Fallback)",
                    description="SSL certificate verification is disabled.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Enable SSL verification (default behavior).",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - HTTP URLs in HttpClient
        - RequireHttpsMetadata = false
        - Weak SSL/TLS protocols
        - Certificate validation disabled
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based C# analysis for network encryption."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Pattern 1: HTTP URLs in string literals (CRITICAL)
        string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
        for string_node in string_literals:
            string_text = parser.get_node_text(string_node, code_bytes)
            if 'http://' in string_text.lower() and not any(x in string_text.lower() for x in ['localhost', '127.0.0.1']):
                line_num = code[:string_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Unencrypted HTTP Connection",
                    description=(
                        f"HTTP URL detected at line {line_num}. "
                        f"All network communication must use HTTPS with TLS encryption. "
                        f"HTTP exposes data to interception and tampering."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use HTTPS URLs:\n"
                        "var response = await client.GetAsync(\"https://api.example.com/data\");\n"
                        "Configure middleware to enforce HTTPS redirection."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break  # Only report once
        
        # Pattern 2: RequireHttpsMetadata = false (CRITICAL)
        # Find assignment expressions where left side is RequireHttpsMetadata
        assignments = parser.find_nodes_by_type(tree.root_node, 'assignment_expression')
        for assign_node in assignments:
            assign_text = parser.get_node_text(assign_node, code_bytes)
            if 'RequireHttpsMetadata' in assign_text and 'false' in assign_text:
                line_num = code[:assign_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="HTTPS Metadata Requirement Disabled",
                    description=(
                        f"RequireHttpsMetadata set to false at line {line_num}. "
                        f"This allows OpenID Connect/OAuth metadata to be retrieved over HTTP, "
                        f"exposing authentication configuration to interception."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Require HTTPS for metadata:\n"
                        "options.RequireHttpsMetadata = true;  // Default in production\n"
                        "Only set to false in local development with valid justification."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        # Pattern 3: Weak SSL protocols (HIGH)
        # Find member access expressions like SecurityProtocolType.Ssl3, SslProtocols.Tls
        member_access_nodes = parser.find_nodes_by_type(tree.root_node, 'member_access_expression')
        weak_protocols = ['Ssl2', 'Ssl3', 'Tls', 'Tls11', 'Tls10']
        
        for member_node in member_access_nodes:
            member_text = parser.get_node_text(member_node, code_bytes)
            if any(proto in member_text for proto in weak_protocols):
                # Check it's actually a protocol type (SecurityProtocolType or SslProtocols)
                if 'SecurityProtocolType' in member_text or 'SslProtocols' in member_text:
                    line_num = code[:member_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Weak SSL/TLS Protocol Version",
                        description=(
                            f"Weak SSL/TLS protocol configured at line {line_num}. "
                            f"Protocols prior to TLS 1.2 have known vulnerabilities (POODLE, BEAST, CRIME). "
                            f"FedRAMP requires TLS 1.2+ for all network connections."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use TLS 1.2 or higher:\n"
                            "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;\n"
                            "Or configure in system settings to use system defaults (recommended)."
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex-based C# analysis (fallback when AST unavailable)."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs (CRITICAL)
        if re.search(r'["\']http://[^"\']*["\']', code):
            line_num = self._find_line(lines, r'["\']http://')
            if line_num > 0:
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                if not re.search(r'http://(localhost|127\.0\.0\.1)', line_content, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Unencrypted HTTP Connection",
                        description=(
                            f"HTTP URL detected at line {line_num}. "
                            f"All network communication must use HTTPS with TLS encryption. "
                            f"HTTP exposes data to interception and tampering."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use HTTPS URLs:\n"
                            "var response = await client.GetAsync(\"https://api.example.com/data\");\n"
                            "Configure middleware to enforce HTTPS redirection."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: RequireHttpsMetadata = false (CRITICAL)
        if re.search(r'RequireHttpsMetadata\s*=\s*false', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'RequireHttpsMetadata')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="HTTPS Metadata Requirement Disabled",
                description=(
                    f"RequireHttpsMetadata set to false at line {line_num}. "
                    f"This allows OpenID Connect/OAuth metadata to be retrieved over HTTP, "
                    f"exposing authentication configuration to interception."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Require HTTPS for metadata:\n"
                    "options.RequireHttpsMetadata = true;  // Default in production\n"
                    "Only set to false in local development with valid justification."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Weak SSL protocols (HIGH)
        weak_ssl_patterns = [
            r'SecurityProtocolType\.Ssl3',
            r'SecurityProtocolType\.Tls\b(?!12|13)',
            r'SslProtocols\.(Ssl2|Ssl3|Tls|Tls11)',
        ]
        
        for pattern in weak_ssl_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Weak SSL/TLS Protocol Configured",
                    description=(
                        f"Weak SSL/TLS protocol at line {line_num}. "
                        f"SSLv2, SSLv3, TLS 1.0, and TLS 1.1 have known vulnerabilities. "
                        f"Minimum TLS 1.2 is required for secure communication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use TLS 1.2 or higher:\n"
                        "ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;\n"
                        "or configure in appsettings.json with Switch.System.Net.DontEnableTls13 = false"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - HTTP connections without TLS
        - SSL verification disabled
        - Weak TLS configurations
        - HostnameVerifier disabled
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Java analysis for network encryption."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Pattern 1: HTTP URLs in string literals (CRITICAL)
        string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
        for string_node in string_literals:
            string_text = parser.get_node_text(string_node, code_bytes)
            if 'http://' in string_text.lower() and not any(x in string_text.lower() for x in ['localhost', '127.0.0.1']):
                line_num = code[:string_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Unencrypted HTTP Connection",
                    description=(
                        f"HTTP connection at line {line_num}. "
                        f"All network traffic must use HTTPS with TLS encryption. "
                        f"HTTP connections expose data to interception."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use HTTPS URLs:\n"
                        "URL url = new URL(\"https://api.example.com/data\");\n"
                        "WebClient.builder().baseUrl(\"https://api.example.com\").build();\n"
                        "Ensure server has valid TLS certificate."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        # Pattern 2: SSL verification disabled - look for specific identifiers and type_identifiers
        identifiers = parser.find_nodes_by_type(tree.root_node, 'identifier')
        type_identifiers = parser.find_nodes_by_type(tree.root_node, 'type_identifier')
        
        for ident_node in identifiers:
            ident_text = parser.get_node_text(ident_node, code_bytes)
            if ident_text in ['ALLOW_ALL_HOSTNAME_VERIFIER', 'NoopHostnameVerifier']:
                line_num = code[:ident_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="SSL Certificate Verification Disabled",
                    description=(
                        f"Hostname verification disabled at line {line_num}. "
                        f"This bypasses certificate validation, making connections vulnerable "
                        f"to man-in-the-middle attacks even with HTTPS."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Enable proper SSL verification:\n"
                        "Remove ALLOW_ALL_HOSTNAME_VERIFIER and NoopHostnameVerifier\n"
                        "Use default hostname verification."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        for ident_node in type_identifiers:
            ident_text = parser.get_node_text(ident_node, code_bytes)
            if ident_text == 'X509TrustManager':
                # Check if this is an empty implementation (bypassing SSL verification)
                line_num = code[:ident_node.start_byte].count('\n') + 1
                # Look for empty checkClientTrusted or checkServerTrusted methods
                context_start = max(0, ident_node.start_byte - 100)
                context_end = min(len(code), ident_node.end_byte + 300)
                context = code[context_start:context_end]
                
                if ('checkServerTrusted' in context and '{}' in context) or \
                   (re.search(r'checkServerTrusted.*?\{[\s]*\}', context, re.DOTALL)):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="SSL Certificate Verification Disabled (Empty TrustManager)",
                        description=(
                            f"Custom X509TrustManager with empty checkServerTrusted at line {line_num}. "
                            f"This completely bypasses SSL certificate validation, allowing attackers "
                            f"to perform man-in-the-middle attacks by presenting any certificate."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use proper SSL verification:\n"
                            "Remove custom TrustManager implementations that bypass validation\n"
                            "Use the default TrustManager from TrustManagerFactory:\n\n"
                            "TrustManagerFactory tmf = TrustManagerFactory.getInstance(\n"
                            "    TrustManagerFactory.getDefaultAlgorithm());\n"
                            "tmf.init((KeyStore) null);  // Use default trust store\n"
                            "sslContext.init(null, tmf.getTrustManagers(), null);"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        # Pattern 3: Weak TLS versions in string literals
        for string_node in string_literals:
            string_text = parser.get_node_text(string_node, code_bytes)
            if any(proto in string_text for proto in ['TLSv1.0', 'TLSv1.1', 'TLSv1"', 'SSLv2', 'SSLv3']):
                line_num = code[:string_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Weak TLS Protocol Version",
                    description=(
                        f"Weak TLS version configured at line {line_num}. "
                        f"TLS 1.0, TLS 1.1, and SSL protocols have known vulnerabilities. "
                        f"Minimum TLS 1.2 is required."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Configure TLS 1.2+:\n"
                        "SSLContext sslContext = SSLContext.getInstance(\"TLSv1.2\");\n"
                        "or in Spring Boot application.properties:\n"
                        "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3"
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex-based Java analysis (fallback when AST unavailable)."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs (CRITICAL)
        if re.search(r'["\']http://[^"\']* ["\']', code):
            line_num = self._find_line(lines, r'["\']http://')
            if line_num > 0:
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                # Exclude localhost/127.0.0.1 for development
                if not re.search(r'http://(localhost|127\.0\.0\.1)', line_content, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Unencrypted HTTP Connection",
                        description=(
                            f"HTTP connection at line {line_num}. "
                            f"All network traffic must use HTTPS with TLS encryption. "
                            f"HTTP connections expose data to interception."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use HTTPS URLs:\n"
                        "URL url = new URL(\"https://api.example.com/data\");\n"
                        "WebClient.builder().baseUrl(\"https://api.example.com\").build();\n"
                        "Ensure server has valid TLS certificate."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: SSL verification disabled (CRITICAL)
        # Check for hostname verifier bypass
        if re.search(r'ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier', code):
            line_num = self._find_line(lines, r'ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier')
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="SSL Certificate Verification Disabled",
                    description=(
                        f"Hostname verification disabled at line {line_num}. "
                        f"This bypasses certificate validation, making connections vulnerable "
                        f"to man-in-the-middle attacks even with HTTPS."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Enable proper SSL verification:\n"
                        "Remove ALLOW_ALL_HOSTNAME_VERIFIER and NoopHostnameVerifier\n"
                        "Use default hostname verification."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Check for empty TrustManager (multi-line pattern)
        if re.search(r'X509TrustManager.*checkServerTrusted.*\{\s*\}', code, re.DOTALL):
            # Find line with checkServerTrusted since pattern spans multiple lines
            line_num = self._find_line(lines, r'checkServerTrusted')
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="SSL Certificate Verification Disabled",
                    description=(
                        f"Empty X509TrustManager detected at line {line_num}. "
                        f"This bypasses all certificate validation, making connections vulnerable "
                        f"to man-in-the-middle attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use default TrustManager with proper certificate validation\n"
                        "For self-signed certs, add to truststore instead of disabling validation."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Weak TLS versions (HIGH)
        if re.search(r'(TLSv1(\.[01])?|SSLv[23])', code):
            line_num = self._find_line(lines, r'TLSv1(\.[01])?|SSLv[23]')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Weak TLS Protocol Version",
                description=(
                    f"Weak TLS version configured at line {line_num}. "
                    f"TLS 1.0, TLS 1.1, and SSL protocols have known vulnerabilities. "
                    f"Minimum TLS 1.2 is required."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Configure TLS 1.2+:\n"
                    "SSLContext sslContext = SSLContext.getInstance(\"TLSv1.2\");\n"
                    "or in Spring Boot application.properties:\n"
                    "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - HTTP URLs in fetch/axios
        - rejectUnauthorized: false
        - Insecure WebSocket connections
        - Missing HTTPS enforcement
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based TypeScript analysis for network encryption."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Pattern 1: HTTP URLs in string literals (CRITICAL)
        string_nodes = parser.find_nodes_by_type(tree.root_node, 'string')
        for string_node in string_nodes:
            string_text = parser.get_node_text(string_node, code_bytes)
            # Check for http:// but exclude localhost/127.0.0.1
            if 'http://' in string_text.lower():
                if not any(x in string_text.lower() for x in ['localhost', '127.0.0.1']):
                    line_num = code[:string_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Unencrypted HTTP Request",
                        description=(
                            f"HTTP request at line {line_num}. "
                            f"All network requests must use HTTPS with TLS encryption. "
                            f"HTTP transmits data in plaintext, exposing sensitive information."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use HTTPS URLs:\n"
                            "fetch('https://api.example.com/data')\n"
                            "axios.get('https://api.example.com/data')\n"
                            "Configure environment variables for API base URLs."
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Only report first occurrence
        
        # Pattern 2: rejectUnauthorized: false (CRITICAL)
        # Look for pair nodes (object properties) with key 'rejectUnauthorized' and value 'false'
        pair_nodes = parser.find_nodes_by_type(tree.root_node, 'pair')
        for pair_node in pair_nodes:
            pair_text = parser.get_node_text(pair_node, code_bytes)
            # Check if this is rejectUnauthorized: false
            if 'rejectUnauthorized' in pair_text and 'false' in pair_text:
                line_num = code[:pair_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="SSL Certificate Validation Disabled",
                    description=(
                        f"rejectUnauthorized set to false at line {line_num}. "
                        f"This disables SSL certificate validation, making connections vulnerable "
                        f"to man-in-the-middle attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Enable SSL validation (default):\n"
                        "Remove rejectUnauthorized: false\n"
                        "For self-signed certificates in development, use NODE_EXTRA_CA_CERTS "
                        "environment variable instead of disabling validation."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        # Pattern 3: Insecure WebSocket ws:// in strings (HIGH)
        for string_node in string_nodes:
            string_text = parser.get_node_text(string_node, code_bytes)
            # Check for ws:// but exclude localhost/127.0.0.1
            if 'ws://' in string_text.lower():
                if not any(x in string_text.lower() for x in ['localhost', '127.0.0.1']):
                    line_num = code[:string_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Unencrypted WebSocket Connection",
                        description=(
                            f"Unencrypted WebSocket (ws://) at line {line_num}. "
                            f"WebSocket connections must use wss:// (WebSocket Secure) for encryption."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use WebSocket Secure:\n"
                            "const ws = new WebSocket('wss://api.example.com/socket');\n"
                            "Ensure server supports WSS with valid TLS certificate."
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        # Pattern 4: Weak TLS versions in minVersion property (HIGH)
        for pair_node in pair_nodes:
            pair_text = parser.get_node_text(pair_node, code_bytes)
            # Check for minVersion with weak TLS (TLSv1, TLSv1.0, TLSv1.1)
            if 'minVersion' in pair_text:
                if any(weak in pair_text for weak in ['TLSv1.0', 'TLSv1.1', "TLSv1'"]):
                    line_num = code[:pair_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Weak TLS Protocol Version",
                        description=(
                            f"Weak TLS minVersion configured at line {line_num}. "
                            f"TLS 1.0 and TLS 1.1 have known vulnerabilities."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use TLS 1.2 or higher:\n"
                            "const options = { minVersion: 'TLSv1.2' };\n"
                            "Or use 'TLSv1.3' for maximum security."
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for TypeScript analysis when AST fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs (CRITICAL)
        if re.search(r'["\']http://[^"\']*["\']', code):
            line_num = self._find_line(lines, r'["\']http://')
            if line_num > 0:
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                if not re.search(r'http://(localhost|127\.0\.0\.1)', line_content, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Unencrypted HTTP Request",
                        description=(
                            f"HTTP request at line {line_num}. "
                            f"All network requests must use HTTPS with TLS encryption. "
                            f"HTTP transmits data in plaintext, exposing sensitive information."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use HTTPS URLs:\n"
                            "fetch('https://api.example.com/data')\n"
                            "axios.get('https://api.example.com/data')\n"
                            "Configure environment variables for API base URLs."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: rejectUnauthorized: false (CRITICAL)
        if re.search(r'rejectUnauthorized\s*:\s*false', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'rejectUnauthorized')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="SSL Certificate Validation Disabled",
                description=(
                    f"rejectUnauthorized set to false at line {line_num}. "
                    f"This disables SSL certificate validation, making connections vulnerable "
                    f"to man-in-the-middle attacks."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Enable SSL validation (default):\n"
                    "Remove rejectUnauthorized: false\n"
                    "For self-signed certificates in development, use NODE_EXTRA_CA_CERTS "
                    "environment variable instead of disabling validation."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Insecure WebSocket (HIGH)
        if re.search(r'ws://(?!localhost|127\.0\.0\.1)', code):
            line_num = self._find_line(lines, r'ws://')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Unencrypted WebSocket Connection",
                description=(
                    f"Unencrypted WebSocket (ws://) at line {line_num}. "
                    f"WebSocket connections must use wss:// (WebSocket Secure) for encryption."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use WebSocket Secure:\n"
                    "const ws = new WebSocket('wss://api.example.com/socket');\n"
                    "Ensure server supports WSS with valid TLS certificate."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 4: Weak TLS versions (HIGH)
        if re.search(r'minVersion.*[\'"]TLSv1(\.[01])?[\'"]', code):
            line_num = self._find_line(lines, r'minVersion')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Weak TLS Protocol Version",
                description=(
                    f"Weak TLS minVersion configured at line {line_num}. "
                    f"TLS 1.0 and TLS 1.1 have known vulnerabilities."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use TLS 1.2 or higher:\n"
                    "const options = { minVersion: 'TLSv1.2' };\n"
                    "Or use 'TLSv1.3' for maximum security."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-02 compliance.
        
        Detects:
        - HTTP-only endpoints
        - HTTPS enforcement disabled
        - Weak TLS versions (< 1.2)
        - Storage accounts without HTTPS requirement
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTPS enforcement disabled (CRITICAL)
        if re.search(r'httpsOnly\s*:\s*false', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'httpsOnly')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="HTTPS Enforcement Disabled",
                description=(
                    f"httpsOnly set to false at line {line_num}. "
                    f"Azure resources must enforce HTTPS to ensure all traffic is encrypted."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Enforce HTTPS:\n"
                    "properties: {\n"
                    "  httpsOnly: true\n"
                    "}\n"
                    "This applies to App Services, Function Apps, and other web resources."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Storage account without HTTPS requirement (CRITICAL)
        storage_matches = list(re.finditer(r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts", code))
        for match in storage_matches:
            block = code[match.start():match.start() + 500]
            if 'supportsHttpsTrafficOnly' not in block:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Storage Account Missing HTTPS Enforcement",
                    description=(
                        f"Storage account at line {line_num} without supportsHttpsTrafficOnly. "
                        f"Storage accounts must require HTTPS to encrypt data in transit."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Enforce HTTPS on storage account:\n"
                        "properties: {\n"
                        "  supportsHttpsTrafficOnly: true\n"
                        "  minimumTlsVersion: 'TLS1_2'\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Weak TLS version (HIGH)
        if re.search(r"minimumTlsVersion\s*:\s*'TLS1_[01]'", code):
            line_num = self._find_line(lines, r"minimumTlsVersion\s*:\s*'TLS1_[01]'")
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Weak TLS Version Configured",
                description=(
                    f"TLS 1.0 or 1.1 configured at line {line_num}. "
                    f"These versions have known vulnerabilities. Minimum TLS 1.2 is required."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use TLS 1.2 or higher:\n"
                    "minimumTlsVersion: 'TLS1_2'\n"
                    "or 'TLS1_3' for maximum security."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-02 compliance.
        
        Detects:
        - HTTP endpoints in Azure resources
        - enable_https_traffic_only = false
        - Weak TLS configurations
        - Missing SSL enforcement
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTPS traffic disabled (CRITICAL)
        if re.search(r'enable_https_traffic_only\s*=\s*false', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'enable_https_traffic_only')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="HTTPS Traffic Not Enforced",
                description=(
                    f"enable_https_traffic_only set to false at line {line_num}. "
                    f"Azure storage accounts must require HTTPS to encrypt all traffic."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Enforce HTTPS traffic:\n"
                    "enable_https_traffic_only = true\n"
                    "This ensures all storage operations use encrypted connections."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Storage account without HTTPS enforcement (CRITICAL)
        storage_matches = list(re.finditer(r'resource\s+"azurerm_storage_account"\s+"\w+"', code))
        for match in storage_matches:
            block = code[match.start():match.start() + 600]
            if 'enable_https_traffic_only' not in block:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Storage Account Missing HTTPS Enforcement",
                    description=(
                        f"Storage account at line {line_num} without enable_https_traffic_only. "
                        f"All storage accounts must enforce HTTPS for encrypted data transfer."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Add HTTPS enforcement:\n"
                        "resource \"azurerm_storage_account\" \"example\" {\n"
                        "  enable_https_traffic_only = true\n"
                        "  min_tls_version          = \"TLS1_2\"\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Weak TLS version (HIGH)
        if re.search(r'min_tls_version\s*=\s*"TLS1_[01]"', code):
            line_num = self._find_line(lines, r'min_tls_version\s*=\s*"TLS1_[01]"')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Weak Minimum TLS Version",
                description=(
                    f"TLS 1.0 or 1.1 configured at line {line_num}. "
                    f"These protocols have known vulnerabilities. TLS 1.2+ is required."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use minimum TLS 1.2:\n"
                    "min_tls_version = \"TLS1_2\"\n"
                    "Consider TLS1_3 for maximum security if supported."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    

        """Find line number matching regex pattern (case-insensitive)."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    return i
        except re.error:
            # Fallback to literal string search if pattern is invalid
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    return i
        return 0
    

        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
