"""
KSI-SVC-02: Network Encryption

Encrypt or otherwise secure network traffic.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


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
    NIST_CONTROLS = ["ac-1", "ac-17.2", "cp-9.8", "sc-8", "sc-8.1", "sc-13", "sc-20", "sc-21", "sc-22", "sc-23"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self):
        super().__init__(
            ksi_id=self.KSI_ID,
            ksi_name=self.KSI_NAME,
            ksi_statement=self.KSI_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-SVC-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - HTTP instead of HTTPS in URLs
        - SSL verification disabled
        - Weak TLS versions
        - Insecure connection configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs in requests (CRITICAL)
        http_patterns = [
            r'requests\.(get|post|put|delete|patch)\s*\(\s*["\']http://',
            r'urllib\.request\.urlopen\s*\(\s*["\']http://',
            r'httpx\.(get|post|put|delete)\s*\(\s*["\']http://',
            r'url\s*=\s*["\']http://(?!localhost|127\.0\.0\.1)',
        ]
        
        for pattern in http_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Unencrypted HTTP Connection",
                    description=(
                        f"HTTP connection detected at line {line_num}. "
                        f"All network traffic must be encrypted using HTTPS/TLS. "
                        f"HTTP transmits data in plaintext, exposing sensitive information."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Replace HTTP with HTTPS:\n"
                        "requests.get('https://api.example.com/data')\n"
                        "Ensure the server supports TLS 1.2+ and has valid SSL certificate."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: SSL verification disabled (CRITICAL)
        if re.search(r'verify\s*=\s*False', code):
            line_num = self._find_line(lines, r'verify\s*=\s*False')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="SSL Certificate Verification Disabled",
                description=(
                    f"SSL verification disabled at line {line_num}. "
                    f"This bypasses certificate validation, making the connection vulnerable "
                    f"to man-in-the-middle attacks even when using HTTPS."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Enable SSL verification (default behavior):\n"
                    "requests.get(url)  # verify=True by default\n"
                    "If using self-signed certificates in development, use verify='/path/to/ca-bundle.crt' instead."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Weak SSL/TLS versions (HIGH)
        weak_tls_patterns = [
            r'ssl\.PROTOCOL_TLSv1\b',
            r'ssl\.PROTOCOL_SSLv[23]',
            r'ssl_version\s*=\s*["\']TLSv1\.[01]',
        ]
        
        for pattern in weak_tls_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Weak TLS Version Configuration",
                    description=(
                        f"Weak TLS version (SSLv2/SSLv3/TLSv1.0/TLSv1.1) configured at line {line_num}. "
                        f"These protocols have known vulnerabilities. Minimum TLS 1.2 is required."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use TLS 1.2 or higher:\n"
                        "import ssl\n"
                        "context = ssl.create_default_context()\n"
                        "context.minimum_version = ssl.TLSVersion.TLSv1_2\n"
                        "Or use ssl.PROTOCOL_TLS_CLIENT with minimum_version set."
                    ),
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
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs (CRITICAL)
        if re.search(r'(new\s+Uri|HttpClient.*GetAsync|PostAsync)\s*\([^)]*http://', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'http://')
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
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs (CRITICAL)
        http_patterns = [
            r'new\s+URL\s*\(\s*"http://',
            r'HttpURLConnection.*http://',
            r'RestTemplate.*http://',
            r'WebClient.*uri\("http://',
        ]
        
        for pattern in http_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
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
        ssl_disable_patterns = [
            r'setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER',
            r'setSSLHostnameVerifier\s*\(\s*NoopHostnameVerifier',
            r'TrustManager\s*\[\].*new\s+X509TrustManager.*checkServerTrusted\s*\([^)]*\)\s*\{\s*\}',
        ]
        
        for pattern in ssl_disable_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="SSL Certificate Verification Disabled",
                    description=(
                        f"SSL verification disabled at line {line_num}. "
                        f"This bypasses certificate validation, making connections vulnerable "
                        f"to man-in-the-middle attacks even with HTTPS."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Enable proper SSL verification:\n"
                        "Remove ALLOW_ALL_HOSTNAME_VERIFIER and NoopHostnameVerifier\n"
                        "Use default TrustManager with proper certificate validation\n"
                        "For self-signed certs, add to truststore instead of disabling validation."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Weak TLS versions (HIGH)
        if re.search(r'(TLSv1\.[01]|SSLv[23])', code):
            line_num = self._find_line(lines, r'TLSv1\.[01]|SSLv[23]')
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
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP URLs (CRITICAL)
        http_patterns = [
            r'fetch\s*\(\s*["\']http://',
            r'axios\.(get|post|put|delete)\s*\(\s*["\']http://',
            r'request\s*\(\s*\{[^}]*url\s*:\s*["\']http://',
            r'baseURL\s*:\s*["\']http://',
        ]
        
        for pattern in http_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
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
    
    def _find_line(self, lines: List[str], pattern: str) -> int:
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
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
