"""
KSI-SVC-09: Communication Integrity

Persistently validate the authenticity and integrity of communications between machine-based information resources using automation.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
import ast
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_SVC_09_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-09: Communication Integrity
    
    **Official Statement:**
    Persistently validate the authenticity and integrity of communications between machine-based information resources using automation.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    
    **NIST Controls:**
    - sc-23
    - si-7.1
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Persistently validate the authenticity and integrity of communications between machine-based informa...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-09"
    KSI_NAME = "Communication Integrity"
    KSI_STATEMENT = """Persistently validate the authenticity and integrity of communications between machine-based information resources using automation."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("sc-23", "Session Authenticity"),
        ("si-7.1", "Integrity Checks")
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
        Analyze Python code for KSI-SVC-09 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - SSL/TLS certificate verification disabled (verify=False)
        - Missing mutual TLS (mTLS) for service-to-service communication
        - Certificate validation bypassed in any HTTP library
        """
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fallback to regex if AST parsing fails
            return self._python_regex_fallback(code, lines, file_path)
        
        # Pattern 1: verify=False in function calls (CRITICAL)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for keyword argument verify=False
                for keyword in node.keywords:
                    if keyword.arg == 'verify' and isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is False:
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                title="HTTP Request Without Certificate Verification",
                                description=(
                                    f"HTTP request with verify=False at line {node.lineno} disables SSL/TLS certificate validation. "
                                    f"KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                                    f"disabling certificate verification allows man-in-the-middle attacks, "
                                    f"connection hijacking, and impersonation of trusted services."
                                ),
                                file_path=file_path,
                                line_number=node.lineno,
                                snippet=self._get_snippet(lines, node.lineno, context=3),
                                remediation=(
                                    "Enable certificate verification (default behavior):\n"
                                    "import requests\n\n"
                                    "# Option 1: Use default verification (recommended)\n"
                                    "response = requests.get('https://api.example.com/data')\n"
                                    "# verify=True is default, no need to specify\n\n"
                                    "# Option 2: Explicit verification with custom CA bundle\n"
                                    "response = requests.get(\n"
                                    "    'https://api.example.com/data',\n"
                                    "    verify='/path/to/ca-bundle.crt'\n"
                                    ")\n\n"
                                    "# Option 3: Mutual TLS (mTLS) for service-to-service\n"
                                    "response = requests.get(\n"
                                    "    'https://api.example.com/data',\n"
                                    "    cert=('/path/to/client.crt', '/path/to/client.key'),\n"
                                    "    verify='/path/to/ca-bundle.crt'\n"
                                    ")\n\n"
                                    "NEVER use verify=False in production!\n\n"
                                    "Ref: NIST SP 800-52 Rev. 2 - Guidelines for TLS Implementations "
                                    "(https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                                ),
                                ksi_id=self.KSI_ID
                            ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        if re.search(r'verify\s*=\s*False', code):
            result = self._find_line(lines, r'verify\s*=\s*False', use_regex=True)
            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="HTTP Request Without Certificate Verification (Regex Fallback)",
                    description=(
                        f"Detected verify=False at line {line_num}. "
                        f"This disables SSL/TLS certificate validation."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Enable certificate verification by removing verify=False or using verify=True.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-09 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - ServerCertificateValidationCallback that always returns true
        - Missing certificate validation in HttpClient
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: ServerCertificateValidationCallback => true (CRITICAL)
        if re.search(r'ServerCertificateValidationCallback.*=>\s*true', code):
            result = self._find_line(lines, r'ServerCertificateValidationCallback', use_regex=True)
            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Certificate Validation Callback Always Returns True",
                    description=(
                        f"ServerCertificateValidationCallback at line {line_num} configured to always return true, disabling certificate validation. "
                        f"KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                        f"bypassing certificate validation allows man-in-the-middle attacks, "
                        f"connection hijacking, and impersonation of trusted services."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Remove or properly implement certificate validation:\n"
                        "// Option 1: Use default validation (recommended)\n"
                        "using var httpClient = new HttpClient();\n"
                        "// Default behavior validates certificates\n\n"
                        "// Option 2: Custom validation with proper checks\n"
                        "var handler = new HttpClientHandler\n"
                        "{{\n"
                        "    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>\n"
                        "    {{\n"
                        "        // Only accept specific certificate thumbprints\n"
                        "        var allowedThumbprints = new[] {{ \"expected-thumbprint\" }};\n"
                        "        return errors == SslPolicyErrors.None &&\n"
                        "               allowedThumbprints.Contains(cert.GetCertHashString());\n"
                        "    }}\n"
                        "}};\n\n"
                        "// Option 3: Mutual TLS (mTLS) for service-to-service\n"
                        "var clientCert = new X509Certificate2(\"/path/to/client.pfx\", \"password\");\n"
                        "var handler = new HttpClientHandler();\n"
                        "handler.ClientCertificates.Add(clientCert);\n"
                        "using var httpClient = new HttpClient(handler);\n\n"
                        "NEVER bypass certificate validation in production!\n\n"
                        "Ref: .NET Security Best Practices (https://learn.microsoft.com/dotnet/standard/security/security-best-practices)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-09 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Trust-all TrustManager implementations
        - HostnameVerifier that always returns true
        - Missing certificate validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Empty checkServerTrusted() in TrustManager (CRITICAL)
        if re.search(r'X509TrustManager.*checkServerTrusted.*\{\s*\}', code, re.DOTALL):
            result = self._find_line(lines, r'checkServerTrusted', use_regex=True)
            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Trust-All TrustManager Implementation",
                    description=(
                        f"Custom TrustManager with empty checkServerTrusted() at line {line_num}, disabling certificate validation. "
                        f"KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                        f"trust-all TrustManagers accept any certificate, allowing man-in-the-middle attacks, "
                        f"connection hijacking, and impersonation of trusted services."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use default TrustManager or implement proper validation:\n"
                        "// Option 1: Use default SSL context (recommended)\n"
                        "HttpClient client = HttpClient.newBuilder()\n"
                        "    .sslContext(SSLContext.getDefault())\n"
                        "    .build();\n\n"
                        "// Option 2: Custom TrustManager with proper validation\n"
                        "TrustManagerFactory tmf = TrustManagerFactory.getInstance(\n"
                        "    TrustManagerFactory.getDefaultAlgorithm()\n"
                        ");\n"
                        "KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());\n"
                        "try (InputStream is = new FileInputStream(\"/path/to/truststore.jks\")) {{\n"
                        "    ks.load(is, \"password\".toCharArray());\n"
                        "}}\n"
                        "tmf.init(ks);\n"
                        "SSLContext sslContext = SSLContext.getInstance(\"TLS\");\n"
                        "sslContext.init(null, tmf.getTrustManagers(), null);\n\n"
                        "// Option 3: Mutual TLS (mTLS) for service-to-service\n"
                        "KeyManagerFactory kmf = KeyManagerFactory.getInstance(\n"
                        "    KeyManagerFactory.getDefaultAlgorithm()\n"
                        ");\n"
                        "KeyStore clientKs = KeyStore.getInstance(\"PKCS12\");\n"
                        "try (InputStream is = new FileInputStream(\"/path/to/client.p12\")) {{\n"
                        "    clientKs.load(is, \"password\".toCharArray());\n"
                        "}}\n"
                        "kmf.init(clientKs, \"password\".toCharArray());\n"
                        "sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);\n\n"
                        "NEVER use trust-all TrustManagers in production!\n\n"
                        "Ref: Java PKI Programmer's Guide (https://docs.oracle.com/en/java/javase/17/security/java-pki-programmers-guide.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-09 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - HTTPS agent with rejectUnauthorized: false
        - Missing certificate validation in fetch/axios
        - Insecure TLS configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: rejectUnauthorized: false (CRITICAL)
        if re.search(r'rejectUnauthorized\s*:\s*false', code):
            result = self._find_line(lines, r'rejectUnauthorized', use_regex=True)
            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Certificate Validation Disabled (rejectUnauthorized: false)",
                description=(
                    "HTTPS agent configured with rejectUnauthorized: false, disabling certificate validation. "
                    "KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                    "disabling certificate validation allows man-in-the-middle attacks, "
                    "connection hijacking, and impersonation of trusted services."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Enable certificate validation (default behavior):\n"
                    "// Option 1: Use default HTTPS agent (recommended)\n"
                    "import https from 'https';\n"
                    "import axios from 'axios';\n\n"
                    "const response = await axios.get('https://api.example.com/data');\n"
                    "// Default behavior validates certificates\n\n"
                    "// Option 2: Custom CA bundle for self-signed certificates\n"
                    "import fs from 'fs';\n"
                    "const ca = fs.readFileSync('/path/to/ca-bundle.crt');\n"
                    "const agent = new https.Agent({ ca });\n"
                    "const response = await axios.get('https://api.example.com/data', {\n"
                    "  httpsAgent: agent\n"
                    "});\n\n"
                    "// Option 3: Mutual TLS (mTLS) for service-to-service\n"
                    "const cert = fs.readFileSync('/path/to/client.crt');\n"
                    "const key = fs.readFileSync('/path/to/client.key');\n"
                    "const ca = fs.readFileSync('/path/to/ca-bundle.crt');\n"
                    "const agent = new https.Agent({ cert, key, ca });\n"
                    "const response = await axios.get('https://api.example.com/data', {\n"
                    "  httpsAgent: agent\n"
                    "});\n\n"
                    "NEVER use rejectUnauthorized: false in production!\n\n"
                    "Ref: Node.js HTTPS Module (https://nodejs.org/api/https.html#https_https_request_url_options_callback)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-09 compliance.
        
        Detects:
        - Application Gateway without proper SSL policy
        - API Management without client certificate validation
        - Front Door without HTTPS enforcement
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Application Gateway without SSL policy (MEDIUM)
        appgw_result = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Network/applicationGateways@", use_regex=True)
        
        if appgw_result:
            line_num = appgw_result['line_num']
            # Check if sslPolicy is configured in the resource block
            has_ssl_policy = any('sslPolicy' in line for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_ssl_policy:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Application Gateway Without Proper SSL Policy",
                    description=(
                        "Application Gateway resource without sslPolicy configuration. "
                        "KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                        "missing SSL policy may allow weak TLS versions (1.0/1.1) or insecure cipher suites, "
                        "weakening communication security."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure Application Gateway with secure SSL policy:\n"
                        "resource appGateway 'Microsoft.Network/applicationGateways@2023-05-01' = {\n"
                        "  name: appGatewayName\n"
                        "  location: location\n"
                        "  properties: {\n"
                        "    sslPolicy: {\n"
                        "      policyType: 'Predefined'\n"
                        "      policyName: 'AppGwSslPolicy20220101'  // TLS 1.2+\n"
                        "    }\n"
                        "    // Or custom policy with strong ciphers:\n"
                        "    // sslPolicy: {\n"
                        "    //   policyType: 'Custom'\n"
                        "    //   minProtocolVersion: 'TLSv1_2'\n"
                        "    //   cipherSuites: [\n"
                        "    //     'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'\n"
                        "    //     'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'\n"
                        "    //   ]\n"
                        "    // }\n"
                        "    // ... other properties\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Application Gateway SSL Policy (https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: API Management without client certificate validation (MEDIUM)
        apim_result = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.ApiManagement/service@", use_regex=True)
        
        if apim_result:
            line_num = apim_result['line_num']
            # Check if customProperties with client cert validation exists
            has_cert_validation = any('Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30' in line 
                                     for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_cert_validation:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="API Management Without Backend Certificate Validation",
                    description=(
                        "API Management service without backend certificate validation configuration. "
                        "KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                        "missing backend certificate validation may allow connections to untrusted backend services."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure API Management with backend certificate validation:\n"
                        "resource apimService 'Microsoft.ApiManagement/service@2023-03-01-preview' = {\n"
                        "  name: apimServiceName\n"
                        "  location: location\n"
                        "  properties: {\n"
                        "    customProperties: {\n"
                        "      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30': 'false'\n"
                        "      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10': 'false'\n"
                        "      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11': 'false'\n"
                        "      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': 'false'\n"
                        "      'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11': 'false'\n"
                        "    }\n"
                        "    // ... other properties\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure API Management Security (https://learn.microsoft.com/azure/api-management/api-management-howto-mutual-certificates)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-09 compliance.
        
        Detects:
        - Application Gateway without SSL policy
        - API Management without TLS settings
        - Storage/Database without SSL enforcement
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Application Gateway without SSL policy (MEDIUM)
        appgw_result = self._find_line(lines, r'resource\s+"azurerm_application_gateway"', use_regex=True)
        
        if appgw_result:
            line_num = appgw_result['line_num']
            # Check if ssl_policy block exists
            has_ssl_policy = any('ssl_policy' in line for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_ssl_policy:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Application Gateway Without SSL Policy",
                    description=(
                        "azurerm_application_gateway resource without ssl_policy configuration. "
                        "KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                        "missing SSL policy may allow weak TLS versions or insecure cipher suites."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure Application Gateway with secure SSL policy:\n"
                        'resource "azurerm_application_gateway" "example" {\n'
                        '  name                = "example-appgw"\n'
                        '  resource_group_name = azurerm_resource_group.example.name\n'
                        '  location            = azurerm_resource_group.example.location\n\n'
                        '  ssl_policy {\n'
                        '    policy_type = "Predefined"\n'
                        '    policy_name = "AppGwSslPolicy20220101"  # TLS 1.2+\n'
                        '  }\n\n'
                        '  # Or custom policy:\n'
                        '  # ssl_policy {\n'
                        '  #   policy_type          = "Custom"\n'
                        '  #   min_protocol_version = "TLSv1_2"\n'
                        '  #   cipher_suites = [\n'
                        '  #     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",\n'
                        '  #     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"\n'
                        '  #   ]\n'
                        '  # }\n'
                        '  # ... other configuration\n'
                        '}\n\n'
                        "Ref: Terraform azurerm_application_gateway (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway#ssl_policy)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Storage Account without HTTPS enforcement (HIGH)
        storage_result = self._find_line(lines, r'resource\s+"azurerm_storage_account"', use_regex=True)
        
        if storage_result:
            line_num = storage_result['line_num']
            # Check for enable_https_traffic_only = false
            has_https_disabled_result = self._find_line(
                lines[line_num:min(line_num+30, len(lines))],
                r'enable_https_traffic_only\s*=\s*false',
                use_regex=True
            )
            
            if has_https_disabled_result:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Storage Account With HTTPS Disabled",
                    description=(
                        "azurerm_storage_account configured with enable_https_traffic_only = false. "
                        "KSI-SVC-09 requires persistent validation of communication authenticity and integrity (SC-23, SI-7.1) - "
                        "allowing HTTP traffic exposes data to eavesdropping and man-in-the-middle attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num + has_https_disabled_result['line_num'] if has_https_disabled_result else line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Enable HTTPS-only traffic for Storage Account:\n"
                        'resource "azurerm_storage_account" "example" {\n'
                        '  name                     = "examplestorageacct"\n'
                        '  resource_group_name      = azurerm_resource_group.example.name\n'
                        '  location                 = azurerm_resource_group.example.location\n'
                        '  account_tier             = "Standard"\n'
                        '  account_replication_type = "GRS"\n\n'
                        '  enable_https_traffic_only = true  # Enforce HTTPS\n'
                        '  min_tls_version          = "TLS1_2"\n'
                        '}\n\n'
                        "Ref: Terraform azurerm_storage_account (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#enable_https_traffic_only)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-09 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-09 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-09 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-SVC-09.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Communication Integrity",
            "evidence_type": "log-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Azure Application Gateway",
                "Azure Front Door",
                "Azure Policy",
                "Azure Monitor",
                "Microsoft Defender for Cloud"
            ],
            "collection_methods": [
                "Azure Application Gateway and Front Door WAF logs to track TLS handshakes and certificate validation",
                "Azure Policy to enforce minimum TLS versions and mutual TLS (mTLS) authentication",
                "Azure Monitor to track message integrity failures and certificate validation errors",
                "Defender for Cloud recommendations for weak TLS/SSL configurations and missing integrity controls"
            ],
            "implementation_steps": [
                "1. Enable Azure Application Gateway with mutual TLS: (a) Configure TLS termination with minimum TLS 1.2, (b) Enable client certificate authentication, (c) Configure trusted root certificate chain, (d) Enable WAF for request/response inspection",
                "2. Deploy Azure Policy initiative 'Communication Integrity Controls': (a) Audit services without HTTPS enforcement, (b) Require TLS >= 1.2 for all external endpoints, (c) Deny weak cipher suites, (d) Audit missing certificate pinning",
                "3. Configure Azure Front Door end-to-end TLS: (a) Enable HTTPS-only mode, (b) Configure custom domain with TLS certificate, (c) Enable origin certificate validation, (d) Configure health probes with integrity checks",
                "4. Build Azure Monitor workbook 'Communication Integrity Dashboard': (a) TLS version distribution, (b) Certificate validation failures, (c) Cipher suite usage, (d) Message integrity check failures, (e) mTLS adoption rate",
                "5. Enable diagnostic logging for all gateway/Front Door resources: (a) ApplicationGatewayAccessLog, (b) ApplicationGatewayFirewallLog, (c) Front Door access logs with TLS details",
                "6. Generate monthly evidence package via Azure Automation: (a) Export gateway/Front Door TLS metrics, (b) Export Policy compliance for integrity controls, (c) Export Defender TLS/SSL recommendations, (d) Export certificate validation logs"
            ],
            "evidence_artifacts": [
                "Application Gateway/Front Door TLS Handshake Logs showing certificate validation and cipher negotiation",
                "Azure Policy Compliance Report for communication integrity requirements (TLS versions, mTLS, HTTPS enforcement)",
                "Azure Monitor Certificate Validation Error Logs tracking integrity check failures",
                "Defender for Cloud TLS/SSL Recommendations Report identifying weak configurations",
                "Communication Integrity Dashboard from Azure Monitor with monthly snapshots of TLS adoption and compliance"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team / Network Operations Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "TLS handshake and certificate validation audit",
                "query": """AzureDiagnostics
| where ResourceType in ('APPLICATIONGATEWAYS', 'FRONTDOORS')
| where Category in ('ApplicationGatewayAccessLog', 'ApplicationGatewayFirewallLog', 'FrontDoorAccessLog')
| extend TLSVersion = tostring(parse_json(tlsVersion_s))
| extend CertValidation = tostring(parse_json(sslValidation_s))
| summarize HandshakeCount = count(), FailedValidations = countif(CertValidation == 'Failed'), TLSVersions = make_set(TLSVersion) by Resource, bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
                "purpose": "Track TLS handshakes and certificate validation to ensure communication integrity"
            },
            {
                "query_type": "Azure Policy REST API",
                "query_name": "Communication integrity policy compliance",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01&$filter=policyDefinitionCategory eq 'Network' and (policyDefinitionName contains 'TLS' or policyDefinitionName contains 'HTTPS')",
                "purpose": "Retrieve policy compliance for TLS versions, HTTPS enforcement, and communication integrity controls"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Services without HTTPS/TLS enforcement",
                "query": """Resources
| where type in ('microsoft.web/sites', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/applicationgateways')
| extend HTTPSOnly = case(
    type == 'microsoft.web/sites', properties.httpsOnly,
    type == 'microsoft.storage/storageaccounts', properties.supportsHttpsTrafficOnly,
    type == 'microsoft.sql/servers', properties.minimalTlsVersion,
    type == 'microsoft.network/applicationgateways', properties.sslPolicy.minProtocolVersion,
    'unknown'
)
| where HTTPSOnly == false or HTTPSOnly < '1.2' or HTTPSOnly == 'unknown'
| project name, type, resourceGroup, HTTPSOnly, location
| order by type asc""",
                "purpose": "Identify Azure services without HTTPS/TLS enforcement for communication integrity gaps"
            },
            {
                "query_type": "Microsoft Defender for Cloud REST API",
                "query_name": "TLS/SSL security recommendations",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01&$filter=properties/displayName contains 'TLS' or properties/displayName contains 'SSL' or properties/displayName contains 'certificate'",
                "purpose": "Retrieve Defender recommendations for weak TLS/SSL configurations impacting communication integrity"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Message integrity check failures",
                "query": """AzureDiagnostics
| where ResourceType in ('APPLICATIONGATEWAYS', 'FRONTDOORS')
| where httpStatus_d >= 400 or tlsHandshakeStatus_s == 'Failed'
| extend FailureReason = coalesce(errorInfo_s, httpStatusDetails_s, 'Unknown')
| summarize FailureCount = count() by Resource, FailureReason, bin(TimeGenerated, 1h)
| order by FailureCount desc""",
                "purpose": "Detect message integrity check failures and TLS handshake errors indicating potential tampering"
            }
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect.
        
        Returns:
            List of artifact dictionaries
        """
        return [
            {
                "artifact_name": "Application Gateway/Front Door TLS Logs",
                "artifact_type": "Azure Diagnostic Logs",
                "description": "Complete logs of TLS handshakes, certificate validation, and cipher suite negotiation for all gateway traffic",
                "collection_method": "Azure Monitor KQL query exporting ApplicationGatewayAccessLog and FrontDoorAccessLog with TLS details",
                "storage_location": "Azure Log Analytics workspace with 12-month retention for compliance auditing"
            },
            {
                "artifact_name": "Communication Integrity Policy Compliance Report",
                "artifact_type": "Azure Policy Report",
                "description": "Policy compliance status for TLS versions, HTTPS enforcement, and mTLS requirements",
                "collection_method": "Azure Policy Insights API to export compliance for communication integrity policies",
                "storage_location": "Azure Storage Account with monthly compliance snapshots"
            },
            {
                "artifact_name": "Certificate Validation Error Logs",
                "artifact_type": "Azure Monitor Logs",
                "description": "Logs of certificate validation failures and message integrity check errors",
                "collection_method": "Azure Monitor KQL query filtering for TLS handshake failures and certificate validation errors",
                "storage_location": "Azure Log Analytics workspace with alerting for critical validation failures"
            },
            {
                "artifact_name": "Defender TLS/SSL Recommendations Report",
                "artifact_type": "Security Recommendations Export",
                "description": "Report of all Defender for Cloud recommendations related to weak TLS/SSL configurations and missing integrity controls",
                "collection_method": "Microsoft Defender for Cloud REST API to retrieve and filter TLS/SSL security recommendations",
                "storage_location": "Azure Storage Account with JSON exports organized by severity"
            },
            {
                "artifact_name": "Communication Integrity Dashboard",
                "artifact_type": "Azure Monitor Workbook",
                "description": "Comprehensive dashboard showing TLS version adoption, certificate validation status, cipher usage, and integrity failures",
                "collection_method": "Azure Monitor workbook aggregating data from Application Gateway, Front Door, and Policy compliance",
                "storage_location": "Azure Monitor Workbooks with monthly PDF exports archived to Storage Account"
            }
        ]
    