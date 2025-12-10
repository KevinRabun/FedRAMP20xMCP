"""
KSI-IAM-03: Non-User Accounts

Enforce appropriately secure authentication methods for non-user accounts and services.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_IAM_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-IAM-03: Non-User Accounts
    
    **Official Statement:**
    Enforce appropriately secure authentication methods for non-user accounts and services.
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2
    - ac-2.2
    - ac-4
    - ac-6.5
    - ia-3
    - ia-5.2
    - ra-5.5
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Enforce appropriately secure authentication methods for non-user accounts and services....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-IAM-03"
    KSI_NAME = "Non-User Accounts"
    KSI_STATEMENT = """Enforce appropriately secure authentication methods for non-user accounts and services."""
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-2", "Account Management"),
        ("ac-2.2", "Automated Temporary and Emergency Account Management"),
        ("ac-4", "Information Flow Enforcement"),
        ("ac-6.5", "Privileged Accounts"),
        ("ia-3", "Device Identification and Authentication"),
        ("ia-5.2", "Public Key-based Authentication"),
        ("ra-5.5", "Privileged Access")
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
        Analyze Python code for KSI-IAM-03 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Service account passwords in code
        - Missing managed identity usage
        - Hardcoded service principal credentials
        - DefaultAzureCredential validation
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_python_ast(code, file_path, parser, tree)
        else:
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Python analysis for service account credentials."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        root_node = tree.root_node
        
        try:
            # Track secure credential types
            has_azure_identity_import = False
            has_default_credential = False
            has_managed_identity = False
            has_certificate_credential = False
            has_service_principal_creds = False
            
            # Check imports for Azure Identity and credential types
            import_nodes = (parser.find_nodes_by_type(root_node, 'import_from_statement') +
                          parser.find_nodes_by_type(root_node, 'import_statement'))
            for node in import_nodes:
                import_text = parser.get_node_text(node, code_bytes)
                
                if 'azure.identity' in import_text.lower():
                    has_azure_identity_import = True
                    
                    if 'DefaultAzureCredential' in import_text:
                        has_default_credential = True
                    if 'ManagedIdentityCredential' in import_text:
                        has_managed_identity = True
                    if 'CertificateCredential' in import_text:
                        has_certificate_credential = True
                
                if 'ServicePrincipalCredentials' in import_text:
                    has_service_principal_creds = True
            
            # Check for hardcoded service account credentials (assignment nodes)
            service_cred_keywords = [
                'service_account_password', 'service_account_key',
                'service_principal_secret', 'app_password', 
                'client_secret', 'serviceAccountPassword', 'servicePrincipalSecret'
            ]
            
            for node in parser.find_nodes_by_type(root_node, 'assignment'):
                assignment_text = parser.get_node_text(node, code_bytes)
                
                # Check if it's a hardcoded credential (not from env/config)
                for keyword in service_cred_keywords:
                    if keyword in assignment_text.lower() and '=' in assignment_text:
                        # Check if it's hardcoded (string literal on right side)
                        if any(quote in assignment_text for quote in ['"', "'"]):
                            # Exclude environment variables and config access
                            if not any(safe_pattern in assignment_text for safe_pattern in 
                                     ['os.environ', 'os.getenv', 'config[', 'settings.', 'Configuration[']):
                                line_num = node.start_point[0] + 1
                                findings.append(Finding(
                                    severity=Severity.CRITICAL,
                                    title="Service Account Credentials Hardcoded",
                                    description=(
                                        f"Service account credentials found hardcoded in code at line {line_num}. "
                                        f"Non-user accounts must use secure authentication methods like managed identities "
                                        f"or certificate-based authentication, never hardcoded passwords."
                                    ),
                                    file_path=file_path,
                                    line_number=line_num,
                                    snippet=self._get_snippet(lines, line_num),
                                    remediation=(
                                        "Use Azure Managed Identity (DefaultAzureCredential) or certificate-based "
                                        "authentication for service accounts. Store credentials in Azure Key Vault "
                                        "if managed identities cannot be used."
                                    ),
                                    ksi_id=self.KSI_ID
                                ))
                                break
            
            # Finding 2: Weak credential type when Azure Identity is imported
            if has_azure_identity_import:
                # Check if using weak credential types
                has_weak_credential = False
                for node in parser.find_nodes_by_type(root_node, 'call'):
                    call_text = parser.get_node_text(node, code_bytes)
                    if 'ClientSecretCredential' in call_text:
                        has_weak_credential = True
                        break
                
                if has_weak_credential or not (has_default_credential or has_managed_identity or has_certificate_credential):
                    result = self._find_line(lines, r'from azure\.identity|import azure\.identity|ClientSecretCredential')

                    line_num = result['line_num'] if result else 0
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Weak Credential Type for Service Authentication",
                        description=(
                            "Azure SDK authentication detected but not using recommended credential types. "
                            "Service accounts should use DefaultAzureCredential, ManagedIdentityCredential, "
                            "or CertificateCredential for secure authentication."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use DefaultAzureCredential() which automatically uses managed identity in Azure, "
                            "or explicitly use ManagedIdentityCredential() or CertificateCredential() for "
                            "service accounts."
                        ),
                        ksi_id=self.KSI_ID
                    ))
            
            # Finding 3: ServicePrincipalCredentials with password parameter
            if has_service_principal_creds:
                for node in parser.find_nodes_by_type(root_node, 'call'):
                    call_text = parser.get_node_text(node, code_bytes)
                    if 'ServicePrincipalCredentials' in call_text and 'password' in call_text.lower():
                        line_num = node.start_point[0] + 1
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Service Principal Using Password Authentication",
                            description=(
                                f"Service principal configured with password authentication at line {line_num}. "
                                f"Non-user accounts must use certificate-based authentication or managed identities, "
                                f"not password-based authentication."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num),
                            remediation=(
                                "Use certificate-based authentication with CertificateCredential or managed "
                                "identities with DefaultAzureCredential/ManagedIdentityCredential."
                            ),
                            ksi_id=self.KSI_ID
                        ))
                        break
        
        except Exception as e:
            # Fallback to regex-based analysis
            return self._analyze_python_regex(code, file_path)
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based fallback for Python analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Service account password/credential in code (CRITICAL)
        service_cred_patterns = [
            r'service[_-]?account[_-]?password\s*=\s*["\']',
            r'service[_-]?principal[_-]?secret\s*=\s*["\']',
            r'app[_-]?password\s*=\s*["\']',
            r'client[_-]?secret\s*=\s*["\'](?!\{\{|\$\{)',  # Not templated
            r'service[_-]?account[_-]?key\s*=\s*["\']'
        ]
        
        for pattern in service_cred_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Account Credentials Hardcoded",
                    description=(
                        f"Service account credentials found hardcoded in code at line {line_num}. "
                        f"Non-user accounts must use secure authentication methods like managed identities "
                        f"or certificate-based authentication, never hardcoded passwords."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use Azure Managed Identity (DefaultAzureCredential) or certificate-based "
                        "authentication for service accounts. Store credentials in Azure Key Vault "
                        "if managed identities cannot be used."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Missing DefaultAzureCredential (HIGH)
        if re.search(r'from azure\.identity import \w+Credential', code, re.IGNORECASE):
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential|CertificateCredential', code):
                result = self._find_line(lines, r'from azure\.identity', use_regex=True)
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Weak Credential Type for Service Authentication",
                    description=(
                        "Azure SDK authentication detected but not using recommended credential types. "
                        "Service accounts should use DefaultAzureCredential, ManagedIdentityCredential, "
                        "or CertificateCredential for secure authentication."
                    ),
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    remediation=(
                        "Use DefaultAzureCredential() which automatically uses managed identity in Azure, "
                        "or explicitly use ManagedIdentityCredential() or CertificateCredential() for "
                        "service accounts."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Service account with password authentication (CRITICAL)
        if re.search(r'ServicePrincipalCredentials\s*\(.*password\s*=', code, re.IGNORECASE):
            result = self._find_line(lines, r'ServicePrincipalCredentials')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Service Principal Using Password Authentication",
                description=(
                    f"Service principal configured with password authentication at line {line_num}. "
                    f"Non-user accounts must use certificate-based authentication or managed identities, "
                    f"not password-based authentication."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use certificate-based authentication with CertificateCredential or managed "
                    "identities with DefaultAzureCredential/ManagedIdentityCredential."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-03 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Hardcoded service principal credentials
        - Missing managed identity configuration
        - Password-based service account authentication
        - Certificate-based authentication validation
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based C# analysis for service account credentials."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        root_node = tree.root_node
        
        has_azure_import = False
        has_default_credential = False
        has_managed_identity = False
        has_azure_client = False
        
        # Check using directives
        for node in parser.find_nodes_by_type(root_node, 'using_directive'):
            using_text = parser.get_node_text(node, code_bytes)
            if 'Azure.' in using_text:
                has_azure_import = True
            if 'DefaultAzureCredential' in using_text:
                has_default_credential = True
            if 'ManagedIdentityCredential' in using_text:
                has_managed_identity = True
        
        # Check for hardcoded credentials in object creation and assignments
        nodes_to_check = []
        nodes_to_check.extend(parser.find_nodes_by_type(root_node, 'object_creation_expression'))
        nodes_to_check.extend(parser.find_nodes_by_type(root_node, 'assignment_expression'))
        
        for node in nodes_to_check:
            node_text = parser.get_node_text(node, code_bytes)
            
            # Check for ClientSecretCredential with hardcoded secret
            if 'ClientSecretCredential' in node_text and '"' in node_text:
                if not any(safe in node_text for safe in ['Configuration[', 'Environment.']):
                    line_num = node.start_point[0] + 1
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Service Principal Credentials Hardcoded",
                        description=(
                            f"Service principal credentials found hardcoded at line {line_num}. "
                            f"Non-user accounts must use managed identities or certificate-based "
                            f"authentication, never hardcoded secrets."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Use DefaultAzureCredential or ManagedIdentityCredential for Azure services. "
                            "If service principal is required, use CertificateCredential with certificates "
                            "stored in Azure Key Vault or Windows Certificate Store."
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
            
            # Check for hardcoded secrets in assignments
            if any(keyword in node_text for keyword in ['ServicePrincipalSecret', 'AppPassword', 'ClientSecret']):
                if '=' in node_text and '"' in node_text:
                    if not any(safe in node_text for safe in ['Configuration[', 'Environment.']):
                        line_num = node.start_point[0] + 1
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Service Principal Credentials Hardcoded",
                            description=(
                                f"Service principal credentials found hardcoded at line {line_num}. "
                                f"Non-user accounts must use managed identities or certificate-based "
                                f"authentication, never hardcoded secrets."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num),
                            remediation=(
                                "Use DefaultAzureCredential or ManagedIdentityCredential for Azure services. "
                                "If service principal is required, use CertificateCredential with certificates "
                                "stored in Azure Key Vault or Windows Certificate Store."
                            ),
                            ksi_id=self.KSI_ID
                        ))
                        break
            
            # Check for Azure client instantiation
            if 'Client(' in node_text and 'new' in node_text:
                has_azure_client = True
        
        # Finding 2: Azure SDK without managed identity
        if has_azure_import and has_azure_client:
            if not (has_default_credential or has_managed_identity):
                result = self._find_line(lines, r'new\s+\w+Client')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Azure SDK Client Without Managed Identity",
                    description=(
                        f"Azure SDK client instantiation at line {line_num} not using managed identity. "
                        f"Service accounts should authenticate using DefaultAzureCredential or "
                        f"ManagedIdentityCredential for secure, credential-less authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use: new DefaultAzureCredential() or new ManagedIdentityCredential() "
                        "when creating Azure SDK clients for service accounts."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Finding 3: Password-based authentication
        for node in parser.find_nodes_by_type(root_node, 'invocation_expression'):
            node_text = parser.get_node_text(node, code_bytes)
            if 'UsePassword' in node_text or 'UseBasicAuthentication' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Account Using Password Authentication",
                    description=(
                        f"Service account configured with password/basic authentication at line {line_num}. "
                        f"Non-user accounts must use certificate-based or managed identity authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Configure certificate-based authentication with .UseCertificate() or use "
                        "managed identities with Azure.Identity SDK."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based fallback for C# analysis."""
        findings = []
        lines = code.split('\n')
        
        sp_cred_patterns = [
            r'new\s+ClientSecretCredential\s*\([^)]*["\'][^"\'{]+["\']',
            r'ServicePrincipalSecret\s*=\s*["\']',
            r'AppPassword\s*=\s*["\']',
            r'ClientSecret\s*=\s*["\'](?!Configuration\[|Environment\.)',
        ]
        
        for pattern in sp_cred_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Principal Credentials Hardcoded",
                    description=(
                        f"Service principal credentials found hardcoded at line {line_num}. "
                        f"Non-user accounts must use managed identities or certificate-based "
                        f"authentication, never hardcoded secrets."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use DefaultAzureCredential or ManagedIdentityCredential for Azure services. "
                        "If service principal is required, use CertificateCredential with certificates "
                        "stored in Azure Key Vault or Windows Certificate Store."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        if re.search(r'new\s+\w+Client\s*\(', code) and re.search(r'using Azure\.', code):
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential|ChainedTokenCredential', code):
                result = self._find_line(lines, r'new\s+\w+Client')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Azure SDK Client Without Managed Identity",
                    description=(
                        f"Azure SDK client instantiation at line {line_num} not using managed identity. "
                        f"Service accounts should authenticate using DefaultAzureCredential or "
                        f"ManagedIdentityCredential for secure, credential-less authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use: new DefaultAzureCredential() or new ManagedIdentityCredential() "
                        "when creating Azure SDK clients for service accounts."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        if re.search(r'AddAuthentication.*\.UsePassword|UseBasicAuthentication', code, re.IGNORECASE):
            result = self._find_line(lines, r'UsePassword|UseBasicAuthentication')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Service Account Using Password Authentication",
                description=(
                    f"Service account configured with password/basic authentication at line {line_num}. "
                    f"Non-user accounts must use certificate-based or managed identity authentication."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Configure certificate-based authentication with .UseCertificate() or use "
                    "managed identities with Azure.Identity SDK."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-03 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Hardcoded service account credentials
        - Missing managed identity usage
        - Password-based service authentication
        - ClientSecretCredential validation
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Java analysis for service account credentials."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        root_node = tree.root_node
        
        has_azure_import = False
        has_default_credential = False
        has_managed_identity = False
        
        # Check imports
        for node in parser.find_nodes_by_type(root_node, 'import_declaration'):
            import_text = parser.get_node_text(node, code_bytes)
            if 'com.azure.' in import_text:
                has_azure_import = True
            if 'DefaultAzureCredentialBuilder' in import_text:
                has_default_credential = True
            if 'ManagedIdentityCredentialBuilder' in import_text:
                has_managed_identity = True
        
        # Check for hardcoded credentials in method invocations
        for node in parser.find_nodes_by_type(root_node, 'method_invocation'):
            node_text = parser.get_node_text(node, code_bytes)
            
            # Check for hardcoded secrets
            if any(keyword in node_text for keyword in ['setClientSecret', 'clientSecret', 'withPassword']):
                if '"' in node_text:
                    if not any(safe in node_text for safe in ['System.getenv', 'config.get', 'properties.']):
                        line_num = node.start_point[0] + 1
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Service Account Credentials Hardcoded in Code",
                            description=(
                                f"Service account credentials found hardcoded at line {line_num}. "
                                f"Non-user accounts must use managed identities or certificate-based "
                                f"authentication for Azure services."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num),
                            remediation=(
                                "Use DefaultAzureCredentialBuilder or ManagedIdentityCredentialBuilder for "
                                "service accounts. If certificates are needed, use ClientCertificateCredentialBuilder "
                                "with certificates from Azure Key Vault."
                            ),
                            ksi_id=self.KSI_ID
                        ))
                        break
        
        # Check variable declarations for hardcoded passwords
        for node in parser.find_nodes_by_type(root_node, 'variable_declarator'):
            node_text = parser.get_node_text(node, code_bytes)
            if 'serviceAccountPassword' in node_text and '=' in node_text and '"' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Account Credentials Hardcoded in Code",
                    description=(
                        f"Service account credentials found hardcoded at line {line_num}. "
                        f"Non-user accounts must use managed identities or certificate-based "
                        f"authentication for Azure services."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use DefaultAzureCredentialBuilder or ManagedIdentityCredentialBuilder for "
                        "service accounts. If certificates are needed, use ClientCertificateCredentialBuilder "
                        "with certificates from Azure Key Vault."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        # Finding 2: Azure SDK without managed identity
        if has_azure_import and not (has_default_credential or has_managed_identity):
            result = self._find_line(lines, r'import com\.azure\.')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Azure SDK Without Managed Identity Credentials",
                description=(
                    f"Azure SDK usage detected at line {line_num} but not using managed identity. "
                    f"Service accounts should use DefaultAzureCredentialBuilder or "
                    f"ManagedIdentityCredentialBuilder for secure authentication."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use: new DefaultAzureCredentialBuilder().build() or "
                    "new ManagedIdentityCredentialBuilder().build() for service account authentication."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Finding 3: Basic authentication
        for node in parser.find_nodes_by_type(root_node, 'method_invocation'):
            node_text = parser.get_node_text(node, code_bytes)
            if 'httpBasic()' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Account Using Basic Authentication",
                    description=(
                        f"Service account configured with basic/password authentication at line {line_num}. "
                        f"Non-user accounts must use certificate-based or managed identity authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Configure certificate-based authentication or use managed identities. "
                        "For Spring Security, use x509() authentication or Azure AD integration."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        # Check for BasicAuthenticationEntryPoint in object creation
        for node in parser.find_nodes_by_type(root_node, 'object_creation_expression'):
            node_text = parser.get_node_text(node, code_bytes)
            if 'BasicAuthenticationEntryPoint' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Account Using Basic Authentication",
                    description=(
                        f"Service account configured with basic/password authentication at line {line_num}. "
                        f"Non-user accounts must use certificate-based or managed identity authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Configure certificate-based authentication or use managed identities. "
                        "For Spring Security, use x509() authentication or Azure AD integration."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based fallback for Java analysis."""
        findings = []
        lines = code.split('\n')
        
        sa_cred_patterns = [
            r'setClientSecret\s*\(\s*["\']',
            r'serviceAccountPassword\s*=\s*["\']',
            r'new\s+ClientSecretCredentialBuilder\(\).*clientSecret\(["\']',
            r'withPassword\(\s*["\']',
        ]
        
        for pattern in sa_cred_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Account Credentials Hardcoded in Code",
                    description=(
                        f"Service account credentials found hardcoded at line {line_num}. "
                        f"Non-user accounts must use managed identities or certificate-based "
                        f"authentication for Azure services."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use DefaultAzureCredentialBuilder or ManagedIdentityCredentialBuilder for "
                        "service accounts. If certificates are needed, use ClientCertificateCredentialBuilder "
                        "with certificates from Azure Key Vault."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        if re.search(r'import com\.azure\.', code):
            if not re.search(r'DefaultAzureCredentialBuilder|ManagedIdentityCredentialBuilder', code):
                result = self._find_line(lines, r'import com\.azure\.')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Azure SDK Without Managed Identity Credentials",
                    description=(
                        f"Azure SDK usage detected at line {line_num} but not using managed identity. "
                        f"Service accounts should use DefaultAzureCredentialBuilder or "
                        f"ManagedIdentityCredentialBuilder for secure authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use: new DefaultAzureCredentialBuilder().build() or "
                        "new ManagedIdentityCredentialBuilder().build() for service account authentication."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        if re.search(r'@Configuration.*BasicAuthenticationEntryPoint|httpBasic\(\)', code, re.IGNORECASE):
            result = self._find_line(lines, r'BasicAuthenticationEntryPoint|httpBasic')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Service Account Using Basic Authentication",
                description=(
                    f"Service account configured with basic/password authentication at line {line_num}. "
                    f"Non-user accounts must use certificate-based or managed identity authentication."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Configure certificate-based authentication or use managed identities. "
                    "For Spring Security, use x509() authentication or Azure AD integration."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-03 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Hardcoded service account tokens/secrets
        - Missing DefaultAzureCredential usage
        - API keys in service authentication
        - Managed identity configuration
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based TypeScript/JavaScript analysis for service account credentials."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        root_node = tree.root_node
        
        has_azure_identity = False
        has_default_credential = False
        has_managed_identity = False
        
        # Check imports
        for node in parser.find_nodes_by_type(root_node, 'import_statement'):
            import_text = parser.get_node_text(node, code_bytes)
            if '@azure/identity' in import_text:
                has_azure_identity = True
                if 'DefaultAzureCredential' in import_text:
                    has_default_credential = True
                if 'ManagedIdentityCredential' in import_text:
                    has_managed_identity = True
        
        # Check variable declarations for hardcoded tokens
        var_nodes = (parser.find_nodes_by_type(root_node, 'variable_declarator') + 
                     parser.find_nodes_by_type(root_node, 'lexical_declaration'))
        for node in var_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            
            # Check for hardcoded secrets
            if any(keyword in node_text for keyword in ['serviceAccountToken', 'clientSecret', 'apiKey', 'bearerToken']):
                if '=' in node_text and ('"' in node_text or "'" in node_text):
                    if not any(safe in node_text for safe in ['process.env', 'config.', '${']):
                        line_num = node.start_point[0] + 1
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Service Account Token Hardcoded",
                            description=(
                                f"Service account token/secret found hardcoded at line {line_num}. "
                                f"Non-user accounts must use managed identities or secure credential stores, "
                                f"never hardcoded tokens or API keys."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num),
                            remediation=(
                                "Use DefaultAzureCredential from @azure/identity for Azure services. "
                                "Store credentials in Azure Key Vault and retrieve via managed identity. "
                                "Use process.env for environment variables, never hardcode secrets."
                            ),
                            ksi_id=self.KSI_ID
                        ))
                        break
        
        # Check object properties for hardcoded credentials
        for node in parser.find_nodes_by_type(root_node, 'pair'):
            node_text = parser.get_node_text(node, code_bytes)
            if any(keyword in node_text for keyword in ['clientSecret:', 'apiKey:', 'serviceAccountToken:']):
                if ':' in node_text and ('"' in node_text or "'" in node_text):
                    if not any(safe in node_text for safe in ['process.env', 'config.', '${']):
                        line_num = node.start_point[0] + 1
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            title="Service Account Token Hardcoded",
                            description=(
                                f"Service account token/secret found hardcoded at line {line_num}. "
                                f"Non-user accounts must use managed identities or secure credential stores, "
                                f"never hardcoded tokens or API keys."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num),
                            remediation=(
                                "Use DefaultAzureCredential from @azure/identity for Azure services. "
                                "Store credentials in Azure Key Vault and retrieve via managed identity. "
                                "Use process.env for environment variables, never hardcode secrets."
                            ),
                            ksi_id=self.KSI_ID
                        ))
                        break
        
        # Finding 2: Azure Identity without managed identity
        if has_azure_identity and not (has_default_credential or has_managed_identity):
            result = self._find_line(lines, r'@azure/identity')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Azure Identity Without Managed Identity",
                description=(
                    f"Azure Identity package used at line {line_num} but not using recommended "
                    f"credential types. Service accounts should use DefaultAzureCredential or "
                    f"ManagedIdentityCredential for secure authentication."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use: new DefaultAzureCredential() or new ManagedIdentityCredential() "
                    "for service account authentication in Azure."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Finding 3: Basic authentication
        auth_nodes = (parser.find_nodes_by_type(root_node, 'call_expression') +
                     parser.find_nodes_by_type(root_node, 'member_expression'))
        for node in auth_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            # Check for passport.authenticate with basic or BasicStrategy usage
            if ('passport.authenticate' in node_text and 'basic' in node_text.lower()) or 'BasicStrategy' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Service Account Using Basic Authentication",
                    description=(
                        f"Service account configured with basic/username-password authentication at line {line_num}. "
                        f"Non-user accounts should use token-based, certificate, or managed identity authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use OAuth2 bearer tokens, client certificates, or Azure managed identities "
                        "for service-to-service authentication. Avoid username/password for non-user accounts."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        # Check for auth config objects with username
        for node in parser.find_nodes_by_type(root_node, 'object'):
            node_text = parser.get_node_text(node, code_bytes)
            if 'auth:' in node_text and 'username:' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Service Account Using Basic Authentication",
                    description=(
                        f"Service account configured with basic/username-password authentication at line {line_num}. "
                        f"Non-user accounts should use token-based, certificate, or managed identity authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use OAuth2 bearer tokens, client certificates, or Azure managed identities "
                        "for service-to-service authentication. Avoid username/password for non-user accounts."
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based fallback for TypeScript/JavaScript analysis."""
        findings = []
        lines = code.split('\n')
        
        token_patterns = [
            r'serviceAccountToken\s*[=:]\s*["\']',
            r'clientSecret\s*[=:]\s*["\'](?!process\.env|config\.|\$\{)',
            r'apiKey\s*[=:]\s*["\'](?!process\.env|config\.|\$\{)',
            r'bearerToken\s*[=:]\s*["\'](?!process\.env)',
        ]
        
        for pattern in token_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Service Account Token Hardcoded",
                    description=(
                        f"Service account token/secret found hardcoded at line {line_num}. "
                        f"Non-user accounts must use managed identities or secure credential stores, "
                        f"never hardcoded tokens or API keys."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use DefaultAzureCredential from @azure/identity for Azure services. "
                        "Store credentials in Azure Key Vault and retrieve via managed identity. "
                        "Use process.env for environment variables, never hardcode secrets."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        if re.search(r'from ["\']@azure/identity["\']|require\(["\']@azure/identity["\']\)', code):
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential|ChainedTokenCredential', code):
                result = self._find_line(lines, r'@azure/identity')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Azure Identity Without Managed Identity",
                    description=(
                        f"Azure Identity package used at line {line_num} but not using recommended "
                        f"credential types. Service accounts should use DefaultAzureCredential or "
                        f"ManagedIdentityCredential for secure authentication."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use: new DefaultAzureCredential() or new ManagedIdentityCredential() "
                        "for service account authentication in Azure."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        if re.search(r'passport\.authenticate\(["\']basic["\']|auth:\s*\{\s*username:', code, re.IGNORECASE):
            result = self._find_line(lines, r'basic["\']|auth:\s*\{')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Service Account Using Basic Authentication",
                description=(
                    f"Service account configured with basic/username-password authentication at line {line_num}. "
                    f"Non-user accounts should use token-based, certificate, or managed identity authentication."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use OAuth2 bearer tokens, client certificates, or Azure managed identities "
                    "for service-to-service authentication. Avoid username/password for non-user accounts."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-IAM-03 compliance.
        
        Detects:
        - Missing managed identity configuration
        - System-assigned vs user-assigned identity
        - Service principal without certificate authentication
        - Resources without identity configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Resources without managed identity (HIGH)
        resource_types = ['Microsoft.Web/sites', 'Microsoft.ContainerInstance/containerGroups', 
                         'Microsoft.Compute/virtualMachines', 'Microsoft.Logic/workflows']
        
        for resource_type in resource_types:
            if re.search(rf'resource.*{resource_type.split("/")[1]}.*{resource_type.split("/")[0]}', code, re.IGNORECASE):
                if not re.search(r'identity:\s*\{', code):
                    result = self._find_line(lines, resource_type.split('/')[1])
                    line_num = result['line_num'] if result else 0
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{resource_type} Without Managed Identity",
                        description=(
                            f"Azure resource {resource_type} at line {line_num} deployed without managed identity. "
                            f"Service resources should use managed identities for secure authentication to Azure services."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            f"Add managed identity configuration:\n"
                            f"identity: {{\n"
                            f"  type: 'SystemAssigned'  // or 'UserAssigned'\n"
                            f"}}\n"
                            f"Then grant RBAC permissions to the identity for required resources."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: User-assigned identity best practice (INFO)
        if re.search(r"type:\s*'SystemAssigned'", code):
            result = self._find_line(lines, r"type:\s*'SystemAssigned'")

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.INFO,
                title="Consider User-Assigned Managed Identity",
                description=(
                    f"System-assigned managed identity used at line {line_num}. "
                    f"For production workloads, consider user-assigned managed identities for "
                    f"better lifecycle management and reusability across resources."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Create a user-assigned managed identity resource and reference it:\n"
                    "identity: {\n"
                    "  type: 'UserAssigned'\n"
                    "  userAssignedIdentities: { '${userIdentity.id}': {} }\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-IAM-03 compliance.
        
        Detects:
        - Missing managed identity blocks
        - Service principal credentials in code
        - Identity configuration for Azure resources
        - Certificate-based authentication validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure resources without identity block (HIGH)
        resource_types = [
            ('azurerm_app_service', 'App Service'),
            ('azurerm_linux_web_app', 'Linux Web App'),
            ('azurerm_windows_web_app', 'Windows Web App'),
            ('azurerm_container_group', 'Container Instance'),
            ('azurerm_linux_virtual_machine', 'Linux VM'),
            ('azurerm_windows_virtual_machine', 'Windows VM'),
        ]
        
        for resource_type, display_name in resource_types:
            resource_matches = list(re.finditer(rf'resource\s+"{resource_type}"\s+"\w+"\s*\{{', code))
            for match in resource_matches:
                # Get the resource block
                start_pos = match.start()
                # Simple heuristic: check next 500 chars for identity block
                block = code[start_pos:start_pos + 500]
                if 'identity {' not in block and 'identity{' not in block:
                    line_num = code[:start_pos].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{display_name} Without Managed Identity",
                        description=(
                            f"Azure {display_name} resource at line {line_num} deployed without managed identity. "
                            f"Service resources must use managed identities for secure authentication."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            f"Add managed identity configuration to the resource:\n"
                            f"identity {{\n"
                            f"  type = \"SystemAssigned\"  # or \"UserAssigned\"\n"
                            f"}}\n"
                            f"Then assign RBAC roles using azurerm_role_assignment."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Service principal with password/secret (CRITICAL)
        if re.search(r'azurerm_service_principal_password|client_secret\s*=\s*"', code):
            result = self._find_line(lines, r'azurerm_service_principal_password|client_secret\s*=')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Service Principal Using Password Authentication",
                description=(
                    f"Service principal configured with password/secret at line {line_num}. "
                    f"Service principals should use certificate-based authentication, not passwords."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use azurerm_service_principal_certificate instead of "
                    "azurerm_service_principal_password. Store certificates in Azure Key Vault "
                    "and reference them via data sources."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-IAM-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-IAM-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-IAM-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-IAM-03.
        
        **KSI-IAM-03: Non-User Accounts**
        Enforce appropriately secure authentication methods for non-user accounts and services.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-IAM-03",
            "ksi_name": "Non-User Accounts",
            "azure_services": [
                {
                    "service": "Azure Managed Identity",
                    "purpose": "Secure authentication for applications without managing credentials",
                    "capabilities": [
                        "System-assigned and user-assigned identities",
                        "Automatic credential rotation",
                        "Integration with Azure services and RBAC",
                        "No secrets in code or configuration"
                    ]
                },
                {
                    "service": "Azure AD Service Principals",
                    "purpose": "Manage service account authentication and authorization",
                    "capabilities": [
                        "Certificate-based authentication",
                        "Federated credentials (workload identity)",
                        "Service principal audit logs",
                        "Credential expiration tracking"
                    ]
                },
                {
                    "service": "Azure Key Vault",
                    "purpose": "Store service account credentials when Managed Identity not available",
                    "capabilities": [
                        "Secure secret storage",
                        "Access policies for service principals",
                        "Secret rotation tracking",
                        "Certificate management for service accounts"
                    ]
                },
                {
                    "service": "Azure Monitor",
                    "purpose": "Audit and monitor service account authentication activity",
                    "capabilities": [
                        "Sign-in logs for service principals",
                        "Failed authentication attempts",
                        "Service account usage patterns",
                        "Anomaly detection"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Enforce Managed Identity usage and prevent password-based authentication",
                    "capabilities": [
                        "Require Managed Identity for VM/container apps",
                        "Audit resources not using Managed Identity",
                        "Block storage account key access",
                        "Enforce workload identity federation"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Managed Identity Inventory",
                    "description": "Export all Managed Identities and their role assignments",
                    "automation": "Resource Graph query for Managed Identities",
                    "frequency": "Daily",
                    "evidence_produced": "Complete inventory of service identities"
                },
                {
                    "method": "Service Principal Authentication Monitoring",
                    "description": "Monitor service principal sign-ins and authentication methods",
                    "automation": "Azure AD sign-in logs via KQL",
                    "frequency": "Continuous (with weekly reports)",
                    "evidence_produced": "Service account authentication activity report"
                },
                {
                    "method": "Credential Expiration Tracking",
                    "description": "Track service principal credentials and certificate expiration dates",
                    "automation": "Microsoft Graph API queries",
                    "frequency": "Weekly",
                    "evidence_produced": "Credential expiration report with rotation status"
                },
                {
                    "method": "Managed Identity Policy Compliance",
                    "description": "Audit resources for Managed Identity usage vs. password-based auth",
                    "automation": "Azure Policy compliance scans",
                    "frequency": "Daily",
                    "evidence_produced": "Policy compliance report for service authentication"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["config-based", "log-based"],
            "implementation_guidance": {
                "quick_start": "Deploy Managed Identities, migrate from service principal passwords to certificates/workload identity, enable Azure Policy for enforcement, configure sign-in log monitoring",
                "azure_well_architected": "Follows Azure WAF security pillar for identity and zero-trust principles",
                "compliance_mapping": "Addresses NIST controls ac-2, ac-2.2, ac-4, ac-6.5, ia-3, ia-5.2, ra-5.5"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-IAM-03 evidence.
        """
        return {
            "ksi_id": "KSI-IAM-03",
            "queries": [
                {
                    "name": "Managed Identity Inventory",
                    "type": "azure_resource_graph",
                    "query": """
                        resources
                        | where type == 'microsoft.managedidentity/userassignedidentities' 
                            or identity has 'SystemAssigned'
                        | extend identityType = iff(type == 'microsoft.managedidentity/userassignedidentities', 'User-Assigned', 'System-Assigned')
                        | project name, resourceGroup, location, identityType, id
                        | order by identityType, name
                        """,
                    "purpose": "List all Managed Identities in the environment",
                    "expected_result": "Comprehensive inventory with identity types"
                },
                {
                    "name": "Service Principal Sign-Ins",
                    "type": "kql",
                    "workspace": "Log Analytics with Azure AD logs",
                    "query": """
                        AADServicePrincipalSignInLogs
                        | where TimeGenerated > ago(30d)
                        | summarize SignInCount = count(), LastSignIn = max(TimeGenerated), 
                                    SuccessCount = countif(ResultType == 0),
                                    FailureCount = countif(ResultType != 0)
                                    by ServicePrincipalName, AppId
                        | extend SuccessRate = round((SuccessCount * 100.0) / SignInCount, 2)
                        | order by SignInCount desc
                        """,
                    "purpose": "Monitor service principal authentication activity",
                    "expected_result": "Active service principals with high success rates"
                },
                {
                    "name": "Service Principal Credential Expiration",
                    "type": "microsoft_graph",
                    "endpoint": "/servicePrincipals?$select=id,appDisplayName,keyCredentials,passwordCredentials",
                    "method": "GET",
                    "purpose": "Track service principal credentials and expiration dates",
                    "expected_result": "No expired credentials, documented rotation schedule"
                },
                {
                    "name": "Managed Identity Policy Compliance",
                    "type": "azure_resource_graph",
                    "query": """
                        policyresources
                        | where type == 'microsoft.policyinsights/policystates'
                        | where properties.policyDefinitionName contains 'managed-identity' or properties.policyDefinitionName contains 'service-principal'
                        | summarize CompliantCount = countif(properties.complianceState == 'Compliant'),
                                    NonCompliantCount = countif(properties.complianceState == 'NonCompliant')
                                    by tostring(properties.policyDefinitionName)
                        | extend ComplianceRate = round((CompliantCount * 100.0) / (CompliantCount + NonCompliantCount), 2)
                        """,
                    "purpose": "Show policy compliance for Managed Identity usage",
                    "expected_result": "High compliance rates with documented exceptions"
                },
                {
                    "name": "Failed Service Principal Authentications",
                    "type": "kql",
                    "workspace": "Log Analytics with Azure AD logs",
                    "query": """
                        AADServicePrincipalSignInLogs
                        | where TimeGenerated > ago(7d)
                        | where ResultType != 0
                        | summarize FailureCount = count(), ErrorCodes = make_set(ResultType) by ServicePrincipalName, AppId
                        | order by FailureCount desc
                        | take 20
                        """,
                    "purpose": "Detect authentication failures for service accounts",
                    "expected_result": "Minimal failures with investigation of anomalies"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI or Managed Identity",
                "permissions_required": [
                    "Reader for Resource Graph queries",
                    "Log Analytics Reader for KQL queries",
                    "Application.Read.All and Directory.Read.All for Graph API",
                    "Policy Reader for compliance queries"
                ],
                "automation_tools": [
                    "Azure CLI (az ad sp list, az identity list)",
                    "PowerShell Az.Resources and Az.ManagedServiceIdentity modules",
                    "Microsoft Graph PowerShell SDK"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-IAM-03.
        """
        return {
            "ksi_id": "KSI-IAM-03",
            "artifacts": [
                {
                    "name": "Managed Identity Inventory Report",
                    "description": "Complete inventory of all Managed Identities and their assignments",
                    "source": "Azure Resource Graph",
                    "format": "CSV from Resource Graph query",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "Scheduled Resource Graph query"
                },
                {
                    "name": "Service Principal Authentication Report",
                    "description": "Service account sign-in activity showing authentication methods and success rates",
                    "source": "Azure AD Sign-in Logs",
                    "format": "CSV from KQL query",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "Log Analytics scheduled query"
                },
                {
                    "name": "Credential Expiration Tracking Report",
                    "description": "Service principal credentials with expiration dates and rotation status",
                    "source": "Microsoft Graph API",
                    "format": "JSON export",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "PowerShell script with Graph SDK"
                },
                {
                    "name": "Managed Identity Policy Compliance Report",
                    "description": "Resources using Managed Identity vs. password-based authentication",
                    "source": "Azure Policy",
                    "format": "CSV compliance report",
                    "collection_frequency": "Daily",
                    "retention_period": "1 year",
                    "automation": "Azure Policy compliance export"
                },
                {
                    "name": "Service Account Security Baseline",
                    "description": "Documented standard for service account authentication methods",
                    "source": "Configuration documentation",
                    "format": "Markdown or PDF",
                    "collection_frequency": "Quarterly (or on change)",
                    "retention_period": "3 years",
                    "automation": "Maintained in Git repository"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["ac-2", "ac-2.2", "ac-4", "ac-6.5", "ia-3", "ia-5.2", "ra-5.5"],
                "evidence_purpose": "Demonstrate secure authentication for service accounts using Managed Identity and certificate-based methods"
            }
        }
