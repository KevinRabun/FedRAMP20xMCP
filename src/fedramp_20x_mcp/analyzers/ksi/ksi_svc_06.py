"""
KSI-SVC-06 Enhanced Analyzer: Secret Management

AST-based analyzer for detecting hardcoded secrets and validating Azure Key Vault usage.

Official FedRAMP 20x Definition:
Automate management, protection, and regular rotation of digital keys, certificates, and other secrets.
"""

import re
from typing import List, Set, Dict, Any
from ..base import Finding, Severity, AnalysisResult
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage
from ..semantic_analysis import SemanticAnalyzer


class KSI_SVC_06_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced AST-based analyzer for KSI-SVC-06: Secret Management.
    
    Detects:
    - Hardcoded passwords, API keys, tokens, connection strings
    - Missing Azure Key Vault integration
    - Secrets in environment variables (sub-optimal)
    - Missing managed identity authentication
    - Missing secret rotation/versioning
    - Key Vault configuration issues (soft delete, purge protection, RBAC)
    
    Languages: Python, C#, Java, JavaScript, TypeScript, Bicep, Terraform
    """
    
    KSI_ID = "KSI-SVC-06"
    KSI_NAME = "Secret Management"
    KSI_STATEMENT = "Implement secure secret management using Azure Key Vault or equivalent"
    FAMILY = "SVC"
    FAMILY_NAME = "Service Protection"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-17.2", "Protection of Confidentiality and Integrity Using Encryption"),
        ("ia-5.2", "Public Key-based Authentication"),
        ("ia-5.6", "Protection of Authenticators"),
        ("sc-12", "Cryptographic Key Establishment and Management"),
        ("sc-17", "Public Key Infrastructure Certificates")
    ]
    
    # Patterns that indicate hardcoded secrets
    SECRET_VARIABLE_NAMES = {
        "password", "passwd", "pwd", "pass",
        "api_key", "apikey", "api-key",
        "secret", "secret_key", "secretkey",
        "token", "auth_token", "access_token",
        "private_key", "privatekey",
        "connection_string", "connectionstring",
        "client_secret", "clientsecret",
        "database_password", "db_password",
        "django_secret_key", "secret_key"
    }
    
    # Azure Key Vault indicators
    KEYVAULT_IMPORTS = {
        "azure.keyvault", "azure.keyvault.secrets", "SecretClient",
        "Azure.Security.KeyVault", "Azure.Security.KeyVault.Secrets",
        "com.azure.security.keyvault", "@azure/keyvault-secrets"
    }
    
    # Managed identity indicators
    MANAGED_IDENTITY_PATTERNS = {
        "DefaultAzureCredential", "ManagedIdentityCredential",
        "ChainedTokenCredential", "DefaultAzureCredentialBuilder"
    }
    
    # Environment variable patterns (sub-optimal)
    ENV_VAR_PATTERNS = {
        "os.getenv", "os.environ", "Environment.GetEnvironmentVariable",
        "process.env", "System.getenv", "System.getProperty"
    }
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Python code for hardcoded secrets and Key Vault usage."""
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        if tree:
            semantic_analyzer = SemanticAnalyzer(CodeLanguage.PYTHON)
            return self._analyze_python_ast(tree, code, file_path, semantic_analyzer, parser)
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# code for hardcoded secrets and Key Vault usage."""
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        if tree:
            semantic_analyzer = SemanticAnalyzer(CodeLanguage.CSHARP)
            return self._analyze_csharp_ast(tree, code, file_path, semantic_analyzer, parser)
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code for hardcoded secrets and Key Vault usage."""
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        if tree:
            semantic_analyzer = SemanticAnalyzer(CodeLanguage.JAVA)
            return self._analyze_java_ast(tree, code, file_path, semantic_analyzer, parser)
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript code for hardcoded secrets and Key Vault usage."""
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        if tree:
            semantic_analyzer = SemanticAnalyzer(CodeLanguage.TYPESCRIPT)
            return self._analyze_typescript_ast(tree, code, file_path, semantic_analyzer, parser)
        return []
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep IaC for Key Vault configuration."""
        # Bicep doesn't have tree-sitter support, use direct analysis
        return self._analyze_bicep_ast(None, code, file_path, None)
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform IaC for Key Vault configuration."""
        # Terraform doesn't have tree-sitter support, use direct analysis
        return self._analyze_terraform_ast(None, code, file_path, None)
    
    def _analyze_python_ast(self, tree, code: str, file_path: str, semantic_info, parser: ASTParser) -> List[Finding]:
        """Analyze Python AST for hardcoded secrets and Key Vault usage."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Track imports by parsing AST directly
        has_keyvault = False
        has_managed_identity = False
        has_env_vars = False
        has_django = False
        
        # Extract imports from AST
        if tree:
            imports = parser.find_nodes_by_type(tree.root_node, "import_statement")
            imports.extend(parser.find_nodes_by_type(tree.root_node, "import_from_statement"))
            
            for imp in imports:
                imp_text = parser.get_node_text(imp, code_bytes)
                imp_lower = imp_text.lower()
                
                if any(kv in imp_lower for kv in self.KEYVAULT_IMPORTS):
                    has_keyvault = True
                if any(mi in imp_text for mi in self.MANAGED_IDENTITY_PATTERNS):
                    has_managed_identity = True
                if "django" in imp_lower:
                    has_django = True
        
        # Traverse AST to find assignments
        def visit_node(node):
            nonlocal has_env_vars
            
            # Check for hardcoded secrets in assignments
            if node.type == "assignment":
                # Get left side (variable name)
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                
                if left and right:
                    var_name = self._get_node_text(left, code).lower()
                    value = self._get_node_text(right, code)
                    
                    # Check if variable name suggests a secret
                    if any(secret in var_name for secret in self.SECRET_VARIABLE_NAMES):
                        # Check if it's a hardcoded string (not env var or Key Vault call)
                        if right.type in ("string", "string_literal", "concatenated_string"):
                            if not self._is_placeholder_or_env_var(value):
                                line_num = right.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title=f"Hardcoded Secret: {var_name}",
                                    description=f"Variable '{var_name}' contains a hardcoded secret. Use Azure Key Vault for secure secret management.",
                                    severity=Severity.CRITICAL,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    recommendation="Use Azure Key Vault: from azure.keyvault.secrets import SecretClient; secret = client.get_secret('secret-name').value"
                                ))
            
            # Check for environment variable usage
            if node.type == "call":
                func = node.child_by_field_name("function")
                if func:
                    func_text = self._get_node_text(func, code)
                    if any(env in func_text for env in self.ENV_VAR_PATTERNS):
                        has_env_vars = True
            
            # Check Django SECRET_KEY
            if has_django and node.type == "assignment":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left and right:
                    var_name = self._get_node_text(left, code)
                    if "SECRET_KEY" in var_name:
                        if right.type in ("string", "string_literal"):
                            value = self._get_node_text(right, code)
                            if not self._is_placeholder_or_env_var(value):
                                line_num = right.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title="Django SECRET_KEY Hardcoded",
                                    description="Django SECRET_KEY is hardcoded. This key should be stored in Azure Key Vault and rotated regularly.",
                                    severity=Severity.CRITICAL,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    recommendation="Load from Key Vault: SECRET_KEY = secret_client.get_secret('django-secret-key').value"
                                ))
            
            # Recurse
            for child in node.children:
                visit_node(child)
        
        visit_node(tree.root_node)
        
        # Check Key Vault configuration
        if has_keyvault:
            if not has_managed_identity:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Managed Identity",
                    description="Azure Key Vault SDK is used but DefaultAzureCredential or ManagedIdentityCredential is not detected. Use managed identities for credential-less authentication.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Use DefaultAzureCredential: from azure.identity import DefaultAzureCredential; credential = DefaultAzureCredential()"
                ))
            
            # Check for secret versioning awareness (simplified check)
            if "version" not in code.lower() and "list_properties" not in code.lower():
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Secret Version Management Detected",
                    description="Key Vault is used but no version-aware secret retrieval detected. KSI-SVC-06 requires automated secret rotation.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Implement secret rotation: always retrieve latest version and handle version updates gracefully"
                ))
        elif has_env_vars and not has_keyvault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Secrets in Environment Variables",
                description="Secrets are retrieved from environment variables. While better than hardcoding, KSI-SVC-06 requires Azure Key Vault for automated rotation.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                recommendation="Migrate to Azure Key Vault for centralized secret management and automated rotation"
            ))
        
        return findings
    
    def _analyze_csharp_ast(self, tree, code: str, file_path: str, semantic_info, parser: ASTParser) -> List[Finding]:
        """Analyze C# AST for hardcoded secrets and Key Vault usage."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Track using directives by parsing AST directly
        has_keyvault = False
        has_managed_identity = False
        has_configuration = False
        
        # Extract using directives from AST
        if tree:
            using_directives = parser.find_nodes_by_type(tree.root_node, "using_directive")
            
            for using in using_directives:
                using_text = parser.get_node_text(using, code_bytes)
                
                if any(kv in using_text for kv in ["Azure.Security.KeyVault", "SecretClient"]):
                    has_keyvault = True
                if any(mi in using_text for mi in self.MANAGED_IDENTITY_PATTERNS):
                    has_managed_identity = True
                if "Microsoft.Extensions.Configuration" in using_text:
                    has_configuration = True
        
        # Traverse AST
        def visit_node(node):
            # Check for hardcoded secrets in variable declarations
            if node.type == "variable_declarator":
                # Get identifier - first child is usually the name
                identifier = None
                initializer = None
                
                for child in node.children:
                    if child.type == "identifier" and not identifier:
                        identifier = child
                    elif child.type in ("string_literal", "object_creation_expression", "invocation_expression"):
                        initializer = child
                
                if identifier and initializer:
                    var_name = self._get_node_text(identifier, code).lower()
                    value = self._get_node_text(initializer, code)
                    
                    # Check if variable name suggests a secret
                    if any(secret in var_name for secret in self.SECRET_VARIABLE_NAMES):
                        # Check if it's a hardcoded string
                        if initializer.type == "string_literal":
                            if not self._is_placeholder_or_env_var(value):
                                line_num = initializer.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title=f"Hardcoded Secret: {var_name}",
                                    description=f"Variable '{var_name}' contains a hardcoded secret. Use Azure Key Vault for secure secret management.",
                                    severity=Severity.CRITICAL,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    recommendation="Use Azure Key Vault: var secret = await secretClient.GetSecretAsync('secret-name');"
                                ))
                    
                    # Also check for connection string content patterns
                    if initializer.type == "string_literal":
                        value_lower = value.lower()
                        if any(pattern in value_lower for pattern in ["server=", "password=", "user id=", "pwd="]):
                            if not self._is_placeholder_or_env_var(value):
                                line_num = initializer.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title=f"Hardcoded Connection String: {var_name}",
                                    description=f"Variable '{var_name}' contains a hardcoded connection string with credentials. Use Azure Key Vault.",
                                    severity=Severity.CRITICAL,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    recommendation="Store connection string in Key Vault and retrieve: var connStr = await secretClient.GetSecretAsync('connection-string');"
                                ))
            
            # Check for hardcoded connection strings in assignments
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                
                if left and right:
                    var_name = self._get_node_text(left, code).lower()
                    value = self._get_node_text(right, code)
                    
                    if "connectionstring" in var_name or "password" in var_name:
                        if right.type == "string_literal" and not self._is_placeholder_or_env_var(value):
                            line_num = right.start_point[0] + 1
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title=f"Hardcoded Secret: {var_name}",
                                description=f"Connection string or password hardcoded in '{var_name}'. Use Azure Key Vault.",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num),
                                recommendation="Use Azure Key Vault: var secret = await secretClient.GetSecretAsync('secret-name');"
                            ))
            
            # Recurse
            for child in node.children:
                visit_node(child)
        
        visit_node(tree.root_node)
        
        # Check Key Vault configuration
        if has_keyvault:
            if not has_managed_identity:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Managed Identity",
                    description="SecretClient is used without DefaultAzureCredential or ManagedIdentityCredential.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Use managed identity: var credential = new DefaultAzureCredential();"
                ))
        elif has_configuration and not has_keyvault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Configuration Without Key Vault Integration",
                description="IConfiguration is used but no Key Vault integration detected. Secrets in appsettings.json are not rotatable.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                recommendation="Integrate Key Vault: builder.Configuration.AddAzureKeyVault(new Uri(kvUrl), new DefaultAzureCredential());"
            ))
        
        return findings
    
    def _analyze_java_ast(self, tree, code: str, file_path: str, semantic_info, parser: ASTParser) -> List[Finding]:
        """Analyze Java AST for hardcoded secrets and Key Vault usage."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Track imports by parsing AST directly
        has_keyvault = False
        has_managed_identity = False
        has_spring_config = False
        
        # Extract import declarations from AST
        if tree:
            imports = parser.find_nodes_by_type(tree.root_node, "import_declaration")
            
            for imp in imports:
                import_text = parser.get_node_text(imp, code_bytes)
                
                if "com.azure.security.keyvault" in import_text or "SecretClient" in import_text:
                    has_keyvault = True
                if any(mi in import_text for mi in self.MANAGED_IDENTITY_PATTERNS):
                    has_managed_identity = True
            
            # Check for Spring annotations in code
            if "@Value" in code or "@ConfigurationProperties" in code:
                has_spring_config = True
        
        # Traverse AST
        def visit_node(node):
            # Check for hardcoded secrets in variable declarations
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                
                if name_node and value_node:
                    var_name = self._get_node_text(name_node, code).lower()
                    value = self._get_node_text(value_node, code)
                    
                    # Check if variable name suggests a secret
                    if any(secret in var_name for secret in self.SECRET_VARIABLE_NAMES):
                        # Check if it's a hardcoded string
                        if value_node.type == "string_literal":
                            if not self._is_placeholder_or_env_var(value):
                                line_num = value_node.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title=f"Hardcoded Secret: {var_name}",
                                    description=f"Variable '{var_name}' contains a hardcoded secret. Use Azure Key Vault for secure secret management.",
                                    severity=Severity.CRITICAL,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    recommendation="Use Azure Key Vault: SecretClient secretClient = new SecretClientBuilder().credential(new DefaultAzureCredentialBuilder().build()).buildClient();"
                                ))
            
            # Check for hardcoded JDBC URLs with passwords
            if node.type == "string_literal":
                text = self._get_node_text(node, code)
                if "jdbc:" in text.lower() and "password=" in text.lower():
                    line_num = node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Hardcoded Database Password in JDBC URL",
                        description="JDBC URL contains hardcoded password. Use Azure Key Vault for secure credential management.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation="Load password from Key Vault and construct connection string dynamically"
                    ))
            
            # Recurse
            for child in node.children:
                visit_node(child)
        
        visit_node(tree.root_node)
        
        # Check Key Vault configuration
        if has_keyvault:
            if not has_managed_identity:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Managed Identity",
                    description="SecretClient is used without DefaultAzureCredential.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Use managed identity: new DefaultAzureCredentialBuilder().build()"
                ))
        elif has_spring_config and not has_keyvault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Spring Configuration Without Key Vault",
                description="Spring configuration detected but no Key Vault integration. Secrets in application.properties are not rotatable.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                recommendation="Add azure-spring-boot-starter-keyvault-secrets dependency and configure Key Vault integration"
            ))
        
        return findings
    
    def _analyze_typescript_ast(self, tree, code: str, file_path: str, semantic_info, parser: ASTParser) -> List[Finding]:
        """Analyze JavaScript/TypeScript AST for hardcoded secrets and Key Vault usage."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Track imports by parsing AST
        has_keyvault = False
        has_managed_identity = False
        has_env_vars = False
        
        # Extract imports from AST
        if tree:
            imports = parser.find_nodes_by_type(tree.root_node, "import_statement")
            
            for imp in imports:
                import_text = parser.get_node_text(imp, code_bytes)
                import_lower = import_text.lower()
                
                if "@azure/keyvault-secrets" in import_lower or "SecretClient" in import_text:
                    has_keyvault = True
                if any(mi in import_text for mi in self.MANAGED_IDENTITY_PATTERNS):
                    has_managed_identity = True
        
        # Traverse AST
        def visit_node(node):
            nonlocal has_env_vars
            
            # Check for hardcoded secrets in variable declarations
            if node.type in ("variable_declarator", "lexical_declaration"):
                # Find identifier and initializer
                for child in node.children:
                    if child.type == "variable_declarator":
                        name_node = child.child_by_field_name("name")
                        value_node = child.child_by_field_name("value")
                        
                        if name_node and value_node:
                            var_name = parser.get_node_text(name_node, code_bytes).lower()
                            value = parser.get_node_text(value_node, code_bytes)
                            
                            # Check if variable name suggests a secret
                            if any(secret in var_name for secret in self.SECRET_VARIABLE_NAMES):
                                # Check if it's a hardcoded string
                                if value_node.type in ("string", "string_fragment", "template_string"):
                                    if not self._is_placeholder_or_env_var(value):
                                        line_num = value_node.start_point[0] + 1
                                        findings.append(Finding(
                                            ksi_id=self.KSI_ID,
                                            title=f"Hardcoded Secret: {var_name}",
                                            description=f"Variable '{var_name}' contains a hardcoded secret. Use Azure Key Vault for secure secret management.",
                                            severity=Severity.CRITICAL,
                                            file_path=file_path,
                                            line_number=line_num,
                                            code_snippet=self._get_snippet(lines, line_num),
                                            recommendation="Use Azure Key Vault: const secret = await secretClient.getSecret('secret-name');"
                                        ))
            
            # Check for process.env usage
            if node.type == "member_expression":
                text = parser.get_node_text(node, code_bytes)
                if "process.env" in text:
                    has_env_vars = True
            
            # Recurse
            for child in node.children:
                visit_node(child)
        
        visit_node(tree.root_node)
        
        # Check Key Vault configuration
        if has_keyvault:
            if not has_managed_identity:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Managed Identity",
                    description="SecretClient is used without DefaultAzureCredential.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Use managed identity: const credential = new DefaultAzureCredential();"
                ))
        elif has_env_vars and not has_keyvault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Secrets in Environment Variables",
                description="Secrets stored in process.env. KSI-SVC-06 requires Azure Key Vault for automated rotation.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                recommendation="Migrate to Azure Key Vault: import { SecretClient } from '@azure/keyvault-secrets';"
            ))
        
        return findings
    
    def _analyze_bicep_ast(self, tree, code: str, file_path: str, semantic_info) -> List[Finding]:
        """Analyze Bicep IaC for Key Vault configuration and CMK enforcement."""
        findings = []
        lines = code.split('\n')
        
        # ============================================================================
        # KEY VAULT CONFIGURATION CHECKS (existing logic)
        # ============================================================================
        has_keyvault = "Microsoft.KeyVault/vaults" in code
        has_soft_delete = "enableSoftDelete" in code and "true" in code
        has_purge_protection = "enablePurgeProtection" in code and "true" in code
        has_rbac = "enableRbacAuthorization" in code and "true" in code
        
        if has_keyvault:
            if not has_soft_delete:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Soft Delete",
                    description="Key Vault resource found without enableSoftDelete: true. Soft delete protects against accidental deletion.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Enable soft delete: properties: { enableSoftDelete: true, softDeleteRetentionInDays: 90 }"
                ))
            
            if not has_purge_protection:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Purge Protection",
                    description="Key Vault resource found without enablePurgeProtection: true. Purge protection prevents permanent deletion.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Enable purge protection: properties: { enablePurgeProtection: true }"
                ))
            
            if not has_rbac:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Using Legacy Access Policies",
                    description="Key Vault should use RBAC instead of access policies for better access management.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Enable RBAC: properties: { enableRbacAuthorization: true }"
                ))
        else:
            # Check for app resources without Key Vault
            has_app_resources = any(res in code for res in ["Microsoft.Web/sites", "Microsoft.App/containerApps", "Microsoft.Sql"])
            if has_app_resources:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Key Vault Resource Defined",
                    description="Application resources detected but no Azure Key Vault is defined for secret management.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Create Key Vault: resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = { properties: { enableSoftDelete: true, enablePurgeProtection: true } }"
                ))
        
        # ============================================================================
        # CUSTOMER-MANAGED KEY (CMK) ENFORCEMENT
        # ============================================================================
        # KSI-SVC-06 Secret Management requires organizations to control key lifecycle
        # including revocation capability. This necessitates customer-managed keys (CMK).
        
        # Pattern 1: Storage Account without CMK (HIGH)
        in_storage_resource = False
        storage_start_line = 0
        has_keyvault_encryption = False
        resource_name = ""
        
        for i, line in enumerate(lines, 1):
            if re.search(r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts@", line):
                in_storage_resource = True
                storage_start_line = i
                has_keyvault_encryption = False
                match = re.search(r"resource\s+(\w+)\s+", line)
                resource_name = match.group(1) if match else "storage account"
            
            if in_storage_resource:
                # Platform-managed key (BAD)
                if re.search(r"keySource:\s*['\"]Microsoft\.Storage['\"]", line):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Storage Account Using Platform-Managed Keys ({resource_name})",
                        description=(
                            f"Storage account at line {storage_start_line} uses platform-managed keys (PMK). "
                            f"KSI-SVC-06 Secret Management requires customer-managed keys (CMK) "
                            f"to enable key lifecycle control including revocation capability. Platform-managed keys "
                            f"are controlled by Microsoft, limiting your ability to revoke access per FedRAMP 20x."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_code_snippet(lines, i),
                        recommendation=(
                            f"Configure {resource_name} with customer-managed keys:\n\n"
                            "resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {\n"
                            "  name: 'kv-${uniqueString(resourceGroup().id)}'\n"
                            "  properties: {\n"
                            "    sku: { family: 'A', name: 'premium' }  // Premium for HSM\n"
                            "    enableSoftDelete: true\n"
                            "    enablePurgeProtection: true\n"
                            "  }\n"
                            "}\n"
                            "resource key 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {\n"
                            "  parent: keyVault\n"
                            "  name: 'storage-encryption-key'\n"
                            "  properties: { kty: 'RSA', keySize: 2048 }\n"
                            "}\n"
                            f"resource {resource_name} 'Microsoft.Storage/storageAccounts@2023-01-01' = {{\n"
                            "  identity: { type: 'SystemAssigned' }\n"
                            "  properties: {\n"
                            "    encryption: {\n"
                            "      keySource: 'Microsoft.Keyvault'  // Use CMK\n"
                            "      keyvaultproperties: {\n"
                            "        keyname: key.name\n"
                            "        keyvaulturi: keyVault.properties.vaultUri\n"
                            "      }\n"
                            "    }\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: KSI-SVC-06 Secret Management, Azure Storage CMK (https://learn.microsoft.com/azure/storage/common/customer-managed-keys-overview)"
                        )
                    ))
                
                # Customer-managed key (GOOD)
                if re.search(r"keySource:\s*['\"]Microsoft\.Keyvault['\"]", line):
                    has_keyvault_encryption = True
                
                # End of resource
                if re.match(r'^}\s*$', line) and in_storage_resource:
                    if not has_keyvault_encryption and storage_start_line > 0:
                        has_encryption_property = any(
                            'keySource' in lines[j] 
                            for j in range(storage_start_line - 1, min(i, len(lines)))
                        )
                        if not has_encryption_property:
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title=f"Storage Account Missing Encryption Configuration ({resource_name})",
                                description=(
                                    f"Storage account at line {storage_start_line} has no encryption configuration. "
                                    f"KSI-SVC-06 Secret Management requires customer-managed keys (CMK). Without explicit CMK configuration, "
                                    f"Azure defaults to platform-managed keys (PMK) which limit key lifecycle control."
                                ),
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=storage_start_line,
                                code_snippet=self._get_code_snippet(lines, storage_start_line),
                                recommendation=f"Add CMK encryption to {resource_name} (see previous recommendation)"
                            ))
                    in_storage_resource = False
        
        # Pattern 2: SQL Database without CMK (HIGH)
        for i, line in enumerate(lines, 1):
            if re.search(r"Microsoft\.Sql/(servers/databases|managedInstances)", line):
                context_start = max(0, i - 10)
                context_end = min(len(lines), i + 20)
                context = '\n'.join(lines[context_start:context_end])
                
                has_tde_cmk = re.search(r"transparentDataEncryption.*customer", context, re.IGNORECASE | re.DOTALL)
                
                if not has_tde_cmk:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="SQL Database Without Customer-Managed Key Encryption",
                        description=(
                            f"SQL Database at line {i} lacks customer-managed key (CMK) for TDE. "
                            f"KSI-SVC-06 Secret Management requires CMK for transparent data encryption on databases with federal data."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_code_snippet(lines, i),
                        recommendation=(
                            "Configure SQL with CMK for TDE:\n\n"
                            "resource sqlServerKey 'Microsoft.Sql/servers/keys@2023-05-01-preview' = {\n"
                            "  parent: sqlServer\n"
                            "  name: '${keyVault.name}_${key.name}'\n"
                            "  properties: {\n"
                            "    serverKeyType: 'AzureKeyVault'\n"
                            "    uri: key.properties.keyUriWithVersion\n"
                            "  }\n"
                            "}\n"
                            "resource sqlServerTDE 'Microsoft.Sql/servers/encryptionProtector@2023-05-01-preview' = {\n"
                            "  parent: sqlServer\n"
                            "  name: 'current'\n"
                            "  properties: {\n"
                            "    serverKeyType: 'AzureKeyVault'\n"
                            "    serverKeyName: sqlServerKey.name\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: Azure SQL TDE with CMK (https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-byok-overview)"
                        )
                    ))
        
        # Pattern 3: Managed Disk without Disk Encryption Set (MEDIUM)
        for i, line in enumerate(lines, 1):
            if re.search(r"Microsoft\.Compute/disks@", line):
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 20)
                context = '\n'.join(lines[context_start:context_end])
                
                has_disk_encryption_set = 'diskEncryptionSet' in context
                
                if not has_disk_encryption_set:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Managed Disk Without Disk Encryption Set (CMK)",
                        description=(
                            f"Managed Disk at line {i} does not reference a Disk Encryption Set. "
                            f"KSI-SVC-06 Secret Management requires customer-managed keys for disk encryption to maintain key lifecycle control."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_code_snippet(lines, i),
                        recommendation=(
                            "Configure Disk with Disk Encryption Set:\n\n"
                            "resource diskEncryptionSet 'Microsoft.Compute/diskEncryptionSets@2023-04-02' = {\n"
                            "  name: 'des-${uniqueString(resourceGroup().id)}'\n"
                            "  identity: { type: 'SystemAssigned' }\n"
                            "  properties: {\n"
                            "    activeKey: { keyUrl: key.properties.keyUriWithVersion }\n"
                            "    encryptionType: 'EncryptionAtRestWithCustomerKey'\n"
                            "  }\n"
                            "}\n"
                            "resource disk 'Microsoft.Compute/disks@2023-04-02' = {\n"
                            "  properties: {\n"
                            "    encryption: { diskEncryptionSetId: diskEncryptionSet.id }\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: Azure Disk Encryption with CMK (https://learn.microsoft.com/azure/virtual-machines/disk-encryption)"
                        )
                    ))
        
        # Pattern 4: Cosmos DB without Customer-Managed Key (HIGH)
        for i, line in enumerate(lines, 1):
            if re.search(r"Microsoft\.DocumentDB/databaseAccounts@", line):
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 25)
                context = '\n'.join(lines[context_start:context_end])
                
                has_keyvault_key_uri = 'keyVaultKeyUri' in context
                
                if not has_keyvault_key_uri:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Cosmos DB Without Customer-Managed Key (CMK)",
                        description=(
                            f"Cosmos DB account at line {i} does not configure keyVaultKeyUri. "
                            f"KSI-SVC-06 Secret Management requires customer-managed keys for encryption to maintain key lifecycle control and revocation capability."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_code_snippet(lines, i),
                        recommendation=(
                            "Configure Cosmos DB with CMK:\n\n"
                            "resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {\n"
                            "  identity: { type: 'SystemAssigned' }\n"
                            "  properties: {\n"
                            "    keyVaultKeyUri: key.properties.keyUriWithVersion  // CMK requirement\n"
                            "    // ... other properties\n"
                            "  }\n"
                            "}\n"
                            "// Grant Cosmos DB identity access to Key Vault key\n"
                            "resource keyVaultAccessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2023-07-01' = {\n"
                            "  parent: keyVault\n"
                            "  name: 'add'\n"
                            "  properties: {\n"
                            "    accessPolicies: [{\n"
                            "      tenantId: cosmosAccount.identity.tenantId\n"
                            "      objectId: cosmosAccount.identity.principalId\n"
                            "      permissions: { keys: ['get', 'unwrapKey', 'wrapKey'] }\n"
                            "    }]\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: Cosmos DB encryption with CMK (https://learn.microsoft.com/azure/cosmos-db/how-to-setup-cmk)"
                        )
                    ))
        
        return findings
    
    def _analyze_terraform_ast(self, tree, code: str, file_path: str, semantic_info) -> List[Finding]:
        """Analyze Terraform IaC for Key Vault configuration and CMK enforcement."""
        findings = []
        lines = code.split('\n')
        
        # ============================================================================
        # KEY VAULT CONFIGURATION CHECKS (existing logic)
        # ============================================================================
        has_keyvault = "azurerm_key_vault" in code
        has_soft_delete = "soft_delete_retention_days" in code
        has_purge_protection = "purge_protection_enabled" in code and "true" in code
        has_rbac = "enable_rbac_authorization" in code and "true" in code
        
        if has_keyvault:
            if not has_soft_delete:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Soft Delete",
                    description="azurerm_key_vault resource found without soft_delete_retention_days configured.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Configure soft delete: soft_delete_retention_days = 90"
                ))
            
            if not has_purge_protection:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Without Purge Protection",
                    description="azurerm_key_vault resource found without purge_protection_enabled = true.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Enable purge protection: purge_protection_enabled = true"
                ))
            
            if not has_rbac:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault Using Legacy Access Policies",
                    description="Key Vault should use RBAC instead of access policies.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation="Enable RBAC: enable_rbac_authorization = true"
                ))
        else:
            # Check for app resources without Key Vault
            has_app_resources = any(res in code for res in ["azurerm_app_service", "azurerm_container_app", "azurerm_sql_server"])
            if has_app_resources:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Key Vault Resource Defined",
                    description="Application resources detected but no azurerm_key_vault is defined for secret management.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    recommendation='Create Key Vault: resource "azurerm_key_vault" "example" { soft_delete_retention_days = 90, purge_protection_enabled = true }'
                ))
        
        # ============================================================================
        # CUSTOMER-MANAGED KEY (CMK) ENFORCEMENT
        # ============================================================================
        # KSI-SVC-06 Secret Management requires customer-managed keys for key lifecycle control
        
        # Pattern 1: Storage Account without CMK (HIGH)
        in_storage_resource = False
        storage_start_line = 0
        has_cmk_config = False
        resource_name = ""
        brace_depth = 0
        
        for i, line in enumerate(lines, 1):
            if re.search(r'resource\s+"azurerm_storage_account"', line):
                in_storage_resource = True
                storage_start_line = i
                has_cmk_config = False
                brace_depth = 0
                match = re.search(r'resource\s+"azurerm_storage_account"\s+"(\w+)"', line)
                resource_name = match.group(1) if match else "storage_account"
            
            if in_storage_resource:
                brace_depth += line.count('{')
                brace_depth -= line.count('}')
                
                if 'customer_managed_key' in line:
                    has_cmk_config = True
                
                if brace_depth == 0 and in_storage_resource and i > storage_start_line:
                    if not has_cmk_config:
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title=f"Storage Account Without Customer-Managed Key ({resource_name})",
                            description=(
                                f"Storage account '{resource_name}' at line {storage_start_line} lacks CMK configuration. "
                                f"KSI-SVC-06 Secret Management requires customer-managed keys for key lifecycle control. "
                                f"Without customer_managed_key block, storage uses platform-managed keys (PMK)."
                            ),
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=storage_start_line,
                            code_snippet=self._get_code_snippet(lines, storage_start_line),
                            recommendation=(
                                f"Configure {resource_name} with CMK:\n\n"
                                "resource \"azurerm_key_vault\" \"cmk\" {\n"
                                "  sku_name = \"premium\"  # Required for HSM\n"
                                "  soft_delete_retention_days = 90\n"
                                "  purge_protection_enabled = true\n"
                                "}\n"
                                "resource \"azurerm_key_vault_key\" \"storage\" {\n"
                                "  key_vault_id = azurerm_key_vault.cmk.id\n"
                                "  key_type = \"RSA\"\n"
                                "  key_size = 2048\n"
                                "}\n"
                                f"resource \"azurerm_storage_account\" \"{resource_name}\" {{\n"
                                "  identity { type = \"SystemAssigned\" }\n"
                                "  customer_managed_key {\n"
                                "    key_vault_key_id = azurerm_key_vault_key.storage.id\n"
                                "  }\n"
                                "}\n\n"
                                "Ref: KSI-SVC-06 Secret Management, Terraform azurerm_storage_account CMK"
                            )
                        ))
                    in_storage_resource = False
        
        # Pattern 2: SQL Database without CMK (HIGH)
        for i, line in enumerate(lines, 1):
            if re.search(r'resource\s+"azurerm_mssql_(database|server)"', line):
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 30)
                context = '\n'.join(lines[context_start:context_end])
                
                has_tde_cmk = re.search(r'azurerm_mssql_server_transparent_data_encryption.*customer_managed_key', 
                                       context, re.DOTALL)
                
                if 'azurerm_mssql_database' in line and not has_tde_cmk:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="SQL Database Without Customer-Managed TDE Key",
                        description=(
                            f"SQL Database at line {i} lacks customer-managed key for TDE. "
                            f"KSI-SVC-06 Secret Management requires CMK for transparent data encryption."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_code_snippet(lines, i),
                        recommendation=(
                            "Configure SQL with CMK for TDE:\n\n"
                            "resource \"azurerm_mssql_server_transparent_data_encryption\" \"tde\" {\n"
                            "  server_id = azurerm_mssql_server.sql.id\n"
                            "  key_vault_key_id = azurerm_key_vault_key.sql.id\n"
                            "}\n\n"
                            "Ref: Terraform TDE with CMK"
                        )
                    ))
        
        # Pattern 3: Managed Disk without disk_encryption_set_id (MEDIUM)
        for i, line in enumerate(lines, 1):
            if re.search(r'resource\s+"azurerm_managed_disk"', line):
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 20)
                context = '\n'.join(lines[context_start:context_end])
                
                has_des = 'disk_encryption_set_id' in context
                
                if not has_des:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Managed Disk Without Disk Encryption Set",
                        description=(
                            f"Managed Disk at line {i} lacks disk_encryption_set_id. "
                            f"KSI-SVC-06 Secret Management requires customer-managed keys for disk encryption."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_code_snippet(lines, i),
                        recommendation=(
                            "Configure Disk with Disk Encryption Set:\n\n"
                            "resource \"azurerm_disk_encryption_set\" \"des\" {\n"
                            "  key_vault_key_id = azurerm_key_vault_key.disk.id\n"
                            "  identity { type = \"SystemAssigned\" }\n"
                            "}\n"
                            "resource \"azurerm_managed_disk\" \"disk\" {\n"
                            "  disk_encryption_set_id = azurerm_disk_encryption_set.des.id\n"
                            "}\n\n"
                            "Ref: Terraform Disk Encryption Set"
                        )
                    ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _get_node_text(self, node, code: str) -> str:
        """Extract text for a given AST node."""
        if not node:
            return ""
        return code[node.start_byte:node.end_byte]
    
    def _is_placeholder_or_env_var(self, value: str) -> bool:
        """Check if value is a placeholder or environment variable reference."""
        value_lower = value.lower()
        placeholders = [
            "os.getenv", "os.environ", "${", "process.env",
            "environment.", "configuration[", "your", "example",
            "<", ">", "***", "xxx", "placeholder", "todo"
        ]
        return any(ph in value_lower for ph in placeholders)
    
    def _get_code_snippet(self, lines: List[str], line_number: int, context: int = 3) -> str:
        """Get code snippet around line number."""
        if line_number == 0 or line_number > len(lines):
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-SVC-06.
        
        **KSI-SVC-06: Secret Management**
        Automate management, protection, and regular rotation of digital keys, certificates, and other secrets.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-SVC-06",
            "ksi_name": "Secret Management",
            "azure_services": [
                {
                    "service": "Azure Key Vault",
                    "purpose": "Centralized secret, key, and certificate storage with FIPS 140-2 compliance",
                    "capabilities": [
                        "Secret storage with versioning",
                        "Automated certificate lifecycle management",
                        "Managed HSM for cryptographic key protection",
                        "Soft delete and purge protection",
                        "RBAC and audit logging for secret access"
                    ]
                },
                {
                    "service": "Azure Monitor / Log Analytics",
                    "purpose": "Secret access audit logging and rotation monitoring",
                    "capabilities": [
                        "Key Vault diagnostic logs for secret access",
                        "Secret expiration monitoring",
                        "Rotation compliance tracking",
                        "Anomaly detection for secret usage patterns"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Enforce Key Vault security configuration standards",
                    "capabilities": [
                        "Require soft delete and purge protection",
                        "Enforce RBAC over access policies",
                        "Validate network access restrictions",
                        "Audit non-compliant Key Vault configurations"
                    ]
                },
                {
                    "service": "Microsoft Defender for Cloud",
                    "purpose": "Secret security posture and vulnerability scanning",
                    "capabilities": [
                        "Detect hardcoded secrets in code repositories",
                        "Recommend Key Vault for secret storage",
                        "Monitor certificate expiration",
                        "Identify overprivileged secret access"
                    ]
                },
                {
                    "service": "Azure Managed Identity",
                    "purpose": "Eliminate credentials for Azure service authentication",
                    "capabilities": [
                        "Passwordless authentication to Azure services",
                        "Automatic credential lifecycle management",
                        "Integration with Key Vault for secret retrieval",
                        "Audit trail of identity-based access"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Key Vault Configuration Audit",
                    "description": "Export all Key Vault configurations showing security settings (soft delete, purge protection, RBAC, network rules)",
                    "automation": "Resource Graph query or Azure CLI",
                    "frequency": "Monthly",
                    "evidence_produced": "Key Vault security configuration compliance report"
                },
                {
                    "method": "Secret Access Audit Log",
                    "description": "Query Key Vault diagnostic logs for secret access patterns and privileged operations",
                    "automation": "Log Analytics KQL queries",
                    "frequency": "Weekly",
                    "evidence_produced": "Secret access activity report with anomaly highlights"
                },
                {
                    "method": "Secret Expiration and Rotation Report",
                    "description": "Monitor secret and certificate expiration dates, track rotation compliance",
                    "automation": "Key Vault REST API or Azure Monitor alerts",
                    "frequency": "Daily",
                    "evidence_produced": "Secret rotation compliance report with expiring credentials"
                },
                {
                    "method": "Hardcoded Secret Detection",
                    "description": "Scan code repositories for hardcoded secrets using Defender for Cloud or GitHub Advanced Security",
                    "automation": "Microsoft Defender for DevOps integration",
                    "frequency": "Continuous (on commit)",
                    "evidence_produced": "Code scanning report with secret exposure findings"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["config-based", "log-based"],
            "implementation_guidance": {
                "quick_start": "Deploy Key Vault with soft delete and purge protection, enable diagnostic logging, use Managed Identity for authentication, configure secret rotation policies, enable Defender for DevOps",
                "azure_well_architected": "Follows Azure WAF security pillar for secure secrets management and zero trust principles",
                "compliance_mapping": "Addresses NIST controls ac-17.2, ia-5.2, ia-5.6, sc-12, sc-17"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-SVC-06 evidence.
        """
        return {
            "ksi_id": "KSI-SVC-06",
            "queries": [
                {
                    "name": "Key Vault Security Configuration",
                    "type": "azure_resource_graph",
                    "query": """
                        resources
                        | where type == 'microsoft.keyvault/vaults'
                        | extend softDeleteEnabled = tostring(properties.enableSoftDelete)
                        | extend purgeProtection = tostring(properties.enablePurgeProtection)
                        | extend rbacEnabled = tostring(properties.enableRbacAuthorization)
                        | extend publicAccess = tostring(properties.publicNetworkAccess)
                        | project name, resourceGroup, softDeleteEnabled, purgeProtection, rbacEnabled, publicAccess, location
                        | where softDeleteEnabled != 'true' or purgeProtection != 'true' or rbacEnabled != 'true'
                        """,
                    "purpose": "Identify Key Vaults with suboptimal security configuration",
                    "expected_result": "Empty result set indicates all Key Vaults properly configured"
                },
                {
                    "name": "Secret Access Audit Trail",
                    "type": "kql",
                    "workspace": "Log Analytics workspace with Key Vault diagnostic logs",
                    "query": """
                        AzureDiagnostics
                        | where ResourceType == "VAULTS"
                        | where OperationName == "SecretGet" or OperationName == "SecretList"
                        | where TimeGenerated > ago(7d)
                        | summarize AccessCount = count(), LastAccess = max(TimeGenerated) by CallerIPAddress, identity_claim_upn_s, id_s
                        | order by AccessCount desc
                        """,
                    "purpose": "Demonstrate secret access is audited and monitored",
                    "expected_result": "Logs showing controlled secret access by authorized identities"
                },
                {
                    "name": "Expiring Secrets and Certificates",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/secrets?api-version=7.4",
                    "method": "GET",
                    "purpose": "Identify secrets approaching expiration requiring rotation",
                    "expected_result": "List of secrets with expiration dates, minimal near-expiring items"
                },
                {
                    "name": "Managed Identity Usage",
                    "type": "azure_resource_graph",
                    "query": """
                        resources
                        | where type in ('microsoft.compute/virtualmachines', 'microsoft.web/sites', 'microsoft.containerinstance/containergroups')
                        | extend hasIdentity = isnotempty(identity)
                        | extend identityType = tostring(identity.type)
                        | project name, type, resourceGroup, hasIdentity, identityType
                        | where hasIdentity == false
                        """,
                    "purpose": "Find resources not using Managed Identity (may be using credentials)",
                    "expected_result": "Minimal resources without Managed Identity where applicable"
                },
                {
                    "name": "Secret Rotation Compliance",
                    "type": "kql",
                    "workspace": "Log Analytics with Key Vault logs",
                    "query": """
                        AzureDiagnostics
                        | where ResourceType == "VAULTS"
                        | where OperationName == "SecretSet"
                        | where TimeGenerated > ago(90d)
                        | summarize LastRotation = max(TimeGenerated), RotationCount = count() by id_s
                        | extend DaysSinceRotation = datetime_diff('day', now(), LastRotation)
                        | where DaysSinceRotation > 90
                        """,
                    "purpose": "Identify secrets not rotated within policy (e.g., 90 days)",
                    "expected_result": "Empty or minimal result set indicating active rotation"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI (az login) with Key Vault permissions or Managed Identity",
                "permissions_required": [
                    "Reader role for Resource Graph queries",
                    "Key Vault Reader for configuration queries",
                    "Log Analytics Reader for KQL queries",
                    "Key Vault Secrets User for secret metadata (not values)"
                ],
                "automation_tools": [
                    "Azure CLI (az keyvault, az graph)",
                    "PowerShell Az.KeyVault and Az.Monitor modules",
                    "Python azure-keyvault-secrets and azure-identity SDKs"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-SVC-06.
        """
        return {
            "ksi_id": "KSI-SVC-06",
            "artifacts": [
                {
                    "name": "Key Vault Security Configuration Report",
                    "description": "Complete inventory of all Key Vaults with security settings (soft delete, purge protection, RBAC, network access)",
                    "source": "Azure Resource Graph",
                    "format": "CSV from Resource Graph query",
                    "collection_frequency": "Monthly",
                    "retention_period": "3 years",
                    "automation": "Scheduled Resource Graph query export to Blob Storage"
                },
                {
                    "name": "Secret Access Audit Log",
                    "description": "Historical log of all secret access operations with caller identity and IP address",
                    "source": "Key Vault diagnostic logs in Log Analytics",
                    "format": "CSV from KQL query",
                    "collection_frequency": "Weekly",
                    "retention_period": "7 years (audit evidence)",
                    "automation": "Scheduled KQL query with long-term storage export"
                },
                {
                    "name": "Secret Rotation Compliance Report",
                    "description": "Report showing secret rotation dates and compliance with rotation policy",
                    "source": "Key Vault audit logs and secret metadata",
                    "format": "JSON with secret rotation dates and compliance status",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "PowerShell or Python script querying Key Vault API"
                },
                {
                    "name": "Expiring Credentials Report",
                    "description": "List of secrets and certificates approaching expiration",
                    "source": "Key Vault REST API",
                    "format": "CSV with expiration dates and days until expiry",
                    "collection_frequency": "Daily",
                    "retention_period": "1 year",
                    "automation": "Azure Function with alert on near-expiring items"
                },
                {
                    "name": "Hardcoded Secret Scan Results",
                    "description": "Security scanning results from code repositories for hardcoded secrets",
                    "source": "Microsoft Defender for DevOps or GitHub Advanced Security",
                    "format": "JSON SARIF format from security scanning",
                    "collection_frequency": "Continuous (on commit)",
                    "retention_period": "1 year",
                    "automation": "CI/CD pipeline integration with security scanning"
                },
                {
                    "name": "Managed Identity Usage Report",
                    "description": "Inventory of Azure resources with Managed Identity enabled vs. credential-based authentication",
                    "source": "Azure Resource Graph",
                    "format": "CSV from Resource Graph query",
                    "collection_frequency": "Monthly",
                    "retention_period": "1 year",
                    "automation": "Scheduled Resource Graph query"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["ac-17.2", "ia-5.2", "ia-5.6", "sc-12", "sc-17"],
                "evidence_purpose": "Demonstrate automated secret management, rotation, and protection using Azure Key Vault"
            }
        }


def create_analyzer(language: str) -> KSI_SVC_06_Analyzer:
    """Factory function to create analyzer for specified language."""
    lang_map = {
        "python": CodeLanguage.PYTHON,
        "csharp": CodeLanguage.CSHARP,
        "c#": CodeLanguage.CSHARP,
        "java": CodeLanguage.JAVA,
        "javascript": CodeLanguage.JAVASCRIPT,
        "typescript": CodeLanguage.TYPESCRIPT,
        "bicep": CodeLanguage.BICEP,
        "terraform": CodeLanguage.TERRAFORM,
    }
    
    code_language = lang_map.get(language.lower())
    if not code_language:
        raise ValueError(f"Unsupported language: {language}. Supported: python, csharp, java, javascript, typescript, bicep, terraform")
    
    return KSI_SVC_06_Analyzer(code_language)

