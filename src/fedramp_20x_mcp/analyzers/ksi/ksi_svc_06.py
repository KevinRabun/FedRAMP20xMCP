"""
KSI-SVC-06: Secret Management

Automate management, protection, and regular rotation of digital keys, certificates, and other secrets.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_SVC_06_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-06: Secret Management
    
    **Official Statement:**
    Automate management, protection, and regular rotation of digital keys, certificates, and other secrets.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-17.2
    - ia-5.2
    - ia-5.6
    - sc-12
    - sc-17
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Automate management, protection, and regular rotation of digital keys, certificates, and other secre...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-06"
    KSI_NAME = "Secret Management"
    KSI_STATEMENT = """Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-17.2", "ia-5.2", "ia-5.6", "sc-12", "sc-17"]
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
        Analyze Python code for KSI-SVC-06 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Patterns Detected:
        - Hardcoded passwords, API keys, connection strings
        - Azure Key Vault SDK usage and configuration
        - Environment variable usage for secrets
        - Secret rotation mechanisms
        - Certificate management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern for hardcoded secrets (HIGH severity)
        hardcoded_patterns = [
            (r'password\s*=\s*["\'][^"\']', 'Hardcoded password detected'),
            (r'api[_-]?key\s*=\s*["\'][^"\']', 'Hardcoded API key detected'),
            (r'secret\s*=\s*["\'][^"\']', 'Hardcoded secret detected'),
            (r'token\s*=\s*["\'][^"\']', 'Hardcoded token detected'),
            (r'connection[_-]?string\s*=\s*["\'][^"\']', 'Hardcoded connection string detected'),
            (r'private[_-]?key\s*=\s*["\'][^"\']', 'Hardcoded private key detected')
        ]
        
        for pattern, message in hardcoded_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                # Skip if it's clearly a placeholder or environment variable reference
                matched_text = match.group(0)
                if re.search(r'(os\.getenv|os\.environ|\${.*}|\[.*\]|<.*>|your.*here|example)', matched_text, re.IGNORECASE):
                    continue
                
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=message,
                    description=f"{message}. Hardcoded secrets in source code violate KSI-SVC-06 and create security risks. Secrets must be stored in secure vaults like Azure Key Vault.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Use Azure Key Vault with azure-keyvault-secrets SDK: from azure.keyvault.secrets import SecretClient; secret = client.get_secret('secret-name')"
                ))
        
        # Check for Azure Key Vault usage
        has_keyvault = bool(re.search(r'from\s+azure\.keyvault|import\s+azure\.keyvault|SecretClient', code))
        has_env_vars = bool(re.search(r'os\.getenv|os\.environ\[', code))
        
        # Check if secrets are retrieved from Key Vault properly
        if has_keyvault:
            # Check for DefaultAzureCredential (recommended)
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without managed identity authentication",
                    description="Azure Key Vault SDK is used but DefaultAzureCredential or ManagedIdentityCredential is not detected. Use managed identities for secure, credential-less authentication.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'SecretClient'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'SecretClient')),
                    recommendation="Use DefaultAzureCredential: from azure.identity import DefaultAzureCredential; credential = DefaultAzureCredential()"
                ))
            
            # Check for secret rotation/versioning awareness
            if not re.search(r'properties\.version|get_secret.*version|list_properties_of_secret_versions', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No secret version management detected",
                    description="Key Vault is used but no version-aware secret retrieval detected. KSI-SVC-06 requires automated secret rotation.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'get_secret'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'get_secret')),
                    recommendation="Implement secret rotation: always retrieve latest version and handle version updates gracefully"
                ))
        elif has_env_vars:
            # Environment variables are better than hardcoding but not ideal
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Secrets stored in environment variables",
                description="Secrets are retrieved from environment variables. While better than hardcoding, KSI-SVC-06 requires centralized secret management with Azure Key Vault for automated rotation.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'os\.getenv.*password|os\.environ.*api'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'os\.getenv')),
                recommendation="Migrate to Azure Key Vault for centralized secret management and automated rotation"
            ))
        
        # Check Django SECRET_KEY configuration
        if 'django' in code.lower():
            if re.search(r'SECRET_KEY\s*=\s*["\'][^"\'{}<>]{20,}["\']', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Django SECRET_KEY hardcoded",
                    description="Django SECRET_KEY appears to be hardcoded in settings. This key should be stored in Azure Key Vault and rotated regularly.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'SECRET_KEY'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'SECRET_KEY')),
                    recommendation="Load SECRET_KEY from Key Vault: SECRET_KEY = secret_client.get_secret('django-secret-key').value"
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-06 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Patterns Detected:
        - Hardcoded passwords, connection strings, API keys
        - Azure Key Vault SecretClient usage
        - Configuration management (IConfiguration, appsettings.json)
        - Managed identity authentication
        """
        findings = []
        lines = code.split('\n')
        
        # Hardcoded secret patterns
        hardcoded_patterns = [
            (r'password\s*=\s*"[^"]+"', 'Hardcoded password'),
            (r'ConnectionString\s*=\s*"[^"]+"', 'Hardcoded connection string'),
            (r'ApiKey\s*=\s*"[^"]+"', 'Hardcoded API key'),
            (r'Secret\s*=\s*"[^"]+"', 'Hardcoded secret'),
            (r'PrivateKey\s*=\s*"[^"]+"', 'Hardcoded private key')
        ]
        
        for pattern, message in hardcoded_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                if re.search(r'(Configuration\[|Environment\.|<.*>|your.*here)', matched_text, re.IGNORECASE):
                    continue
                
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"{message} detected",
                    description=f"{message} found in source code. Use Azure Key Vault for secret management.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Use Azure Key Vault: var secret = await secretClient.GetSecretAsync('secret-name');"
                ))
        
        # Check for Key Vault usage
        has_keyvault = bool(re.search(r'using\s+Azure\.Security\.KeyVault|SecretClient', code))
        has_config = bool(re.search(r'IConfiguration|ConfigurationBuilder', code))
        
        if has_keyvault:
            # Check for managed identity
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without managed identity",
                    description="SecretClient is used without DefaultAzureCredential or ManagedIdentityCredential.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'SecretClient'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'SecretClient')),
                    recommendation="Use managed identity: var credential = new DefaultAzureCredential();"
                ))
        elif has_config and not has_keyvault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Configuration without Key Vault integration",
                description="IConfiguration is used but no Key Vault integration detected. Secrets in appsettings.json are not rotatable.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'IConfiguration'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'IConfiguration')),
                recommendation="Integrate Key Vault: builder.Configuration.AddAzureKeyVault(new Uri(kvUrl), new DefaultAzureCredential());"
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-06 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Patterns Detected:
        - Hardcoded passwords, JDBC URLs, API keys
        - Azure Key Vault SecretClient usage
        - Spring @Value and application.properties
        - Managed identity authentication
        """
        findings = []
        lines = code.split('\n')
        
        # Hardcoded secret patterns
        hardcoded_patterns = [
            (r'password\s*=\s*"[^"]+"', 'Hardcoded password'),
            (r'jdbcUrl\s*=\s*"[^"]+password=[^"]+"', 'Hardcoded database password in JDBC URL'),
            (r'apiKey\s*=\s*"[^"]+"', 'Hardcoded API key'),
            (r'secretKey\s*=\s*"[^"]+"', 'Hardcoded secret key'),
            (r'spring\.datasource\.password\s*=\s*\S+', 'Hardcoded database password')
        ]
        
        for pattern, message in hardcoded_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                if re.search(r'(\$\{|Environment\.|<.*>|your.*here)', matched_text, re.IGNORECASE):
                    continue
                
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"{message} detected",
                    description=f"{message} found in source code. Use Azure Key Vault for secret management.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Use Azure Key Vault: SecretClient secretClient = new SecretClientBuilder().credential(new DefaultAzureCredentialBuilder().build()).buildClient();"
                ))
        
        # Check for Key Vault usage
        has_keyvault = bool(re.search(r'import\s+com\.azure\.security\.keyvault|SecretClient', code))
        has_spring_config = bool(re.search(r'@Value|@ConfigurationProperties|application\.properties', code))
        
        if has_keyvault:
            # Check for managed identity
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without managed identity",
                    description="SecretClient is used without DefaultAzureCredential.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'SecretClient'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'SecretClient')),
                    recommendation="Use managed identity: new DefaultAzureCredentialBuilder().build()"
                ))
        elif has_spring_config and not has_keyvault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Spring configuration without Key Vault",
                description="Spring configuration detected but no Key Vault integration. Secrets in application.properties are not rotatable.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'@Value|application\.properties'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'@Value')),
                recommendation="Add azure-spring-boot-starter-keyvault-secrets dependency and configure Key Vault integration"
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-06 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Patterns Detected:
        - Hardcoded API keys, passwords, tokens
        - Azure Key Vault SecretClient usage
        - Environment variable usage (process.env)
        - Managed identity authentication
        """
        findings = []
        lines = code.split('\n')
        
        # Hardcoded secret patterns
        hardcoded_patterns = [
            (r'password\s*[=:]\s*["\'][^"\']', 'Hardcoded password'),
            (r'apiKey\s*[=:]\s*["\'][^"\']', 'Hardcoded API key'),
            (r'api_key\s*[=:]\s*["\'][^"\']', 'Hardcoded API key'),
            (r'connectionString\s*[=:]\s*["\'][^"\']', 'Hardcoded connection string'),
            (r'secret\s*[=:]\s*["\'][^"\']', 'Hardcoded secret'),
            (r'token\s*[=:]\s*["\'][^"\']', 'Hardcoded token')
        ]
        
        for pattern, message in hardcoded_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                if re.search(r'(process\.env|\$\{|<.*>|your.*here|example)', matched_text, re.IGNORECASE):
                    continue
                
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"{message} detected",
                    description=f"{message} found in source code. Use Azure Key Vault for secret management.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Use Azure Key Vault: const secret = await secretClient.getSecret('secret-name');"
                ))
        
        # Check for Key Vault usage
        has_keyvault = bool(re.search(r'@azure/keyvault-secrets|SecretClient', code))
        has_env_vars = bool(re.search(r'process\.env\.[A-Z_]+', code))
        
        if has_keyvault:
            # Check for managed identity
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without managed identity",
                    description="SecretClient is used without DefaultAzureCredential.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'SecretClient'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'SecretClient')),
                    recommendation="Use managed identity: const credential = new DefaultAzureCredential();"
                ))
        elif has_env_vars:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Secrets in environment variables",
                description="Secrets stored in process.env. KSI-SVC-06 requires Azure Key Vault for automated rotation.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'process\.env'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'process\.env')),
                recommendation="Migrate to Azure Key Vault: import { SecretClient } from '@azure/keyvault-secrets';"
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-06 compliance.
        
        Checks:
        - Azure Key Vault resources and configuration
        - Secret rotation policies
        - Managed identity assignments
        - RBAC for Key Vault access
        - Soft delete and purge protection
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Key Vault resources
        has_keyvault = bool(re.search(r'Microsoft\.KeyVault/vaults', code, re.IGNORECASE))
        
        if has_keyvault:
            # Check for soft delete
            if not re.search(r'enableSoftDelete\s*:\s*true', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without soft delete enabled",
                    description="Key Vault resource found without enableSoftDelete: true. Soft delete protects against accidental deletion.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'Microsoft\.KeyVault/vaults'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'Microsoft\.KeyVault/vaults')),
                    recommendation="Enable soft delete: properties: { enableSoftDelete: true, softDeleteRetentionInDays: 90 }"
                ))
            
            # Check for purge protection
            if not re.search(r'enablePurgeProtection\s*:\s*true', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without purge protection",
                    description="Key Vault resource found without enablePurgeProtection: true. Purge protection prevents permanent deletion.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'Microsoft\.KeyVault/vaults'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'Microsoft\.KeyVault/vaults')),
                    recommendation="Enable purge protection: properties: { enablePurgeProtection: true }"
                ))
            
            # Check for RBAC-based access control
            if not re.search(r'enableRbacAuthorization\s*:\s*true', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault using legacy access policies",
                    description="Key Vault should use RBAC instead of access policies for better access management.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'Microsoft\.KeyVault/vaults'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'Microsoft\.KeyVault/vaults')),
                    recommendation="Enable RBAC: properties: { enableRbacAuthorization: true }"
                ))
        else:
            # Check if there are resources that might need secrets
            if re.search(r'Microsoft\.Web/sites|Microsoft\.App/containerApps|Microsoft\.Sql', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Key Vault resource defined",
                    description="Application resources detected but no Azure Key Vault is defined for secret management.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Create Key Vault: resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = { properties: { enableSoftDelete: true, enablePurgeProtection: true } }"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-06 compliance.
        
        Checks:
        - azurerm_key_vault resources and configuration
        - Secret rotation policies
        - Managed identity assignments
        - RBAC for Key Vault access
        - Soft delete and purge protection
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Key Vault resources
        has_keyvault = bool(re.search(r'resource\s+"azurerm_key_vault"|azurerm_key_vault', code, re.IGNORECASE))
        
        if has_keyvault:
            # Check for soft delete
            if not re.search(r'soft_delete_retention_days\s*=\s*\d+', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without soft delete configured",
                    description="azurerm_key_vault resource found without soft_delete_retention_days configured.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'azurerm_key_vault'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'azurerm_key_vault')),
                    recommendation="Configure soft delete: soft_delete_retention_days = 90"
                ))
            
            # Check for purge protection
            if not re.search(r'purge_protection_enabled\s*=\s*true', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault without purge protection",
                    description="azurerm_key_vault resource found without purge_protection_enabled = true.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'azurerm_key_vault'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'azurerm_key_vault')),
                    recommendation="Enable purge protection: purge_protection_enabled = true"
                ))
            
            # Check for RBAC
            if not re.search(r'enable_rbac_authorization\s*=\s*true', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Key Vault using legacy access policies",
                    description="Key Vault should use RBAC instead of access policies.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'azurerm_key_vault'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'azurerm_key_vault')),
                    recommendation="Enable RBAC: enable_rbac_authorization = true"
                ))
        else:
            # Check if there are resources that need secrets
            if re.search(r'azurerm_app_service|azurerm_container_app|azurerm_sql_server', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Key Vault resource defined",
                    description="Application resources detected but no azurerm_key_vault is defined for secret management.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation='Create Key Vault: resource "azurerm_key_vault" "example" { soft_delete_retention_days = 90, purge_protection_enabled = true }'
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-06 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-06 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-06 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> int:
        """Find line number matching regex pattern."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    return i
        except re.error:
            # Fallback to substring search if regex fails
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0 or line_number > len(lines):
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
