"""
KSI-IAM-03: Non-User Accounts

Enforce appropriately secure authentication methods for non-user accounts and services.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


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
    NIST_CONTROLS = ["ac-2", "ac-2.2", "ac-4", "ac-6.5", "ia-3", "ia-5.2", "ra-5.5"]
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
        Analyze Python code for KSI-IAM-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Service account passwords in code
        - Missing managed identity usage
        - Hardcoded service principal credentials
        - DefaultAzureCredential validation
        """
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
            line_num = self._find_line(lines, pattern)
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
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Weak Credential Type for Service Authentication",
                    description=(
                        "Azure SDK authentication detected but not using recommended credential types. "
                        "Service accounts should use DefaultAzureCredential, ManagedIdentityCredential, "
                        "or CertificateCredential for secure authentication."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r'from azure\.identity'),
                    snippet=self._get_snippet(lines, self._find_line(lines, r'from azure\.identity')),
                    remediation=(
                        "Use DefaultAzureCredential() which automatically uses managed identity in Azure, "
                        "or explicitly use ManagedIdentityCredential() or CertificateCredential() for "
                        "service accounts."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Service account with password authentication (CRITICAL)
        if re.search(r'ServicePrincipalCredentials\s*\(.*password\s*=', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'ServicePrincipalCredentials')
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
        Analyze C# code for KSI-IAM-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Hardcoded service principal credentials
        - Missing managed identity configuration
        - Password-based service account authentication
        - Certificate-based authentication validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hardcoded service principal credentials (CRITICAL)
        sp_cred_patterns = [
            r'new\s+ClientSecretCredential\s*\([^)]*["\'][^"\'{]+["\']',
            r'ServicePrincipalSecret\s*=\s*["\']',
            r'AppPassword\s*=\s*["\']',
            r'ClientSecret\s*=\s*["\'](?!Configuration\[|Environment\.)',
        ]
        
        for pattern in sp_cred_patterns:
            line_num = self._find_line(lines, pattern)
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
        
        # Pattern 2: Missing managed identity for Azure SDK (HIGH)
        if re.search(r'new\s+\w+Client\s*\(', code) and re.search(r'using Azure\.', code):
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential|ChainedTokenCredential', code):
                line_num = self._find_line(lines, r'new\s+\w+Client')
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
        
        # Pattern 3: Service account with password authentication (CRITICAL)
        if re.search(r'AddAuthentication.*\.UsePassword|UseBasicAuthentication', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'UsePassword|UseBasicAuthentication')
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
        Analyze Java code for KSI-IAM-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Hardcoded service account credentials
        - Missing managed identity usage
        - Password-based service authentication
        - ClientSecretCredential validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hardcoded service account credentials (CRITICAL)
        sa_cred_patterns = [
            r'setClientSecret\s*\(\s*["\']',
            r'serviceAccountPassword\s*=\s*["\']',
            r'new\s+ClientSecretCredentialBuilder\(\).*clientSecret\(["\']',
            r'withPassword\(\s*["\']',
        ]
        
        for pattern in sa_cred_patterns:
            line_num = self._find_line(lines, pattern)
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
        
        # Pattern 2: Missing managed identity for Azure SDK (HIGH)
        if re.search(r'import com\.azure\.', code):
            if not re.search(r'DefaultAzureCredentialBuilder|ManagedIdentityCredentialBuilder', code):
                line_num = self._find_line(lines, r'import com\.azure\.')
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
        
        # Pattern 3: Service account with basic authentication (CRITICAL)
        if re.search(r'@Configuration.*BasicAuthenticationEntryPoint|httpBasic\(\)', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'BasicAuthenticationEntryPoint|httpBasic')
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
        Analyze TypeScript/JavaScript code for KSI-IAM-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Hardcoded service account tokens/secrets
        - Missing DefaultAzureCredential usage
        - API keys in service authentication
        - Managed identity configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hardcoded service account tokens (CRITICAL)
        token_patterns = [
            r'serviceAccountToken\s*[=:]\s*["\']',
            r'clientSecret\s*[=:]\s*["\'](?!process\.env|config\.|\$\{)',
            r'apiKey\s*[=:]\s*["\'](?!process\.env|config\.|\$\{)',
            r'bearerToken\s*[=:]\s*["\'](?!process\.env)',
        ]
        
        for pattern in token_patterns:
            line_num = self._find_line(lines, pattern)
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
        
        # Pattern 2: Missing DefaultAzureCredential (HIGH)
        if re.search(r'from ["\']@azure/identity["\']|require\(["\']@azure/identity["\']\)', code):
            if not re.search(r'DefaultAzureCredential|ManagedIdentityCredential|ChainedTokenCredential', code):
                line_num = self._find_line(lines, r'@azure/identity')
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
        
        # Pattern 3: Basic auth for service accounts (HIGH)
        if re.search(r'passport\.authenticate\(["\']basic["\']|auth:\s*\{\s*username:', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'basic["\']|auth:\s*\{')
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
                    line_num = self._find_line(lines, resource_type.split('/')[1])
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
            line_num = self._find_line(lines, r"type:\s*'SystemAssigned'")
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
                    "  userAssignedIdentities: { '\${userIdentity.id}': {} }\n"
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
            line_num = self._find_line(lines, r'azurerm_service_principal_password|client_secret\s*=')
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
