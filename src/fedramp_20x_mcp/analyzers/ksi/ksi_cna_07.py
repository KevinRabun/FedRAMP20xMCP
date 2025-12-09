"""
KSI-CNA-07: Best Practices

Ensure cloud-native information resources are implemented based on host provider's best practices and documented guidance.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_07_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CNA-07: Best Practices
    
    **Official Statement:**
    Ensure cloud-native information resources are implemented based on host provider's best practices and documented guidance.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-17.3
    - cm-2
    - pl-10
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-07"
    KSI_NAME = "Best Practices"
    KSI_STATEMENT = """Ensure cloud-native information resources are implemented based on host provider's best practices and documented guidance."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-17.3", "Managed Access Control Points"),
        ("cm-2", "Baseline Configuration"),
        ("pl-10", "Baseline Selection")
    ]
    CODE_DETECTABLE = False
    IMPLEMENTATION_STATUS = "NOT_IMPLEMENTED"
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
        Analyze Python code for KSI-CNA-07 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Ensure cloud-native information resources are implemented based on host provider...
        """
        findings = []
        
        # TODO: Implement Python-specific detection logic
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-07 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Ensure cloud-native information resources are implemented based on host provider...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-07 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Ensure cloud-native information resources are implemented based on host provider...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-07 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Ensure cloud-native information resources are implemented based on host provider...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-07 compliance.
        
        Detects:
        - Outdated API versions (not following Azure provider best practices)
        - Missing managed identities (Azure best practice for authentication)
        - Deprecated resource configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Outdated API versions (MEDIUM)
        # Azure best practice: Use latest stable API versions
        resource_matches = []
        for i, line in enumerate(lines, start=1):
            match = re.search(r"resource\s+(\w+)\s+'([^@']+)@(\d{4}-\d{2}-\d{2})(?:-preview)?'", line)
            if match:
                resource_matches.append((i, match.group(2), match.group(3)))
        
        for line_num, resource_type, api_version in resource_matches:
            # Check for old API versions (before 2022 is generally outdated)
            year = int(api_version.split('-')[0])
            if year < 2022:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Outdated Azure Resource API Version",
                    description=(
                        f"Resource uses API version '{api_version}' which is outdated. "
                        "KSI-CNA-07 requires implementing cloud-native resources based on "
                        "host provider's best practices and documented guidance. "
                        "Azure best practice is to use the latest stable API versions "
                        "to access new features, security improvements, and bug fixes. "
                        "Outdated API versions may lack important security controls "
                        "and are not supported by Azure's latest guidance."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Update to latest stable API version:\n"
                        f"// Before (outdated): {resource_type}@{api_version}\n"
                        f"// After (latest): {resource_type}@2023-XX-XX or later\n\n"
                        "Check Azure documentation for latest API versions:\n"
                        "1. Visit https://learn.microsoft.com/azure/templates/\n"
                        "2. Find your resource type\n"
                        "3. Use the latest non-preview API version\n\n"
                        "Example: Storage Account with latest API\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: 'mystorageaccount'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: {\n"
                        "    name: 'Standard_LRS'\n"
                        "  }\n"
                        "  kind: 'StorageV2'  // Latest storage account type\n"
                        "  properties: {\n"
                        "    minimumTlsVersion: 'TLS1_2'  // Security best practice\n"
                        "    supportsHttpsTrafficOnly: true  // Security best practice\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Resource Provider API versions (https://learn.microsoft.com/azure/templates/)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: App Service without managed identity (MEDIUM)
        # Azure best practice: Use managed identities instead of connection strings
        app_service_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Web/sites")
        
        if app_service_match:
            line_num = app_service_match['line_num']
            # Check if managed identity is configured
            app_end = min(len(lines), line_num + 40)
            app_lines = lines[line_num:app_end]
            
            has_identity = any(re.search(r"identity:\s*{", line) 
                             for line in app_lines)
            
            if not has_identity:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="App Service Without Managed Identity",
                    description=(
                        "App Service deployed without managed identity configuration. "
                        "KSI-CNA-07 requires following Azure best practices for cloud-native resources. "
                        "Azure's documented guidance recommends using managed identities "
                        "for authentication instead of storing credentials in code or configuration. "
                        "This follows the principle of least privilege (AC-17.3) "
                        "and reduces the risk of credential exposure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable managed identity per Azure best practices:\n"
                        "resource appService 'Microsoft.Web/sites@2023-01-01' = {\n"
                        "  name: 'myapp'\n"
                        "  location: resourceGroup().location\n"
                        "  // Azure best practice: Enable managed identity\n"
                        "  identity: {\n"
                        "    type: 'SystemAssigned'  // Recommended for most scenarios\n"
                        "    // Or use UserAssigned for cross-resource scenarios:\n"
                        "    // type: 'UserAssigned'\n"
                        "    // userAssignedIdentities: {\n"
                        r"    //   '${userAssignedIdentity.id}': {}" + "\n"
                        "    // }\n"
                        "  }\n"
                        "  properties: {\n"
                        "    httpsOnly: true  // Security best practice\n"
                        "    clientAffinityEnabled: false  // Stateless best practice\n"
                        "    siteConfig: {\n"
                        "      minTlsVersion: '1.2'  // Security best practice\n"
                        "      ftpsState: 'Disabled'  // Security best practice\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "// Grant identity access to Azure resources (e.g., Key Vault)\n"
                        "resource keyVaultAccessPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2023-02-01' = {\n"
                        "  parent: keyVault\n"
                        "  name: 'add'\n"
                        "  properties: {\n"
                        "    accessPolicies: [\n"
                        "      {\n"
                        "        tenantId: subscription().tenantId\n"
                        "        objectId: appService.identity.principalId\n"
                        "        permissions: {\n"
                        "          secrets: ['get', 'list']\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Managed Identities Best Practices (https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/managed-identity-best-practice-recommendations)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Storage account with deprecated SKU (LOW)
        storage_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts")
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check for deprecated 'Standard' kind (should use 'StorageV2')
            storage_end = min(len(lines), line_num + 15)
            storage_lines = lines[line_num:storage_end]
            
            has_deprecated_kind = any(re.search(r"kind:\s*'(Storage|BlobStorage)'", line) 
                                    for line in storage_lines)
            
            if has_deprecated_kind:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="Storage Account Using Deprecated Kind",
                    description=(
                        "Storage account uses deprecated 'Storage' or 'BlobStorage' kind. "
                        "KSI-CNA-07 requires following Azure's documented guidance and best practices. "
                        "Azure recommends using 'StorageV2' (general-purpose v2) for all new storage accounts "
                        "as it provides access to the latest features, better performance, "
                        "and lower pricing. Legacy storage account types have limited capabilities "
                        "and are not aligned with Azure's current best practices."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use StorageV2 per Azure best practices:\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: 'mystorageaccount'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: {\n"
                        "    name: 'Standard_LRS'  // Or GRS, GZRS based on requirements\n"
                        "  }\n"
                        "  kind: 'StorageV2'  // Azure best practice (not 'Storage' or 'BlobStorage')\n"
                        "  properties: {\n"
                        "    // Security best practices from Azure documentation\n"
                        "    minimumTlsVersion: 'TLS1_2'\n"
                        "    supportsHttpsTrafficOnly: true\n"
                        "    allowBlobPublicAccess: false  // Prevent anonymous access\n"
                        "    // Access tier based on workload (Hot, Cool, or Archive)\n"
                        "    accessTier: 'Hot'\n"
                        "    // Enable soft delete for data protection\n"
                        "    deleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 7\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Note: StorageV2 provides:\n"
                        "- All features of Storage and BlobStorage\n"
                        "- Lower transaction costs\n"
                        "- Support for all access tiers\n"
                        "- Better integration with Azure services\n\n"
                        "Ref: Storage Account Overview (https://learn.microsoft.com/azure/storage/common/storage-account-overview)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-07 compliance.
        
        Detects:
        - Outdated azurerm provider versions
        - Missing managed identities
        - Deprecated resource configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Outdated azurerm provider version (MEDIUM)
        provider_match = self._find_line(lines, r'required_providers\s*{')
        
        if provider_match:
            line_num = provider_match['line_num']
            # Check azurerm provider version
            provider_end = min(len(lines), line_num + 10)
            provider_lines = lines[line_num:provider_end]
            
            for i, line in enumerate(provider_lines, start=line_num):
                version_match = re.search(r'azurerm.*version\s*=\s*["\']~>\s*(\d+)\.(\d+)', line)
                if version_match:
                    major = int(version_match.group(1))
                    minor = int(version_match.group(2))
                    
                    # Check if version is outdated (< 3.0 is generally outdated)
                    if major < 3:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Outdated Azure Provider Version",
                            description=(
                                f"Terraform uses azurerm provider version ~> {major}.{minor} which is outdated. "
                                "KSI-CNA-07 requires implementing resources based on Azure's best practices and guidance. "
                                "HashiCorp and Microsoft recommend using the latest stable azurerm provider version "
                                "to access new Azure features, security improvements, and bug fixes. "
                                "Outdated providers may not support latest Azure resources "
                                "or security controls required by FedRAMP 20x."
                            ),
                            file_path=file_path,
                            line_number=i,
                            snippet=self._get_snippet(lines, i, context=3),
                            remediation=(
                                "Update to latest azurerm provider version:\n"
                                "terraform {\n"
                                "  required_version = \">= 1.5.0\"\n"
                                "  required_providers {\n"
                                "    azurerm = {\n"
                                "      source  = \"hashicorp/azurerm\"\n"
                                "      version = \"~> 3.0\"  # Use latest 3.x version\n"
                                "    }\n"
                                "  }\n"
                                "}\n\n"
                                "provider \"azurerm\" {\n"
                                "  features {\n"
                                "    # Azure best practice: Enable key vault purge protection\n"
                                "    key_vault {\n"
                                "      purge_soft_delete_on_destroy    = false\n"
                                "      recover_soft_deleted_key_vaults = true\n"
                                "    }\n"
                                "    # Azure best practice: Prevent accidental VM deletion\n"
                                "    virtual_machine {\n"
                                "      delete_os_disk_on_deletion     = false\n"
                                "      graceful_shutdown              = true\n"
                                "    }\n"
                                "  }\n"
                                "}\n\n"
                                "Check release notes: https://github.com/hashicorp/terraform-provider-azurerm/releases\n"
                                "Migration guide: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/3.0-upgrade-guide\n"
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        # Pattern 2: App Service without managed identity (MEDIUM)
        app_service_match = self._find_line(lines, r'resource\s+"azurerm_(linux|windows|function)_app')
        
        if app_service_match:
            line_num = app_service_match['line_num']
            # Check if managed identity is configured
            app_end = min(len(lines), line_num + 50)
            app_lines = lines[line_num:app_end]
            
            has_identity = any(re.search(r'identity\s*{', line) 
                             for line in app_lines)
            
            if not has_identity:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="App Service Without Managed Identity",
                    description=(
                        "App Service deployed without managed identity configuration. "
                        "KSI-CNA-07 requires following Azure best practices for cloud-native resources. "
                        "Azure's documented guidance and Terraform best practices recommend "
                        "using managed identities for authentication instead of storing credentials. "
                        "This follows AC-17.3 (remote access mechanisms) "
                        "and CM-2 (baseline configuration) requirements."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable managed identity per Azure/Terraform best practices:\n"
                        "resource \"azurerm_linux_app_service\" \"example\" {\n"
                        "  name                = \"example-app\"\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  app_service_plan_id = azurerm_app_service_plan.example.id\n\n"
                        "  # Azure best practice: Enable managed identity\n"
                        "  identity {\n"
                        "    type = \"SystemAssigned\"  # Recommended for most scenarios\n"
                        "    # Or use UserAssigned for cross-resource access:\n"
                        "    # type         = \"UserAssigned\"\n"
                        "    # identity_ids = [azurerm_user_assigned_identity.example.id]\n"
                        "  }\n\n"
                        "  # Security best practices from Azure documentation\n"
                        "  https_only              = true\n"
                        "  client_affinity_enabled = false  # Stateless best practice\n\n"
                        "  site_config {\n"
                        "    min_tls_version = \"1.2\"\n"
                        "    ftps_state      = \"Disabled\"\n"
                        "  }\n"
                        "}\n\n"
                        "# Grant identity access to Key Vault (example)\n"
                        "resource \"azurerm_key_vault_access_policy\" \"app\" {\n"
                        "  key_vault_id = azurerm_key_vault.example.id\n"
                        "  tenant_id    = data.azurerm_client_config.current.tenant_id\n"
                        "  object_id    = azurerm_linux_app_service.example.identity[0].principal_id\n\n"
                        "  secret_permissions = [\n"
                        "    \"Get\",\n"
                        "    \"List\"\n"
                        "  ]\n"
                        "}\n\n"
                        "Ref: azurerm_linux_app_service identity (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_app_service#identity)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    

        """
        Find first line matching regex pattern.
        Returns dict with line_num and line content, or None if not found.
        """
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.IGNORECASE):
                return {'line_num': i, 'line': line}
        return None
        return 0
    

        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

