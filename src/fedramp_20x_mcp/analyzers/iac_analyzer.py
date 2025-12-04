"""
Infrastructure as Code (IaC) analyzers for FedRAMP 20x compliance.

Supports Bicep and Terraform code analysis.
"""

import re
from typing import Optional

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult


class BicepAnalyzer(BaseAnalyzer):
    """
    Analyzer for Azure Bicep Infrastructure as Code files.
    
    Checks for FedRAMP 20x compliance in Azure resource definitions.
    """
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze Bicep code for FedRAMP 20x compliance.
        
        Args:
            code: Bicep code content
            file_path: Path to the Bicep file
            
        Returns:
            AnalysisResult with findings
        """
        self.result = AnalysisResult()
        self.result.files_analyzed = 1
        
        # Check for diagnostic settings (KSI-MLA-05)
        self._check_diagnostic_settings(code, file_path)
        
        # Check for Key Vault usage (KSI-SVC-06)
        self._check_key_vault_secrets(code, file_path)
        
        # Check for Network Security Groups (KSI-CNA-01)
        self._check_network_security(code, file_path)
        
        # Check for RBAC assignments (KSI-IAM-03)
        self._check_rbac_assignments(code, file_path)
        
        # Check for encryption (KSI-SVC-03)
        self._check_encryption(code, file_path)
        
        return self.result
    
    def _check_diagnostic_settings(self, code: str, file_path: str) -> None:
        """Check if resources have diagnostic settings enabled (KSI-MLA-05)."""
        # Find Azure resources that should have logging
        loggable_resources = [
            r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts@",
            r"resource\s+\w+\s+'Microsoft\.Sql/servers@",
            r"resource\s+\w+\s+'Microsoft\.KeyVault/vaults@",
            r"resource\s+\w+\s+'Microsoft\.Web/sites@",
            r"resource\s+\w+\s+'Microsoft\.ContainerService/managedClusters@",
        ]
        
        has_loggable_resource = False
        for pattern in loggable_resources:
            if re.search(pattern, code):
                has_loggable_resource = True
                break
        
        if has_loggable_resource:
            # Check if diagnostic settings are defined
            has_diagnostics = bool(re.search(r"'Microsoft\.Insights/diagnosticSettings@", code))
            
            if not has_diagnostics:
                line_num = self.get_line_number(code, "resource")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.HIGH,
                    title="Missing diagnostic logging configuration",
                    description="Azure resource created without diagnostic settings. FedRAMP 20x requires audit logs for all data operations to support incident investigation and continuous monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add diagnostic settings resource to enable logging. Example:\n```bicep\nresource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n  name: 'logs'\n  scope: yourResource\n  properties: {\n    logs: [{ category: 'AuditEvent', enabled: true }]\n    workspaceId: logAnalyticsWorkspace.id\n  }\n}\n```\nSource: Azure Monitor best practices (https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings)"
                ))
            else:
                # Good practice detected
                line_num = self.get_line_number(code, "diagnosticSettings")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.INFO,
                    title="Diagnostic logging properly configured",
                    description="Resource has diagnostic settings enabled for audit logging.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Continue monitoring log retention and ensure logs are sent to centralized workspace.",
                    good_practice=True
                ))
    
    def _check_key_vault_secrets(self, code: str, file_path: str) -> None:
        """Check for hardcoded secrets and Key Vault usage (KSI-SVC-06)."""
        # Check for potential hardcoded secrets
        secret_patterns = [
            (r"password\s*[:=]\s*['\"][^'\"]+['\"]", "password"),
            (r"connectionString\s*[:=]\s*['\"][^'\"]+['\"]", "connection string"),
            (r"apiKey\s*[:=]\s*['\"][^'\"]+['\"]", "API key"),
            (r"secret\s*[:=]\s*['\"][^'\"]+['\"]", "secret"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                # Skip if it's a Key Vault reference
                if "@Microsoft.KeyVault" in match.group(0) or "reference" in match.group(0):
                    continue
                
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-06",
                    severity=Severity.HIGH,
                    title=f"Potential hardcoded {secret_type} detected",
                    description=f"Found {secret_type} in code. FedRAMP 20x requires secrets to be stored in Azure Key Vault with managed identities for access.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation=f"Store {secret_type} in Azure Key Vault and reference it using:\n```bicep\nparam keyVaultName string\nresource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' existing = {{\n  name: keyVaultName\n}}\nvar secretValue = keyVault.getSecret('secretName')\n```\nSource: Azure Key Vault best practices (https://learn.microsoft.com/azure/key-vault/general/best-practices)"
                ))
        
        # Check for Key Vault good practices
        if re.search(r"Microsoft\.KeyVault/vaults", code):
            # Check if managed identity is used
            if re.search(r"identity:\s*{\s*type:\s*'SystemAssigned'", code) or \
               re.search(r"identity:\s*{\s*type:\s*'UserAssigned'", code):
                line_num = self.get_line_number(code, "identity")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-06",
                    severity=Severity.INFO,
                    title="Managed identity configured for Key Vault access",
                    description="Resource uses managed identity for Key Vault authentication (no credentials in code).",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure Key Vault access policies or RBAC assignments grant appropriate permissions.",
                    good_practice=True
                ))
    
    def _check_network_security(self, code: str, file_path: str) -> None:
        """Check for Network Security Group configuration (KSI-CNA-01)."""
        # Check if VNets or subnets exist without NSG
        has_vnet = bool(re.search(r"Microsoft\.Network/virtualNetworks", code))
        has_nsg = bool(re.search(r"Microsoft\.Network/networkSecurityGroups", code))
        
        if has_vnet and not has_nsg:
            line_num = self.get_line_number(code, "virtualNetworks")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-01",
                severity=Severity.HIGH,
                title="Virtual network created without Network Security Group",
                description="VNet configured without NSG rules. FedRAMP 20x requires network segmentation and access controls.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Network Security Group with least-privilege rules:\n```bicep\nresource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {\n  name: 'nsg-${resourceGroup().name}'\n  location: location\n  properties: {\n    securityRules: [\n      {\n        name: 'DenyAllInbound'\n        properties: {\n          priority: 4096\n          access: 'Deny'\n          direction: 'Inbound'\n          protocol: '*'\n        }\n      }\n    ]\n  }\n}\n```\nSource: Azure Network Security best practices (https://learn.microsoft.com/azure/security/fundamentals/network-best-practices)"
            ))
        elif has_nsg:
            # Check for overly permissive rules
            if re.search(r"sourceAddressPrefix:\s*['\"][\*]", code):
                line_num = self.get_line_number(code, "sourceAddressPrefix")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-01",
                    severity=Severity.MEDIUM,
                    title="Overly permissive NSG rule detected",
                    description="NSG rule allows traffic from any source (*).",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Restrict source to specific IP ranges or service tags following least-privilege principle."
                ))
            else:
                line_num = self.get_line_number(code, "networkSecurityGroups")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-01",
                    severity=Severity.INFO,
                    title="Network Security Group configured with restricted rules",
                    description="NSG implements network segmentation and access controls.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Regularly review NSG rules to ensure they follow least-privilege access.",
                    good_practice=True
                ))
    
    def _check_rbac_assignments(self, code: str, file_path: str) -> None:
        """Check for RBAC role assignments (KSI-IAM-03)."""
        # Check for role assignments
        if re.search(r"Microsoft\.Authorization/roleAssignments", code):
            # Check for overly broad roles
            broad_roles = [
                r"'Owner'",
                r"'Contributor'",
                r"roleDefinitionId.*00000000-0000-0000-0000-000000000000",  # Owner role ID pattern
            ]
            
            has_broad_role = False
            for pattern in broad_roles:
                if re.search(pattern, code):
                    has_broad_role = True
                    line_num = self.get_line_number(code, pattern)
                    self.add_finding(Finding(
                        requirement_id="KSI-IAM-03",
                        severity=Severity.MEDIUM,
                        title="Overly broad RBAC role assignment detected",
                        description="Using Owner or Contributor roles grants excessive permissions. FedRAMP 20x requires least-privilege access.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Use specific built-in roles (e.g., 'Key Vault Secrets User', 'Storage Blob Data Reader') or create custom roles with minimal permissions.\nSource: Azure RBAC best practices (https://learn.microsoft.com/azure/role-based-access-control/best-practices)"
                    ))
                    break
            
            if not has_broad_role:
                line_num = self.get_line_number(code, "roleAssignments")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-03",
                    severity=Severity.INFO,
                    title="RBAC configured with appropriate roles",
                    description="Role assignments use specific, least-privilege roles.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Continue to review role assignments periodically and remove unused assignments.",
                    good_practice=True
                ))
    
    def _check_encryption(self, code: str, file_path: str) -> None:
        """Check for encryption configuration (KSI-SVC-03)."""
        # Check storage accounts for encryption
        if re.search(r"Microsoft\.Storage/storageAccounts", code):
            # Check if customer-managed keys are used
            if re.search(r"keySource:\s*['\"]Microsoft\.Keyvault", code):
                line_num = self.get_line_number(code, "keySource")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-03",
                    severity=Severity.INFO,
                    title="Customer-managed encryption keys configured",
                    description="Storage account uses customer-managed keys from Key Vault for enhanced security.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure key rotation policies are configured and monitored.",
                    good_practice=True
                ))


class TerraformAnalyzer(BaseAnalyzer):
    """
    Analyzer for Terraform Infrastructure as Code files.
    
    Checks for FedRAMP 20x compliance in Azure resource definitions (azurerm provider).
    """
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze Terraform code for FedRAMP 20x compliance.
        
        Args:
            code: Terraform code content
            file_path: Path to the Terraform file
            
        Returns:
            AnalysisResult with findings
        """
        self.result = AnalysisResult()
        self.result.files_analyzed = 1
        
        # Check for diagnostic settings (KSI-MLA-05)
        self._check_diagnostic_settings(code, file_path)
        
        # Check for Key Vault usage (KSI-SVC-06)
        self._check_key_vault_secrets(code, file_path)
        
        # Check for Network Security Groups (KSI-CNA-01)
        self._check_network_security(code, file_path)
        
        # Check for RBAC assignments (KSI-IAM-03)
        self._check_rbac_assignments(code, file_path)
        
        # Check for encryption (KSI-SVC-03)
        self._check_encryption(code, file_path)
        
        return self.result
    
    def _check_diagnostic_settings(self, code: str, file_path: str) -> None:
        """Check if resources have diagnostic settings enabled (KSI-MLA-05)."""
        # Find Azure resources that should have logging
        loggable_resources = [
            r"resource\s+\"azurerm_storage_account\"",
            r"resource\s+\"azurerm_mssql_server\"",
            r"resource\s+\"azurerm_key_vault\"",
            r"resource\s+\"azurerm_app_service\"",
            r"resource\s+\"azurerm_kubernetes_cluster\"",
        ]
        
        has_loggable_resource = False
        for pattern in loggable_resources:
            if re.search(pattern, code):
                has_loggable_resource = True
                break
        
        if has_loggable_resource:
            # Check if monitor diagnostic setting is defined
            has_diagnostics = bool(re.search(r"resource\s+\"azurerm_monitor_diagnostic_setting\"", code))
            
            if not has_diagnostics:
                line_num = self.get_line_number(code, "resource")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.HIGH,
                    title="Missing diagnostic logging configuration",
                    description="Azure resource created without diagnostic settings. FedRAMP 20x requires audit logs for all data operations.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add monitor diagnostic setting:\n```hcl\nresource \"azurerm_monitor_diagnostic_setting\" \"example\" {\n  name               = \"logs\"\n  target_resource_id = azurerm_storage_account.example.id\n  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n\n  enabled_log {\n    category = \"StorageWrite\"\n  }\n}\n```\nSource: Azure Monitor best practices (https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings)"
                ))
            else:
                line_num = self.get_line_number(code, "azurerm_monitor_diagnostic_setting")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.INFO,
                    title="Diagnostic logging properly configured",
                    description="Resource has diagnostic settings enabled.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Continue monitoring log retention policies.",
                    good_practice=True
                ))
    
    def _check_key_vault_secrets(self, code: str, file_path: str) -> None:
        """Check for hardcoded secrets and Key Vault usage (KSI-SVC-06)."""
        # Check for potential hardcoded secrets
        secret_patterns = [
            (r"password\s*=\s*\"[^\"]+\"", "password"),
            (r"connection_string\s*=\s*\"[^\"]+\"", "connection string"),
            (r"value\s*=\s*\"[^\"]*[Pp]assword=[^\"]+\"", "connection string with password"),
            (r"api_key\s*=\s*\"[^\"]+\"", "API key"),
            (r"secret\s*=\s*\"[^\"]+\"", "secret"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                # Skip if it's a Key Vault data source or variable reference
                if "data.azurerm_key_vault_secret" in match.group(0) or "var." in match.group(0):
                    continue
                
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-06",
                    severity=Severity.HIGH,
                    title=f"Potential hardcoded {secret_type} detected",
                    description=f"Found {secret_type} value in Terraform code. FedRAMP 20x requires secrets in Key Vault.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation=f"Store {secret_type} in Azure Key Vault and reference it:\n```hcl\ndata \"azurerm_key_vault_secret\" \"example\" {{\n  name         = \"secret-name\"\n  key_vault_id = azurerm_key_vault.example.id\n}}\n\nresource \"azurerm_app_service\" \"example\" {{\n  connection_string {{\n    name  = \"Database\"\n    type  = \"SQLAzure\"\n    value = data.azurerm_key_vault_secret.example.value\n  }}\n}}\n```\nSource: Azure Key Vault best practices (https://learn.microsoft.com/azure/key-vault/general/best-practices)"
                ))
        
        # Check for Key Vault good practices
        if re.search(r"azurerm_key_vault\"", code):
            if re.search(r"identity\s*{\s*type\s*=\s*\"SystemAssigned\"", code) or \
               re.search(r"identity\s*{\s*type\s*=\s*\"UserAssigned\"", code):
                line_num = self.get_line_number(code, "identity")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-06",
                    severity=Severity.INFO,
                    title="Managed identity configured for Key Vault",
                    description="Resource uses managed identity for authentication.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Verify Key Vault access policies grant minimal permissions.",
                    good_practice=True
                ))
    
    def _check_network_security(self, code: str, file_path: str) -> None:
        """Check for Network Security Group configuration (KSI-CNA-01)."""
        has_vnet = bool(re.search(r"azurerm_virtual_network\"", code))
        has_nsg = bool(re.search(r"azurerm_network_security_group\"", code))
        
        if has_vnet and not has_nsg:
            line_num = self.get_line_number(code, "azurerm_virtual_network")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-01",
                severity=Severity.HIGH,
                title="Virtual network without Network Security Group",
                description="VNet created without NSG. FedRAMP 20x requires network access controls.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add NSG with deny-all default:\n```hcl\nresource \"azurerm_network_security_group\" \"example\" {\n  name                = \"nsg-example\"\n  location            = azurerm_resource_group.example.location\n  resource_group_name = azurerm_resource_group.example.name\n\n  security_rule {\n    name                       = \"DenyAllInbound\"\n    priority                   = 4096\n    direction                  = \"Inbound\"\n    access                     = \"Deny\"\n    protocol                   = \"*\"\n    source_port_range          = \"*\"\n    destination_port_range     = \"*\"\n    source_address_prefix      = \"*\"\n    destination_address_prefix = \"*\"\n  }\n}\n```\nSource: Azure Network Security (https://learn.microsoft.com/azure/security/fundamentals/network-best-practices)"
            ))
        elif has_nsg:
            if re.search(r"source_address_prefix\s*=\s*\"\*\"", code):
                line_num = self.get_line_number(code, "source_address_prefix")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-01",
                    severity=Severity.MEDIUM,
                    title="Overly permissive NSG rule",
                    description="NSG allows traffic from any source.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Restrict to specific IP ranges or service tags."
                ))
            else:
                line_num = self.get_line_number(code, "azurerm_network_security_group")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-01",
                    severity=Severity.INFO,
                    title="Network Security Group properly configured",
                    description="NSG implements network segmentation.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Review NSG rules regularly.",
                    good_practice=True
                ))
    
    def _check_rbac_assignments(self, code: str, file_path: str) -> None:
        """Check for RBAC role assignments (KSI-IAM-03)."""
        if re.search(r"azurerm_role_assignment\"", code):
            # Check for overly broad roles
            if re.search(r"role_definition_name\s*=\s*\"(Owner|Contributor)\"", code):
                line_num = self.get_line_number(code, "role_definition_name")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-03",
                    severity=Severity.MEDIUM,
                    title="Overly broad RBAC role detected",
                    description="Owner/Contributor roles grant excessive permissions.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use specific roles like 'Key Vault Secrets User' or custom roles.\nSource: Azure RBAC best practices (https://learn.microsoft.com/azure/role-based-access-control/best-practices)"
                ))
            else:
                line_num = self.get_line_number(code, "azurerm_role_assignment")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-03",
                    severity=Severity.INFO,
                    title="RBAC configured with least-privilege roles",
                    description="Role assignments use appropriate permissions.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Review assignments periodically.",
                    good_practice=True
                ))
    
    def _check_encryption(self, code: str, file_path: str) -> None:
        """Check for encryption configuration (KSI-SVC-03)."""
        if re.search(r"azurerm_storage_account\"", code):
            if re.search(r"customer_managed_key\s*{", code):
                line_num = self.get_line_number(code, "customer_managed_key")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-03",
                    severity=Severity.INFO,
                    title="Customer-managed encryption keys enabled",
                    description="Storage uses customer-managed keys from Key Vault.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure key rotation policies.",
                    good_practice=True
                ))
