"""
Terraform Infrastructure as Code analyzer for FedRAMP 20x compliance (Azure RM provider).

Supports Terraform code analysis for Azure resource definitions.
"""

import re
from typing import Optional

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult

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
        
        # Phase 2: Critical Infrastructure Security
        self._check_mfa_enforcement(code, file_path)
        self._check_privileged_access(code, file_path)
        self._check_container_security(code, file_path)
        self._check_immutable_infrastructure(code, file_path)
        self._check_api_gateway(code, file_path)
        self._check_backup_configuration(code, file_path)
        self._check_patch_management(code, file_path)
        self._check_centralized_logging(code, file_path)
        self._check_log_retention(code, file_path)
        
        # Phase 5: Runtime Security & Monitoring
        self._check_security_monitoring(code, file_path)      # KSI-MLA-03
        self._check_performance_monitoring(code, file_path)   # KSI-MLA-04
        self._check_log_analysis(code, file_path)            # KSI-MLA-06
        self._check_incident_detection(code, file_path)       # KSI-INR-01
        self._check_incident_response_logging(code, file_path) # KSI-INR-02
        self._check_threat_intelligence(code, file_path)      # KSI-AFR-03
        
        # Phase 6A: Core Infrastructure (Recovery, Network, Access, Crypto)
        self._check_recovery_objectives(code, file_path)      # KSI-RPL-01
        self._check_recovery_plan(code, file_path)            # KSI-RPL-02
        self._check_system_backups(code, file_path)           # KSI-RPL-03
        self._check_recovery_testing(code, file_path)         # KSI-RPL-04
        self._check_traffic_flow(code, file_path)             # KSI-CNA-03
        self._check_ddos_protection(code, file_path)          # KSI-CNA-05
        self._check_least_privilege(code, file_path)          # KSI-IAM-05
        self._check_cryptographic_modules(code, file_path)    # KSI-AFR-11
        
        # Phase 6B: Service Management, Advanced Monitoring, Secure Config, Microservices
        self._check_communication_integrity(code, file_path)  # KSI-SVC-09
        self._check_data_destruction(code, file_path)         # KSI-SVC-10
        self._check_event_types_monitoring(code, file_path)   # KSI-MLA-07
        self._check_log_data_access(code, file_path)          # KSI-MLA-08
        self._check_secure_configuration(code, file_path)     # KSI-AFR-07
        self._check_microservices_security(code, file_path)   # KSI-CNA-08
        self._check_incident_after_action(code, file_path)    # KSI-INR-03
        self._check_change_management(code, file_path)        # KSI-CMT-04
        
        # Phase 7: Supply Chain and Policy Requirements
        self._check_supply_chain_security(code, file_path)    # KSI-TPR-03
        self._check_third_party_monitoring(code, file_path)   # KSI-TPR-04
        
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
    
    # Phase 2: Critical Infrastructure Security Methods (Terraform-specific)
    
    def _check_mfa_enforcement(self, code: str, file_path: str) -> None:
        """Check for MFA enforcement in Conditional Access policies (KSI-IAM-02)."""
        # Check for azuread_conditional_access_policy resource
        has_conditional_access = bool(re.search(r"resource\s+['\"]azuread_conditional_access_policy['\"]", code))
        
        if has_conditional_access:
            # Check if MFA grant control is configured
            has_mfa = bool(re.search(r"grant_controls\s*{[^}]*built_in_controls\s*=\s*\[[^\]]*['\"]mfa['\"]", code, re.DOTALL))
            
            if not has_mfa:
                line_num = self.get_line_number(code, "azuread_conditional_access_policy")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-02",
                    severity=Severity.HIGH,
                    title="Conditional Access policy missing MFA enforcement",
                    description="FedRAMP 20x requires phishing-resistant multi-factor authentication for all users.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add MFA requirement:\n```hcl\ngrant_controls {\n  built_in_controls = [\"mfa\"]\n  authentication_strength_policy_id = azuread_authentication_strength_policy.phishing_resistant.id\n}\n```\nSource: Azure Conditional Access (https://learn.microsoft.com/entra/identity/conditional-access/)"
                ))
            else:
                line_num = self.get_line_number(code, "built_in_controls")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-02",
                    severity=Severity.INFO,
                    title="MFA enforcement configured in Conditional Access",
                    description="Policy requires multi-factor authentication for user access.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Verify phishing-resistant methods (FIDO2, Windows Hello) are enabled.",
                    good_practice=True
                ))
    
    def _check_privileged_access(self, code: str, file_path: str) -> None:
        """Check for Privileged Identity Management configuration (KSI-IAM-06)."""
        # Check for permanent admin role assignments (anti-pattern)
        admin_pattern = r"azurerm_role_assignment[^}]*role_definition_name\s*=\s*['\"]Owner['\"]|['\"]Contributor['\"]"
        
        if re.search(admin_pattern, code, re.DOTALL):
            # Check if it's for a user principal (not managed identity)
            if re.search(r"principal_type\s*=\s*['\"]User['\"]", code):
                line_num = self.get_line_number(code, "role_definition_name")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-06",
                    severity=Severity.HIGH,
                    title="Permanent privileged role assignment detected",
                    description="Privileged roles should use Just-In-Time (JIT) access via Privileged Identity Management, not permanent assignments. FedRAMP 20x requires time-limited elevated access.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement Azure PIM:\n1. Remove permanent admin assignments\n2. Use azurerm_pim_eligible_role_assignment for eligible access\n3. Configure approval workflows and maximum duration\n\nSource: Azure PIM best practices (https://learn.microsoft.com/entra/id-governance/privileged-identity-management/)"
                ))
        
        # Check for PIM configuration (good practice)
        if re.search(r"azurerm_pim_eligible_role_assignment|azurerm_pim_active_role_assignment", code):
            line_num = self.get_line_number(code, "pim")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-06",
                severity=Severity.INFO,
                title="Privileged Identity Management configured",
                description="Just-in-time access configured for privileged roles.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure approval workflows and maximum duration are configured appropriately.",
                good_practice=True
            ))
    
    def _check_container_security(self, code: str, file_path: str) -> None:
        """Check for container security and isolation (KSI-CNA-02)."""
        # Check for AKS cluster
        if re.search(r"azurerm_kubernetes_cluster\"", code):
            issues = []
            
            # Check for Defender for Containers
            if not re.search(r"microsoft_defender\s*{[^}]*enabled\s*=\s*true", code, re.DOTALL):
                issues.append("Defender for Containers not enabled")
            
            # Check for network policy
            if not re.search(r"network_policy\s*=\s*['\"]azure['\"]|['\"]calico['\"]", code):
                issues.append("Network policy not enabled for pod isolation")
            
            # Check for Azure Policy addon
            if not re.search(r"azure_policy_enabled\s*=\s*true", code):
                issues.append("Azure Policy addon not enabled for pod security")
            
            if issues:
                line_num = self.get_line_number(code, "azurerm_kubernetes_cluster")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-02",
                    severity=Severity.HIGH,
                    title="Container security controls missing",
                    description=f"AKS cluster missing critical security controls: {', '.join(issues)}. FedRAMP 20x requires comprehensive container security.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable container security:\n```hcl\nmicrosoft_defender {\n  enabled = true\n}\nnetwork_profile {\n  network_policy = \"azure\"\n}\nazure_policy_enabled = true\n```\nSource: AKS security best practices (https://learn.microsoft.com/azure/aks/concepts-security)"
                ))
        
        # Check for Azure Container Registry
        if re.search(r"azurerm_container_registry\"", code):
            if not re.search(r"quarantine_policy_enabled\s*=\s*true|trust_policy\s*{", code):
                line_num = self.get_line_number(code, "azurerm_container_registry")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-02",
                    severity=Severity.MEDIUM,
                    title="Container registry missing security policies",
                    description="ACR should have quarantine and trust policies enabled to prevent untrusted images.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable ACR security:\n```hcl\nquarantine_policy_enabled = true\ntrust_policy {\n  enabled = true\n}\n```"
                ))
    
    def _check_immutable_infrastructure(self, code: str, file_path: str) -> None:
        """Check for immutable infrastructure patterns (KSI-CNA-04)."""
        # Check for critical resources
        critical_patterns = [
            r"azurerm_storage_account\"",
            r"azurerm_mssql_server\"",
            r"azurerm_key_vault\"",
            r"azurerm_virtual_network\"",
        ]
        
        has_critical_resources = any(re.search(pattern, code) for pattern in critical_patterns)
        
        if has_critical_resources:
            has_lock = bool(re.search(r"azurerm_management_lock\"", code))
            
            if not has_lock:
                line_num = self.get_line_number(code, "resource")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-04",
                    severity=Severity.MEDIUM,
                    title="Critical resources missing resource locks",
                    description="FedRAMP 20x requires immutable infrastructure. Critical resources should have locks to prevent manual modifications.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add resource lock:\n```hcl\nresource \"azurerm_management_lock\" \"prevent_deletion\" {\n  name       = \"prevent-deletion\"\n  scope      = azurerm_storage_account.example.id\n  lock_level = \"CanNotDelete\"\n  notes      = \"Prevent manual deletion - use IaC only\"\n}\n```\nSource: Azure Resource Locks (https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources)"
                ))
            else:
                line_num = self.get_line_number(code, "azurerm_management_lock")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-04",
                    severity=Severity.INFO,
                    title="Resource locks configured for immutability",
                    description="Critical resources protected with locks to enforce IaC-only changes.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure lock applies to production resources and bypass process is documented.",
                    good_practice=True
                ))
    
    def _check_api_gateway(self, code: str, file_path: str) -> None:
        """Check for API Management security configuration (KSI-CNA-06)."""
        # Check for API Management
        if re.search(r"azurerm_api_management\"", code):
            # Check for policy configuration
            if not re.search(r"azurerm_api_management_api_policy|azurerm_api_management_policy", code):
                line_num = self.get_line_number(code, "azurerm_api_management")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-06",
                    severity=Severity.HIGH,
                    title="API Management missing security policies",
                    description="APIM should have policies configured for rate limiting, authentication, and CORS. FedRAMP 20x requires API security controls.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure API security policies:\n```hcl\nresource \"azurerm_api_management_api_policy\" \"example\" {\n  xml_content = <<XML\n<policies>\n  <inbound>\n    <rate-limit calls=\"100\" renewal-period=\"60\" />\n    <validate-jwt>\n      <openid-config url=\"https://login.microsoftonline.com/...\" />\n    </validate-jwt>\n  </inbound>\n</policies>\nXML\n}\n```\nSource: APIM security policies (https://learn.microsoft.com/azure/api-management/api-management-policies)"
                ))
            else:
                # Check for wildcard CORS
                if re.search(r"<allowed-origins>.*<origin>\*</origin>", code):
                    line_num = self.get_line_number(code, "allowed-origins")
                    self.add_finding(Finding(
                        requirement_id="KSI-CNA-06",
                        severity=Severity.MEDIUM,
                        title="API Management CORS set to wildcard",
                        description="CORS allows all origins (*) which is a security risk.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Restrict CORS to specific domains."
                    ))
    
    def _check_backup_configuration(self, code: str, file_path: str) -> None:
        """Check for backup and recovery configuration (KSI-SVC-04)."""
        # Check for resources that should have backups
        backup_patterns = [
            (r"azurerm_storage_account\"", "Storage accounts"),
            (r"azurerm_mssql_database\"", "SQL databases"),
            (r"azurerm_(linux|windows)_virtual_machine\"", "Virtual machines"),
        ]
        
        for pattern, resource_type in backup_patterns:
            if re.search(pattern, code):
                has_backup = bool(re.search(r"azurerm_backup_|azurerm_recovery_services_vault", code))
                
                if not has_backup:
                    line_num = self.get_line_number(code, pattern.split("\"")[0])
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-04",
                        severity=Severity.HIGH,
                        title=f"{resource_type} missing backup configuration",
                        description="FedRAMP 20x requires backup and recovery capabilities for all critical data and systems.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation=f"Configure Azure Backup:\n```hcl\nresource \"azurerm_recovery_services_vault\" \"vault\" {{\n  name                = \"backup-vault\"\n  location            = azurerm_resource_group.example.location\n  resource_group_name = azurerm_resource_group.example.name\n  sku                 = \"Standard\"\n  storage_mode_type   = \"GeoRedundant\"  // FedRAMP requirement\n}}\n```\nSource: Azure Backup (https://learn.microsoft.com/azure/backup/)"
                    ))
                    break
    
    def _check_patch_management(self, code: str, file_path: str) -> None:
        """Check for automated patch management (KSI-SVC-05)."""
        # Check for virtual machines
        vm_patterns = [r"azurerm_linux_virtual_machine\"", r"azurerm_windows_virtual_machine\""]
        
        for pattern in vm_patterns:
            if re.search(pattern, code):
                has_patch_management = bool(re.search(r"patch_mode\s*=\s*['\"]AutomaticByPlatform['\"]|automatic_updates_enabled\s*=\s*true", code))
                
                if not has_patch_management:
                    line_num = self.get_line_number(code, pattern.split("\"")[0])
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-05",
                        severity=Severity.HIGH,
                        title="Virtual machines missing automatic patch management",
                        description="FedRAMP 20x requires automated patching to maintain security baselines.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Enable automatic OS patching:\n```hcl\npatch_mode = \"AutomaticByPlatform\"\npatch_assessment_mode = \"AutomaticByPlatform\"\n```\nSource: Azure Update Management (https://learn.microsoft.com/azure/update-manager/)"
                    ))
                else:
                    line_num = self.get_line_number(code, "patch_mode")
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-05",
                        severity=Severity.INFO,
                        title="Automatic patch management configured",
                        description="VM configured for automatic OS updates and patching.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Ensure maintenance windows are configured for production systems.",
                        good_practice=True
                    ))
                break
        
        # Check for AKS auto-upgrade
        if re.search(r"azurerm_kubernetes_cluster\"", code):
            if not re.search(r"automatic_channel_upgrade\s*=\s*['\"]patch['\"]", code):
                line_num = self.get_line_number(code, "azurerm_kubernetes_cluster")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-05",
                    severity=Severity.MEDIUM,
                    title="AKS cluster missing automatic upgrade configuration",
                    description="Kubernetes clusters should have automatic upgrades enabled for security patches.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable AKS automatic upgrades:\n```hcl\nautomatic_channel_upgrade = \"patch\"\n```"
                ))
    
    def _check_centralized_logging(self, code: str, file_path: str) -> None:
        """Check for centralized logging to SIEM (KSI-MLA-01)."""
        # Check if Log Analytics workspace exists
        has_workspace = bool(re.search(r"azurerm_log_analytics_workspace\"", code))
        
        # Check if Sentinel is configured
        has_sentinel = bool(re.search(r"azurerm_sentinel_", code))
        
        # Check if diagnostic settings point to workspace
        has_diagnostics = bool(re.search(r"azurerm_monitor_diagnostic_setting\"", code))
        
        if has_diagnostics and not has_workspace:
            line_num = self.get_line_number(code, "azurerm_monitor_diagnostic_setting")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-01",
                severity=Severity.HIGH,
                title="Diagnostic settings without centralized Log Analytics workspace",
                description="FedRAMP 20x requires all logs sent to centralized SIEM for security monitoring.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Create Log Analytics workspace and configure Sentinel:\n```hcl\nresource \"azurerm_log_analytics_workspace\" \"security_logs\" {\n  name                = \"security-logs\"\n  retention_in_days   = 90\n  sku                 = \"PerGB2018\"\n}\n\nresource \"azurerm_sentinel_onboarding\" \"example\" {\n  workspace_id = azurerm_log_analytics_workspace.security_logs.id\n}\n```\nSource: Azure Sentinel (https://learn.microsoft.com/azure/sentinel/)"
            ))
        elif has_workspace and has_sentinel:
            line_num = self.get_line_number(code, "azurerm_log_analytics_workspace")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-01",
                severity=Severity.INFO,
                title="Centralized logging with Sentinel configured",
                description="Logs sent to Log Analytics workspace with Sentinel SIEM enabled.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure all critical resources send logs to this workspace.",
                good_practice=True
            ))
    
    def _check_log_retention(self, code: str, file_path: str) -> None:
        """Check for audit log retention policies (KSI-MLA-02)."""
        # Check Log Analytics workspace retention
        if re.search(r"azurerm_log_analytics_workspace\"", code):
            retention_match = re.search(r"retention_in_days\s*=\s*(\d+)", code)
            
            if retention_match:
                retention_days = int(retention_match.group(1))
                
                if retention_days < 90:
                    line_num = self.get_line_number(code, "retention_in_days")
                    self.add_finding(Finding(
                        requirement_id="KSI-MLA-02",
                        severity=Severity.HIGH,
                        title=f"Insufficient log retention ({retention_days} days)",
                        description="FedRAMP 20x requires minimum 90-day log retention for audit purposes.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Increase retention to meet compliance:\n```hcl\nretention_in_days = 90  # FedRAMP minimum\n# Consider 365+ for high-impact systems\n```\nSource: FedRAMP logging requirements"
                    ))
                else:
                    line_num = self.get_line_number(code, "retention_in_days")
                    self.add_finding(Finding(
                        requirement_id="KSI-MLA-02",
                        severity=Severity.INFO,
                        title=f"Adequate log retention configured ({retention_days} days)",
                        description="Log retention meets FedRAMP 20x minimum requirements.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Consider archival to long-term storage for extended retention.",
                        good_practice=True
                    ))
            else:
                line_num = self.get_line_number(code, "azurerm_log_analytics_workspace")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-02",
                    severity=Severity.MEDIUM,
                    title="Log retention not explicitly configured",
                    description="Relying on default retention may not meet FedRAMP requirements.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Explicitly set retention to 90+ days."
                ))
        
        # Check for immutable storage for long-term retention
        if re.search(r"azurerm_storage_account\".*logs", code, re.IGNORECASE | re.DOTALL):
            has_immutability = bool(re.search(r"immutability_policy\s*{|versioning_enabled\s*=\s*true", code))
            
            if not has_immutability:
                line_num = self.get_line_number(code, "azurerm_storage_account")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-02",
                    severity=Severity.MEDIUM,
                    title="Log storage missing immutability policy",
                    description="Audit logs should be stored with immutability to prevent tampering.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable immutable storage:\n```hcl\nblob_properties {\n  versioning_enabled = true\n}\n```"
                ))
    
    def _check_security_monitoring(self, code: str, file_path: str) -> None:
        """Check for security monitoring and alert configuration (KSI-MLA-03)."""
        # Check for Application Insights
        has_app_insights = bool(re.search(r"azurerm_application_insights\"", code))
        
        # Check for Azure Monitor metric alerts
        has_metric_alerts = bool(re.search(r"azurerm_monitor_metric_alert\"", code))
        
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"azurerm_log_analytics_workspace\"", code))
        
        # Check for alert rules
        has_alert_rules = bool(re.search(r"(azurerm_monitor_.*_alert|azurerm_log_analytics.*alert)", code))
        
        if not has_app_insights and not has_log_analytics:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.HIGH,
                title="Missing security monitoring configuration",
                description="No Application Insights or Log Analytics workspace configured. FedRAMP 20x requires real-time security monitoring and alerting.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure monitoring infrastructure:\n```hcl\nresource \"azurerm_log_analytics_workspace\" \"main\" {\n  name                = \"law-${var.workload_name}\"\n  location            = var.location\n  resource_group_name = azurerm_resource_group.main.name\n  sku                 = \"PerGB2018\"\n  retention_in_days   = 90\n}\n\nresource \"azurerm_application_insights\" \"main\" {\n  name                = \"appi-${var.workload_name}\"\n  location            = var.location\n  resource_group_name = azurerm_resource_group.main.name\n  application_type    = \"web\"\n  workspace_id        = azurerm_log_analytics_workspace.main.id\n}\n```\nSource: Azure WAF - Reliability (https://learn.microsoft.com/azure/well-architected/reliability/monitoring-alerting-strategy)"
            ))
        elif (has_app_insights or has_log_analytics) and not has_alert_rules and not has_metric_alerts:
            line_num = self.get_line_number(code, "azurerm_application_insights") or self.get_line_number(code, "azurerm_log_analytics_workspace")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.MEDIUM,
                title="Monitoring configured but no alert rules defined",
                description="Monitoring workspace exists but no alert rules are configured. FedRAMP 20x requires security alerts for anomalous activities.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add security alert rules:\n```hcl\nresource \"azurerm_monitor_scheduled_query_rules_alert_v2\" \"security\" {\n  name                = \"alert-security-${var.workload_name}\"\n  location            = var.location\n  resource_group_name = azurerm_resource_group.main.name\n  \n  evaluation_frequency = \"PT5M\"\n  window_duration      = \"PT5M\"\n  scopes               = [azurerm_log_analytics_workspace.main.id]\n  severity             = 1\n  \n  criteria {\n    query                   = <<-QUERY\n      SecurityEvent\n      | where EventID == 4625\n      | summarize count() by bin(TimeGenerated, 5m)\n    QUERY\n    threshold               = 10\n    operator                = \"GreaterThan\"\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_monitor") or self.get_line_number(code, "azurerm_application_insights")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.INFO,
                title="Security monitoring and alerting configured",
                description="Application monitoring and alert rules are properly configured.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure alert rules cover security events, failed authentication, and anomalous behavior.",
                good_practice=True
            ))
    
    def _check_performance_monitoring(self, code: str, file_path: str) -> None:
        """Check for performance monitoring configuration (KSI-MLA-04)."""
        # Check for Application Insights
        has_app_insights = bool(re.search(r"azurerm_application_insights\"", code))
        
        # Check for autoscale settings
        has_autoscale = bool(re.search(r"azurerm_monitor_autoscale_setting\"", code))
        
        # Check for scalable resources (App Service Plan, AKS, VMSS)
        has_scalable_resources = bool(re.search(r"(azurerm_service_plan|azurerm_kubernetes_cluster|azurerm_(linux|windows)_virtual_machine_scale_set)", code))
        
        if has_scalable_resources and not has_app_insights:
            line_num = self.get_line_number(code, "azurerm_service_plan") or self.get_line_number(code, "azurerm_kubernetes_cluster")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.MEDIUM,
                title="Scalable resources without performance monitoring",
                description="Resources configured for scaling but Application Insights not configured. FedRAMP 20x requires performance monitoring to detect anomalies.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Application Insights:\n```hcl\nresource \"azurerm_application_insights\" \"main\" {\n  name                = \"appi-${var.workload_name}\"\n  location            = var.location\n  resource_group_name = azurerm_resource_group.main.name\n  application_type    = \"web\"\n  workspace_id        = azurerm_log_analytics_workspace.main.id\n}\n\nresource \"azurerm_linux_web_app\" \"main\" {\n  # ... other config\n  \n  app_settings = {\n    \"APPINSIGHTS_INSTRUMENTATIONKEY\"             = azurerm_application_insights.main.instrumentation_key\n    \"APPLICATIONINSIGHTS_CONNECTION_STRING\"      = azurerm_application_insights.main.connection_string\n    \"ApplicationInsightsAgent_EXTENSION_VERSION\" = \"~3\"\n  }\n}\n```"
            ))
        elif has_scalable_resources and not has_autoscale:
            line_num = self.get_line_number(code, "azurerm_service_plan") or self.get_line_number(code, "azurerm_kubernetes_cluster")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.LOW,
                title="No autoscale settings configured",
                description="Scalable resources exist but autoscale rules not configured. Consider adding autoscale for performance optimization.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure autoscale settings:\n```hcl\nresource \"azurerm_monitor_autoscale_setting\" \"main\" {\n  name                = \"autoscale-${var.workload_name}\"\n  resource_group_name = azurerm_resource_group.main.name\n  location            = var.location\n  target_resource_id  = azurerm_service_plan.main.id\n  \n  profile {\n    name = \"Auto scale based on CPU\"\n    \n    capacity {\n      default = 2\n      minimum = 1\n      maximum = 10\n    }\n    \n    rule {\n      metric_trigger {\n        metric_name        = \"CpuPercentage\"\n        metric_resource_id = azurerm_service_plan.main.id\n        operator           = \"GreaterThan\"\n        threshold          = 70\n        time_aggregation   = \"Average\"\n        time_window        = \"PT5M\"\n        time_grain         = \"PT1M\"\n      }\n      \n      scale_action {\n        direction = \"Increase\"\n        type      = \"ChangeCount\"\n        value     = \"1\"\n        cooldown  = \"PT5M\"\n      }\n    }\n  }\n}\n```"
            ))
        elif has_app_insights:
            line_num = self.get_line_number(code, "azurerm_application_insights")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.INFO,
                title="Performance monitoring configured",
                description="Application Insights configured for performance monitoring.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure performance baselines and anomaly detection are configured.",
                good_practice=True
            ))
    
    def _check_log_analysis(self, code: str, file_path: str) -> None:
        """Check for log analysis automation (KSI-MLA-06)."""
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"azurerm_log_analytics_workspace\"", code))
        
        # Check for saved queries
        has_saved_queries = bool(re.search(r"azurerm_log_analytics_saved_search\"", code))
        
        # Check for Sentinel
        has_sentinel = bool(re.search(r"azurerm_sentinel", code))
        
        # Check for analytics rules
        has_analytics_rules = bool(re.search(r"azurerm_sentinel_alert_rule", code))
        
        if not has_log_analytics and not has_sentinel:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.HIGH,
                title="No log analysis infrastructure configured",
                description="Missing Log Analytics workspace or Sentinel. FedRAMP 20x requires automated log analysis and correlation for threat detection.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Log Analytics and Sentinel:\n```hcl\nresource \"azurerm_log_analytics_workspace\" \"security\" {\n  name                = \"law-security-${var.workload_name}\"\n  location            = var.location\n  resource_group_name = azurerm_resource_group.main.name\n  sku                 = \"PerGB2018\"\n  retention_in_days   = 90\n}\n\nresource \"azurerm_log_analytics_solution\" \"sentinel\" {\n  solution_name         = \"SecurityInsights\"\n  location              = var.location\n  resource_group_name   = azurerm_resource_group.main.name\n  workspace_resource_id = azurerm_log_analytics_workspace.security.id\n  workspace_name        = azurerm_log_analytics_workspace.security.name\n  \n  plan {\n    publisher = \"Microsoft\"\n    product   = \"OMSGallery/SecurityInsights\"\n  }\n}\n```\nSource: Azure Security Benchmark - Logging and threat detection (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-logging-threat-detection)"
            ))
        elif (has_log_analytics or has_sentinel) and not has_analytics_rules:
            line_num = self.get_line_number(code, "azurerm_log_analytics_workspace") or self.get_line_number(code, "azurerm_sentinel")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.MEDIUM,
                title="Log analysis workspace without automated analytics",
                description="Log Analytics/Sentinel configured but no analytics rules defined. FedRAMP 20x requires automated threat detection through KQL queries.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Sentinel analytics rules:\n```hcl\nresource \"azurerm_sentinel_alert_rule_scheduled\" \"failed_login\" {\n  name                       = \"Multiple Failed Login Attempts\"\n  log_analytics_workspace_id = azurerm_log_analytics_solution.sentinel.workspace_resource_id\n  display_name               = \"Multiple Failed Login Attempts\"\n  description                = \"Detects multiple failed login attempts from same IP\"\n  severity                   = \"High\"\n  enabled                    = true\n  \n  query = <<QUERY\n    SigninLogs\n    | where ResultType != 0\n    | summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)\n    | where FailedAttempts > 5\n  QUERY\n  \n  query_frequency            = \"PT5M\"\n  query_period               = \"PT5M\"\n  trigger_operator           = \"GreaterThan\"\n  trigger_threshold          = 0\n  \n  tactics = [\"InitialAccess\"]\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_sentinel_alert_rule") or self.get_line_number(code, "azurerm_sentinel")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.INFO,
                title="Log analysis automation configured",
                description="Automated log analysis and threat detection rules are configured.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review and update analytics rules based on threat landscape.",
                good_practice=True
            ))
    
    def _check_incident_detection(self, code: str, file_path: str) -> None:
        """Check for incident detection automation (KSI-INR-01)."""
        # Check for Sentinel
        has_sentinel = bool(re.search(r"azurerm_sentinel", code))
        
        # Check for automation rules
        has_automation_rules = bool(re.search(r"azurerm_sentinel_automation_rule\"", code))
        
        # Check for Logic Apps for incident response
        has_logic_apps = bool(re.search(r"azurerm_logic_app_workflow\"", code))
        
        if not has_sentinel:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.HIGH,
                title="No incident detection system configured",
                description="Microsoft Sentinel not configured. FedRAMP 20x requires automated incident detection and classification.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Sentinel for incident detection:\n```hcl\nresource \"azurerm_log_analytics_solution\" \"sentinel\" {\n  solution_name         = \"SecurityInsights\"\n  location              = var.location\n  resource_group_name   = azurerm_resource_group.main.name\n  workspace_resource_id = azurerm_log_analytics_workspace.main.id\n  workspace_name        = azurerm_log_analytics_workspace.main.name\n  \n  plan {\n    publisher = \"Microsoft\"\n    product   = \"OMSGallery/SecurityInsights\"\n  }\n}\n\n# Add analytics rule with incident creation\nresource \"azurerm_sentinel_alert_rule_scheduled\" \"incident_rule\" {\n  name                       = \"Security Incident Auto-Creation\"\n  log_analytics_workspace_id = azurerm_log_analytics_solution.sentinel.workspace_resource_id\n  display_name               = \"Security Incident Auto-Creation\"\n  enabled                    = true\n  severity                   = \"High\"\n  \n  query = \"SecurityAlert | where AlertSeverity in ('High', 'Medium')\"\n  query_frequency            = \"PT5M\"\n  query_period               = \"PT5M\"\n  trigger_operator           = \"GreaterThan\"\n  trigger_threshold          = 0\n  \n  incident_configuration {\n    create_incident = true\n    \n    grouping {\n      enabled                 = true\n      reopen_closed_incidents = false\n      lookback_duration       = \"PT5H\"\n      entity_matching_method  = \"AllEntities\"\n    }\n  }\n}\n```"
            ))
        elif has_sentinel and not has_automation_rules:
            line_num = self.get_line_number(code, "azurerm_sentinel")
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.MEDIUM,
                title="Incident detection without automation rules",
                description="Sentinel configured but no automation rules for incident handling. FedRAMP 20x requires automated incident triage and classification.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add automation rules:\n```hcl\nresource \"azurerm_sentinel_automation_rule\" \"severity_classification\" {\n  name                       = \"Auto-classify incident severity\"\n  log_analytics_workspace_id = azurerm_log_analytics_solution.sentinel.workspace_resource_id\n  display_name               = \"Auto-classify incident severity\"\n  order                      = 1\n  enabled                    = true\n  \n  triggers_on  = \"Incidents\"\n  triggers_when = \"Created\"\n  \n  action_incident {\n    order  = 1\n    status = \"New\"\n    severity = \"High\"\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_sentinel_automation_rule") or self.get_line_number(code, "azurerm_sentinel")
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.INFO,
                title="Automated incident detection configured",
                description="Sentinel with automation rules configured for incident detection and classification.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure automation rules cover all critical security events.",
                good_practice=True
            ))
    
    def _check_incident_response_logging(self, code: str, file_path: str) -> None:
        """Check for incident response logging configuration (KSI-INR-02)."""
        # Check for Sentinel
        has_sentinel = bool(re.search(r"azurerm_sentinel", code))
        
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"azurerm_log_analytics_workspace\"", code))
        
        # Check for Logic Apps (for response automation)
        has_logic_apps = bool(re.search(r"azurerm_logic_app_workflow\"", code))
        
        # Check for diagnostic settings on Logic Apps
        has_response_logging = bool(re.search(r"azurerm_monitor_diagnostic_setting.*logic", code, re.IGNORECASE))
        
        if (has_sentinel or has_logic_apps) and not has_response_logging:
            line_num = self.get_line_number(code, "azurerm_logic_app_workflow") or self.get_line_number(code, "azurerm_sentinel")
            self.add_finding(Finding(
                requirement_id="KSI-INR-02",
                severity=Severity.MEDIUM,
                title="Incident response actions not logged",
                description="Incident response automation exists but actions are not logged. FedRAMP 20x requires all incident response activities to be logged for audit.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Enable diagnostic logging on Logic Apps:\n```hcl\nresource \"azurerm_monitor_diagnostic_setting\" \"logic_app\" {\n  name               = \"diag-incident-response\"\n  target_resource_id = azurerm_logic_app_workflow.incident_response.id\n  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id\n  \n  enabled_log {\n    category = \"WorkflowRuntime\"\n    \n    retention_policy {\n      enabled = true\n      days    = 365  # FedRAMP requires 1-year retention\n    }\n  }\n  \n  metric {\n    category = \"AllMetrics\"\n    enabled  = true\n  }\n}\n```\nSource: FedRAMP 20x Incident Response Logging (FRR-INR)"
            ))
        elif has_response_logging:
            line_num = self.get_line_number(code, "azurerm_monitor_diagnostic_setting")
            self.add_finding(Finding(
                requirement_id="KSI-INR-02",
                severity=Severity.INFO,
                title="Incident response logging configured",
                description="Diagnostic logging enabled for incident response actions.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure logs include all response actions, timestamps, and outcome.",
                good_practice=True
            ))
    
    def _check_threat_intelligence(self, code: str, file_path: str) -> None:
        """Check for threat intelligence integration (KSI-AFR-03)."""
        # Check for Sentinel
        has_sentinel = bool(re.search(r"azurerm_sentinel", code))
        
        # Check for threat intelligence connectors
        has_ti_connectors = bool(re.search(r"azurerm_sentinel_data_connector.*threat", code, re.IGNORECASE))
        
        # Check for Security Center (Defender for Cloud)
        has_defender = bool(re.search(r"azurerm_security_center", code))
        
        if not has_sentinel and not has_defender:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-03",
                severity=Severity.HIGH,
                title="No threat intelligence integration configured",
                description="Missing Sentinel or Defender for Cloud. FedRAMP 20x requires threat intelligence feeds for proactive threat detection.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Defender for Cloud and Sentinel:\n```hcl\n# Enable Defender for Cloud\nresource \"azurerm_security_center_subscription_pricing\" \"vms\" {\n  tier          = \"Standard\"\n  resource_type = \"VirtualMachines\"\n}\n\nresource \"azurerm_security_center_subscription_pricing\" \"app_services\" {\n  tier          = \"Standard\"\n  resource_type = \"AppServices\"\n}\n\n# Configure Sentinel threat intelligence\nresource \"azurerm_sentinel_data_connector_threat_intelligence\" \"ti\" {\n  name                       = \"ThreatIntelligence\"\n  log_analytics_workspace_id = azurerm_log_analytics_solution.sentinel.workspace_resource_id\n}\n```\nSource: Azure Security Benchmark - Threat protection (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-posture-vulnerability-management)"
            ))
        elif has_sentinel and not has_ti_connectors:
            line_num = self.get_line_number(code, "azurerm_sentinel")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-03",
                severity=Severity.MEDIUM,
                title="Threat intelligence feeds not configured",
                description="Sentinel deployed but threat intelligence connectors not configured. FedRAMP 20x requires external threat intelligence for IOC matching.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add threat intelligence data connectors:\n```hcl\nresource \"azurerm_sentinel_data_connector_threat_intelligence_taxii\" \"taxii\" {\n  name                       = \"ThreatIntelligenceTAXII\"\n  log_analytics_workspace_id = azurerm_log_analytics_solution.sentinel.workspace_resource_id\n  display_name               = \"Threat Intelligence TAXII\"\n  api_root_url               = \"https://your-taxii-server.com/taxii2/\"\n  collection_id              = \"your-collection-id\"\n  polling_frequency          = \"OnceADay\"\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_sentinel_data_connector") or self.get_line_number(code, "azurerm_security_center")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-03",
                severity=Severity.INFO,
                title="Threat intelligence integration configured",
                description="Threat intelligence feeds and connectors are properly configured.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly validate threat intelligence feeds are active and IOCs are being ingested.",
                good_practice=True
            ))
    
    def _check_recovery_objectives(self, code: str, file_path: str) -> None:
        """Check for recovery objectives configuration (KSI-RPL-01)."""
        # Check for Recovery Services Vault or backup vault
        has_recovery_vault = bool(re.search(r"azurerm_recovery_services_vault", code))
        has_backup = bool(re.search(r"azurerm_backup", code))
        
        # Check for RTO/RPO in tags
        has_rto_rpo = bool(re.search(r"(rto|recoveryTimeObjective|rpo|recoveryPointObjective)", code, re.IGNORECASE))
        
        if not has_recovery_vault and not has_backup:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-01",
                severity=Severity.HIGH,
                title="Recovery objectives not configured",
                description="Missing Recovery Services Vault or backup configuration. FedRAMP 20x requires defined RTO and RPO for disaster recovery.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Recovery Services Vault with RTO/RPO:\n```hcl\nresource \"azurerm_recovery_services_vault\" \"vault\" {\n  name                = \"recovery-vault-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku                 = \"Standard\"\n\n  tags = {\n    rto               = \"4hours\"  # Recovery Time Objective\n    rpo               = \"1hour\"   # Recovery Point Objective\n    fedramp           = \"required\"\n  }\n}\n\nresource \"azurerm_backup_policy_vm\" \"policy\" {\n  name                = \"vm-backup-policy\"\n  resource_group_name = azurerm_resource_group.rg.name\n  recovery_vault_name = azurerm_recovery_services_vault.vault.name\n\n  backup {\n    frequency = \"Daily\"\n    time      = \"02:00\"\n  }\n\n  retention_daily {\n    count = 365  # FedRAMP requires 1-year retention\n  }\n}\n```\nSource: Azure WAF Reliability - Backup and disaster recovery (https://learn.microsoft.com/azure/well-architected/reliability/backup-and-recovery)"
            ))
        elif not has_rto_rpo:
            line_num = self.get_line_number(code, "azurerm_recovery_services_vault") or self.get_line_number(code, "azurerm_backup")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-01",
                severity=Severity.MEDIUM,
                title="RTO/RPO objectives not documented",
                description="Recovery infrastructure exists but RTO/RPO not explicitly defined. FedRAMP 20x requires documented recovery objectives.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Document RTO/RPO in resource tags:\n```hcl\ntags = {\n  rto              = \"4hours\"\n  rpo              = \"1hour\"\n  criticalityTier = \"tier1\"\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "rto") or self.get_line_number(code, "azurerm_recovery_services_vault")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-01",
                severity=Severity.INFO,
                title="Recovery objectives properly configured",
                description="RTO/RPO objectives are documented with recovery infrastructure.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review and test that actual recovery times meet defined RTO/RPO.",
                good_practice=True
            ))
    
    def _check_recovery_plan(self, code: str, file_path: str) -> None:
        """Check for recovery plan configuration (KSI-RPL-02)."""
        # Check for Site Recovery replication
        has_replication = bool(re.search(r"azurerm_site_recovery.*replication", code))
        
        # Check for recovery plan
        has_recovery_plan = bool(re.search(r"azurerm_site_recovery_.*recovery_plan", code))
        
        # Check for replication policy
        has_policy = bool(re.search(r"azurerm_site_recovery_replication_policy", code))
        
        if not has_replication and not has_policy and not has_recovery_plan:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-02",
                severity=Severity.HIGH,
                title="No recovery plan configured",
                description="Missing Site Recovery replication or recovery plan. FedRAMP 20x requires documented and tested recovery procedures.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure Site Recovery:\n```hcl\nresource \"azurerm_site_recovery_replication_policy\" \"policy\" {\n  name                                                 = \"replication-policy\"\n  resource_group_name                                  = azurerm_resource_group.rg.name\n  recovery_vault_name                                  = azurerm_recovery_services_vault.vault.name\n  recovery_point_retention_in_minutes                  = 1440  # 24 hours\n  application_consistent_snapshot_frequency_in_minutes = 60\n}\n\nresource \"azurerm_site_recovery_network_mapping\" \"recovery_plan\" {\n  name                        = \"dr-recovery-plan\"\n  resource_group_name         = azurerm_resource_group.rg.name\n  recovery_vault_name         = azurerm_recovery_services_vault.vault.name\n  source_recovery_fabric_name = azurerm_site_recovery_fabric.primary.name\n  target_recovery_fabric_name = azurerm_site_recovery_fabric.secondary.name\n  source_network_id           = azurerm_virtual_network.primary.id\n  target_network_id           = azurerm_virtual_network.secondary.id\n}\n```\nSource: Azure WAF Reliability - Disaster recovery (https://learn.microsoft.com/azure/well-architected/reliability/disaster-recovery)"
            ))
        elif (has_replication or has_policy) and not has_recovery_plan:
            line_num = self.get_line_number(code, "azurerm_site_recovery")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-02",
                severity=Severity.MEDIUM,
                title="Recovery plan not formally defined",
                description="Replication configured but no recovery plan resource. FedRAMP 20x requires orchestrated recovery procedures.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add recovery plan resource to orchestrate failover operations."
            ))
        elif has_recovery_plan:
            line_num = self.get_line_number(code, "recovery_plan")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-02",
                severity=Severity.INFO,
                title="Recovery plan properly configured",
                description="Site Recovery replication and recovery plans are configured.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Conduct regular DR drills and update recovery plans based on test results.",
                good_practice=True
            ))
    
    def _check_system_backups(self, code: str, file_path: str) -> None:
        """Check for system backup configuration (KSI-RPL-03)."""
        # Check for backup resources
        has_backup_vault = bool(re.search(r"azurerm_recovery_services_vault", code))
        has_backup_policy = bool(re.search(r"azurerm_backup_policy", code))
        has_protected_item = bool(re.search(r"azurerm_backup_protected", code))
        
        # Check for resources needing backup
        has_vm = bool(re.search(r"azurerm_virtual_machine|azurerm_linux_virtual_machine|azurerm_windows_virtual_machine", code))
        has_sql = bool(re.search(r"azurerm_mssql", code))
        has_storage = bool(re.search(r"azurerm_storage_account", code))
        
        needs_backup = has_vm or has_sql or has_storage
        
        if needs_backup and not has_backup_vault:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-03",
                severity=Severity.HIGH,
                title="System backups not configured",
                description="Critical resources deployed without backup protection. FedRAMP 20x requires aligned backups to meet RPO.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure Backup:\n```hcl\nresource \"azurerm_recovery_services_vault\" \"vault\" {\n  name                = \"backup-vault\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku                 = \"Standard\"\n}\n\nresource \"azurerm_backup_policy_vm\" \"policy\" {\n  name                = \"vm-backup-policy\"\n  resource_group_name = azurerm_resource_group.rg.name\n  recovery_vault_name = azurerm_recovery_services_vault.vault.name\n\n  backup {\n    frequency = \"Daily\"\n    time      = \"02:00\"\n  }\n\n  retention_daily {\n    count = 365\n  }\n}\n\nresource \"azurerm_backup_protected_vm\" \"vm\" {\n  resource_group_name = azurerm_resource_group.rg.name\n  recovery_vault_name = azurerm_recovery_services_vault.vault.name\n  source_vm_id        = azurerm_virtual_machine.vm.id\n  backup_policy_id    = azurerm_backup_policy_vm.policy.id\n}\n```\nSource: Azure WAF Reliability - Backup strategies (https://learn.microsoft.com/azure/well-architected/reliability/backup-and-recovery)"
            ))
        elif needs_backup and not has_backup_policy:
            line_num = self.get_line_number(code, "azurerm_recovery_services_vault")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-03",
                severity=Severity.MEDIUM,
                title="Backup policies not configured",
                description="Backup vault exists but policies not defined. FedRAMP 20x requires backup schedules aligned with RPO.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Define backup policies with appropriate retention (365 days for FedRAMP)."
            ))
        elif has_backup_vault and has_backup_policy:
            line_num = self.get_line_number(code, "azurerm_backup_policy")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-03",
                severity=Severity.INFO,
                title="System backups properly configured",
                description="Backup infrastructure with policies configured for critical resources.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly verify backup jobs complete successfully and test restore procedures.",
                good_practice=True
            ))
    
    def _check_recovery_testing(self, code: str, file_path: str) -> None:
        """Check for recovery testing configuration (KSI-RPL-04)."""
        # Check for automation account
        has_automation = bool(re.search(r"azurerm_automation_account", code))
        has_runbook = bool(re.search(r"azurerm_automation_runbook", code))
        has_schedule = bool(re.search(r"azurerm_automation_schedule", code))
        
        # Check for test failover references
        has_test_failover = bool(re.search(r"(testFailover|test.*recovery)", code, re.IGNORECASE))
        
        if not has_automation and not has_test_failover:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-04",
                severity=Severity.MEDIUM,
                title="Recovery testing not automated",
                description="No test failover or automated recovery testing configured. FedRAMP 20x requires regular recovery capability validation.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure automated recovery testing:\n```hcl\nresource \"azurerm_automation_account\" \"automation\" {\n  name                = \"automation-account\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku_name            = \"Basic\"\n}\n\nresource \"azurerm_automation_runbook\" \"test_recovery\" {\n  name                    = \"Test-RecoveryPlan\"\n  location                = azurerm_resource_group.rg.location\n  resource_group_name     = azurerm_resource_group.rg.name\n  automation_account_name = azurerm_automation_account.automation.name\n  log_verbose             = true\n  log_progress            = true\n  runbook_type            = \"PowerShell\"\n  description             = \"Automated recovery testing - runs monthly DR drills\"\n\n  content = file(\"${path.module}/test-recovery.ps1\")\n}\n\nresource \"azurerm_automation_schedule\" \"monthly\" {\n  name                    = \"MonthlyRecoveryTest\"\n  resource_group_name     = azurerm_resource_group.rg.name\n  automation_account_name = azurerm_automation_account.automation.name\n  frequency               = \"Month\"\n  interval                = 1\n  start_time              = \"2024-01-01T02:00:00Z\"\n}\n```\nSource: Azure WAF Reliability - Testing (https://learn.microsoft.com/azure/well-architected/reliability/testing-strategy)"
            ))
        elif has_automation and not has_schedule:
            line_num = self.get_line_number(code, "azurerm_automation")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-04",
                severity=Severity.MEDIUM,
                title="Recovery testing not scheduled",
                description="Automation infrastructure exists but no scheduled recovery tests. FedRAMP 20x requires regular DR drills.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add automation schedule for monthly test failovers to validate RTO/RPO compliance."
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_automation_runbook") or self.get_line_number(code, "azurerm_automation")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-04",
                severity=Severity.INFO,
                title="Recovery testing automation configured",
                description="Automated recovery testing infrastructure is in place.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure test results are documented and recovery plans updated based on findings.",
                good_practice=True
            ))
    
    def _check_traffic_flow(self, code: str, file_path: str) -> None:
        """Check for traffic flow enforcement (KSI-CNA-03)."""
        # Check for Azure Firewall or Application Gateway
        has_firewall = bool(re.search(r"azurerm_firewall", code))
        has_app_gateway = bool(re.search(r"azurerm_application_gateway", code))
        
        # Check for route tables
        has_routes = bool(re.search(r"azurerm_route_table", code))
        
        # Check for NSG flow logs
        has_flow_logs = bool(re.search(r"azurerm_network_watcher_flow_log", code))
        
        if not has_firewall and not has_app_gateway and not has_routes:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-CNA-03",
                severity=Severity.HIGH,
                title="Traffic flow controls not enforced",
                description="Missing Azure Firewall or route tables for traffic control. FedRAMP 20x requires logical networking to enforce traffic flow.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure Firewall with network rules:\n```hcl\nresource \"azurerm_firewall\" \"fw\" {\n  name                = \"firewall\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku_name            = \"AZFW_VNet\"\n  sku_tier            = \"Standard\"\n  threat_intel_mode   = \"Alert\"  # Or \"Deny\" for FedRAMP\n\n  ip_configuration {\n    name                 = \"configuration\"\n    subnet_id            = azurerm_subnet.firewall_subnet.id\n    public_ip_address_id = azurerm_public_ip.firewall_ip.id\n  }\n}\n\nresource \"azurerm_route_table\" \"rt\" {\n  name                = \"route-table\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n\n  route {\n    name                   = \"route-to-firewall\"\n    address_prefix         = \"0.0.0.0/0\"\n    next_hop_type          = \"VirtualAppliance\"\n    next_hop_in_ip_address = azurerm_firewall.fw.ip_configuration[0].private_ip_address\n  }\n}\n```\nSource: Azure WAF Security - Network security (https://learn.microsoft.com/azure/well-architected/security/networking)"
            ))
        elif not has_flow_logs:
            line_num = self.get_line_number(code, "azurerm_firewall") or self.get_line_number(code, "azurerm_route_table")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-03",
                severity=Severity.MEDIUM,
                title="NSG flow logs not enabled",
                description="Traffic controls exist but flow logging not configured. FedRAMP 20x requires traffic flow monitoring.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Enable NSG Flow Logs:\n```hcl\nresource \"azurerm_network_watcher_flow_log\" \"flow_log\" {\n  network_watcher_name = azurerm_network_watcher.watcher.name\n  resource_group_name  = azurerm_resource_group.rg.name\n  network_security_group_id = azurerm_network_security_group.nsg.id\n  storage_account_id        = azurerm_storage_account.logs.id\n  enabled                   = true\n\n  retention_policy {\n    enabled = true\n    days    = 365\n  }\n\n  traffic_analytics {\n    enabled               = true\n    workspace_id          = azurerm_log_analytics_workspace.logs.workspace_id\n    workspace_region      = azurerm_log_analytics_workspace.logs.location\n    workspace_resource_id = azurerm_log_analytics_workspace.logs.id\n    interval_in_minutes   = 10\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_network_watcher_flow_log")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-03",
                severity=Severity.INFO,
                title="Traffic flow controls properly configured",
                description="Azure Firewall and NSG flow logs enforce and monitor traffic flow.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review flow logs and firewall rules for unauthorized traffic patterns.",
                good_practice=True
            ))
    
    def _check_ddos_protection(self, code: str, file_path: str) -> None:
        """Check for DDoS protection (KSI-CNA-05)."""
        # Check for DDoS Protection Plan
        has_ddos_plan = bool(re.search(r"azurerm_network_ddos_protection_plan", code))
        
        # Check for VNets
        vnet_pattern = r"resource\s+\"azurerm_virtual_network\""
        has_vnet = bool(re.search(vnet_pattern, code))
        
        # Check if DDoS is enabled on VNet
        ddos_enabled = bool(re.search(r"ddos_protection_plan.*=", code))
        
        if has_vnet and not has_ddos_plan:
            line_num = self.get_line_number(code, "azurerm_virtual_network")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-05",
                severity=Severity.HIGH,
                title="DDoS Protection not configured",
                description="Virtual networks deployed without DDoS Protection Plan. FedRAMP 20x requires protection against denial of service attacks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure DDoS Protection Standard:\n```hcl\nresource \"azurerm_network_ddos_protection_plan\" \"ddos\" {\n  name                = \"ddos-plan\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n}\n\nresource \"azurerm_virtual_network\" \"vnet\" {\n  name                = \"vnet\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  address_space       = [\"10.0.0.0/16\"]\n\n  ddos_protection_plan {\n    id     = azurerm_network_ddos_protection_plan.ddos.id\n    enable = true\n  }\n}\n```\nSource: Azure WAF Security - DDoS protection (https://learn.microsoft.com/azure/well-architected/security/ddos-protection)\n\nNote: DDoS Protection Standard costs ~$2,944/month but is typically required for FedRAMP compliance."
            ))
        elif has_ddos_plan and not ddos_enabled:
            line_num = self.get_line_number(code, "azurerm_network_ddos_protection_plan")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-05",
                severity=Severity.MEDIUM,
                title="DDoS Protection Plan not associated with VNets",
                description="DDoS Protection Plan exists but not enabled on virtual networks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Enable DDoS protection on VNets:\n```hcl\nddos_protection_plan {\n  id     = azurerm_network_ddos_protection_plan.ddos.id\n  enable = true\n}\n```"
            ))
        elif has_ddos_plan and ddos_enabled:
            line_num = self.get_line_number(code, "azurerm_network_ddos_protection_plan")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-05",
                severity=Severity.INFO,
                title="DDoS Protection properly configured",
                description="Azure DDoS Protection Standard is enabled on virtual networks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Monitor DDoS metrics and alerts regularly for attack patterns.",
                good_practice=True
            ))
    
    def _check_least_privilege(self, code: str, file_path: str) -> None:
        """Check for least privilege access configuration (KSI-IAM-05)."""
        # Check for role assignments
        has_rbac = bool(re.search(r"azurerm_role_assignment", code))
        
        # Check for overly permissive roles
        has_owner = bool(re.search(r"role_definition_name.*=.*\"Owner\"", code))
        has_contributor = bool(re.search(r"role_definition_name.*=.*\"Contributor\"", code))
        
        # Check for JIT access
        has_jit = bool(re.search(r"azurerm_security_center_jit_access_policy", code))
        
        # Check for managed identity
        has_managed_identity = bool(re.search(r"identity\s*\{", code))
        
        if not has_rbac:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.HIGH,
                title="RBAC not configured",
                description="No role assignments defined. FedRAMP 20x requires least privilege access controls.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure RBAC with least privilege roles:\n```hcl\nresource \"azurerm_role_assignment\" \"reader\" {\n  scope                = azurerm_resource_group.rg.id\n  role_definition_name = \"Reader\"  # Use specific roles instead of Owner/Contributor\n  principal_id         = data.azurerm_client_config.current.object_id\n}\n\n# Configure JIT access for privileged operations\nresource \"azurerm_security_center_jit_access_policy\" \"jit\" {\n  resource_group_name = azurerm_resource_group.rg.name\n  location            = azurerm_resource_group.rg.location\n  name                = \"jit-policy\"\n  kind                = \"Basic\"\n\n  virtual_machine_ids = [azurerm_virtual_machine.vm.id]\n\n  policy {\n    port {\n      number                     = 22\n      protocol                   = \"TCP\"\n      allowed_source_address_prefix = \"*\"\n      max_request_access_duration = \"PT3H\"\n    }\n  }\n}\n```\nSource: Azure WAF Security - Identity and access management (https://learn.microsoft.com/azure/well-architected/security/identity-access)"
            ))
        elif has_owner or has_contributor:
            line_num = self.get_line_number(code, "Owner") or self.get_line_number(code, "Contributor")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.HIGH,
                title="Overly permissive roles assigned",
                description="Owner or Contributor roles assigned. FedRAMP 20x requires least privilege - use specific roles instead.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Replace with specific roles:\n- Instead of 'Owner': Use 'User Access Administrator' + specific resource role\n- Instead of 'Contributor': Use specific roles like 'Virtual Machine Contributor', 'Storage Account Contributor'\n- Implement Azure AD PIM for privileged access\n- Use custom roles with minimal required permissions"
            ))
        elif not has_jit and not has_managed_identity:
            line_num = self.get_line_number(code, "azurerm_role_assignment")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.MEDIUM,
                title="JIT access not configured",
                description="RBAC configured but no JIT or managed identity for privileged access. FedRAMP 20x encourages time-limited privilege escalation.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement JIT access for administrative operations. Use managed identities for service-to-service authentication."
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_security_center_jit") or self.get_line_number(code, "azurerm_role_assignment")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.INFO,
                title="Least privilege access properly configured",
                description="RBAC with specific roles and JIT/managed identity for privileged access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review role assignments and access logs to ensure continued compliance with least privilege.",
                good_practice=True
            ))
    
    def _check_cryptographic_modules(self, code: str, file_path: str) -> None:
        """Check for FIPS-validated cryptographic modules (KSI-AFR-11)."""
        # Check for Key Vault with premium SKU (HSM-backed)
        has_key_vault = bool(re.search(r"azurerm_key_vault", code))
        has_premium_sku = bool(re.search(r"sku_name\s*=\s*\"premium\"", code))
        
        # Check for TLS configuration
        has_tls_config = bool(re.search(r"(min_tls_version|minimum_tls_version|ssl_policy)", code, re.IGNORECASE))
        has_tls_12 = bool(re.search(r"(min_tls_version\s*=\s*\"1\.2\"|minimum_tls_version\s*=\s*\"TLS1_2\")", code))
        
        # Check for encryption
        has_encryption = bool(re.search(r"(encryption|customer_managed_key)", code, re.IGNORECASE))
        
        if not has_key_vault and not has_tls_12:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.HIGH,
                title="FIPS-validated cryptographic modules not configured",
                description="Missing Key Vault Premium and TLS 1.2+ enforcement. FedRAMP 20x requires FIPS 140-2/140-3 validated cryptography for federal data.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Key Vault Premium (HSM-backed) and enforce TLS 1.2+:\n```hcl\nresource \"azurerm_key_vault\" \"kv\" {\n  name                = \"kv-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  tenant_id           = data.azurerm_client_config.current.tenant_id\n  sku_name            = \"premium\"  # Uses FIPS 140-2 Level 2 validated HSMs\n\n  enabled_for_disk_encryption     = true\n  enabled_for_deployment          = true\n  enabled_for_template_deployment = true\n  enable_rbac_authorization       = true\n\n  network_acls {\n    default_action = \"Deny\"\n    bypass         = \"AzureServices\"\n  }\n}\n\n# For storage accounts, enforce TLS 1.2\nresource \"azurerm_storage_account\" \"storage\" {\n  name                     = \"st${random_id.suffix.hex}\"\n  resource_group_name      = azurerm_resource_group.rg.name\n  location                 = azurerm_resource_group.rg.location\n  account_tier             = \"Standard\"\n  account_replication_type = \"GRS\"\n  min_tls_version          = \"TLS1_2\"\n  enable_https_traffic_only = true\n\n  customer_managed_key {\n    key_vault_key_id          = azurerm_key_vault_key.key.id\n    user_assigned_identity_id = azurerm_user_assigned_identity.identity.id\n  }\n}\n\n# For SQL, enable TDE\nresource \"azurerm_mssql_server\" \"sql\" {\n  name                         = \"sql-${random_id.suffix.hex}\"\n  resource_group_name          = azurerm_resource_group.rg.name\n  location                     = azurerm_resource_group.rg.location\n  version                      = \"12.0\"\n  minimum_tls_version          = \"1.2\"\n  administrator_login          = \"sqladmin\"\n  administrator_login_password = random_password.sql_password.result\n}\n\nresource \"azurerm_mssql_server_transparent_data_encryption\" \"tde\" {\n  server_id        = azurerm_mssql_server.sql.id\n  key_vault_key_id = azurerm_key_vault_key.key.id\n}\n```\nSource: Azure Security Benchmark - Data protection (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-data-protection)\n\nNote: Azure Key Vault Premium uses FIPS 140-2 Level 2 validated HSMs. Managed HSM uses FIPS 140-2 Level 3."
            ))
        elif not has_tls_12:
            line_num = self.get_line_number(code, "azurerm_key_vault") or 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.HIGH,
                title="TLS 1.2 not enforced",
                description="Cryptographic infrastructure exists but TLS 1.2+ not enforced. FedRAMP 20x requires strong transport encryption.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Enforce TLS 1.2+ on all resources:\n```hcl\n# Storage\nmin_tls_version = \"TLS1_2\"\n\n# App Service\nmin_tls_version = \"1.2\"\n\n# SQL\nminimum_tls_version = \"1.2\"\n\n# Application Gateway\nssl_policy {\n  policy_type = \"Custom\"\n  min_protocol_version = \"TLSv1_2\"\n  cipher_suites = [\n    \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\",\n    \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"\n  ]\n}\n```"
            ))
        elif not has_premium_sku:
            line_num = self.get_line_number(code, "min_tls_version") or self.get_line_number(code, "minimum_tls_version")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.MEDIUM,
                title="HSM-backed key storage not configured",
                description="TLS 1.2 enforced but not using Key Vault Premium. FedRAMP 20x recommends FIPS 140-2 Level 2+ for sensitive keys.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Upgrade to Key Vault Premium for HSM-backed keys:\n```hcl\nsku_name = \"premium\"  # FIPS 140-2 Level 2 HSMs\n```\nFor higher assurance, consider Azure Managed HSM (FIPS 140-2 Level 3)."
            ))
        else:
            line_num = self.get_line_number(code, "premium") or self.get_line_number(code, "azurerm_key_vault")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.INFO,
                title="FIPS-validated cryptographic modules configured",
                description="Key Vault Premium and TLS 1.2+ properly configured for FIPS 140-2 compliance.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly rotate cryptographic keys and review cipher suites for algorithm deprecations.",
                good_practice=True
            ))
    
    def _check_communication_integrity(self, code: str, file_path: str) -> None:
        """Check for communication integrity validation (KSI-SVC-09)."""
        # Check for App Service client certificates
        has_client_cert = bool(re.search(r"client_certificate_(enabled|mode)", code))
        
        # Check for API Management client certificates
        has_apim_cert = bool(re.search(r"azurerm_api_management.*certificate", code, re.DOTALL))
        
        # Check for Application Gateway mutual auth
        has_appgw_ssl = bool(re.search(r"azurerm_application_gateway.*ssl_(policy|profile|certificate)", code, re.DOTALL))
        
        # Check for Front Door custom HTTPS
        has_frontdoor_https = bool(re.search(r"azurerm_frontdoor.*custom_https", code, re.DOTALL))
        
        if not has_client_cert and not has_apim_cert and not has_appgw_ssl:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-SVC-09",
                severity=Severity.MEDIUM,
                title="Communication integrity not validated",
                description="Missing mTLS or certificate-based authentication. FedRAMP 20x requires persistent validation of communication authenticity.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure mutual TLS for service-to-service communications:\n```hcl\n# App Service with client certificates\nresource \"azurerm_linux_web_app\" \"app\" {\n  name                = \"app-${random_id.suffix.hex}\"\n  resource_group_name = azurerm_resource_group.rg.name\n  location            = azurerm_resource_group.rg.location\n  service_plan_id     = azurerm_service_plan.plan.id\n\n  https_only                = true\n  client_certificate_enabled = true\n  client_certificate_mode    = \"Required\"\n\n  site_config {\n    minimum_tls_version = \"1.2\"\n  }\n}\n\n# API Management with client certificate validation\nresource \"azurerm_api_management\" \"apim\" {\n  name                = \"apim-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  publisher_name      = \"FedRAMP Publisher\"\n  publisher_email     = \"admin@example.com\"\n  sku_name            = \"Premium_1\"\n\n  certificate {\n    encoded_certificate  = filebase64(\"client-cert.pfx\")\n    certificate_password = var.cert_password\n    store_name           = \"CertificateAuthority\"\n  }\n}\n\nresource \"azurerm_api_management_api\" \"api\" {\n  name                = \"secure-api\"\n  resource_group_name = azurerm_resource_group.rg.name\n  api_management_name = azurerm_api_management.apim.name\n  revision            = \"1\"\n  display_name        = \"Secure API\"\n  protocols           = [\"https\"]\n}\n\nresource \"azurerm_api_management_api_policy\" \"policy\" {\n  api_name            = azurerm_api_management_api.api.name\n  api_management_name = azurerm_api_management.apim.name\n  resource_group_name = azurerm_resource_group.rg.name\n\n  xml_content = <<XML\n<policies>\n  <inbound>\n    <base />\n    <check-header name=\"X-Client-Certificate\" failed-check-httpcode=\"403\" />\n    <validate-jwt header-name=\"Authorization\">\n      <openid-config url=\"https://login.microsoftonline.com/${data.azurerm_client_config.current.tenant_id}/.well-known/openid-configuration\" />\n    </validate-jwt>\n  </inbound>\n</policies>\nXML\n}\n```\nSource: Azure WAF Security - Network security (https://learn.microsoft.com/azure/well-architected/security/networking)"
            ))
        else:
            line_num = self.get_line_number(code, "client_certificate") or self.get_line_number(code, "ssl_policy")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-09",
                severity=Severity.INFO,
                title="Communication integrity validation configured",
                description="mTLS or certificate-based authentication configured for service communications.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly rotate certificates and validate certificate chains. Monitor for certificate expiration.",
                good_practice=True
            ))
    
    def _check_data_destruction(self, code: str, file_path: str) -> None:
        """Check for secure data destruction capabilities (KSI-SVC-10)."""
        # Check for Key Vault soft delete
        has_kv_soft_delete = bool(re.search(r"soft_delete_(enabled|retention_days)", code))
        has_purge_protection = bool(re.search(r"purge_protection_enabled", code))
        
        # Check for Storage soft delete
        has_storage_soft_delete = bool(re.search(r"(blob|container)_delete_retention_policy", code))
        
        # Check for SQL backup retention
        has_sql_backup = bool(re.search(r"backup_retention_days", code))
        
        # Check for Cosmos DB backup
        has_cosmos_backup = bool(re.search(r"backup\s*\{", code))
        
        if not has_kv_soft_delete and not has_storage_soft_delete:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-SVC-10",
                severity=Severity.MEDIUM,
                title="Data destruction capabilities not configured",
                description="Missing soft delete and purge protection. FedRAMP 20x requires prompt customer data removal while preventing accidental deletion.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure soft delete and purge protection:\n```hcl\n# Key Vault with soft delete and purge protection\nresource \"azurerm_key_vault\" \"kv\" {\n  name                        = \"kv-${random_id.suffix.hex}\"\n  location                    = azurerm_resource_group.rg.location\n  resource_group_name         = azurerm_resource_group.rg.name\n  tenant_id                   = data.azurerm_client_config.current.tenant_id\n  sku_name                    = \"premium\"\n  soft_delete_retention_days  = 90  # 90-day retention\n  purge_protection_enabled    = true  # Prevent permanent deletion during retention\n  enable_rbac_authorization   = true\n}\n\n# Storage account with soft delete\nresource \"azurerm_storage_account\" \"storage\" {\n  name                     = \"st${random_id.suffix.hex}\"\n  resource_group_name      = azurerm_resource_group.rg.name\n  location                 = azurerm_resource_group.rg.location\n  account_tier             = \"Standard\"\n  account_replication_type = \"GRS\"\n\n  blob_properties {\n    delete_retention_policy {\n      days = 30  # FedRAMP: align with retention requirements\n    }\n    container_delete_retention_policy {\n      days = 30\n    }\n    versioning_enabled = true\n  }\n}\n\n# SQL database with backup retention\nresource \"azurerm_mssql_database\" \"db\" {\n  name           = \"sqldb-${random_id.suffix.hex}\"\n  server_id      = azurerm_mssql_server.sql.id\n  sku_name       = \"S0\"\n  ledger_enabled = true  # Immutable ledger for audit trail\n\n  short_term_retention_policy {\n    retention_days = 35  # Point-in-time restore window\n  }\n\n  long_term_retention_policy {\n    weekly_retention  = \"P12W\"\n    monthly_retention = \"P12M\"\n    yearly_retention  = \"P5Y\"\n  }\n}\n\n# Cosmos DB with point-in-time restore\nresource \"azurerm_cosmosdb_account\" \"cosmos\" {\n  name                = \"cosmos-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  offer_type          = \"Standard\"\n\n  backup {\n    type                = \"Continuous\"\n    tier                = \"Continuous30Days\"\n  }\n\n  consistency_policy {\n    consistency_level = \"Session\"\n  }\n}\n```\nSource: Azure WAF Reliability - Backup (https://learn.microsoft.com/azure/well-architected/reliability/backup-and-recovery)"
            ))
        else:
            line_num = self.get_line_number(code, "soft_delete") or self.get_line_number(code, "delete_retention")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-10",
                severity=Severity.INFO,
                title="Data destruction capabilities configured",
                description="Soft delete and retention policies enable prompt data removal while preventing accidental deletion.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Document data destruction procedures and test customer data removal workflows quarterly.",
                good_practice=True
            ))
    
    def _check_event_types_monitoring(self, code: str, file_path: str) -> None:
        """Check for documented event types and monitoring (KSI-MLA-07)."""
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"azurerm_log_analytics_workspace", code))
        
        # Check for diagnostic settings with log categories
        has_log_categories = bool(re.search(r"enabled_log\s*\{", code))
        
        # Check for data collection rules
        has_dcr = bool(re.search(r"azurerm_monitor_data_collection_rule", code))
        
        # Check for workbooks
        has_workbook = bool(re.search(r"azurerm_application_insights_workbook", code))
        
        if not has_log_analytics and not has_log_categories:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-07",
                severity=Severity.MEDIUM,
                title="Event types not documented or monitored",
                description="Missing Log Analytics workspace or specific log category configuration. FedRAMP 20x requires maintaining a list of monitored event types.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Log Analytics with specific event type monitoring:\n```hcl\n# Log Analytics workspace\nresource \"azurerm_log_analytics_workspace\" \"law\" {\n  name                = \"law-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku                 = \"PerGB2018\"\n  retention_in_days   = 365  # FedRAMP requirement\n}\n\n# Diagnostic settings with specific log categories\nresource \"azurerm_monitor_diagnostic_setting\" \"diag\" {\n  name                       = \"diag-settings\"\n  target_resource_id         = azurerm_key_vault.kv.id\n  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id\n\n  enabled_log {\n    category = \"AuditEvent\"\n  }\n  enabled_log {\n    category = \"AllMetrics\"\n  }\n\n  metric {\n    category = \"AllMetrics\"\n    enabled  = true\n  }\n}\n\n# Data collection rule for specific event types\nresource \"azurerm_monitor_data_collection_rule\" \"dcr\" {\n  name                = \"dcr-security-events\"\n  resource_group_name = azurerm_resource_group.rg.name\n  location            = azurerm_resource_group.rg.location\n  description         = \"Security event types for FedRAMP monitoring\"\n\n  destinations {\n    log_analytics {\n      workspace_resource_id = azurerm_log_analytics_workspace.law.id\n      name                  = \"law\"\n    }\n  }\n\n  data_flow {\n    streams      = [\"Microsoft-SecurityEvent\"]\n    destinations = [\"law\"]\n  }\n\n  data_sources {\n    windows_event_log {\n      name    = \"SecurityEvents\"\n      streams = [\"Microsoft-SecurityEvent\"]\n      x_path_queries = [\n        \"Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648)]]\",  # Logon events\n        \"Security!*[System[(EventID=4719 or EventID=4739)]]\",  # Policy changes\n      ]\n    }\n\n    syslog {\n      name           = \"SyslogAuth\"\n      facility_names = [\"auth\", \"authpriv\", \"security\"]\n      log_levels     = [\"Alert\", \"Critical\", \"Error\", \"Warning\"]\n      streams        = [\"Microsoft-Syslog\"]\n    }\n  }\n}\n```\nSource: Azure Monitor - Data collection (https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection)"
            ))
        elif not has_dcr and not has_workbook:
            line_num = self.get_line_number(code, "azurerm_log_analytics_workspace")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-07",
                severity=Severity.LOW,
                title="Event types not formally documented",
                description="Log Analytics configured but missing data collection rules or monitoring workbooks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Data Collection Rules to document specific event types."
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_monitor_data_collection_rule") or self.get_line_number(code, "enabled_log")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-07",
                severity=Severity.INFO,
                title="Event types documented and monitored",
                description="Data collection rules and monitoring infrastructure properly configured.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review and update monitored event types based on threat intelligence.",
                good_practice=True
            ))
    
    def _check_log_data_access(self, code: str, file_path: str) -> None:
        """Check for least-privilege access to log data (KSI-MLA-08)."""
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"azurerm_log_analytics_workspace", code))
        
        # Check for RBAC assignments
        has_rbac = bool(re.search(r"azurerm_role_assignment", code))
        
        # Check for private endpoint
        has_private_endpoint = bool(re.search(r"azurerm_private_endpoint.*log_analytics", code, re.DOTALL))
        
        if has_log_analytics and has_rbac:
            line_num = self.get_line_number(code, "azurerm_role_assignment") or self.get_line_number(code, "azurerm_log_analytics_workspace")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-08",
                severity=Severity.INFO,
                title="Log data access properly restricted",
                description="Least-privilege RBAC configured for Log Analytics workspace access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review log access permissions and use PIM for just-in-time access. Consider adding Private Link endpoints.",
                good_practice=True
            ))
        elif has_log_analytics:
            line_num = self.get_line_number(code, "azurerm_log_analytics_workspace")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-08",
                severity=Severity.HIGH,
                title="Log data access not restricted",
                description="Log Analytics workspace without RBAC role assignments. FedRAMP 20x requires least-privileged access for log data.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure workspace-level RBAC:\n```hcl\n# Log Analytics workspace\nresource \"azurerm_log_analytics_workspace\" \"law\" {\n  name                = \"law-${random_id.suffix.hex}\"\n  resource_group_name = azurerm_resource_group.rg.name\n  location            = azurerm_resource_group.rg.location\n  sku                 = \"PerGB2018\"\n  retention_in_days   = 365\n}\n\n# RBAC: Log Analytics Reader\nresource \"azurerm_role_assignment\" \"log_reader\" {\n  scope                = azurerm_log_analytics_workspace.law.id\n  role_definition_name = \"Log Analytics Reader\"\n  principal_id         = data.azurerm_client_config.current.object_id\n}\n\n# Private endpoint for secure access\nresource \"azurerm_private_endpoint\" \"pe_law\" {\n  name                = \"pe-law\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  subnet_id           = azurerm_subnet.subnet.id\n\n  private_service_connection {\n    name                           = \"law-connection\"\n    private_connection_resource_id = azurerm_log_analytics_workspace.law.id\n    is_manual_connection           = false\n    subresource_names              = [\"azuremonitor\"]\n  }\n}\n```\nSource: Azure Monitor - Access control (https://learn.microsoft.com/azure/azure-monitor/logs/manage-access)"
            ))
    
    def _check_secure_configuration(self, code: str, file_path: str) -> None:
        """Check for secure-by-default configurations (KSI-AFR-07)."""
        # Check for secure defaults
        has_https_only = bool(re.search(r"https_only\s*=\s*true", code))
        has_min_tls = bool(re.search(r"(min_tls_version|minimum_tls_version)\s*=\s*\"(1\.2|TLS1_2)\"", code))
        has_public_access_disabled = bool(re.search(r"public_network_access_enabled\s*=\s*false", code))
        
        # Check for insecure configurations
        has_public_blob_access = bool(re.search(r"allow_nested_items_to_be_public\s*=\s*true", code))
        has_public_network_enabled = bool(re.search(r"public_network_access_enabled\s*=\s*true", code))
        has_weak_tls = bool(re.search(r"(min_tls_version|minimum_tls_version)\s*=\s*\"(1\.[01]|TLS1_[01])\"", code))
        
        secure_defaults = sum([has_https_only, has_min_tls, has_public_access_disabled])
        insecure_configs = sum([has_public_blob_access, has_public_network_enabled, has_weak_tls])
        
        if insecure_configs > 0:
            line_num = self.get_line_number(code, "public_network_access_enabled.*true") or self.get_line_number(code, "allow_nested_items_to_be_public.*true")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-07",
                severity=Severity.HIGH,
                title="Insecure default configurations detected",
                description="Resources configured with insecure defaults. FedRAMP 20x requires secure-by-default configurations.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Apply secure default configurations:\n```hcl\n# App Service secure defaults\nresource \"azurerm_linux_web_app\" \"app\" {\n  name                = \"app-${random_id.suffix.hex}\"\n  resource_group_name = azurerm_resource_group.rg.name\n  location            = azurerm_resource_group.rg.location\n  service_plan_id     = azurerm_service_plan.plan.id\n  https_only          = true  # Redirect HTTP to HTTPS\n\n  site_config {\n    minimum_tls_version = \"1.2\"\n    ftps_state          = \"Disabled\"  # Disable FTP\n    http2_enabled       = true\n    always_on           = true\n  }\n}\n\n# Storage account secure defaults\nresource \"azurerm_storage_account\" \"storage\" {\n  name                            = \"st${random_id.suffix.hex}\"\n  resource_group_name             = azurerm_resource_group.rg.name\n  location                        = azurerm_resource_group.rg.location\n  account_tier                    = \"Standard\"\n  account_replication_type        = \"GRS\"\n  allow_nested_items_to_be_public = false  # No anonymous access\n  public_network_access_enabled   = false  # Private endpoints only\n  min_tls_version                 = \"TLS1_2\"\n  enable_https_traffic_only       = true\n  shared_access_key_enabled       = false  # Force Azure AD auth\n\n  infrastructure_encryption_enabled = true  # Double encryption\n}\n\n# SQL Server secure defaults\nresource \"azurerm_mssql_server\" \"sql\" {\n  name                         = \"sql-${random_id.suffix.hex}\"\n  resource_group_name          = azurerm_resource_group.rg.name\n  location                     = azurerm_resource_group.rg.location\n  version                      = \"12.0\"\n  minimum_tls_version          = \"1.2\"\n  public_network_access_enabled = false\n\n  azuread_administrator {\n    login_username = \"AzureAD Admin\"\n    object_id      = data.azurerm_client_config.current.object_id\n  }\n}\n```\nSource: Azure Security Baseline - Secure configuration (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-posture-vulnerability-management)"
            ))
        elif secure_defaults == 0:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-07",
                severity=Severity.MEDIUM,
                title="Secure default configurations not enforced",
                description="Missing secure-by-default settings. FedRAMP 20x requires documented secure configurations.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Apply secure defaults: HTTPS only, TLS 1.2+, disable public access, Azure AD authentication."
            ))
        else:
            line_num = self.get_line_number(code, "https_only") or self.get_line_number(code, "min_tls_version")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-07",
                severity=Severity.INFO,
                title="Secure default configurations applied",
                description="Resources configured with secure defaults (HTTPS, TLS 1.2+, restricted access).",
                file_path=file_path,
                line_number=line_num,
                recommendation="Document secure configuration standards and use Azure Policy to enforce organization-wide.",
                good_practice=True
            ))
    
    def _check_microservices_security(self, code: str, file_path: str) -> None:
        """Check for microservices security configuration (KSI-CNA-08)."""
        # Check for AKS with service mesh
        has_aks_service_mesh = bool(re.search(r"azurerm_kubernetes_cluster.*service_mesh_profile", code, re.DOTALL))
        
        # Check for Container Apps with Dapr
        has_container_apps_dapr = bool(re.search(r"azurerm_container_app.*dapr", code, re.DOTALL))
        
        # Check for API Management
        has_apim = bool(re.search(r"azurerm_api_management", code))
        
        # Check for network policies
        has_network_policy = bool(re.search(r"network_policy", code))
        
        if not has_aks_service_mesh and not has_container_apps_dapr and not has_apim:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-CNA-08",
                severity=Severity.MEDIUM,
                title="Microservices security controls missing",
                description="Missing service mesh or API gateway. FedRAMP 20x requires persistent security posture assessment for machine-based resources.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure service mesh or API Management:\n```hcl\n# AKS with service mesh\nresource \"azurerm_kubernetes_cluster\" \"aks\" {\n  name                = \"aks-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  dns_prefix          = \"aks\"\n\n  service_mesh_profile {\n    mode = \"Istio\"  # Enable Istio service mesh\n    internal_ingress_gateway_enabled = true\n    external_ingress_gateway_enabled = false\n  }\n\n  network_profile {\n    network_plugin = \"azure\"\n    network_policy = \"cilium\"  # Or 'azure', 'calico'\n  }\n\n  default_node_pool {\n    name       = \"default\"\n    node_count = 3\n    vm_size    = \"Standard_D2s_v3\"\n  }\n}\n\n# Container Apps with Dapr\nresource \"azurerm_container_app\" \"app\" {\n  name                         = \"app-${random_id.suffix.hex}\"\n  container_app_environment_id = azurerm_container_app_environment.env.id\n  resource_group_name          = azurerm_resource_group.rg.name\n  revision_mode                = \"Single\"\n\n  template {\n    container {\n      name   = \"app\"\n      image  = \"mcr.microsoft.com/azuredocs/aci-helloworld:latest\"\n      cpu    = 0.25\n      memory = \"0.5Gi\"\n    }\n  }\n\n  dapr {\n    app_id       = \"myapp\"\n    app_protocol = \"grpc\"\n    app_port     = 3000\n  }\n\n  ingress {\n    external_enabled = false  # Internal only\n    target_port      = 3000\n    transport        = \"http2\"  # gRPC support\n  }\n}\n\n# API Management for microservices gateway\nresource \"azurerm_api_management\" \"apim\" {\n  name                = \"apim-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  publisher_name      = \"FedRAMP Publisher\"\n  publisher_email     = \"admin@example.com\"\n  sku_name            = \"Premium_1\"\n  virtual_network_type = \"Internal\"\n}\n```\nSource: Azure WAF Security - Application security (https://learn.microsoft.com/azure/well-architected/security/application-design)"
            ))
        else:
            line_num = self.get_line_number(code, "service_mesh_profile") or self.get_line_number(code, "dapr") or self.get_line_number(code, "azurerm_api_management")
            recommendation = "Monitor service mesh metrics and regularly review service-to-service authentication policies."
            if (has_aks_service_mesh or has_container_apps_dapr) and not has_network_policy:
                recommendation += " Consider adding network policies to enforce pod-to-pod communication rules."
            self.add_finding(Finding(
                requirement_id="KSI-CNA-08",
                severity=Severity.INFO,
                title="Microservices security controls configured",
                description="Service mesh or API gateway provides security posture assessment and mTLS.",
                file_path=file_path,
                line_number=line_num,
                recommendation=recommendation,
                good_practice=True
            ))
    
    def _check_incident_after_action(self, code: str, file_path: str) -> None:
        """Check for incident after-action reporting (KSI-INR-03)."""
        # Check for Logic Apps
        has_logic_app = bool(re.search(r"azurerm_logic_app_workflow", code))
        
        # Check for Automation accounts
        has_automation = bool(re.search(r"azurerm_automation_account", code))
        
        # Check for Functions (serverless workflows)
        has_functions = bool(re.search(r"azurerm_function_app", code))
        
        if not has_logic_app and not has_automation and not has_functions:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-INR-03",
                severity=Severity.MEDIUM,
                title="Incident after-action reporting not automated",
                description="Missing automation for incident after-action reports. FedRAMP 20x requires generating after-action reports and incorporating lessons learned.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure automated incident after-action reporting:\n```hcl\n# Logic App for incident after-action\nresource \"azurerm_logic_app_workflow\" \"incident_workflow\" {\n  name                = \"incident-after-action\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n}\n\n# Cosmos DB for incident reports\nresource \"azurerm_cosmosdb_account\" \"cosmos\" {\n  name                = \"cosmos-incidents\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  offer_type          = \"Standard\"\n\n  consistency_policy {\n    consistency_level = \"Session\"\n  }\n\n  geo_location {\n    location          = azurerm_resource_group.rg.location\n    failover_priority = 0\n  }\n}\n\n# Automation runbook for lessons learned\nresource \"azurerm_automation_account\" \"automation\" {\n  name                = \"auto-incident-review\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku_name            = \"Basic\"\n}\n\nresource \"azurerm_automation_runbook\" \"runbook\" {\n  name                    = \"Integrate-LessonsLearned\"\n  location                = azurerm_resource_group.rg.location\n  resource_group_name     = azurerm_resource_group.rg.name\n  automation_account_name = azurerm_automation_account.automation.name\n  log_verbose             = true\n  log_progress            = true\n  description             = \"Quarterly review to integrate lessons learned\"\n  runbook_type            = \"PowerShell\"\n}\n```\nSource: Azure Sentinel - Incident management (https://learn.microsoft.com/azure/sentinel/incident-investigation)"
            ))
        else:
            line_num = self.get_line_number(code, "azurerm_logic_app_workflow") or self.get_line_number(code, "azurerm_automation_account")
            self.add_finding(Finding(
                requirement_id="KSI-INR-03",
                severity=Severity.INFO,
                title="Incident after-action automation configured",
                description="Automation workflows configured for incident after-action reporting.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Conduct quarterly reviews to incorporate lessons learned into security procedures.",
                good_practice=True
            ))
    
    def _check_change_management(self, code: str, file_path: str) -> None:
        """Check for change management procedure implementation (KSI-CMT-04)."""
        # Check for resource tags with change tracking
        has_change_tags = bool(re.search(r"tags\s*=\s*\{[^}]*(changeTicket|changeId|deploymentId|version)", code, re.IGNORECASE))
        
        # Check for deployment slots
        has_deployment_slots = bool(re.search(r"azurerm_(linux|windows)_web_app_slot", code))
        
        # Check for Traffic Manager (blue-green deployments)
        has_traffic_manager = bool(re.search(r"azurerm_traffic_manager_profile", code))
        
        # Check for resource locks
        has_locks = bool(re.search(r"azurerm_management_lock", code))
        
        if not has_change_tags and not has_deployment_slots and not has_traffic_manager:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-CMT-04",
                severity=Severity.MEDIUM,
                title="Change management procedures not implemented",
                description="Missing change tracking tags and staged deployment patterns. FedRAMP 20x requires documented change management procedures.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement change management in IaC:\n```hcl\n# Resource tags for change tracking\nlocals {\n  change_tags = {\n    changeTicket  = \"CHG-12345\"  # ServiceNow/ADO work item\n    deployedBy    = \"pipeline-name\"\n    deploymentId  = \"${timestamp()}\"\n    version       = \"v1.2.3\"\n    environment   = \"production\"\n    approvedBy    = \"security-team@company.com\"\n  }\n}\n\n# App Service with deployment slots\nresource \"azurerm_linux_web_app\" \"app\" {\n  name                = \"app-${random_id.suffix.hex}\"\n  resource_group_name = azurerm_resource_group.rg.name\n  location            = azurerm_resource_group.rg.location\n  service_plan_id     = azurerm_service_plan.plan.id\n  tags                = local.change_tags\n}\n\nresource \"azurerm_linux_web_app_slot\" \"staging\" {\n  name           = \"staging\"\n  app_service_id = azurerm_linux_web_app.app.id\n  tags           = local.change_tags\n\n  site_config {}\n}\n\n# Traffic Manager for blue-green deployment\nresource \"azurerm_traffic_manager_profile\" \"tm\" {\n  name                   = \"tm-${random_id.suffix.hex}\"\n  resource_group_name    = azurerm_resource_group.rg.name\n  traffic_routing_method = \"Weighted\"\n  tags                   = local.change_tags\n\n  dns_config {\n    relative_name = \"tm-${random_id.suffix.hex}\"\n    ttl           = 60\n  }\n}\n\nresource \"azurerm_traffic_manager_azure_endpoint\" \"blue\" {\n  name               = \"blue\"\n  profile_id         = azurerm_traffic_manager_profile.tm.id\n  weight             = 100  # Current stable\n  target_resource_id = azurerm_linux_web_app.app_blue.id\n}\n\nresource \"azurerm_traffic_manager_azure_endpoint\" \"green\" {\n  name               = \"green\"\n  profile_id         = azurerm_traffic_manager_profile.tm.id\n  weight             = 0  # Ready for cutover\n  target_resource_id = azurerm_linux_web_app.app_green.id\n}\n\n# Resource locks to prevent accidental changes\nresource \"azurerm_management_lock\" \"production_lock\" {\n  name       = \"production-lock\"\n  scope      = azurerm_linux_web_app.app.id\n  lock_level = \"CanNotDelete\"\n  notes      = \"Production resource - requires change management approval\"\n}\n```\nSource: Azure CAF - Change management (https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/development-strategy-development-lifecycle)"
            ))
        else:
            line_num = self.get_line_number(code, "changeTicket") or self.get_line_number(code, "azurerm.*_slot")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-04",
                severity=Severity.INFO,
                title="Change management procedures implemented",
                description="Change tracking tags and staged deployment patterns configured for controlled rollouts.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Document change management procedures and integrate with ITSM system for audit trail.",
                good_practice=True
            ))


    def _check_supply_chain_security(self, code: str, file_path: str) -> None:
        """Check for supply chain security controls (KSI-TPR-03)."""
        # Check for Azure Container Registry (ACR) with security features
        has_acr = bool(re.search(r"azurerm_container_registry\"", code))
        
        if has_acr:
            # Check for trusted image policies
            has_trust_policy = bool(re.search(r"trust_policy\s*{[^}]*enabled\s*=\s*true", code, re.DOTALL))
            
            # Check for quarantine policy
            has_quarantine = bool(re.search(r"quarantine_policy_enabled\s*=\s*true", code))
            
            # Check for private network access
            has_private_endpoint = bool(re.search(r"(azurerm_private_endpoint|public_network_access_enabled\s*=\s*false)", code))
            
            # Check for retention policy (auto-cleanup)
            has_retention = bool(re.search(r"retention_policy\s*{", code))
            
            issues = []
            if not has_trust_policy:
                issues.append("No content trust/image signing configured")
            if not has_quarantine:
                issues.append("No quarantine policy for unscanned images")
            if not has_private_endpoint:
                issues.append("Registry exposed to public network")
            
            if issues:
                line_num = self.get_line_number(code, "azurerm_container_registry")
                self.add_finding(Finding(
                    requirement_id="KSI-TPR-03",
                    severity=Severity.HIGH,
                    title="Container registry missing supply chain security controls",
                    description=f"ACR security issues: {'; '.join(issues)}. FedRAMP 20x requires supply chain risk mitigation.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement ACR supply chain security:\n```hcl\nresource \"azurerm_container_registry\" \"acr\" {\n  name                = \"acr${random_id.suffix.hex}\"\n  resource_group_name = azurerm_resource_group.rg.name\n  location            = azurerm_resource_group.rg.location\n  sku                 = \"Premium\"  # Required for trust policies\n  \n  public_network_access_enabled = false  # Private endpoints only\n  quarantine_policy_enabled     = true   # Quarantine unscanned images\n  \n  trust_policy {\n    enabled = true  # Content trust / image signing (Notary)\n  }\n  \n  retention_policy {\n    days    = 30\n    enabled = true  # Automatic cleanup of untagged images\n  }\n  \n  network_rule_set {\n    default_action = \"Deny\"\n  }\n}\n\n# Private endpoint for secure access\nresource \"azurerm_private_endpoint\" \"acr_pe\" {\n  name                = \"pe-acr\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  subnet_id           = azurerm_subnet.private.id\n  \n  private_service_connection {\n    name                           = \"acr-connection\"\n    private_connection_resource_id = azurerm_container_registry.acr.id\n    is_manual_connection           = false\n    subresource_names              = [\"registry\"]\n  }\n}\n```\nSource: ACR security best practices (https://learn.microsoft.com/azure/container-registry/container-registry-best-practices)"
                ))
            else:
                line_num = self.get_line_number(code, "azurerm_container_registry")
                self.add_finding(Finding(
                    requirement_id="KSI-TPR-03",
                    severity=Severity.INFO,
                    title="Supply chain security controls configured",
                    description="Container registry has image signing, quarantine, and private access configured.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure image signing is enforced in deployment pipelines and SBOM generation is enabled.",
                    good_practice=True
                ))
        
        # Check for AKS with supply chain security
        if re.search(r"azurerm_kubernetes_cluster\"", code):
            # Check for image cleaner
            has_image_cleaner = bool(re.search(r"image_cleaner_enabled\s*=\s*true", code))
            
            # Check for workload identity
            has_workload_identity = bool(re.search(r"workload_identity_enabled\s*=\s*true", code))
            
            # Check for Azure Policy addon
            has_policy_addon = bool(re.search(r"azure_policy_enabled\s*=\s*true", code))
            
            # Check for Defender for Containers
            has_defender = bool(re.search(r"microsoft_defender\s*{[^}]*enabled\s*=\s*true", code, re.DOTALL))
            
            if not has_policy_addon:
                line_num = self.get_line_number(code, "azurerm_kubernetes_cluster")
                self.add_finding(Finding(
                    requirement_id="KSI-TPR-03",
                    severity=Severity.MEDIUM,
                    title="AKS cluster missing Azure Policy addon for supply chain enforcement",
                    description="Azure Policy addon can enforce trusted container registries and image policies. FedRAMP 20x requires supply chain risk controls.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable Azure Policy addon:\n```hcl\nresource \"azurerm_kubernetes_cluster\" \"aks\" {\n  name                = \"aks-${random_id.suffix.hex}\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  dns_prefix          = \"aks\"\n  \n  azure_policy_enabled = true  # Enforce trusted registries\n  workload_identity_enabled = true  # Secure pod identity\n  \n  image_cleaner_enabled = true  # Remove vulnerable images\n  image_cleaner_interval_hours = 24\n  \n  microsoft_defender {\n    log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id\n    enabled = true\n  }\n  \n  default_node_pool {\n    name = \"default\"\n    node_count = 3\n    vm_size = \"Standard_D2s_v3\"\n  }\n  \n  identity {\n    type = \"SystemAssigned\"\n  }\n}\n```\nSource: AKS security (https://learn.microsoft.com/azure/aks/use-azure-policy)"
                ))
    
    def _check_third_party_monitoring(self, code: str, file_path: str) -> None:
        """Check for third-party software monitoring (KSI-TPR-04)."""
        # Check for Log Analytics workspace (for security alerts)
        has_log_analytics = bool(re.search(r"azurerm_log_analytics_workspace\"", code))
        
        # Check for Sentinel (SIEM for security monitoring)
        has_sentinel = bool(re.search(r"azurerm_sentinel", code))
        
        # Check for Application Insights (runtime monitoring)
        has_app_insights = bool(re.search(r"azurerm_application_insights\"", code))
        
        # Check for Defender for Cloud
        has_defender = bool(re.search(r"azurerm_security_center", code))
        
        # Check for automation accounts with vulnerability monitoring
        has_automation = bool(re.search(r"azurerm_automation_account\"", code))
        
        # Check for diagnostic settings
        has_diagnostics = bool(re.search(r"azurerm_monitor_diagnostic_setting\"", code))
        
        # Check for security monitoring setup: (LogAnalytics OR Sentinel) AND Diagnostics OR Defender OR Automation
        has_security_monitoring = ((has_log_analytics or has_sentinel) and has_diagnostics) or has_defender or has_automation or (has_sentinel and has_automation)
        
        if not has_security_monitoring:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-TPR-04",
                severity=Severity.MEDIUM,
                title="Third-party software monitoring not configured",
                description="No automated monitoring for third-party dependencies, vulnerabilities, or security advisories. FedRAMP 20x requires continuous monitoring of third-party information resources.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement third-party monitoring:\n```hcl\n# Log Analytics workspace for security monitoring\nresource \"azurerm_log_analytics_workspace\" \"law\" {\n  name                = \"law-security\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku                 = \"PerGB2018\"\n  retention_in_days   = 90\n}\n\n# Sentinel for SIEM\nresource \"azurerm_sentinel_log_analytics_workspace_onboarding\" \"sentinel\" {\n  workspace_id = azurerm_log_analytics_workspace.law.id\n}\n\n# Defender for Cloud\nresource \"azurerm_security_center_subscription_pricing\" \"vm\" {\n  tier          = \"Standard\"\n  resource_type = \"VirtualMachines\"\n}\n\nresource \"azurerm_security_center_subscription_pricing\" \"containers\" {\n  tier          = \"Standard\"\n  resource_type = \"Containers\"  # Includes dependency scanning\n}\n\n# Automation account for vulnerability monitoring\nresource \"azurerm_automation_account\" \"aa\" {\n  name                = \"aa-vuln-monitoring\"\n  location            = azurerm_resource_group.rg.location\n  resource_group_name = azurerm_resource_group.rg.name\n  sku_name            = \"Basic\"\n}\n\n# Runbook to monitor third-party advisories\nresource \"azurerm_automation_runbook\" \"vuln_check\" {\n  name                    = \"Check-ThirdPartyAdvisories\"\n  location                = azurerm_resource_group.rg.location\n  resource_group_name     = azurerm_resource_group.rg.name\n  automation_account_name = azurerm_automation_account.aa.name\n  log_verbose             = true\n  log_progress            = true\n  description             = \"Monitor third-party software for security advisories\"\n  runbook_type            = \"PowerShell\"\n  \n  publish_content_link {\n    uri = \"https://raw.githubusercontent.com/example/runbook.ps1\"\n  }\n}\n\n# Schedule daily vulnerability checks\nresource \"azurerm_automation_schedule\" \"daily\" {\n  name                    = \"Daily-Vuln-Check\"\n  resource_group_name     = azurerm_resource_group.rg.name\n  automation_account_name = azurerm_automation_account.aa.name\n  frequency               = \"Day\"\n  interval                = 1\n  start_time              = \"2024-01-01T02:00:00Z\"\n  timezone                = \"UTC\"\n}\n```\nNote: Use GitHub Advanced Security, Dependabot, or Snyk in CI/CD pipelines for comprehensive dependency scanning.\nSource: Defender for DevOps (https://learn.microsoft.com/azure/defender-for-cloud/defender-for-devops-introduction)"
            ))
        elif has_defender or has_automation or has_sentinel:
            line_num = self.get_line_number(code, "azurerm_security_center") or self.get_line_number(code, "azurerm_automation_account") or self.get_line_number(code, "azurerm_sentinel")
            self.add_finding(Finding(
                requirement_id="KSI-TPR-04",
                severity=Severity.INFO,
                title="Third-party software monitoring configured",
                description="Automated monitoring for dependencies and security advisories is configured.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure monitoring covers: 1) NVD/CVE feeds, 2) Vendor security advisories, 3) SBOM validation, 4) License compliance.",
                good_practice=True
            ))
