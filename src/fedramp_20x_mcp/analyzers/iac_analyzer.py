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
        
        # Phase 1: Foundation checks
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
        # Check for MFA enforcement (KSI-IAM-02)
        self._check_mfa_enforcement(code, file_path)
        
        # Check for privileged access management (KSI-IAM-06)
        self._check_privileged_access(code, file_path)
        
        # Check for container security (KSI-CNA-02)
        self._check_container_security(code, file_path)
        
        # Check for immutable infrastructure (KSI-CNA-04)
        self._check_immutable_infrastructure(code, file_path)
        
        # Check for API gateway configuration (KSI-CNA-06)
        self._check_api_gateway(code, file_path)
        
        # Check for backup configuration (KSI-SVC-04)
        self._check_backup_configuration(code, file_path)
        
        # Check for patch management (KSI-SVC-05)
        self._check_patch_management(code, file_path)
        
        # Check for centralized logging (KSI-MLA-01)
        self._check_centralized_logging(code, file_path)
        
        # Check for log retention (KSI-MLA-02)
        self._check_log_retention(code, file_path)
        
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
    
    # Phase 2: Critical Infrastructure Security Methods
    
    def _check_mfa_enforcement(self, code: str, file_path: str) -> None:
        """Check for MFA enforcement in Conditional Access policies (KSI-IAM-02)."""
        # Check for Conditional Access policies
        has_conditional_access = bool(re.search(r"Microsoft\.ManagedIdentity/conditionalAccessPolicies|conditionalAccessPolicy", code, re.IGNORECASE))
        
        if has_conditional_access:
            # Check if MFA is enforced
            has_mfa = bool(re.search(r"mfa|multiFactorAuthentication|phishingResistant", code, re.IGNORECASE))
            
            if not has_mfa:
                line_num = self.get_line_number(code, "conditionalAccess")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-02",
                    severity=Severity.HIGH,
                    title="Conditional Access policy missing MFA enforcement",
                    description="FedRAMP 20x requires phishing-resistant multi-factor authentication for all users.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add MFA requirement to Conditional Access policy:\n```bicep\ngrantControls: {\n  builtInControls: ['mfa']\n  authenticationStrength: 'phishingResistant'  // FIDO2/Windows Hello\n}\n```\nSource: Azure Conditional Access (https://learn.microsoft.com/entra/identity/conditional-access/)"
                ))
            else:
                line_num = self.get_line_number(code, "mfa")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-02",
                    severity=Severity.INFO,
                    title="MFA enforcement configured in Conditional Access",
                    description="Policy requires multi-factor authentication for user access.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Verify phishing-resistant methods (FIDO2, Windows Hello) are prioritized over SMS/voice.",
                    good_practice=True
                ))
    
    def _check_privileged_access(self, code: str, file_path: str) -> None:
        """Check for Privileged Identity Management configuration (KSI-IAM-06)."""
        # Check for permanent admin role assignments (anti-pattern)
        admin_patterns = [
            r"principalType:\s*['\"]User['\"].*roleDefinitionId.*Owner",
            r"principalType:\s*['\"]User['\"].*roleDefinitionId.*Contributor",
            r"Microsoft\.Authorization/roleAssignments.*Owner",
        ]
        
        has_permanent_admin = False
        for pattern in admin_patterns:
            if re.search(pattern, code, re.IGNORECASE | re.DOTALL):
                has_permanent_admin = True
                line_num = self.get_line_number(code, "roleDefinitionId")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-06",
                    severity=Severity.HIGH,
                    title="Permanent privileged role assignment detected",
                    description="Privileged roles should use Just-In-Time (JIT) access via Privileged Identity Management, not permanent assignments. FedRAMP 20x requires time-limited elevated access.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement Azure PIM for privileged roles:\n1. Remove permanent admin assignments\n2. Configure eligible assignments in PIM\n3. Require approval for activation\n4. Set maximum activation duration (e.g., 8 hours)\n\nSource: Azure PIM best practices (https://learn.microsoft.com/entra/id-governance/privileged-identity-management/)"
                ))
                break
        
        # Check for PIM configuration (good practice)
        if re.search(r"eligibleAssignments|pim|justInTime", code, re.IGNORECASE):
            line_num = self.get_line_number(code, "eligible")
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
        # Check for Azure Kubernetes Service (AKS)
        if re.search(r"Microsoft\.ContainerService/managedClusters", code):
            issues = []
            
            # Check for container image scanning
            if not re.search(r"imageScanning|defender|vulnerabilityAssessment", code, re.IGNORECASE):
                issues.append("Container image scanning not configured")
            
            # Check for network policies
            if not re.search(r"networkPolicy|calico|azure", code, re.IGNORECASE):
                issues.append("Network policies not enabled for pod isolation")
            
            # Check for pod security
            if not re.search(r"podSecurityPolicy|podSecurityStandard", code, re.IGNORECASE):
                issues.append("Pod security policies/standards not configured")
            
            if issues:
                line_num = self.get_line_number(code, "managedClusters")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-02",
                    severity=Severity.HIGH,
                    title="Container security controls missing",
                    description=f"AKS cluster missing critical security controls: {', '.join(issues)}. FedRAMP 20x requires comprehensive container security.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable container security features:\n```bicep\nproperties: {\n  securityProfile: {\n    defender: { enabled: true }  // Container image scanning\n  }\n  networkProfile: {\n    networkPolicy: 'azure'  // Pod network isolation\n  }\n  podSecurityStandard: 'restricted'  // Pod security\n}\n```\nSource: AKS security best practices (https://learn.microsoft.com/azure/aks/concepts-security)"
                ))
        
        # Check for Azure Container Registry (ACR)
        if re.search(r"Microsoft\.ContainerRegistry/registries", code):
            if not re.search(r"quarantinePolicy|trustPolicy", code, re.IGNORECASE):
                line_num = self.get_line_number(code, "registries")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-02",
                    severity=Severity.MEDIUM,
                    title="Container registry missing security policies",
                    description="ACR should have quarantine and trust policies enabled to prevent untrusted images.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable ACR security features:\n```bicep\nproperties: {\n  policies: {\n    quarantinePolicy: { status: 'enabled' }\n    trustPolicy: { status: 'enabled' }\n  }\n}\n```"
                ))
    
    def _check_immutable_infrastructure(self, code: str, file_path: str) -> None:
        """Check for immutable infrastructure patterns (KSI-CNA-04)."""
        # Check for resource locks on critical resources
        has_critical_resources = bool(re.search(r"Microsoft\.(Storage|Sql|KeyVault|Network/virtualNetworks)", code))
        
        if has_critical_resources:
            has_lock = bool(re.search(r"Microsoft\.Authorization/locks|lock.*CanNotDelete|lock.*ReadOnly", code))
            
            if not has_lock:
                line_num = self.get_line_number(code, "resource")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-04",
                    severity=Severity.MEDIUM,
                    title="Critical resources missing resource locks",
                    description="FedRAMP 20x requires immutable infrastructure. Critical resources should have locks to prevent manual modifications.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add resource lock:\n```bicep\nresource lock 'Microsoft.Authorization/locks@2020-05-01' = {\n  name: 'preventDeletion'\n  scope: criticalResource\n  properties: {\n    level: 'CanNotDelete'\n    notes: 'Prevent manual deletion - use IaC only'\n  }\n}\n```\nSource: Azure Resource Locks (https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources)"
                ))
            else:
                line_num = self.get_line_number(code, "lock")
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
        if re.search(r"Microsoft\.ApiManagement/service", code):
            issues = []
            
            # Check for rate limiting
            if not re.search(r"rate-limit|quota|throttle", code, re.IGNORECASE):
                issues.append("Rate limiting not configured")
            
            # Check for authentication
            if not re.search(r"validate-jwt|oauth|authentication", code, re.IGNORECASE):
                issues.append("JWT validation/OAuth not configured")
            
            # Check for CORS
            if re.search(r"cors.*origin.*\*", code, re.IGNORECASE):
                issues.append("CORS set to wildcard (*) - security risk")
            
            if issues:
                line_num = self.get_line_number(code, "ApiManagement")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-06",
                    severity=Severity.HIGH,
                    title="API Management missing security policies",
                    description=f"APIM configuration issues: {', '.join(issues)}. FedRAMP 20x requires API security controls.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure API security policies:\n```xml\n<policies>\n  <inbound>\n    <rate-limit calls=\"100\" renewal-period=\"60\" />\n    <validate-jwt>\n      <openid-config url=\"https://login.microsoftonline.com/...\" />\n    </validate-jwt>\n    <cors>\n      <allowed-origins>\n        <origin>https://yourdomain.com</origin>\n      </allowed-origins>\n    </cors>\n  </inbound>\n</policies>\n```\nSource: APIM security policies (https://learn.microsoft.com/azure/api-management/api-management-policies)"
                ))
    
    def _check_backup_configuration(self, code: str, file_path: str) -> None:
        """Check for backup and recovery configuration (KSI-SVC-04)."""
        # Check for resources that should have backups
        backup_required_patterns = [
            (r"Microsoft\.Storage/storageAccounts", "Storage accounts"),
            (r"Microsoft\.Sql/servers/databases", "SQL databases"),
            (r"Microsoft\.Compute/virtualMachines", "Virtual machines"),
        ]
        
        for pattern, resource_type in backup_required_patterns:
            if re.search(pattern, code):
                has_backup = bool(re.search(r"Microsoft\.RecoveryServices/vaults|Microsoft\.Backup|backupPolicy", code, re.IGNORECASE))
                
                if not has_backup:
                    line_num = self.get_line_number(code, pattern.split("/")[-1].replace("\\", ""))
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-04",
                        severity=Severity.HIGH,
                        title=f"{resource_type} missing backup configuration",
                        description="FedRAMP 20x requires backup and recovery capabilities for all critical data and systems.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation=f"Configure Azure Backup:\n```bicep\nresource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {{\n  name: 'backup-vault'\n  properties: {{\n    redundancy: 'GeoRedundant'  // FedRAMP requirement\n  }}\n}}\n\nresource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {{\n  name: 'daily-backup'\n  properties: {{\n    schedulePolicy: {{ scheduleRunFrequency: 'Daily' }}\n    retentionPolicy: {{ dailySchedule: {{ retentionDuration: {{ count: 90 }} }} }}\n  }}\n}}\n```\nSource: Azure Backup (https://learn.microsoft.com/azure/backup/)"
                    ))
                    break
    
    def _check_patch_management(self, code: str, file_path: str) -> None:
        """Check for automated patch management (KSI-SVC-05)."""
        # Check for virtual machines
        if re.search(r"Microsoft\.Compute/virtualMachines", code):
            has_patch_management = bool(re.search(r"automaticOSUpgrade|patchSettings|updateManagement", code, re.IGNORECASE))
            
            if not has_patch_management:
                line_num = self.get_line_number(code, "virtualMachines")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-05",
                    severity=Severity.HIGH,
                    title="Virtual machines missing automatic patch management",
                    description="FedRAMP 20x requires automated patching to maintain security baselines.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable automatic OS patching:\n```bicep\nproperties: {\n  osProfile: {\n    windowsConfiguration: {\n      enableAutomaticUpdates: true\n      patchSettings: {\n        patchMode: 'AutomaticByPlatform'\n        assessmentMode: 'AutomaticByPlatform'\n      }\n    }\n  }\n}\n```\nOr configure Azure Update Management.\nSource: Azure Update Management (https://learn.microsoft.com/azure/update-manager/)"
                ))
            else:
                line_num = self.get_line_number(code, "patchSettings")
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
        
        # Check for AKS node pool patching
        if re.search(r"Microsoft\.ContainerService/managedClusters", code):
            if not re.search(r"autoUpgradeProfile|automaticUpgrade", code, re.IGNORECASE):
                line_num = self.get_line_number(code, "managedClusters")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-05",
                    severity=Severity.MEDIUM,
                    title="AKS cluster missing automatic upgrade configuration",
                    description="Kubernetes clusters should have automatic upgrades enabled for security patches.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable AKS automatic upgrades:\n```bicep\nautoUpgradeProfile: {\n  upgradeChannel: 'patch'  // Auto-upgrade to latest patch version\n}\n```"
                ))
    
    def _check_centralized_logging(self, code: str, file_path: str) -> None:
        """Check for centralized logging to SIEM (KSI-MLA-01)."""
        # Check if Log Analytics workspace exists
        has_workspace = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        
        # Check if Sentinel is configured
        has_sentinel = bool(re.search(r"Microsoft\.SecurityInsights|Microsoft\.Sentinel", code, re.IGNORECASE))
        
        # Check if diagnostic settings point to workspace
        has_diagnostics = bool(re.search(r"diagnosticSettings", code))
        
        if has_diagnostics and not has_workspace:
            line_num = self.get_line_number(code, "diagnosticSettings")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-01",
                severity=Severity.HIGH,
                title="Diagnostic settings without centralized Log Analytics workspace",
                description="FedRAMP 20x requires all logs sent to centralized SIEM for security monitoring.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Create Log Analytics workspace and configure Sentinel:\n```bicep\nresource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n  name: 'security-logs'\n  properties: {\n    retentionInDays: 90\n    sku: { name: 'PerGB2018' }\n  }\n}\n\nresource sentinel 'Microsoft.SecurityInsights/onboardingStates@2023-02-01' = {\n  name: 'default'\n  scope: workspace\n}\n```\nSource: Azure Sentinel (https://learn.microsoft.com/azure/sentinel/)"
            ))
        elif has_workspace and has_sentinel:
            line_num = self.get_line_number(code, "workspace")
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
        if re.search(r"Microsoft\.OperationalInsights/workspaces", code):
            retention_match = re.search(r"retentionInDays:\s*(\d+)", code)
            
            if retention_match:
                retention_days = int(retention_match.group(1))
                
                if retention_days < 90:
                    line_num = self.get_line_number(code, "retentionInDays")
                    self.add_finding(Finding(
                        requirement_id="KSI-MLA-02",
                        severity=Severity.HIGH,
                        title=f"Insufficient log retention ({retention_days} days)",
                        description="FedRAMP 20x requires minimum 90-day log retention for audit purposes.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Increase retention to meet compliance:\n```bicep\nproperties: {\n  retentionInDays: 90  // FedRAMP minimum\n  // Consider 365+ for high-impact systems\n}\n```\nSource: FedRAMP logging requirements"
                    ))
                else:
                    line_num = self.get_line_number(code, "retentionInDays")
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
                line_num = self.get_line_number(code, "workspaces")
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
        if re.search(r"Microsoft\.Storage/storageAccounts.*logs", code, re.IGNORECASE):
            has_immutability = bool(re.search(r"immutabilityPolicy|versioningEnabled", code))
            
            if not has_immutability:
                line_num = self.get_line_number(code, "storageAccounts")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-02",
                    severity=Severity.MEDIUM,
                    title="Log storage missing immutability policy",
                    description="Audit logs should be stored with immutability to prevent tampering.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable immutable storage:\n```bicep\nproperties: {\n  immutableStorageWithVersioning: { enabled: true }\n}\n```"
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

