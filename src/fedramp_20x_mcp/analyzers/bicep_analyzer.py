"""
Bicep Infrastructure as Code analyzer for FedRAMP 20x compliance.

Supports Bicep code analysis for Azure resource definitions.
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
        
        # Phase 5: Runtime Security & Monitoring
        # Check for security monitoring alerts (KSI-MLA-03)
        self._check_security_monitoring(code, file_path)
        
        # Check for performance monitoring (KSI-MLA-04)
        self._check_performance_monitoring(code, file_path)
        
        # Check for log analysis automation (KSI-MLA-06)
        self._check_log_analysis(code, file_path)
        
        # Check for incident detection (KSI-INR-01)
        self._check_incident_detection(code, file_path)
        
        # Check for incident response logging (KSI-INR-02)
        self._check_incident_response_logging(code, file_path)
        
        # Check for threat intelligence integration (KSI-AFR-03)
        self._check_threat_intelligence(code, file_path)
        
        # Phase 6A: Core Infrastructure (Recovery, Network, Access, Crypto)
        # Check for recovery objectives (KSI-RPL-01)
        self._check_recovery_objectives(code, file_path)
        
        # Check for recovery plan (KSI-RPL-02)
        self._check_recovery_plan(code, file_path)
        
        # Check for system backups (KSI-RPL-03)
        self._check_system_backups(code, file_path)
        
        # Check for recovery testing (KSI-RPL-04)
        self._check_recovery_testing(code, file_path)
        
        # Check for traffic flow enforcement (KSI-CNA-03)
        self._check_traffic_flow(code, file_path)
        
        # Check for DDoS protection (KSI-CNA-05)
        self._check_ddos_protection(code, file_path)
        
        # Check for least privilege access (KSI-IAM-05)
        self._check_least_privilege(code, file_path)
        
        # Check for cryptographic modules (KSI-AFR-11)
        self._check_cryptographic_modules(code, file_path)
        
        # Phase 6B: Service Management, Advanced Monitoring, Secure Config, Microservices
        # Check for communication integrity (KSI-SVC-09)
        self._check_communication_integrity(code, file_path)
        
        # Check for data destruction (KSI-SVC-10)
        self._check_data_destruction(code, file_path)
        
        # Check for event types monitoring (KSI-MLA-07)
        self._check_event_types_monitoring(code, file_path)
        
        # Check for log data access (KSI-MLA-08)
        self._check_log_data_access(code, file_path)
        
        # Check for secure configuration (KSI-AFR-07)
        self._check_secure_configuration(code, file_path)
        
        # Check for microservices security (KSI-CNA-08)
        self._check_microservices_security(code, file_path)
        
        # Check for incident after-action (KSI-INR-03)
        self._check_incident_after_action(code, file_path)
        
        # Check for change management (KSI-CMT-04)
        self._check_change_management(code, file_path)
        
        # Phase 7: Supply Chain and Policy Requirements
        # Check for supply chain security (KSI-TPR-03)
        self._check_supply_chain_security(code, file_path)
        
        # Check for third-party monitoring (KSI-TPR-04)
        self._check_third_party_monitoring(code, file_path)
        
        return self.result
    
    def _check_diagnostic_settings(self, code: str, file_path: str) -> None:
        """Check if resources have diagnostic settings enabled (KSI-MLA-05)."""
        # Find Azure resources that should have logging per FedRAMP AU-12 requirements
        # Source: Azure Policy FedRAMP compliance (https://learn.microsoft.com/azure/azure-monitor/fundamentals/security-controls-policy)
        loggable_resources = [
            # Compute
            r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines@",
            r"resource\s+\w+\s+'Microsoft\.ContainerService/managedClusters@",
            r"resource\s+\w+\s+'Microsoft\.Batch/batchAccounts@",
            r"resource\s+\w+\s+'Microsoft\.Web/sites@",  # App Service
            r"resource\s+\w+\s+'Microsoft\.Web/serverFarms@",  # App Service Plan
            
            # Storage & Data
            r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts@",
            r"resource\s+\w+\s+'Microsoft\.Sql/servers@",
            r"resource\s+\w+\s+'Microsoft\.DBforPostgreSQL/servers@",
            r"resource\s+\w+\s+'Microsoft\.DBforMySQL/servers@",
            r"resource\s+\w+\s+'Microsoft\.DocumentDB/databaseAccounts@",  # Cosmos DB
            r"resource\s+\w+\s+'Microsoft\.DataLakeStore/accounts@",
            r"resource\s+\w+\s+'Microsoft\.DataLakeAnalytics/accounts@",
            r"resource\s+\w+\s+'Microsoft\.Synapse/workspaces@",
            
            # Security & Identity
            r"resource\s+\w+\s+'Microsoft\.KeyVault/vaults@",
            r"resource\s+\w+\s+'Microsoft\.KeyVault/managedHSMs@",
            
            # Networking
            r"resource\s+\w+\s+'Microsoft\.Network/applicationGateways@",
            r"resource\s+\w+\s+'Microsoft\.Network/azureFirewalls@",
            r"resource\s+\w+\s+'Microsoft\.Network/networkSecurityGroups@",
            r"resource\s+\w+\s+'Microsoft\.Network/publicIPAddresses@",
            r"resource\s+\w+\s+'Microsoft\.Network/loadBalancers@",
            r"resource\s+\w+\s+'Microsoft\.Network/virtualNetworkGateways@",
            r"resource\s+\w+\s+'Microsoft\.Cdn/profiles@",
            
            # Integration & Messaging
            r"resource\s+\w+\s+'Microsoft\.EventHub/namespaces@",
            r"resource\s+\w+\s+'Microsoft\.ServiceBus/namespaces@",
            r"resource\s+\w+\s+'Microsoft\.Logic/workflows@",
            r"resource\s+\w+\s+'Microsoft\.StreamAnalytics/streamingjobs@",
            r"resource\s+\w+\s+'Microsoft\.EventGrid/topics@",
            r"resource\s+\w+\s+'Microsoft\.ApiManagement/service@",
            
            # Analytics & AI
            r"resource\s+\w+\s+'Microsoft\.MachineLearningServices/workspaces@",
            r"resource\s+\w+\s+'Microsoft\.CognitiveServices/accounts@",
            r"resource\s+\w+\s+'Microsoft\.Databricks/workspaces@",
            
            # Containers
            r"resource\s+\w+\s+'Microsoft\.ContainerRegistry/registries@",
            r"resource\s+\w+\s+'Microsoft\.ContainerInstance/containerGroups@",
            
            # Automation & Management
            r"resource\s+\w+\s+'Microsoft\.Automation/automationAccounts@",
            r"resource\s+\w+\s+'Microsoft\.RecoveryServices/vaults@",
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
    
    def _check_security_monitoring(self, code: str, file_path: str) -> None:
        """Check for security monitoring and alert configuration (KSI-MLA-03)."""
        # Check for Application Insights
        has_app_insights = bool(re.search(r"Microsoft\.Insights/components", code))
        
        # Check for Azure Monitor metric alerts
        has_metric_alerts = bool(re.search(r"Microsoft\.Insights/metricAlerts", code))
        
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        
        # Check for alert rules
        has_alert_rules = bool(re.search(r"(alertRules|scheduledQueryRules)", code))
        
        if not has_app_insights and not has_log_analytics:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.HIGH,
                title="Missing security monitoring configuration",
                description="No Application Insights or Log Analytics workspace configured. FedRAMP 20x requires real-time security monitoring and alerting.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure monitoring infrastructure:\n```bicep\nresource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n  name: 'law-${workloadName}'\n  location: location\n  properties: {\n    sku: { name: 'PerGB2018' }\n    retentionInDays: 90\n  }\n}\n\nresource appInsights 'Microsoft.Insights/components@2020-02-02' = {\n  name: 'appi-${workloadName}'\n  location: location\n  kind: 'web'\n  properties: {\n    Application_Type: 'web'\n    WorkspaceResourceId: logAnalytics.id\n  }\n}\n```\nSource: Azure WAF - Reliability (https://learn.microsoft.com/azure/well-architected/reliability/monitoring-alerting-strategy)"
            ))
        elif (has_app_insights or has_log_analytics) and not has_alert_rules and not has_metric_alerts:
            line_num = self.get_line_number(code, "Insights") or self.get_line_number(code, "OperationalInsights")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.MEDIUM,
                title="Monitoring configured but no alert rules defined",
                description="Monitoring workspace exists but no alert rules are configured. FedRAMP 20x requires security alerts for anomalous activities.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add security alert rules:\n```bicep\nresource securityAlert 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {\n  name: 'alert-security-${workloadName}'\n  location: location\n  properties: {\n    displayName: 'Security Event Alert'\n    severity: 1  // Critical\n    enabled: true\n    evaluationFrequency: 'PT5M'\n    windowSize: 'PT5M'\n    scopes: [logAnalytics.id]\n    criteria: {\n      allOf: [\n        {\n          query: 'SecurityEvent | where EventID == 4625 | summarize count() by bin(TimeGenerated, 5m)'\n          threshold: 10\n          operator: 'GreaterThan'\n        }\n      ]\n    }\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "alertRules") or self.get_line_number(code, "metricAlerts")
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
        has_app_insights = bool(re.search(r"Microsoft\.Insights/components", code))
        
        # Check for autoscale settings
        has_autoscale = bool(re.search(r"Microsoft\.Insights/autoscalesettings", code))
        
        # Check for performance thresholds in resources
        has_performance_config = bool(re.search(r"(cpu|memory|throughput).*threshold", code, re.IGNORECASE))
        
        # Check for scalable resources (App Service, AKS, VMSS)
        has_scalable_resources = bool(re.search(r"(Microsoft\.Web/serverfarms|Microsoft\.ContainerService/managedClusters|Microsoft\.Compute/virtualMachineScaleSets)", code))
        
        if has_scalable_resources and not has_app_insights:
            line_num = self.get_line_number(code, "serverfarms") or self.get_line_number(code, "managedClusters")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.MEDIUM,
                title="Scalable resources without performance monitoring",
                description="Resources configured for scaling but Application Insights not configured. FedRAMP 20x requires performance monitoring to detect anomalies.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Application Insights:\n```bicep\nresource appInsights 'Microsoft.Insights/components@2020-02-02' = {\n  name: 'appi-${workloadName}'\n  location: location\n  kind: 'web'\n  properties: {\n    Application_Type: 'web'\n    WorkspaceResourceId: logAnalytics.id\n  }\n}\n\n// Connect to App Service\nresource appService 'Microsoft.Web/sites@2022-03-01' existing = {\n  name: appServiceName\n}\n\nresource appSettings 'Microsoft.Web/sites/config@2022-03-01' = {\n  parent: appService\n  name: 'appsettings'\n  properties: {\n    APPINSIGHTS_INSTRUMENTATIONKEY: appInsights.properties.InstrumentationKey\n    APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString\n  }\n}\n```"
            ))
        elif has_app_insights:
            # App Insights configured - check if autoscale would be beneficial
            if has_scalable_resources and not has_autoscale:
                # Optional suggestion, but still recognize App Insights as good practice
                line_num = self.get_line_number(code, "Insights/components")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-04",
                    severity=Severity.INFO,
                    title="Performance monitoring configured",
                    description="Application Insights configured for performance monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure performance baselines and anomaly detection are configured. Consider adding autoscale rules for scalable resources.",
                    good_practice=True
                ))
            else:
                line_num = self.get_line_number(code, "Insights/components")
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
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        
        # Check for saved searches / queries
        has_saved_queries = bool(re.search(r"(savedSearches|queries)", code))
        
        # Check for Sentinel (SIEM)
        has_sentinel = bool(re.search(r"Microsoft\.SecurityInsights", code))
        
        # Check for analytics rules
        has_analytics_rules = bool(re.search(r"(analyticsRules|alertRules)", code))
        
        if not has_log_analytics and not has_sentinel:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.HIGH,
                title="No log analysis infrastructure configured",
                description="Missing Log Analytics workspace or Sentinel. FedRAMP 20x requires automated log analysis and correlation for threat detection.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Log Analytics and Sentinel:\n```bicep\nresource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n  name: 'law-security-${workloadName}'\n  location: location\n  properties: {\n    sku: { name: 'PerGB2018' }\n    retentionInDays: 90\n    features: {\n      enableLogAccessUsingOnlyResourcePermissions: true\n    }\n  }\n}\n\nresource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {\n  name: 'SecurityInsights(${logAnalytics.name})'\n  location: location\n  plan: {\n    name: 'SecurityInsights(${logAnalytics.name})'\n    product: 'OMSGallery/SecurityInsights'\n    publisher: 'Microsoft'\n    promotionCode: ''\n  }\n  properties: {\n    workspaceResourceId: logAnalytics.id\n  }\n}\n```\nSource: Azure Security Benchmark - Logging and threat detection (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-logging-threat-detection)"
            ))
        elif (has_log_analytics or has_sentinel) and not has_analytics_rules:
            line_num = self.get_line_number(code, "OperationalInsights") or self.get_line_number(code, "SecurityInsights")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.MEDIUM,
                title="Log analysis workspace without automated analytics",
                description="Log Analytics/Sentinel configured but no analytics rules defined. FedRAMP 20x requires automated threat detection through KQL queries.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Sentinel analytics rules:\n```bicep\nresource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {\n  scope: logAnalytics\n  name: guid('analytics-rule-failed-login')\n  kind: 'Scheduled'\n  properties: {\n    displayName: 'Multiple Failed Login Attempts'\n    description: 'Detects multiple failed login attempts from same IP'\n    severity: 'High'\n    enabled: true\n    query: '''\n      SigninLogs\n      | where ResultType != 0\n      | summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)\n      | where FailedAttempts > 5\n    '''\n    queryFrequency: 'PT5M'\n    queryPeriod: 'PT5M'\n    triggerOperator: 'GreaterThan'\n    triggerThreshold: 0\n    tactics: ['InitialAccess']\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "analyticsRules") or self.get_line_number(code, "SecurityInsights")
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
        has_sentinel = bool(re.search(r"Microsoft\.SecurityInsights", code))
        
        # Check for automation rules
        has_automation_rules = bool(re.search(r"automationRules", code))
        
        # Check for Logic Apps for incident response
        has_logic_apps = bool(re.search(r"Microsoft\.Logic/workflows", code))
        
        # Check for playbooks
        has_playbooks = bool(re.search(r"(playbook|incident.*response)", code, re.IGNORECASE))
        
        if not has_sentinel:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.HIGH,
                title="No incident detection system configured",
                description="Microsoft Sentinel not configured. FedRAMP 20x requires automated incident detection and classification.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Sentinel for incident detection:\n```bicep\n// First ensure Log Analytics workspace exists\nresource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {\n  name: 'SecurityInsights(${logAnalytics.name})'\n  location: location\n  plan: {\n    name: 'SecurityInsights(${logAnalytics.name})'\n    product: 'OMSGallery/SecurityInsights'\n    publisher: 'Microsoft'\n  }\n  properties: {\n    workspaceResourceId: logAnalytics.id\n  }\n}\n\n// Add analytics rule for automatic incident creation\nresource incidentRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {\n  scope: logAnalytics\n  name: guid('incident-creation-rule')\n  kind: 'Scheduled'\n  properties: {\n    displayName: 'Security Incident Auto-Creation'\n    enabled: true\n    incidentConfiguration: {\n      createIncident: true\n      groupingConfiguration: {\n        enabled: true\n        reopenClosedIncident: false\n        lookbackDuration: 'PT5H'\n        matchingMethod: 'AllEntities'\n      }\n    }\n    query: 'SecurityAlert | where AlertSeverity in (\"High\", \"Medium\")'\n    queryFrequency: 'PT5M'\n    queryPeriod: 'PT5M'\n    severity: 'High'\n    triggerOperator: 'GreaterThan'\n    triggerThreshold: 0\n  }\n}\n```"
            ))
        elif has_sentinel and not has_automation_rules:
            line_num = self.get_line_number(code, "SecurityInsights")
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.MEDIUM,
                title="Incident detection without automation rules",
                description="Sentinel configured but no automation rules for incident handling. FedRAMP 20x requires automated incident triage and classification.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add automation rules:\n```bicep\nresource automationRule 'Microsoft.SecurityInsights/automationRules@2023-02-01' = {\n  scope: logAnalytics\n  name: guid('automation-severity-classification')\n  properties: {\n    displayName: 'Auto-classify incident severity'\n    order: 1\n    triggeringLogic: {\n      isEnabled: true\n      triggersOn: 'Incidents'\n      triggersWhen: 'Created'\n    }\n    actions: [\n      {\n        order: 1\n        actionType: 'ModifyProperties'\n        actionConfiguration: {\n          severity: 'High'\n          status: 'New'\n          owner: {\n            objectId: securityTeamObjectId\n          }\n        }\n      }\n    ]\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "automationRules") or self.get_line_number(code, "SecurityInsights")
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
        has_sentinel = bool(re.search(r"Microsoft\.SecurityInsights", code))
        
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        
        # Check for Logic Apps (for response automation)
        has_logic_apps = bool(re.search(r"Microsoft\.Logic/workflows", code))
        
        # Check for diagnostic settings on Sentinel/Logic Apps
        # Look for diagnosticSettings resource that references Logic Apps or has scope: logicApp
        has_response_logging = bool(re.search(r"(diagnosticSettings|Microsoft\.Insights/diagnosticSettings)", code) and 
                                    (re.search(r"scope:.*logicApp|scope:.*Logic", code) or 
                                     re.search(r"SecurityInsights", code)))
        
        if has_sentinel or has_logic_apps:
            if not has_response_logging:
                line_num = self.get_line_number(code, "Logic/workflows") or self.get_line_number(code, "SecurityInsights")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-02",
                    severity=Severity.MEDIUM,
                    title="Incident response actions not logged",
                    description="Incident response automation exists but actions are not logged. FedRAMP 20x requires all incident response activities to be logged for audit.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable diagnostic logging on Logic Apps:\n```bicep\nresource logicAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n  scope: incidentResponseLogicApp\n  name: 'diag-incident-response'\n  properties: {\n    workspaceId: logAnalytics.id\n    logs: [\n      {\n        category: 'WorkflowRuntime'\n        enabled: true\n        retentionPolicy: {\n          enabled: true\n          days: 365  // FedRAMP requires 1-year retention\n        }\n      }\n    ]\n    metrics: [\n      {\n        category: 'AllMetrics'\n        enabled: true\n      }\n    ]\n  }\n}\n```\nSource: FedRAMP 20x Incident Response Logging (FRR-INR)"
                ))
            else:
                line_num = self.get_line_number(code, "diagnosticSettings")
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
        has_sentinel = bool(re.search(r"Microsoft\.SecurityInsights", code))
        
        # Check for threat intelligence connectors
        has_ti_connectors = bool(re.search(r"(dataConnectors|threatIntelligence)", code))
        
        # Check for Defender for Cloud
        has_defender = bool(re.search(r"Microsoft\.Security/(pricings|securityContacts)", code))
        
        if not has_sentinel and not has_defender:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-03",
                severity=Severity.HIGH,
                title="No threat intelligence integration configured",
                description="Missing Sentinel or Defender for Cloud. FedRAMP 20x requires threat intelligence feeds for proactive threat detection.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Defender for Cloud and Sentinel:\n```bicep\n// Enable Defender for Cloud\nresource defenderPricing 'Microsoft.Security/pricings@2023-01-01' = {\n  name: 'VirtualMachines'\n  properties: {\n    pricingTier: 'Standard'\n  }\n}\n\nresource defenderServers 'Microsoft.Security/pricings@2023-01-01' = {\n  name: 'AppServices'\n  properties: {\n    pricingTier: 'Standard'\n  }\n}\n\n// Configure Sentinel threat intelligence\nresource tiConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01' = {\n  scope: logAnalytics\n  name: guid('ti-connector')\n  kind: 'ThreatIntelligence'\n  properties: {\n    dataTypes: {\n      indicators: {\n        state: 'Enabled'\n      }\n    }\n    tenantId: tenant().tenantId\n  }\n}\n```\nSource: Azure Security Benchmark - Threat protection (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-posture-vulnerability-management)"
            ))
        elif has_sentinel and not has_ti_connectors:
            line_num = self.get_line_number(code, "SecurityInsights")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-03",
                severity=Severity.MEDIUM,
                title="Threat intelligence feeds not configured",
                description="Sentinel deployed but threat intelligence connectors not configured. FedRAMP 20x requires external threat intelligence for IOC matching.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add threat intelligence data connectors:\n```bicep\nresource tiConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01' = {\n  scope: logAnalytics\n  name: guid('ti-taxii-connector')\n  kind: 'ThreatIntelligenceTaxii'\n  properties: {\n    dataTypes: {\n      taxiiClient: {\n        state: 'Enabled'\n      }\n    }\n    friendlyName: 'Threat Intelligence TAXII'\n    taxiiServer: 'https://your-taxii-server.com'\n    collectionId: 'your-collection-id'\n    pollingFrequency: 'OnceADay'\n    tenantId: tenant().tenantId\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "dataConnectors") or self.get_line_number(code, "Security/pricings")
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
        # Check for Site Recovery or backup vault
        has_site_recovery = bool(re.search(r"Microsoft\.RecoveryServices/vaults", code))
        has_backup = bool(re.search(r"Microsoft\.Backup", code))
        
        # Check for RTO/RPO configuration in tags or properties
        has_rto_rpo = bool(re.search(r"(rto|recoveryTimeObjective|rpo|recoveryPointObjective)", code, re.IGNORECASE))
        
        if not has_site_recovery and not has_backup:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-01",
                severity=Severity.HIGH,
                title="Recovery objectives not configured",
                description="Missing Recovery Services Vault or backup configuration. FedRAMP 20x requires defined RTO and RPO for disaster recovery.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Recovery Services Vault with RTO/RPO:\n```bicep\nresource recoveryVault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {\n  name: 'vault-${uniqueString(resourceGroup().id)}'\n  location: location\n  sku: {\n    name: 'Standard'\n  }\n  properties: {}\n  tags: {\n    rto: '4hours'  // Recovery Time Objective\n    rpo: '1hour'   // Recovery Point Objective\n    fedramp: 'required'\n  }\n}\n\nresource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {\n  parent: recoveryVault\n  name: 'DefaultPolicy'\n  properties: {\n    backupManagementType: 'AzureIaasVM'\n    schedulePolicy: {\n      schedulePolicyType: 'SimpleSchedulePolicy'\n      scheduleRunFrequency: 'Daily'\n      scheduleRunTimes: ['2023-01-01T02:00:00Z']\n    }\n    retentionPolicy: {\n      retentionPolicyType: 'LongTermRetentionPolicy'\n      dailySchedule: {\n        retentionTimes: ['2023-01-01T02:00:00Z']\n        retentionDuration: {\n          count: 365\n          durationType: 'Days'\n        }\n      }\n    }\n  }\n}\n```\nSource: Azure WAF Reliability - Backup and disaster recovery (https://learn.microsoft.com/azure/well-architected/reliability/backup-and-recovery)"
            ))
        elif not has_rto_rpo:
            line_num = self.get_line_number(code, "RecoveryServices") or self.get_line_number(code, "Backup")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-01",
                severity=Severity.MEDIUM,
                title="RTO/RPO objectives not documented",
                description="Recovery infrastructure exists but RTO/RPO not explicitly defined. FedRAMP 20x requires documented recovery objectives.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Document RTO/RPO in resource tags or properties:\n```bicep\ntags: {\n  rto: '4hours'\n  rpo: '1hour'\n  criticalityTier: 'tier1'\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "rto") or self.get_line_number(code, "RecoveryServices")
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
        has_replication = bool(re.search(r"(replicationFabrics|replicationProtectionContainers|replicatedProtectedItems)", code))
        
        # Check for ASR recovery plans (match full path or just the word)
        has_recovery_plan = bool(re.search(r"(replicationRecoveryPlans|recoveryPlans)", code))
        
        # Check for failover configuration
        has_failover = bool(re.search(r"(failover|replicationPolicy)", code, re.IGNORECASE))
        
        if not has_replication and not has_failover and not has_recovery_plan:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-02",
                severity=Severity.HIGH,
                title="No recovery plan configured",
                description="Missing Site Recovery replication or recovery plan. FedRAMP 20x requires documented and tested recovery procedures.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure Site Recovery replication:\n```bicep\nresource replicationPolicy 'Microsoft.RecoveryServices/vaults/replicationPolicies@2023-01-01' = {\n  parent: recoveryVault\n  name: 'replication-policy'\n  properties: {\n    providerSpecificInput: {\n      instanceType: 'A2A'\n      recoveryPointHistory: 1440  // 24 hours in minutes\n      crashConsistentFrequencyInMinutes: 5\n      appConsistentFrequencyInMinutes: 60\n      multiVmSyncStatus: 'Enable'\n    }\n  }\n}\n\nresource recoveryPlan 'Microsoft.RecoveryServices/vaults/replicationRecoveryPlans@2023-01-01' = {\n  parent: recoveryVault\n  name: 'dr-recovery-plan'\n  properties: {\n    primaryFabricId: primaryFabric.id\n    recoveryFabricId: secondaryFabric.id\n    failoverDeploymentModel: 'ResourceManager'\n    replicationProviders: ['A2A']\n    allowedOperations: ['PlannedFailover', 'UnplannedFailover', 'TestFailover']\n  }\n}\n```\nSource: Azure WAF Reliability - Disaster recovery (https://learn.microsoft.com/azure/well-architected/reliability/disaster-recovery)"
            ))
        elif (has_replication or has_failover) and not has_recovery_plan:
            line_num = self.get_line_number(code, "replicationFabrics") or self.get_line_number(code, "replicationPolicy")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-02",
                severity=Severity.MEDIUM,
                title="Recovery plan not formally defined",
                description="Replication configured but no recovery plan resource. FedRAMP 20x requires orchestrated recovery procedures.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add recovery plan resource to orchestrate failover:\n```bicep\nresource recoveryPlan 'Microsoft.RecoveryServices/vaults/replicationRecoveryPlans@2023-01-01' = {\n  parent: recoveryVault\n  name: 'dr-recovery-plan'\n  properties: {\n    primaryFabricId: primaryFabric.id\n    recoveryFabricId: secondaryFabric.id\n    failoverDeploymentModel: 'ResourceManager'\n  }\n}\n```"
            ))
        elif has_recovery_plan:
            line_num = self.get_line_number(code, "replicationRecoveryPlans") or self.get_line_number(code, "recoveryPlans")
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
        # Check for backup-enabled resources
        has_backup_vault = bool(re.search(r"Microsoft\.RecoveryServices/vaults", code))
        has_backup_policy = bool(re.search(r"backupPolicies", code))
        has_protected_items = bool(re.search(r"protectedItems", code))
        
        # Check for backup-relevant resources (VMs, SQL, Storage)
        has_vms = bool(re.search(r"Microsoft\.Compute/virtualMachines", code))
        has_sql = bool(re.search(r"Microsoft\.Sql", code))
        has_storage = bool(re.search(r"Microsoft\.Storage/storageAccounts", code))
        
        needs_backup = has_vms or has_sql or has_storage
        
        if needs_backup and not has_backup_vault:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-03",
                severity=Severity.HIGH,
                title="System backups not configured",
                description="Critical resources deployed without backup protection. FedRAMP 20x requires aligned backups to meet RPO.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure Backup for critical resources:\n```bicep\nresource backupVault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {\n  name: 'backup-vault-${uniqueString(resourceGroup().id)}'\n  location: location\n  sku: {\n    name: 'Standard'\n  }\n  properties: {}\n}\n\nresource vmBackupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {\n  parent: backupVault\n  name: 'VMBackupPolicy'\n  properties: {\n    backupManagementType: 'AzureIaasVM'\n    schedulePolicy: {\n      schedulePolicyType: 'SimpleSchedulePolicy'\n      scheduleRunFrequency: 'Daily'\n      scheduleRunTimes: ['2023-01-01T02:00:00Z']\n    }\n    retentionPolicy: {\n      retentionPolicyType: 'LongTermRetentionPolicy'\n      dailySchedule: {\n        retentionTimes: ['2023-01-01T02:00:00Z']\n        retentionDuration: {\n          count: 365  // FedRAMP requires 1-year retention\n          durationType: 'Days'\n        }\n      }\n    }\n    instantRpRetentionRangeInDays: 5\n  }\n}\n\n// For SQL databases\nresource sqlLongTermRetention 'Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies@2023-05-01-preview' = {\n  parent: sqlDatabase\n  name: 'default'\n  properties: {\n    weeklyRetention: 'P5W'\n    monthlyRetention: 'P12M'\n    yearlyRetention: 'P10Y'\n    weekOfYear: 1\n  }\n}\n```\nSource: Azure WAF Reliability - Backup strategies (https://learn.microsoft.com/azure/well-architected/reliability/backup-and-recovery)"
            ))
        elif needs_backup and not has_backup_policy:
            line_num = self.get_line_number(code, "RecoveryServices")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-03",
                severity=Severity.MEDIUM,
                title="Backup policies not configured",
                description="Backup vault exists but policies not defined. FedRAMP 20x requires backup schedules aligned with RPO.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Define backup policies with appropriate retention:\n```bicep\nresource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {\n  parent: backupVault\n  name: 'DefaultPolicy'\n  properties: {\n    backupManagementType: 'AzureIaasVM'\n    schedulePolicy: {\n      schedulePolicyType: 'SimpleSchedulePolicy'\n      scheduleRunFrequency: 'Daily'\n      scheduleRunTimes: ['2023-01-01T02:00:00Z']\n    }\n    retentionPolicy: {\n      retentionPolicyType: 'LongTermRetentionPolicy'\n      dailySchedule: {\n        retentionTimes: ['2023-01-01T02:00:00Z']\n        retentionDuration: {\n          count: 365\n          durationType: 'Days'\n        }\n      }\n    }\n  }\n}\n```"
            ))
        elif has_backup_vault and has_backup_policy:
            line_num = self.get_line_number(code, "backupPolicies")
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
        # Check for test failover or backup test configurations
        has_test_failover = bool(re.search(r"(testFailover|TestFailover)", code))
        has_recovery_plan = bool(re.search(r"recoveryPlans", code))
        
        # Check for automation accounts or runbooks for testing
        has_automation = bool(re.search(r"Microsoft\.Automation", code))
        has_runbooks = bool(re.search(r"(runbooks|testRecovery)", code, re.IGNORECASE))
        
        if not has_test_failover and not has_runbooks:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-RPL-04",
                severity=Severity.MEDIUM,
                title="Recovery testing not automated",
                description="No test failover or automated recovery testing configured. FedRAMP 20x requires regular recovery capability validation.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure automated recovery testing:\n```bicep\nresource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' = {\n  name: 'automation-${uniqueString(resourceGroup().id)}'\n  location: location\n  properties: {\n    sku: {\n      name: 'Basic'\n    }\n  }\n}\n\nresource recoveryTestRunbook 'Microsoft.Automation/automationAccounts/runbooks@2023-11-01' = {\n  parent: automationAccount\n  name: 'Test-RecoveryPlan'\n  properties: {\n    runbookType: 'PowerShell'\n    logProgress: true\n    logVerbose: true\n    description: 'Automated recovery testing - runs monthly DR drills'\n    publishContentLink: {\n      uri: 'https://your-repo.com/test-recovery.ps1'\n    }\n  }\n}\n\nresource recoveryTestSchedule 'Microsoft.Automation/automationAccounts/schedules@2023-11-01' = {\n  parent: automationAccount\n  name: 'MonthlyRecoveryTest'\n  properties: {\n    frequency: 'Month'\n    interval: 1\n    startTime: '2024-01-01T02:00:00Z'\n    description: 'Monthly DR test schedule'\n  }\n}\n\nresource scheduleRunbookLink 'Microsoft.Automation/automationAccounts/jobSchedules@2023-11-01' = {\n  parent: automationAccount\n  name: guid(recoveryTestRunbook.id, recoveryTestSchedule.id)\n  properties: {\n    runbook: {\n      name: recoveryTestRunbook.name\n    }\n    schedule: {\n      name: recoveryTestSchedule.name\n    }\n  }\n}\n```\nSource: Azure WAF Reliability - Testing (https://learn.microsoft.com/azure/well-architected/reliability/testing-strategy)"
            ))
        elif has_recovery_plan and not has_automation:
            line_num = self.get_line_number(code, "recoveryPlans")
            self.add_finding(Finding(
                requirement_id="KSI-RPL-04",
                severity=Severity.MEDIUM,
                title="Recovery testing not scheduled",
                description="Recovery plan exists but no automated testing schedule. FedRAMP 20x requires regular DR drills.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add automation account with scheduled recovery tests. Configure monthly test failovers to validate RTO/RPO compliance."
            ))
        else:
            line_num = self.get_line_number(code, "runbooks") or self.get_line_number(code, "Automation")
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
        # Check for NSG flow logs
        has_nsg_flow_logs = bool(re.search(r"Microsoft\.Network/networkWatchers/flowLogs", code))
        
        # Check for Network Watcher
        has_network_watcher = bool(re.search(r"Microsoft\.Network/networkWatchers", code))
        
        # Check for Application Gateway or Azure Firewall
        has_firewall = bool(re.search(r"(Microsoft\.Network/azureFirewalls|Microsoft\.Network/applicationGateways)", code))
        
        # Check for UDRs (User Defined Routes)
        has_routes = bool(re.search(r"Microsoft\.Network/routeTables", code))
        
        if not has_firewall and not has_routes:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-CNA-03",
                severity=Severity.HIGH,
                title="Traffic flow controls not enforced",
                description="Missing Azure Firewall or route tables for traffic control. FedRAMP 20x requires logical networking to enforce traffic flow.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure Firewall with network rules:\n```bicep\nresource firewall 'Microsoft.Network/azureFirewalls@2023-05-01' = {\n  name: 'firewall-${uniqueString(resourceGroup().id)}'\n  location: location\n  properties: {\n    sku: {\n      name: 'AZFW_VNet'\n      tier: 'Standard'\n    }\n    ipConfigurations: [\n      {\n        name: 'firewallIpConfig'\n        properties: {\n          subnet: {\n            id: firewallSubnet.id\n          }\n          publicIPAddress: {\n            id: firewallPublicIp.id\n          }\n        }\n      }\n    ]\n    threatIntelMode: 'Alert'  // Or 'Deny' for FedRAMP\n    firewallPolicy: {\n      id: firewallPolicy.id\n    }\n  }\n}\n\nresource firewallPolicy 'Microsoft.Network/firewallPolicies@2023-05-01' = {\n  name: 'firewallPolicy'\n  location: location\n  properties: {\n    threatIntelMode: 'Alert'\n    sku: {\n      tier: 'Standard'\n    }\n  }\n}\n\nresource routeTable 'Microsoft.Network/routeTables@2023-05-01' = {\n  name: 'route-table'\n  location: location\n  properties: {\n    routes: [\n      {\n        name: 'route-to-firewall'\n        properties: {\n          addressPrefix: '0.0.0.0/0'\n          nextHopType: 'VirtualAppliance'\n          nextHopIpAddress: firewall.properties.ipConfigurations[0].properties.privateIPAddress\n        }\n      }\n    ]\n  }\n}\n```\nSource: Azure WAF Security - Network security (https://learn.microsoft.com/azure/well-architected/security/networking)"
            ))
        elif not has_nsg_flow_logs:
            line_num = self.get_line_number(code, "azureFirewalls") or self.get_line_number(code, "routeTables")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-03",
                severity=Severity.MEDIUM,
                title="NSG flow logs not enabled",
                description="Traffic controls exist but flow logging not configured. FedRAMP 20x requires traffic flow monitoring.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Enable NSG Flow Logs:\n```bicep\nresource networkWatcher 'Microsoft.Network/networkWatchers@2023-05-01' = {\n  name: 'networkWatcher-${location}'\n  location: location\n}\n\nresource flowLog 'Microsoft.Network/networkWatchers/flowLogs@2023-05-01' = {\n  parent: networkWatcher\n  name: 'nsg-flow-log'\n  location: location\n  properties: {\n    targetResourceId: nsg.id\n    storageId: storageAccount.id\n    enabled: true\n    retentionPolicy: {\n      days: 365\n      enabled: true\n    }\n    format: {\n      type: 'JSON'\n      version: 2\n    }\n  }\n}\n```"
            ))
        else:
            line_num = self.get_line_number(code, "flowLogs")
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
        has_ddos_plan = bool(re.search(r"Microsoft\.Network/ddosProtectionPlans", code))
        
        # Check for VNets with DDoS enabled
        vnet_pattern = r"resource\s+\w+\s+'Microsoft\.Network/virtualNetworks@[^']+'\s*=\s*\{"
        vnet_matches = re.finditer(vnet_pattern, code)
        
        has_vnet = False
        ddos_enabled_on_vnet = False
        
        for match in vnet_matches:
            has_vnet = True
            # Look ahead in the code after this VNet definition
            vnet_start = match.end()
            # Find the closing brace (simplified - assumes balanced braces)
            vnet_section = code[vnet_start:vnet_start+1000]  # Check next 1000 chars
            if re.search(r"enableDdosProtection:\s*true", vnet_section):
                ddos_enabled_on_vnet = True
                break
        
        if has_vnet and not has_ddos_plan:
            line_num = self.get_line_number(code, "Microsoft.Network/virtualNetworks")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-05",
                severity=Severity.HIGH,
                title="DDoS Protection not configured",
                description="Virtual networks deployed without DDoS Protection Plan. FedRAMP 20x requires protection against denial of service attacks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Azure DDoS Protection Standard:\n```bicep\nresource ddosProtectionPlan 'Microsoft.Network/ddosProtectionPlans@2023-05-01' = {\n  name: 'ddos-plan-${uniqueString(resourceGroup().id)}'\n  location: location\n  properties: {}\n}\n\nresource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {\n  name: 'vnet-${uniqueString(resourceGroup().id)}'\n  location: location\n  properties: {\n    enableDdosProtection: true\n    ddosProtectionPlan: {\n      id: ddosProtectionPlan.id\n    }\n    addressSpace: {\n      addressPrefixes: ['10.0.0.0/16']\n    }\n    subnets: [\n      {\n        name: 'default'\n        properties: {\n          addressPrefix: '10.0.1.0/24'\n        }\n      }\n    ]\n  }\n}\n```\nSource: Azure WAF Security - DDoS protection (https://learn.microsoft.com/azure/well-architected/security/ddos-protection)\n\nNote: DDoS Protection Standard costs ~$2,944/month but is typically required for FedRAMP compliance."
            ))
        elif has_ddos_plan and not ddos_enabled_on_vnet:
            line_num = self.get_line_number(code, "ddosProtectionPlans")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-05",
                severity=Severity.MEDIUM,
                title="DDoS Protection Plan not associated with VNets",
                description="DDoS Protection Plan exists but not enabled on virtual networks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Enable DDoS protection on VNets:\n```bicep\nproperties: {\n  enableDdosProtection: true\n  ddosProtectionPlan: {\n    id: ddosProtectionPlan.id\n  }\n}\n```"
            ))
        elif has_ddos_plan and ddos_enabled_on_vnet:
            line_num = self.get_line_number(code, "ddosProtectionPlans")
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
        # Check for RBAC assignments
        has_rbac = bool(re.search(r"Microsoft\.Authorization/roleAssignments", code))
        
        # Check for overly permissive roles (Owner, Contributor at subscription/root scope)
        has_owner_role = bool(re.search(r"roleDefinitionId:.*'Owner'", code, re.IGNORECASE))
        has_contributor_root = bool(re.search(r"(roleDefinitionId:.*'Contributor'|roleDefinitionId:.*'/providers/Microsoft.Authorization/roleDefinitions/b24988ac')", code))
        
        # Check for custom roles
        has_custom_roles = bool(re.search(r"Microsoft\.Authorization/roleDefinitions", code))
        
        # Check for PIM (Privileged Identity Management)
        has_pim = bool(re.search(r"(Microsoft\.ManagedIdentity/userAssignedIdentities|eligibleRoleAssignment)", code))
        
        # Check for JIT access
        has_jit = bool(re.search(r"Microsoft\.Security/jitNetworkAccessPolicies", code))
        
        if not has_rbac:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.HIGH,
                title="RBAC not configured",
                description="No role assignments defined. FedRAMP 20x requires least privilege access controls.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure RBAC with least privilege roles:\n```bicep\n// Use specific built-in roles instead of Owner/Contributor\nresource readerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n  name: guid(resourceGroup().id, principalId, 'Reader')\n  properties: {\n    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')  // Reader\n    principalId: principalId\n    principalType: 'ServicePrincipal'\n  }\n}\n\n// Configure JIT access for privileged operations\nresource jitPolicy 'Microsoft.Security/jitNetworkAccessPolicies@2020-01-01' = {\n  name: 'jit-policy'\n  location: location\n  kind: 'Basic'\n  properties: {\n    virtualMachines: [\n      {\n        id: vm.id\n        ports: [\n          {\n            number: 22\n            protocol: 'TCP'\n            allowedSourceAddressPrefix: '*'\n            maxRequestAccessDuration: 'PT3H'\n          }\n        ]\n      }\n    ]\n  }\n}\n```\nSource: Azure WAF Security - Identity and access management (https://learn.microsoft.com/azure/well-architected/security/identity-access)"
            ))
        elif has_owner_role or has_contributor_root:
            line_num = self.get_line_number(code, "Owner") or self.get_line_number(code, "Contributor")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.HIGH,
                title="Overly permissive roles assigned",
                description="Owner or Contributor roles assigned. FedRAMP 20x requires least privilege - use specific roles instead.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Replace with specific roles:\n- Instead of 'Owner': Use 'User Access Administrator' + specific resource role\n- Instead of 'Contributor': Use specific roles like 'Virtual Machine Contributor', 'Storage Account Contributor'\n- Implement Azure AD PIM for privileged access\n- Use custom roles with minimal required permissions\n\nExample:\n```bicep\nroleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '9980e02c-c2be-4d73-94e8-173b1dc7cf3c')  // Virtual Machine Contributor\n```"
            ))
        elif not has_jit and not has_pim:
            line_num = self.get_line_number(code, "roleAssignments")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.MEDIUM,
                title="JIT access not configured",
                description="RBAC configured but no JIT or PIM for privileged access. FedRAMP 20x encourages time-limited privilege escalation.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement JIT access for administrative operations. Consider Azure AD PIM for role activations with approval workflows."
            ))
        else:
            line_num = self.get_line_number(code, "jitNetworkAccessPolicies") or self.get_line_number(code, "roleAssignments")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.INFO,
                title="Least privilege access properly configured",
                description="RBAC with specific roles and JIT/PIM for privileged access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review role assignments and access logs to ensure continued compliance with least privilege.",
                good_practice=True
            ))
    
    def _check_cryptographic_modules(self, code: str, file_path: str) -> None:
        """Check for FIPS-validated cryptographic modules (KSI-AFR-11)."""
        # Check for Key Vault with HSM
        has_key_vault_hsm = bool(re.search(r"(Microsoft\.KeyVault/managedHSMs|sku:\s*\{\s*family:\s*'A'\s*name:\s*'premium')", code))
        
        # Check for TLS/SSL configuration
        has_tls_config = bool(re.search(r"(minTlsVersion|minimumTlsVersion|sslPolicy)", code, re.IGNORECASE))
        has_tls_12 = bool(re.search(r"(minTlsVersion:\s*'1\.2'|minimumTlsVersion:\s*'TLS1_2')", code))
        
        # Check for encryption settings
        has_encryption = bool(re.search(r"(encryption|customerManagedKey)", code, re.IGNORECASE))
        
        # Check for specific FIPS mentions or SQL TDE
        has_fips = bool(re.search(r"(fips|transparentDataEncryption)", code, re.IGNORECASE))
        
        if not has_key_vault_hsm and not has_tls_12:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.HIGH,
                title="FIPS-validated cryptographic modules not configured",
                description="Missing Key Vault HSM and TLS 1.2+ enforcement. FedRAMP 20x requires FIPS 140-2/140-3 validated cryptography for federal data.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Key Vault Premium (HSM-backed) and enforce TLS 1.2+:\n```bicep\nresource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {\n  name: 'kv-${uniqueString(resourceGroup().id)}'\n  location: location\n  properties: {\n    sku: {\n      family: 'A'\n      name: 'premium'  // Uses FIPS 140-2 Level 2 validated HSMs\n    }\n    tenantId: tenant().tenantId\n    enabledForDiskEncryption: true\n    enabledForDeployment: true\n    enabledForTemplateDeployment: true\n    enableRbacAuthorization: true\n    networkAcls: {\n      defaultAction: 'Deny'\n      bypass: 'AzureServices'\n    }\n  }\n}\n\n// For storage accounts, enforce TLS 1.2\nresource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'st${uniqueString(resourceGroup().id)}'\n  properties: {\n    minimumTlsVersion: 'TLS1_2'\n    supportsHttpsTrafficOnly: true\n    encryption: {\n      requireInfrastructureEncryption: true\n      keySource: 'Microsoft.Keyvault'\n      keyvaultproperties: {\n        keyname: key.name\n        keyvaulturi: keyVault.properties.vaultUri\n      }\n      services: {\n        blob: {\n          enabled: true\n          keyType: 'Account'\n        }\n        file: {\n          enabled: true\n          keyType: 'Account'\n        }\n      }\n    }\n  }\n}\n\n// For SQL, enable TDE with customer-managed keys\nresource sqlTDE 'Microsoft.Sql/servers/databases/transparentDataEncryption@2023-05-01-preview' = {\n  parent: sqlDatabase\n  name: 'current'\n  properties: {\n    state: 'Enabled'\n  }\n}\n\nresource sqlEncryptionProtector 'Microsoft.Sql/servers/encryptionProtector@2023-05-01-preview' = {\n  parent: sqlServer\n  name: 'current'\n  properties: {\n    serverKeyType: 'AzureKeyVault'\n    serverKeyName: '${keyVault.name}_${key.name}_${key.properties.keyUriWithVersion}'\n  }\n}\n```\nSource: Azure Security Benchmark - Data protection (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-data-protection)\n\nNote: Azure Key Vault Premium uses FIPS 140-2 Level 2 validated HSMs. Managed HSM uses FIPS 140-2 Level 3."
            ))
        elif not has_tls_12:
            line_num = self.get_line_number(code, "KeyVault") or 1
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.HIGH,
                title="TLS 1.2 not enforced",
                description="Cryptographic infrastructure exists but TLS 1.2+ not enforced. FedRAMP 20x requires strong transport encryption.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Enforce TLS 1.2+ on all resources:\n```bicep\n// Storage\nminimumTlsVersion: 'TLS1_2'\n\n// App Service\nsiteConfig: {\n  minTlsVersion: '1.2'\n}\n\n// SQL\nminimalTlsVersion: '1.2'\n\n// Azure Firewall / Application Gateway\nsslPolicy: {\n  minProtocolVersion: 'TLSv1_2'\n  cipherSuites: [\n    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'\n    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'\n  ]\n}\n```"
            ))
        elif not has_key_vault_hsm:
            line_num = self.get_line_number(code, "minTlsVersion") or self.get_line_number(code, "minimumTlsVersion")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.MEDIUM,
                title="HSM-backed key storage not configured",
                description="TLS 1.2 enforced but not using Key Vault Premium/Managed HSM. FedRAMP 20x recommends FIPS 140-2 Level 2+ for sensitive keys.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Upgrade to Key Vault Premium for HSM-backed keys:\n```bicep\nsku: {\n  family: 'A'\n  name: 'premium'  // FIPS 140-2 Level 2 HSMs\n}\n```\nFor higher assurance, consider Azure Managed HSM (FIPS 140-2 Level 3)."
            ))
        else:
            line_num = self.get_line_number(code, "premium") or self.get_line_number(code, "managedHSMs")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-11",
                severity=Severity.INFO,
                title="FIPS-validated cryptographic modules configured",
                description="Key Vault HSM and TLS 1.2+ properly configured for FIPS 140-2 compliance.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly rotate cryptographic keys and review cipher suites for algorithm deprecations.",
                good_practice=True
            ))
    
    def _check_communication_integrity(self, code: str, file_path: str) -> None:
        """Check for communication integrity validation (KSI-SVC-09)."""
        # Check for TLS/mTLS configuration
        has_mtls = bool(re.search(r"(clientCertificateMode|mutual.*tls|mtls)", code, re.IGNORECASE))
        
        # Check for certificate validation
        has_cert_validation = bool(re.search(r"(certificateThumbprint|clientCertificate|sslCertificate)", code, re.IGNORECASE))
        
        # Check for API Management with certificate auth
        has_apim_cert = bool(re.search(r"Microsoft\.ApiManagement.*clientCertificateEnabled.*true", code, re.DOTALL))
        
        # Check for App Service client certificates
        has_app_cert = bool(re.search(r"Microsoft\.Web/sites.*clientCertEnabled.*true", code, re.DOTALL))
        
        # Check for Application Gateway with mutual auth
        has_appgw_mtls = bool(re.search(r"Microsoft\.Network/applicationGateways.*sslProfile", code))
        
        if not has_mtls and not has_cert_validation and not has_apim_cert and not has_app_cert:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-SVC-09",
                severity=Severity.MEDIUM,
                title="Communication integrity not validated",
                description="Missing mTLS or certificate-based authentication for machine-to-machine communications. FedRAMP 20x requires persistent validation of communication authenticity and integrity.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure mutual TLS (mTLS) for service-to-service communications:\n```bicep\n// App Service with client certificates\nresource appService 'Microsoft.Web/sites@2022-03-01' = {\n  name: 'app-name'\n  properties: {\n    clientCertEnabled: true\n    clientCertMode: 'Required'\n    httpsOnly: true\n  }\n}\n\n// API Management with client certificate validation\nresource apim 'Microsoft.ApiManagement/service@2022-08-01' = {\n  name: 'apim-name'\n  properties: {\n    certificates: [\n      {\n        encodedCertificate: base64(loadTextContent('client-cert.pfx'))\n        certificatePassword: keyVaultSecret.properties.value\n      }\n    ]\n  }\n}\n\nresource apimApi 'Microsoft.ApiManagement/service/apis@2022-08-01' = {\n  parent: apim\n  name: 'secure-api'\n  properties: {\n    subscriptionRequired: true\n    authentication: {\n      clientCertificateRequired: true\n    }\n  }\n}\n\n// Application Gateway with SSL profile\nresource appGw 'Microsoft.Network/applicationGateways@2023-05-01' = {\n  name: 'appgw-name'\n  properties: {\n    sslProfiles: [\n      {\n        name: 'mtls-profile'\n        properties: {\n          clientAuthConfiguration: {\n            verifyClientCertIssuerDN: true\n          }\n          trustedClientCertificates: [{\n            id: clientCert.id\n          }]\n        }\n      }\n    ]\n  }\n}\n```\nSource: Azure WAF Security - Network security and encryption (https://learn.microsoft.com/azure/well-architected/security/networking)"
            ))
        elif has_mtls or has_cert_validation or has_apim_cert or has_app_cert:
            line_num = self.get_line_number(code, "clientCertificate") or self.get_line_number(code, "mtls")
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
        # Check for soft delete enabled on Key Vault
        has_soft_delete = bool(re.search(r"enableSoftDelete.*true", code))
        has_purge_protection = bool(re.search(r"enablePurgeProtection.*true", code))
        
        # Check for Storage account soft delete
        has_storage_soft_delete = bool(re.search(r"deleteRetentionPolicy.*enabled.*true", code, re.DOTALL))
        
        # Check for SQL backup retention
        has_sql_retention = bool(re.search(r"(Microsoft\.Sql.*retentionDays|backupRetentionDays)", code))
        
        # Check for diagnostic settings with retention
        has_diagnostic_retention = bool(re.search(r"retentionPolicy.*enabled.*true", code, re.DOTALL))
        
        if not has_soft_delete and not has_storage_soft_delete:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-SVC-10",
                severity=Severity.MEDIUM,
                title="Data destruction capabilities not configured",
                description="Missing soft delete and purge protection for data resources. FedRAMP 20x requires prompt removal of federal customer data when requested while preventing accidental deletion.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure soft delete and purge protection:\n```bicep\n// Key Vault with soft delete and purge protection\nresource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {\n  name: 'kv-name'\n  properties: {\n    enableSoftDelete: true  // 90-day retention\n    enablePurgeProtection: true  // Prevents permanent deletion during retention\n    softDeleteRetentionInDays: 90\n  }\n}\n\n// Storage account with soft delete\nresource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'stname'\n  properties: {\n    // Blob soft delete\n    blobServices: {\n      deleteRetentionPolicy: {\n        enabled: true\n        days: 30  // FedRAMP: align with data retention requirements\n      }\n    }\n  }\n}\n\n// SQL database with backup retention\nresource sqlDb 'Microsoft.Sql/servers/databases@2022-05-01-preview' = {\n  name: 'db-name'\n  properties: {\n    backupRetentionDays: 35  // Point-in-time restore window\n    isLedgerDatabase: true  // Immutable ledger for audit trail\n  }\n}\n\n// Cosmos DB with point-in-time restore\nresource cosmos 'Microsoft.DocumentDB/databaseAccounts@2023-04-15' = {\n  name: 'cosmos-name'\n  properties: {\n    backupPolicy: {\n      type: 'Continuous'\n      continuousModeProperties: {\n        tier: 'Continuous30Days'  // 30-day point-in-time restore\n      }\n    }\n  }\n}\n```\nSource: Azure WAF Reliability - Backup and data protection (https://learn.microsoft.com/azure/well-architected/reliability/backup-and-recovery)"
            ))
        elif has_soft_delete or has_storage_soft_delete:
            line_num = self.get_line_number(code, "enableSoftDelete") or self.get_line_number(code, "deleteRetentionPolicy")
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
        """Check for documented event types and monitoring configuration (KSI-MLA-07)."""
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        
        # Check for diagnostic settings with specific log categories
        has_log_categories = bool(re.search(r"(logs.*category|categoryGroup)", code, re.IGNORECASE))
        
        # Check for workbook or dashboard definitions
        has_workbook = bool(re.search(r"(Microsoft\.Insights/workbooks|Microsoft\.Portal/dashboards)", code))
        
        # Check for data collection rules
        has_dcr = bool(re.search(r"Microsoft\.Insights/dataCollectionRules", code))
        
        if not has_log_analytics and not has_log_categories:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-07",
                severity=Severity.MEDIUM,
                title="Event types not documented or monitored",
                description="Missing Log Analytics workspace or specific log category configuration. FedRAMP 20x requires maintaining a list of monitored event types for all information resources.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure Log Analytics with specific event type monitoring:\n```bicep\n// Log Analytics workspace\nresource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n  name: 'law-name'\n  location: location\n  properties: {\n    retentionInDays: 365  // FedRAMP requirement\n    sku: {\n      name: 'PerGB2018'\n    }\n  }\n}\n\n// Diagnostic settings with specific log categories\nresource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n  name: 'diag-settings'\n  scope: targetResource\n  properties: {\n    workspaceId: logAnalytics.id\n    logs: [\n      { category: 'AuditEvent', enabled: true, retentionPolicy: { enabled: true, days: 365 } }\n      { category: 'SignInLogs', enabled: true, retentionPolicy: { enabled: true, days: 365 } }\n      { category: 'AzureActivity', enabled: true, retentionPolicy: { enabled: true, days: 365 } }\n      { category: 'SecurityEvent', enabled: true, retentionPolicy: { enabled: true, days: 365 } }\n    ]\n    metrics: [\n      { category: 'AllMetrics', enabled: true, retentionPolicy: { enabled: true, days: 365 } }\n    ]\n  }\n}\n\n// Data Collection Rule for specific event types\nresource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {\n  name: 'dcr-security-events'\n  location: location\n  properties: {\n    description: 'Security event types for FedRAMP monitoring'\n    dataSources: {\n      windowsEventLogs: [\n        {\n          name: 'SecurityEvents'\n          streams: ['Microsoft-SecurityEvent']\n          xPathQueries: [\n            'Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648)]]'  // Logon events\n            'Security!*[System[(EventID=4719 or EventID=4739)]]'  // Policy changes\n          ]\n        }\n      ]\n      syslog: [\n        {\n          name: 'SyslogAuth'\n          streams: ['Microsoft-Syslog']\n          facilityNames: ['auth', 'authpriv', 'security']\n          logLevels: ['Alert', 'Critical', 'Error', 'Warning']\n        }\n      ]\n    }\n    destinations: {\n      logAnalytics: [{ workspaceResourceId: logAnalytics.id, name: 'law' }]\n    }\n  }\n}\n```\nSource: Azure Monitor - Data collection (https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection)"
            ))
        elif not has_dcr and not has_workbook:
            line_num = self.get_line_number(code, "Microsoft.OperationalInsights")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-07",
                severity=Severity.LOW,
                title="Event types not formally documented",
                description="Log Analytics configured but missing data collection rules or monitoring workbooks. Consider documenting specific event types.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Data Collection Rules to document specific event types and create monitoring workbooks for visibility."
            ))
        else:
            line_num = self.get_line_number(code, "dataCollectionRules") or self.get_line_number(code, "workbooks")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-07",
                severity=Severity.INFO,
                title="Event types documented and monitored",
                description="Data collection rules and monitoring infrastructure properly configured for event type tracking.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review and update the list of monitored event types based on threat intelligence and audit findings.",
                good_practice=True
            ))
    
    def _check_log_data_access(self, code: str, file_path: str) -> None:
        """Check for least-privilege access to log data (KSI-MLA-08)."""
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        
        # Check for RBAC on Log Analytics
        has_rbac = bool(re.search(r"Microsoft\.Authorization/roleAssignments", code))
        
        # Check for table-level RBAC
        has_table_rbac = bool(re.search(r"(table.*access|workspace.*rbac)", code, re.IGNORECASE))
        
        # Check for Private Link for Log Analytics
        has_private_link = bool(re.search(r"Microsoft\.Network/privateEndpoints.*OperationalInsights", code, re.DOTALL))
        
        if has_log_analytics and has_rbac:
            line_num = self.get_line_number(code, "roleAssignments") or self.get_line_number(code, "Microsoft.OperationalInsights")
            # RBAC is configured - this is good practice
            self.add_finding(Finding(
                requirement_id="KSI-MLA-08",
                severity=Severity.INFO,
                title="Log data access properly restricted",
                description="Least-privilege RBAC configured for Log Analytics workspace access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review log access permissions and use PIM for just-in-time access to sensitive logs. Consider adding Private Link endpoints for network-level access control.",
                good_practice=True
            ))
        elif has_log_analytics:
            line_num = self.get_line_number(code, "Microsoft.OperationalInsights")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-08",
                severity=Severity.HIGH,
                title="Log data access not restricted",
                description="Log Analytics workspace without RBAC role assignments. FedRAMP 20x requires least-privileged, role-based access for log data.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure workspace-level and table-level RBAC for Log Analytics:\n```bicep\n// Log Analytics workspace with resource-scoped access\nresource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n  name: 'law-name'\n  properties: {\n    publicNetworkAccessForIngestion: 'Disabled'  // Force Private Link\n    publicNetworkAccessForQuery: 'Disabled'\n    features: {\n      enableLogAccessUsingOnlyResourcePermissions: true  // Resource-context RBAC\n    }\n  }\n}\n\n// RBAC: Read-only access to specific tables\nresource logReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n  scope: logAnalytics\n  name: guid(logAnalytics.id, 'LogReader', principalId)\n  properties: {\n    principalId: principalId\n    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '73c42c96-874c-492b-b04d-ab87d138a893')  // Log Analytics Reader\n  }\n}\n\n// Table-level access control\nresource sensitiveTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {\n  parent: logAnalytics\n  name: 'SecurityEvent'\n  properties: {\n    plan: 'Analytics'\n    retentionInDays: 365\n    totalRetentionInDays: 730  // Archive for extended retention\n    // Table-level RBAC applied via resource context\n  }\n}\n\n// Private endpoint for secure access\nresource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {\n  name: 'pe-law'\n  location: location\n  properties: {\n    subnet: { id: subnetId }\n    privateLinkServiceConnections: [{\n      name: 'law-connection'\n      properties: {\n        privateLinkServiceId: logAnalytics.id\n        groupIds: ['azuremonitor']\n      }\n    }]\n  }\n}\n\n// JIT access using PIM for security analysts\n// Note: PIM eligibility configured via Azure AD, not IaC\n```\nSource: Azure Monitor - Workspace access control (https://learn.microsoft.com/azure/azure-monitor/logs/manage-access)"
            ))
    
    def _check_secure_configuration(self, code: str, file_path: str) -> None:
        """Check for secure-by-default configurations (KSI-AFR-07)."""
        # Check for secure defaults: HTTPS only, TLS 1.2+, encryption
        has_https_only = bool(re.search(r"httpsOnly.*true", code))
        has_min_tls = bool(re.search(r"minTlsVersion.*'1\.2'", code))
        has_public_access_disabled = bool(re.search(r"publicNetworkAccess.*'Disabled'", code))
        
        # Check for insecure configurations
        has_public_blob_access = bool(re.search(r"allowBlobPublicAccess.*true", code))
        has_public_network_enabled = bool(re.search(r"publicNetworkAccess.*'Enabled'", code))
        has_weak_tls = bool(re.search(r"minTlsVersion.*'1\.[01]'", code))
        
        # Count secure defaults
        secure_defaults = sum([has_https_only, has_min_tls, has_public_access_disabled])
        insecure_configs = sum([has_public_blob_access, has_public_network_enabled, has_weak_tls])
        
        if insecure_configs > 0:
            line_num = self.get_line_number(code, "publicNetworkAccess.*'Enabled'") or self.get_line_number(code, "allowBlobPublicAccess.*true")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-07",
                severity=Severity.HIGH,
                title="Insecure default configurations detected",
                description="Resources configured with insecure defaults (public access enabled, weak TLS, public blob access). FedRAMP 20x requires secure-by-default configurations.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Apply secure default configurations:\n```bicep\n// App Service secure defaults\nresource appService 'Microsoft.Web/sites@2022-03-01' = {\n  name: 'app-name'\n  properties: {\n    httpsOnly: true  // Redirect HTTP to HTTPS\n    clientAffinityEnabled: false  // Stateless for scalability\n    siteConfig: {\n      minTlsVersion: '1.2'  // TLS 1.2 minimum\n      ftpsState: 'Disabled'  // Disable FTP\n      http20Enabled: true  // Enable HTTP/2\n      alwaysOn: true\n      use32BitWorkerProcess: false\n    }\n  }\n}\n\n// Storage account secure defaults\nresource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'stname'\n  properties: {\n    allowBlobPublicAccess: false  // No anonymous access\n    publicNetworkAccess: 'Disabled'  // Private endpoints only\n    minimumTlsVersion: 'TLS1_2'\n    supportsHttpsTrafficOnly: true\n    allowSharedKeyAccess: false  // Force Azure AD auth\n    encryption: {\n      requireInfrastructureEncryption: true  // Double encryption\n      services: {\n        blob: { enabled: true, keyType: 'Account' }\n        file: { enabled: true, keyType: 'Account' }\n      }\n    }\n  }\n}\n\n// SQL Server secure defaults\nresource sqlServer 'Microsoft.Sql/servers@2022-05-01-preview' = {\n  name: 'sql-name'\n  properties: {\n    minimalTlsVersion: '1.2'\n    publicNetworkAccess: 'Disabled'\n    administratorLogin: null  // Use Azure AD auth only\n    administrators: {\n      administratorType: 'ActiveDirectory'\n      principalId: adminGroupId\n      azureADOnlyAuthentication: true  // Disable SQL auth\n    }\n  }\n}\n\n// Key Vault secure defaults\nresource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {\n  name: 'kv-name'\n  properties: {\n    enableRbacAuthorization: true  // Use RBAC instead of access policies\n    publicNetworkAccess: 'Disabled'\n    networkAcls: {\n      defaultAction: 'Deny'\n      bypass: 'AzureServices'\n    }\n  }\n}\n```\nSource: Azure Security Baseline - Secure configuration (https://learn.microsoft.com/security/benchmark/azure/security-controls-v3-posture-vulnerability-management)"
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
            line_num = self.get_line_number(code, "httpsOnly") or self.get_line_number(code, "minTlsVersion")
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
        # Check for service mesh (Istio, Linkerd, Dapr)
        has_service_mesh = bool(re.search(r"(serviceMeshProfile|istio|linkerd|dapr)", code, re.IGNORECASE))
        
        # Check for API Management in front of microservices
        has_apim = bool(re.search(r"Microsoft\.ApiManagement", code))
        
        # Check for Container Apps with Dapr
        has_container_apps_dapr = bool(re.search(r"Microsoft\.App/containerApps.*dapr", code, re.DOTALL))
        
        # Check for AKS with network policies
        has_aks_network_policy = bool(re.search(r"managedClusters.*networkPolicy", code, re.DOTALL))
        
        # Check for Azure Front Door or Application Gateway
        has_ingress_controller = bool(re.search(r"(Microsoft\.Network/frontDoors|Microsoft\.Network/applicationGateways)", code))
        
        if not has_service_mesh and not has_apim and not has_container_apps_dapr:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-CNA-08",
                severity=Severity.MEDIUM,
                title="Microservices security controls missing",
                description="Missing service mesh or API gateway for microservices security. FedRAMP 20x requires persistent security posture assessment for machine-based resources.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure service mesh or API Management for microservices:\n```bicep\n// AKS with Istio service mesh\nresource aks 'Microsoft.ContainerService/managedClusters@2023-07-01' = {\n  name: 'aks-name'\n  properties: {\n    serviceMeshProfile: {\n      mode: 'Istio'  // Enable Istio service mesh\n      istio: {\n        components: {\n          ingressGateways: [{ enabled: true }]\n        }\n      }\n    }\n    networkProfile: {\n      networkPolicy: 'cilium'  // Or 'azure', 'calico'\n      serviceMesh: {\n        enabled: true\n      }\n    }\n  }\n}\n\n// Container Apps with Dapr\nresource containerApp 'Microsoft.App/containerApps@2023-05-01' = {\n  name: 'app-name'\n  properties: {\n    configuration: {\n      dapr: {\n        enabled: true\n        appId: 'myapp'\n        appProtocol: 'grpc'\n        appPort: 3000\n        enableApiLogging: true  // Log service-to-service calls\n      }\n      ingress: {\n        external: false  // Internal only\n        transport: 'http2'  // gRPC support\n        clientCertificateMode: 'require'  // mTLS\n      }\n    }\n  }\n}\n\n// API Management for microservices gateway\nresource apim 'Microsoft.ApiManagement/service@2022-08-01' = {\n  name: 'apim-name'\n  properties: {\n    virtualNetworkType: 'Internal'  // Internal VNet integration\n  }\n}\n\nresource apimPolicy 'Microsoft.ApiManagement/service/policies@2022-08-01' = {\n  parent: apim\n  name: 'policy'\n  properties: {\n    value: '''<policies>\n      <inbound>\n        <rate-limit calls=\"100\" renewal-period=\"60\" />\n        <validate-jwt header-name=\"Authorization\">\n          <openid-config url=\"https://login.microsoftonline.com/{{tenant}}/.well-known/openid-configuration\" />\n        </validate-jwt>\n        <check-header name=\"X-Client-Certificate\" failed-check-httpcode=\"403\" />\n      </inbound>\n      <backend><forward-request /></backend>\n      <outbound />\n      <on-error />\n    </policies>'''\n  }\n}\n```\nSource: Azure WAF Security - Application security (https://learn.microsoft.com/azure/well-architected/security/application-design)"
            ))
        elif (has_service_mesh or has_container_apps_dapr or has_apim):
            # Some security controls exist - recognize as good practice
            line_num = self.get_line_number(code, "serviceMeshProfile") or self.get_line_number(code, "dapr") or self.get_line_number(code, "Microsoft.ApiManagement")
            recommendation = "Monitor service mesh metrics and regularly review service-to-service authentication policies."
            if has_service_mesh and not has_aks_network_policy:
                recommendation += " Consider adding AKS network policies to enforce pod-to-pod communication rules for defense-in-depth."
            self.add_finding(Finding(
                requirement_id="KSI-CNA-08",
                severity=Severity.INFO,
                title="Microservices security controls configured",
                description="Service mesh or API gateway provides security posture assessment and mTLS for microservices.",
                file_path=file_path,
                line_number=line_num,
                recommendation=recommendation,
                good_practice=True
            ))
    
    def _check_incident_after_action(self, code: str, file_path: str) -> None:
        """Check for incident after-action reporting (KSI-INR-03)."""
        # Check for automation workflows for incident response
        has_logic_apps = bool(re.search(r"Microsoft\.Logic/workflows", code))
        
        # Check for automation runbooks
        has_automation = bool(re.search(r"Microsoft\.Automation/automationAccounts", code))
        
        # Check for Sentinel playbooks
        has_sentinel_playbook = bool(re.search(r"Microsoft\.Logic/workflows.*SecurityInsights", code, re.DOTALL))
        
        # Check for incident documentation storage (Storage or Cosmos)
        has_incident_storage = bool(re.search(r"(incident|response|after.*action)", code, re.IGNORECASE))
        
        if not has_logic_apps and not has_automation and not has_sentinel_playbook:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-INR-03",
                severity=Severity.MEDIUM,
                title="Incident after-action reporting not automated",
                description="Missing automation for incident after-action reports. FedRAMP 20x requires generating after-action reports and regularly incorporating lessons learned.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure automated incident after-action reporting:\n```bicep\n// Logic App for incident after-action report generation\nresource incidentWorkflow 'Microsoft.Logic/workflows@2019-05-01' = {\n  name: 'incident-after-action'\n  location: location\n  properties: {\n    state: 'Enabled'\n    definition: {\n      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'\n      triggers: {\n        'When_an_incident_is_closed': {\n          type: 'ApiConnectionWebhook'\n          inputs: {\n            host: { connection: { name: '@parameters(\\'$connections\\')[\\'azuresentinel\\'][\\'connectionId\\']' } }\n            path: '/incident-creation'\n          }\n        }\n      }\n      actions: {\n        'Get_incident_details': {\n          type: 'ApiConnection'\n          inputs: {\n            host: { connection: { name: '@parameters(\\'$connections\\')[\\'azuresentinel\\'][\\'connectionId\\']' } }\n            path: '/Incidents/@{triggerBody()?[\\'IncidentNumber\\']}'\n          }\n        }\n        'Generate_after_action_report': {\n          type: 'Compose'\n          inputs: {\n            incidentId: '@{body(\\'Get_incident_details\\')?[\\'name\\']}'\n            severity: '@{body(\\'Get_incident_details\\')?[\\'properties\\']?[\\'severity\\']}'\n            closedTime: '@{utcNow()}'\n            rootCause: '@{body(\\'Get_incident_details\\')?[\\'properties\\']?[\\'description\\']}'\n            lessonsLearned: 'To be completed by incident commander'\n            remediationActions: '@{body(\\'Get_incident_details\\')?[\\'properties\\']?[\\'title\\']}'\n          }\n        }\n        'Store_report_in_Cosmos': {\n          type: 'ApiConnection'\n          inputs: {\n            host: { connection: { name: '@parameters(\\'$connections\\')[\\'documentdb\\'][\\'connectionId\\']' } }\n            method: 'post'\n            path: '/dbs/incidentdb/colls/after-action-reports/docs'\n            body: '@outputs(\\'Generate_after_action_report\\')'\n          }\n        }\n        'Notify_security_team': {\n          type: 'ApiConnection'\n          inputs: {\n            host: { connection: { name: '@parameters(\\'$connections\\')[\\'teams\\'][\\'connectionId\\']' } }\n            method: 'post'\n            path: '/flowbot/actions/PostMessage'\n            body: {\n              messageBody: 'Incident @{body(\\'Get_incident_details\\')?[\\'name\\']} closed. After-action report generated.'\n              recipient: '@{parameters(\\'securityTeamEmail\\')}'\n            }\n          }\n        }\n      }\n    }\n  }\n}\n\n// Cosmos DB for incident reports\nresource cosmos 'Microsoft.DocumentDB/databaseAccounts@2023-04-15' = {\n  name: 'cosmos-incidents'\n  properties: {\n    databaseAccountOfferType: 'Standard'\n    locations: [{ locationName: location }]\n  }\n}\n\n// Automation runbook for lessons learned integration\nresource automation 'Microsoft.Automation/automationAccounts@2022-08-08' = {\n  name: 'auto-incident-review'\n}\n\nresource runbook 'Microsoft.Automation/automationAccounts/runbooks@2022-08-08' = {\n  parent: automation\n  name: 'Integrate-LessonsLearned'\n  properties: {\n    runbookType: 'PowerShell'\n    description: 'Quarterly review to integrate lessons learned into security procedures'\n  }\n}\n```\nSource: Azure Sentinel - Incident management (https://learn.microsoft.com/azure/sentinel/incident-investigation)"
            ))
        elif has_logic_apps or has_automation:
            line_num = self.get_line_number(code, "Microsoft.Logic") or self.get_line_number(code, "Microsoft.Automation")
            self.add_finding(Finding(
                requirement_id="KSI-INR-03",
                severity=Severity.INFO,
                title="Incident after-action automation configured",
                description="Automation workflows configured for incident after-action reporting.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Conduct quarterly reviews to incorporate lessons learned into security procedures and update incident response playbooks.",
                good_practice=True
            ))
    
    def _check_change_management(self, code: str, file_path: str) -> None:
        """Check for change management procedure implementation (KSI-CMT-04)."""
        # Check for resource tags with change tracking
        has_change_tags = bool(re.search(r"(changeTicket|changeId|deploymentId|version)", code, re.IGNORECASE))
        
        # Check for deployment slots (staged rollout)
        has_deployment_slots = bool(re.search(r"Microsoft\.Web/sites/slots", code))
        
        # Check for blue-green deployment pattern (Traffic Manager)
        has_traffic_manager = bool(re.search(r"Microsoft\.Network/trafficManagerProfiles", code))
        
        # Check for Container App revisions
        has_revisions = bool(re.search(r"(revision.*management|trafficWeight)", code, re.IGNORECASE))
        
        # Check for immutable deployment pattern (resource locks)
        has_locks = bool(re.search(r"Microsoft\.Authorization/locks", code))
        
        if not has_change_tags and not has_deployment_slots and not has_traffic_manager:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-CMT-04",
                severity=Severity.MEDIUM,
                title="Change management procedures not implemented",
                description="Missing change tracking tags and staged deployment patterns. FedRAMP 20x requires documented change management procedures.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement change management in IaC:\n```bicep\n// Resource tags for change tracking\nvar changeTags = {\n  changeTicket: 'CHG-12345'  // ServiceNow/ADO work item\n  deployedBy: 'pipeline-name'\n  deploymentId: deployment().name\n  version: 'v1.2.3'\n  environment: 'production'\n  approvedBy: 'security-team@company.com'\n  changeDate: utcNow('yyyy-MM-dd')\n}\n\n// App Service with deployment slots (staged rollout)\nresource appService 'Microsoft.Web/sites@2022-03-01' = {\n  name: 'app-name'\n  tags: changeTags\n  properties: {\n    // Production slot\n  }\n}\n\nresource stagingSlot 'Microsoft.Web/sites/slots@2022-03-01' = {\n  parent: appService\n  name: 'staging'\n  tags: changeTags\n  properties: {\n    // Deploy to staging first, then swap to production\n  }\n}\n\n// Container Apps with traffic splitting (blue-green)\nresource containerApp 'Microsoft.App/containerApps@2023-05-01' = {\n  name: 'app-name'\n  tags: changeTags\n  properties: {\n    configuration: {\n      ingress: {\n        traffic: [\n          { revisionName: 'blue-revision', weight: 90 }  // Current stable\n          { revisionName: 'green-revision', weight: 10 }  // New version canary\n        ]\n      }\n    }\n  }\n}\n\n// Traffic Manager for blue-green deployment\nresource trafficManager 'Microsoft.Network/trafficManagerProfiles@2022-04-01' = {\n  name: 'tm-name'\n  tags: changeTags\n  properties: {\n    trafficRoutingMethod: 'Weighted'\n    endpoints: [\n      { name: 'blue', weight: 100, target: blueApp.properties.defaultHostName }\n      { name: 'green', weight: 0, target: greenApp.properties.defaultHostName }  // Ready for cutover\n    ]\n  }\n}\n\n// Resource locks to prevent accidental changes\nresource productionLock 'Microsoft.Authorization/locks@2020-05-01' = {\n  scope: appService\n  name: 'production-lock'\n  properties: {\n    level: 'CanNotDelete'  // Requires change ticket to modify\n    notes: 'Production resource - requires change management approval'\n  }\n}\n```\nSource: Azure CAF - Change management (https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/development-strategy-development-lifecycle)"
            ))
        elif has_change_tags or has_deployment_slots:
            line_num = self.get_line_number(code, "changeTicket") or self.get_line_number(code, "slots")
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
        has_acr = bool(re.search(r"Microsoft\.ContainerRegistry/registries", code))
        
        if has_acr:
            # Check for trusted image policies
            has_trust_policy = bool(re.search(r"trustPolicy.*status.*enabled", code, re.IGNORECASE | re.DOTALL))
            
            # Check for quarantine policy
            has_quarantine = bool(re.search(r"quarantinePolicy.*status.*enabled", code, re.IGNORECASE | re.DOTALL))
            
            # Check for content trust / image signing (Notation/Cosign)
            has_content_trust = bool(re.search(r"(policies.*trust|contentTrust|notation|cosign)", code, re.IGNORECASE | re.DOTALL))
            
            # Check for private endpoints (supply chain security)
            has_private_endpoint = bool(re.search(r"(privateEndpoint|publicNetworkAccess.*Disabled)", code, re.DOTALL))
            
            issues = []
            if not has_trust_policy and not has_content_trust:
                issues.append("No image signing/trust policy configured")
            if not has_quarantine:
                issues.append("No quarantine policy for untrusted images")
            if not has_private_endpoint:
                issues.append("Registry exposed to public network")
            
            if issues:
                line_num = self.get_line_number(code, "Microsoft.ContainerRegistry/registries")
                self.add_finding(Finding(
                    requirement_id="KSI-TPR-03",
                    severity=Severity.HIGH,
                    title="Container registry missing supply chain security controls",
                    description=f"ACR security issues: {'; '.join(issues)}. FedRAMP 20x requires supply chain risk mitigation.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement ACR supply chain security:\n```bicep\nresource acr 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {\n  name: 'acr${uniqueString(resourceGroup().id)}'\n  location: location\n  sku: {\n    name: 'Premium'  // Required for trust policies\n  }\n  properties: {\n    publicNetworkAccess: 'Disabled'  // Private endpoints only\n    networkRuleBypassOptions: 'AzureServices'\n    policies: {\n      quarantinePolicy: {\n        status: 'enabled'  // Quarantine unscanned images\n      }\n      trustPolicy: {\n        type: 'Notary'  // Content trust / image signing\n        status: 'enabled'\n      }\n      retentionPolicy: {\n        days: 30\n        status: 'enabled'  // Automatic cleanup of untagged images\n      }\n    }\n  }\n}\n\n// Private endpoint for secure access\nresource acrPrivateEndpoint 'Microsoft.Network/privateEndpoints@2022-07-01' = {\n  name: 'pe-acr'\n  location: location\n  properties: {\n    subnet: {\n      id: subnet.id\n    }\n    privateLinkServiceConnections: [\n      {\n        name: 'acr-connection'\n        properties: {\n          privateLinkServiceId: acr.id\n          groupIds: ['registry']\n        }\n      }\n    ]\n  }\n}\n```\nSource: ACR security best practices (https://learn.microsoft.com/azure/container-registry/container-registry-best-practices)"
                ))
            else:
                line_num = self.get_line_number(code, "Microsoft.ContainerRegistry/registries")
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
        
        # Check for managed cluster (AKS) with supply chain security
        if re.search(r"Microsoft\.ContainerService/managedClusters", code):
            # Check for image cleaner (remove vulnerable images)
            has_image_cleaner = bool(re.search(r"imageCleanerEnabled.*true", code))
            
            # Check for workload identity (secure pod identity)
            has_workload_identity = bool(re.search(r"workloadIdentity.*enabled.*true", code, re.IGNORECASE | re.DOTALL))
            
            # Check for Azure Policy addon (enforce trusted registries)
            has_policy_addon = bool(re.search(r"azurePolicyEnabled.*true", code))
            
            if not has_policy_addon:
                line_num = self.get_line_number(code, "Microsoft.ContainerService/managedClusters")
                self.add_finding(Finding(
                    requirement_id="KSI-TPR-03",
                    severity=Severity.MEDIUM,
                    title="AKS cluster missing Azure Policy addon for supply chain enforcement",
                    description="Azure Policy addon can enforce trusted container registries and image policies. FedRAMP 20x requires supply chain risk controls.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Enable Azure Policy addon:\n```bicep\nresource aks 'Microsoft.ContainerService/managedClusters@2023-05-01' = {\n  properties: {\n    addonProfiles: {\n      azurepolicy: {\n        enabled: true  // Enforce trusted registries\n        config: {\n          version: 'v2'\n        }\n      }\n    }\n    securityProfile: {\n      workloadIdentity: {\n        enabled: true  // Secure pod identity\n      }\n      imageCleaner: {\n        enabled: true  // Remove vulnerable images\n        intervalHours: 24\n      }\n    }\n  }\n}\n```\nSource: AKS security (https://learn.microsoft.com/azure/aks/use-azure-policy)"
                ))
    
    def _check_third_party_monitoring(self, code: str, file_path: str) -> None:
        """Check for third-party software monitoring (KSI-TPR-04)."""
        # Check for Defender for DevOps (dependency scanning)
        has_defender_devops = bool(re.search(r"Microsoft\.Security", code))
        
        # Check for automation accounts with vulnerability monitoring runbooks
        has_vuln_monitoring = bool(re.search(r"Microsoft\.Automation", code))
        
        # Check for Log Analytics workspace (for security alerts)
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        
        # Check for Application Insights (runtime monitoring)
        has_app_insights = bool(re.search(r"Microsoft\.Insights/(components|workbooks)", code))
        
        # Check for diagnostic settings sending to SIEM
        has_diagnostics = bool(re.search(r"Microsoft\.Insights/diagnosticSettings", code))
        
        # Has security monitoring if: (LogAnalytics AND diagnostics) OR (Defender OR Automation)
        has_security_monitoring = (has_log_analytics and has_diagnostics) or has_defender_devops or has_vuln_monitoring
        
        if not has_security_monitoring:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-TPR-04",
                severity=Severity.MEDIUM,
                title="Third-party software monitoring not configured",
                description="No automated monitoring for third-party dependencies, vulnerabilities, or security advisories. FedRAMP 20x requires continuous monitoring of third-party information resources.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement third-party monitoring:\n```bicep\n// Log Analytics workspace for security monitoring\nresource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n  name: 'law-security'\n  location: location\n  properties: {\n    sku: {\n      name: 'PerGB2018'\n    }\n    retentionInDays: 90\n  }\n}\n\n// Defender for Cloud (includes dependency scanning)\nresource defenderPricing 'Microsoft.Security/pricings@2023-01-01' = {\n  name: 'VirtualMachines'\n  properties: {\n    pricingTier: 'Standard'  // Enable Defender for Cloud\n  }\n}\n\n// Automation account for vulnerability monitoring\nresource automationAccount 'Microsoft.Automation/automationAccounts@2022-08-08' = {\n  name: 'aa-vuln-monitoring'\n  location: location\n  properties: {\n    sku: {\n      name: 'Basic'\n    }\n  }\n}\n\n// Runbook to check third-party advisories\nresource vulnerabilityMonitoringRunbook 'Microsoft.Automation/automationAccounts/runbooks@2022-08-08' = {\n  parent: automationAccount\n  name: 'Check-ThirdPartyAdvisories'\n  location: location\n  properties: {\n    runbookType: 'PowerShell'\n    logProgress: true\n    logVerbose: true\n    description: 'Monitor third-party software for security advisories (NVD, vendor feeds)'\n    publishContentLink: {\n      uri: 'https://raw.githubusercontent.com/example/runbook.ps1'\n    }\n  }\n}\n\n// Schedule daily vulnerability checks\nresource schedule 'Microsoft.Automation/automationAccounts/schedules@2022-08-08' = {\n  parent: automationAccount\n  name: 'Daily-Vuln-Check'\n  properties: {\n    frequency: 'Day'\n    interval: 1\n    startTime: '2024-01-01T02:00:00Z'\n    timeZone: 'UTC'\n  }\n}\n```\nNote: Use GitHub Advanced Security, Dependabot, or Snyk in CI/CD pipelines for comprehensive dependency scanning.\nSource: Defender for DevOps (https://learn.microsoft.com/azure/defender-for-cloud/defender-for-devops-introduction)"
            ))
        else:
            line_num = self.get_line_number(code, "Microsoft.Security") or self.get_line_number(code, "Microsoft.Automation")
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


