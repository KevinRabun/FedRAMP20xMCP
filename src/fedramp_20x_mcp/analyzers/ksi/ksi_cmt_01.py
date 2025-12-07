"""
KSI-CMT-01: Log and Monitor Changes

Log and monitor modifications to the cloud service offering.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CMT_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CMT-01: Log and Monitor Changes
    
    **Official Statement:**
    Log and monitor modifications to the cloud service offering.
    
    **Family:** CMT - Change Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - au-2
    - cm-3
    - cm-3.2
    - cm-4.2
    - cm-6
    - cm-8.3
    - ma-2
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Log and monitor modifications to the cloud service offering....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CMT-01"
    KSI_NAME = "Log and Monitor Changes"
    KSI_STATEMENT = """Log and monitor modifications to the cloud service offering."""
    FAMILY = "CMT"
    FAMILY_NAME = "Change Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["au-2", "cm-3", "cm-3.2", "cm-4.2", "cm-6", "cm-8.3", "ma-2"]
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
        Analyze Python code for KSI-CMT-01 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Log and monitor modifications to the cloud service offering....
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
        Analyze C# code for KSI-CMT-01 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Log and monitor modifications to the cloud service offering....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CMT-01 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Log and monitor modifications to the cloud service offering....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CMT-01 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Log and monitor modifications to the cloud service offering....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CMT-01 compliance.
        
        Detects:
        - Missing Activity Log diagnostic settings (for change monitoring)
        - Missing Activity Log alert rules
        - Resources without change tracking (diagnostic settings)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing Activity Log diagnostic settings (HIGH)
        # Check if subscription-level activity log diagnostics exist
        has_activity_log = any(re.search(r"Microsoft\.Insights/diagnosticSettings.*activityLog", line, re.IGNORECASE) 
                             for line in lines)
        
        if not has_activity_log and len(lines) > 30:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Activity Log Diagnostic Settings for Change Monitoring",
                description=(
                    "Infrastructure code does not configure Activity Log diagnostic settings. "
                    "KSI-CMT-01 requires logging and monitoring all modifications to cloud services (AU-2, CM-3). "
                    "Azure Activity Log captures all control plane operations (resource create/update/delete, "
                    "configuration changes, role assignments) and must be sent to Log Analytics "
                    "for long-term retention and monitoring. Without Activity Log diagnostics, "
                    "infrastructure changes cannot be audited or monitored as required by CM-3.2, CM-4.2."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Configure Activity Log diagnostic settings (subscription-level change monitoring):\n"
                    "// 1. Create Log Analytics Workspace for change logs\n"
                    "resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n"
                    "  name: 'change-monitoring-workspace'\n"
                    "  location: resourceGroup().location\n"
                    "  properties: {\n"
                    "    retentionInDays: 730  // 2-year retention for FedRAMP\n"
                    "    sku: {\n"
                    "      name: 'PerGB2018'\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "// 2. Enable Activity Log diagnostics (capture ALL changes)\n"
                    "resource activityLogDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                    "  name: 'activity-log-diagnostics'\n"
                    "  scope: subscription()\n"
                    "  properties: {\n"
                    "    workspaceId: logAnalytics.id\n"
                    "    // Log all administrative operations (CM-3: change management)\n"
                    "    logs: [\n"
                    "      {\n"
                    "        category: 'Administrative'  // Resource changes\n"
                    "        enabled: true\n"
                    "      }\n"
                    "      {\n"
                    "        category: 'Security'  // Security-related changes\n"
                    "        enabled: true\n"
                    "      }\n"
                    "      {\n"
                    "        category: 'Policy'  // Policy assignments\n"
                    "        enabled: true\n"
                    "      }\n"
                    "      {\n"
                    "        category: 'ResourceHealth'  // Service health changes\n"
                    "        enabled: true\n"
                    "      }\n"
                    "    ]\n"
                    "  }\n"
                    "}\n\n"
                    "// 3. Create alert for critical changes (CM-4.2: change notifications)\n"
                    "resource criticalChangeAlert 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {\n"
                    "  name: 'critical-infrastructure-changes'\n"
                    "  location: 'global'\n"
                    "  properties: {\n"
                    "    scopes: [\n"
                    "      subscription().id\n"
                    "    ]\n"
                    "    condition: {\n"
                    "      allOf: [\n"
                    "        {\n"
                    "          field: 'category'\n"
                    "          equals: 'Administrative'\n"
                    "        }\n"
                    "        {\n"
                    "          field: 'operationName'\n"
                    "          // Alert on critical operations\n"
                    "          equals: 'Microsoft.Resources/deployments/write'\n"
                    "        }\n"
                    "      ]\n"
                    "    }\n"
                    "    actions: {\n"
                    "      actionGroups: [\n"
                    "        {\n"
                    "          actionGroupId: actionGroup.id\n"
                    "        }\n"
                    "      ]\n"
                    "    }\n"
                    "    enabled: true\n"
                    "  }\n"
                    "}\n\n"
                    "// 4. Action Group for change notifications\n"
                    "resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {\n"
                    "  name: 'change-management-alerts'\n"
                    "  location: 'global'\n"
                    "  properties: {\n"
                    "    enabled: true\n"
                    "    groupShortName: 'ChangeAlerts'\n"
                    "    emailReceivers: [\n"
                    "      {\n"
                    "        name: 'SecurityTeam'\n"
                    "        emailAddress: 'security@example.com'\n"
                    "      }\n"
                    "    ]\n"
                    "  }\n"
                    "}\n\n"
                    "What this provides:\n"
                    "- Comprehensive logging of ALL infrastructure changes (AU-2)\n"
                    "- Change monitoring and alerting (CM-3, CM-3.2)\n"
                    "- Automated notifications for critical changes (CM-4.2)\n"
                    "- 2-year retention for audit compliance (CM-6)\n\n"
                    "Ref: Activity Log diagnostic settings (https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Critical resources without diagnostic settings (MEDIUM)
        # Check for resources that should have diagnostics but don't
        critical_resources = [
            (r"Microsoft\.Storage/storageAccounts", "Storage Account"),
            (r"Microsoft\.Sql/servers/databases", "SQL Database"),
            (r"Microsoft\.KeyVault/vaults", "Key Vault"),
            (r"Microsoft\.Network/applicationGateways", "Application Gateway")
        ]
        
        for resource_pattern, resource_name in critical_resources:
            resource_match = self._find_line(lines, resource_pattern)
            
            if resource_match:
                line_num = resource_match['line_num']
                # Check if diagnostic settings exist for this resource
                # Look for diagnosticSettings within ~40 lines
                check_end = min(len(lines), line_num + 40)
                has_diagnostics = any(
                    re.search(r"Microsoft\.Insights/diagnosticSettings", lines[i], re.IGNORECASE)
                    for i in range(line_num, check_end)
                )
                
                if not has_diagnostics:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"{resource_name} Without Change Tracking (Diagnostic Settings)",
                        description=(
                            f"{resource_name} deployed without diagnostic settings for change tracking. "
                            "KSI-CMT-01 requires logging and monitoring modifications (AU-2, CM-6). "
                            "Diagnostic settings capture resource-level configuration changes, "
                            "access logs, and operational metrics essential for change management. "
                            "Without diagnostics, changes to this resource cannot be audited "
                            "or monitored as required by CM-8.3 (configuration inventory)."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            f"Add diagnostic settings to {resource_name} for change tracking:\n"
                            f"// Example: {resource_name} with diagnostics\n"
                            "resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                            "  scope: <resource>  // Reference your resource here\n"
                            "  name: '\${<resource>.name}-diagnostics'\n"
                            "  properties: {\n"
                            "    workspaceId: logAnalyticsWorkspace.id\n"
                            "    // Capture all logs for change monitoring\n"
                            "    logs: [\n"
                            "      {\n"
                            "        category: 'AuditEvent'  // Configuration changes\n"
                            "        enabled: true\n"
                            "      }\n"
                            "    ]\n"
                            "    metrics: [\n"
                            "      {\n"
                            "        category: 'AllMetrics'\n"
                            "        enabled: true\n"
                            "      }\n"
                            "    ]\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: Diagnostic settings (https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings)\n"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CMT-01 compliance.
        
        Detects:
        - Missing Activity Log diagnostic settings
        - Missing monitor diagnostic settings for critical resources
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing Activity Log diagnostic settings (HIGH)
        has_activity_log = any(re.search(r'azurerm_monitor_diagnostic_setting.*activity.*log|azurerm_monitor_log_profile', line, re.IGNORECASE) 
                             for line in lines)
        
        if not has_activity_log and len(lines) > 30:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Activity Log Diagnostic Settings for Change Monitoring",
                description=(
                    "Infrastructure code does not configure Activity Log diagnostic settings. "
                    "KSI-CMT-01 requires logging and monitoring all modifications (AU-2, CM-3). "
                    "Activity Log captures all control plane operations (resource changes, "
                    "configuration modifications, role assignments) essential for change management. "
                    "Without Activity Log diagnostics, infrastructure changes cannot be audited "
                    "as required by CM-3.2, CM-4.2, MA-2."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Configure Activity Log diagnostic settings (subscription-level change monitoring):\n"
                    "# 1. Create Log Analytics Workspace\n"
                    "resource \"azurerm_log_analytics_workspace\" \"change_monitoring\" {\n"
                    "  name                = \"change-monitoring-workspace\"\n"
                    "  location            = azurerm_resource_group.example.location\n"
                    "  resource_group_name = azurerm_resource_group.example.name\n"
                    "  sku                 = \"PerGB2018\"\n"
                    "  retention_in_days   = 730  # 2-year retention for FedRAMP\n"
                    "}\n\n"
                    "# 2. Enable Activity Log diagnostics (capture ALL changes)\n"
                    "resource \"azurerm_monitor_diagnostic_setting\" \"activity_log\" {\n"
                    "  name               = \"activity-log-diagnostics\"\n"
                    "  target_resource_id = data.azurerm_subscription.current.id\n"
                    "  log_analytics_workspace_id = azurerm_log_analytics_workspace.change_monitoring.id\n\n"
                    "  # Log all administrative operations (CM-3: change management)\n"
                    "  enabled_log {\n"
                    "    category = \"Administrative\"  # Resource changes\n"
                    "  }\n\n"
                    "  enabled_log {\n"
                    "    category = \"Security\"  # Security-related changes\n"
                    "  }\n\n"
                    "  enabled_log {\n"
                    "    category = \"Policy\"  # Policy assignments\n"
                    "  }\n\n"
                    "  enabled_log {\n"
                    "    category = \"ResourceHealth\"  # Service health changes\n"
                    "  }\n"
                    "}\n\n"
                    "# 3. Create alert for critical changes (CM-4.2: notifications)\n"
                    "resource \"azurerm_monitor_activity_log_alert\" \"critical_changes\" {\n"
                    "  name                = \"critical-infrastructure-changes\"\n"
                    "  resource_group_name = azurerm_resource_group.example.name\n"
                    "  scopes              = [data.azurerm_subscription.current.id]\n\n"
                    "  criteria {\n"
                    "    category       = \"Administrative\"\n"
                    "    operation_name = \"Microsoft.Resources/deployments/write\"\n"
                    "  }\n\n"
                    "  action {\n"
                    "    action_group_id = azurerm_monitor_action_group.change_alerts.id\n"
                    "  }\n"
                    "}\n\n"
                    "# 4. Action Group for notifications\n"
                    "resource \"azurerm_monitor_action_group\" \"change_alerts\" {\n"
                    "  name                = \"change-management-alerts\"\n"
                    "  resource_group_name = azurerm_resource_group.example.name\n"
                    "  short_name          = \"ChangeAlert\"\n\n"
                    "  email_receiver {\n"
                    "    name          = \"SecurityTeam\"\n"
                    "    email_address = \"security@example.com\"\n"
                    "  }\n"
                    "}\n\n"
                    "What this provides:\n"
                    "- Comprehensive logging of ALL infrastructure changes (AU-2)\n"
                    "- Change monitoring and alerting (CM-3, CM-3.2)\n"
                    "- Automated notifications (CM-4.2)\n"
                    "- 2-year audit retention (CM-6)\n\n"
                    "Ref: azurerm_monitor_diagnostic_setting (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CMT-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CMT-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CMT-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> Optional[Dict[str, Any]]:
        """
        Find first line matching regex pattern.
        Returns dict with line_num and line content, or None if not found.
        """
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.IGNORECASE):
                return {'line_num': i, 'line': line}
        return None
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
