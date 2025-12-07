"""
KSI-MLA-01: Security Information and Event Management (SIEM)

Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistent logging of events, activities, and changes.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_MLA_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-MLA-01: Security Information and Event Management (SIEM)
    
    **Official Statement:**
    Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistent logging of events, activities, and changes.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-17.1
    - ac-20.1
    - au-2
    - au-3
    - au-3.1
    - au-4
    - au-5
    - au-6.1
    - au-6.3
    - au-7
    - au-7.1
    - au-8
    - au-9
    - au-11
    - ir-4.1
    - si-4.2
    - si-4.4
    - si-7.7
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tam...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-MLA-01"
    KSI_NAME = "Security Information and Event Management (SIEM)"
    KSI_STATEMENT = """Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistent logging of events, activities, and changes."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging, and Auditing"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-17.1", "ac-20.1", "au-2", "au-3", "au-3.1", "au-4", "au-5", "au-6.1", "au-6.3", "au-7", "au-7.1", "au-8", "au-9", "au-11", "ir-4.1", "si-4.2", "si-4.4", "si-7.7"]
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
        Analyze Python code for KSI-MLA-01 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Local file-based logging without centralized SIEM
        - Missing Azure Monitor/Application Insights integration
        - No tamper-resistant logging configuration
        - Direct logging to files instead of centralized system
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Local file logging without centralized logging (HIGH)
        file_logging_patterns = [
            r'logging\.FileHandler\s*\(',
            r'logging\.basicConfig\s*\([^)]*filename\s*=',
            r'open\s*\([^)]*\.log["\']\s*,\s*["\']w',
        ]
        
        for pattern in file_logging_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                # Check if Azure Monitor/Application Insights is also configured
                has_centralized = re.search(
                    r'(from\s+azure\.monitor|from\s+opencensus\.ext\.azure|applicationinsights|AzureLogHandler)',
                    code
                )
                if not has_centralized:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Local File Logging Without Centralized SIEM",
                        description=(
                            f"Local file-based logging at line {line_num} without centralized SIEM integration. "
                            f"FedRAMP requires tamper-resistant centralized logging for security events. "
                            f"Local files can be modified or deleted by attackers."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Integrate with Azure Monitor/Application Insights:\n"
                            "from opencensus.ext.azure.log_exporter import AzureLogHandler\n"
                            "logger.addHandler(AzureLogHandler(connection_string='...'))\n"
                            "or use Azure SDK for Python with diagnostic settings."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Missing telemetry/monitoring SDK (MEDIUM)
        has_logging = re.search(r'import\s+logging|from\s+logging\s+import', code)
        has_azure_monitor = re.search(
            r'(from\s+azure\.monitor|from\s+opencensus\.ext\.azure|from\s+applicationinsights)',
            code
        )
        
        if has_logging and not has_azure_monitor:
            line_num = self._find_line(lines, r'import\s+logging|from\s+logging')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Centralized Monitoring Integration",
                description=(
                    f"Application uses logging at line {line_num} but lacks Azure Monitor or Application Insights integration. "
                    f"Centralized, tamper-resistant logging is required for audit and security event tracking."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add Azure Monitor/Application Insights:\n"
                    "pip install opencensus-ext-azure\n"
                    "from opencensus.ext.azure.log_exporter import AzureLogHandler\n"
                    "logger.addHandler(AzureLogHandler(connection_string=os.getenv('APPLICATIONINSIGHTS_CONNECTION_STRING')))"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-MLA-01 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - File-based logging without centralized system
        - Missing Application Insights telemetry
        - No Azure Monitor integration
        - Local log storage without tamper protection
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: File logging without centralized SIEM (HIGH)
        file_logging_patterns = [
            r'AddFile\s*\(',
            r'new\s+FileLoggerProvider',
            r'LoggerConfiguration.*WriteTo\.File',
        ]
        
        for pattern in file_logging_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                has_centralized = re.search(
                    r'(ApplicationInsights|AddApplicationInsightsTelemetry|AzureMonitor|TelemetryClient)',
                    code,
                    re.IGNORECASE
                )
                if not has_centralized:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="File Logging Without Centralized SIEM",
                        description=(
                            f"File-based logging at line {line_num} without centralized monitoring. "
                            f"FedRAMP requires tamper-resistant centralized logging. Local files are not tamper-resistant "
                            f"and don't provide the centralized visibility required for security operations."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Add Application Insights:\n"
                            "services.AddApplicationInsightsTelemetry();\n"
                            "Or use Azure Monitor with WorkspaceId and SharedKey configuration. "
                            "Configure diagnostic settings in Azure to send logs to Log Analytics."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Missing Application Insights (MEDIUM)
        has_logging = re.search(
            r'(ILogger|LoggerFactory|AddLogging)',
            code,
            re.IGNORECASE
        )
        has_app_insights = re.search(
            r'(ApplicationInsights|AddApplicationInsightsTelemetry|TelemetryClient)',
            code,
            re.IGNORECASE
        )
        
        if has_logging and not has_app_insights:
            line_num = self._find_line(lines, r'ILogger|LoggerFactory')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Application Insights Integration",
                description=(
                    f"Application uses logging at line {line_num} but lacks Application Insights integration. "
                    f"Centralized telemetry is required for security event monitoring and audit compliance."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add Application Insights NuGet package and configure:\n"
                    "services.AddApplicationInsightsTelemetry();\n"
                    "Set APPLICATIONINSIGHTS_CONNECTION_STRING in configuration."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-MLA-01 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Local file appenders (Log4j/Logback) without centralized logging
        - Missing Azure Monitor/Application Insights integration
        - No Micrometer or telemetry SDK configured
        - Direct file system logging without SIEM
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: File appenders without centralized SIEM (HIGH)
        file_appender_patterns = [
            r'FileAppender',
            r'RollingFileAppender',
            r'<appender.*class=".*FileAppender',
        ]
        
        for pattern in file_appender_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                has_centralized = re.search(
                    r'(com\.microsoft\.azure.*applicationinsights|azure.*monitor|micrometer.*azure)',
                    code
                )
                if not has_centralized:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="File Appender Without Centralized SIEM",
                        description=(
                            f"File-based logging appender at line {line_num} without centralized monitoring. "
                            f"FedRAMP requires tamper-resistant centralized logging for security events. "
                            f"File-based logs can be tampered with or deleted."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Add Azure Application Insights:\n"
                            "<dependency>\n"
                            "  <groupId>com.microsoft.azure</groupId>\n"
                            "  <artifactId>applicationinsights-spring-boot-starter</artifactId>\n"
                            "</dependency>\n"
                            "Configure connection string in application.properties."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Missing centralized telemetry (MEDIUM)
        has_logging = re.search(
            r'(import.*slf4j|import.*log4j|import.*logback|@Slf4j)',
            code
        )
        has_azure_monitor = re.search(
            r'(com\.microsoft\.azure.*applicationinsights|micrometer.*azure)',
            code
        )
        
        if has_logging and not has_azure_monitor:
            line_num = self._find_line(lines, r'import.*slf4j|import.*log4j|@Slf4j')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Centralized Telemetry Integration",
                description=(
                    f"Application uses logging at line {line_num} but lacks Azure Monitor/Application Insights. "
                    f"Centralized, tamper-resistant logging is required for security monitoring and audit trails."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add Application Insights dependency and configure:\n"
                    "<dependency>\n"
                    "  <groupId>com.microsoft.azure</groupId>\n"
                    "  <artifactId>applicationinsights-spring-boot-starter</artifactId>\n"
                    "</dependency>\n"
                    "Set APPLICATIONINSIGHTS_CONNECTION_STRING environment variable."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-MLA-01 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Console.log without centralized monitoring
        - File transport logging without SIEM integration
        - Missing Application Insights SDK
        - Local logging without tamper protection
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: File transport logging (HIGH)
        file_transport_patterns = [
            r'winston\..*File',
            r'new\s+transports\.File',
            r'createWriteStream.*\.log',
        ]
        
        for pattern in file_transport_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                has_centralized = re.search(
                    r'(applicationinsights|@azure/monitor|@opentelemetry)',
                    code
                )
                if not has_centralized:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="File Transport Logging Without Centralized SIEM",
                        description=(
                            f"File-based log transport at line {line_num} without centralized monitoring. "
                            f"FedRAMP requires tamper-resistant centralized logging. File logs can be "
                            f"modified or deleted, compromising audit integrity."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Integrate Application Insights:\n"
                            "npm install applicationinsights\n"
                            "const appInsights = require('applicationinsights');\n"
                            "appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING).start();\n"
                            "Use appInsights.defaultClient.trackTrace() for logging."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Console logging in production code (MEDIUM)
        # Only flag if no centralized monitoring detected
        has_console_log = re.search(r'console\.(log|info|warn|error)', code)
        has_app_insights = re.search(
            r'(applicationinsights|@azure/monitor|@opentelemetry)',
            code
        )
        
        if has_console_log and not has_app_insights:
            line_num = self._find_line(lines, r'console\.(log|info|warn|error)')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Console Logging Without Centralized Monitoring",
                description=(
                    f"Console logging at line {line_num} without Application Insights or centralized monitoring. "
                    f"Console logs are ephemeral and not suitable for security event tracking or audit compliance."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add Application Insights:\n"
                    "npm install applicationinsights\n"
                    "Setup in your entry point:\n"
                    "import * as appInsights from 'applicationinsights';\n"
                    "appInsights.setup().start();"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-MLA-01 compliance.
        
        Detects:
        - Missing Log Analytics workspace
        - Resources without diagnostic settings
        - No centralized logging infrastructure
        - Missing Azure Monitor configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: No Log Analytics workspace (CRITICAL)
        has_log_analytics = re.search(
            r"resource.*'Microsoft\.OperationalInsights/workspaces",
            code
        )
        has_resources = re.search(r"resource\s+\w+\s+'Microsoft\.", code)
        
        if has_resources and not has_log_analytics:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Missing Log Analytics Workspace for Centralized Logging",
                description=(
                    "Infrastructure deploys Azure resources without a Log Analytics workspace. "
                    f"FedRAMP requires centralized, tamper-resistant logging via Azure Monitor and Log Analytics. "
                    f"All security events, activities, and changes must be logged to a SIEM."
                ),
                file_path=file_path,
                line_number=1,
                snippet="No Log Analytics workspace found in Bicep template",
                remediation=(
                    "Deploy Log Analytics workspace:\n"
                    "resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {\n"
                    "  name: 'law-${uniqueString(resourceGroup().id)}'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    retentionInDays: 90\n"
                    "    sku: {\n"
                    "      name: 'PerGB2018'\n"
                    "    }\n"
                    "  }\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Resources without diagnostic settings (HIGH)
        # Check for common Azure resources that should have diagnostics
        resource_types = [
            "Microsoft.Web/sites",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.KeyVault/vaults",
            "Microsoft.Sql/servers",
            "Microsoft.Network/applicationGateways",
        ]
        
        for resource_type in resource_types:
            resource_match = re.search(rf"resource\s+\w+\s+'{resource_type}", code)
            if resource_match:
                # Check if there's a corresponding diagnostic setting
                has_diagnostics = re.search(
                    r"resource.*'Microsoft\.Insights/diagnosticSettings",
                    code
                )
                if not has_diagnostics:
                    line_num = code[:resource_match.start()].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Resource Missing Diagnostic Settings",
                        description=(
                            f"{resource_type} at line {line_num} without diagnostic settings. "
                            f"All Azure resources must send logs to Log Analytics for centralized "
                            f"monitoring and security event correlation."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            f"Add diagnostic settings for {resource_type}:\n"
                            "resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                            "  name: 'diag-${resourceName}'\n"
                            "  scope: resourceReference\n"
                            "  properties: {\n"
                            "    workspaceId: logAnalytics.id\n"
                            "    logs: [...]\n"
                            "    metrics: [...]\n"
                            "  }\n"
                            "}"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Only report once
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-MLA-01 compliance.
        
        Detects:
        - Missing azurerm_log_analytics_workspace
        - Resources without azurerm_monitor_diagnostic_setting
        - No centralized logging configuration
        - Missing Azure Monitor integration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: No Log Analytics workspace (CRITICAL)
        has_log_analytics = re.search(
            r'resource\s+"azurerm_log_analytics_workspace"',
            code
        )
        has_azure_resources = re.search(r'resource\s+"azurerm_', code)
        
        if has_azure_resources and not has_log_analytics:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Missing Log Analytics Workspace for Centralized Logging",
                description=(
                    "Terraform configuration deploys Azure resources without Log Analytics workspace. "
                    f"FedRAMP requires centralized, tamper-resistant logging via Azure Monitor. "
                    f"All security events and changes must be logged to a SIEM system."
                ),
                file_path=file_path,
                line_number=1,
                snippet="No azurerm_log_analytics_workspace found in configuration",
                remediation=(
                    "Add Log Analytics workspace:\n"
                    "resource \"azurerm_log_analytics_workspace\" \"siem\" {\n"
                    "  name                = \"law-${var.project}-${var.environment}\"\n"
                    "  location            = azurerm_resource_group.main.location\n"
                    "  resource_group_name = azurerm_resource_group.main.name\n"
                    "  sku                 = \"PerGB2018\"\n"
                    "  retention_in_days   = 90\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Resources without diagnostic settings (HIGH)
        resource_types = [
            "azurerm_app_service",
            "azurerm_storage_account",
            "azurerm_key_vault",
            "azurerm_sql_server",
            "azurerm_application_gateway",
        ]
        
        for resource_type in resource_types:
            resource_match = re.search(rf'resource\s+"{resource_type}"', code)
            if resource_match:
                has_diagnostics = re.search(
                    r'resource\s+"azurerm_monitor_diagnostic_setting"',
                    code
                )
                if not has_diagnostics:
                    line_num = code[:resource_match.start()].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"Azure Resource Missing Diagnostic Settings",
                        description=(
                            f"{resource_type} at line {line_num} without diagnostic settings. "
                            f"All Azure resources must send logs to Log Analytics for centralized "
                            f"security monitoring and audit trail compliance."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            f"Add diagnostic settings:\n"
                            "resource \"azurerm_monitor_diagnostic_setting\" \"example\" {\n"
                            "  name                       = \"diag-${resource_name}\"\n"
                            "  target_resource_id         = azurerm_resource.example.id\n"
                            "  log_analytics_workspace_id = azurerm_log_analytics_workspace.siem.id\n"
                            "  enabled_log { category = \"AuditEvent\" }\n"
                            "  metric { category = \"AllMetrics\" }\n"
                            "}"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Only report once
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-MLA-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-MLA-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-MLA-01 compliance.
        
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
