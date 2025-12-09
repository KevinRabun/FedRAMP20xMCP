"""
KSI-MLA-01: Security Information and Event Management (SIEM)

Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, 
tamper-resistant logging of events, activities, and changes.

**Enhancement Features:**
- AST-based code parsing with tree-sitter for accurate detection
- Multi-language support (Python, C#, Java, TypeScript, Bicep, Terraform)
- Expanded context windows (±15 lines) for centralized logging detection
- Differentiation between local file logging and centralized SIEM integration
- Detection of missing diagnostic settings in IaC
- Framework-specific integration checks (Application Insights, Azure Monitor, Log Analytics)

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer

try:
    import tree_sitter_python as tspython
    import tree_sitter_c_sharp as tscsharp
    import tree_sitter_java as tsjava
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser, Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


class KSI_MLA_01_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-MLA-01: Security Information and Event Management (SIEM)
    
    **Official Statement:**
    Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, 
    tamper-resistant logging of events, activities, and changes.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-17.1, ac-20.1, au-2, au-3, au-3.1, au-4, au-5, au-6.1, au-6.3, au-7, au-7.1, au-8, au-9, au-11, 
      ir-4.1, si-4.2, si-4.4, si-7.7
    
    **Detectability:** Code-Detectable (Enhanced AST-based detection)
    
    **Detection Strategy:**
    Uses AST parsing to detect:
    1. Local file-based logging without centralized SIEM integration
    2. Missing Azure Monitor/Application Insights/Log Analytics configuration
    3. Resources without diagnostic settings in IaC templates
    4. Console/ephemeral logging without persistent centralized storage
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript (AST-based)
    - IaC: Bicep, Terraform (pattern-based)
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI (pattern-based)
    """
    
    KSI_ID = "KSI-MLA-01"
    KSI_NAME = "Security Information and Event Management (SIEM)"
    KSI_STATEMENT = """Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistant logging of events, activities, and changes."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging, and Auditing"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-17.1", "Monitoring and Control"),
        ("ac-20.1", "Limits on Authorized Use"),
        ("au-2", "Event Logging"),
        ("au-3", "Content of Audit Records"),
        ("au-3.1", "Additional Audit Information"),
        ("au-4", "Audit Log Storage Capacity"),
        ("au-5", "Response to Audit Logging Process Failures"),
        ("au-6.1", "Automated Process Integration"),
        ("au-6.3", "Correlate Audit Record Repositories"),
        ("au-7", "Audit Record Reduction and Report Generation"),
        ("au-7.1", "Automatic Processing"),
        ("au-8", "Time Stamps"),
        ("au-9", "Protection of Audit Information"),
        ("au-11", "Audit Record Retention"),
        ("ir-4.1", "Automated Incident Handling Processes"),
        ("si-4.2", "Automated Tools and Mechanisms for Real-time Analysis"),
        ("si-4.4", "Inbound and Outbound Communications Traffic"),
        ("si-7.7", "Integration of Detection and Response")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
        
        # Initialize tree-sitter parsers
        if TREE_SITTER_AVAILABLE:
            self.python_parser = Parser(Language(tspython.language()))
            self.csharp_parser = Parser(Language(tscsharp.language()))
            self.java_parser = Parser(Language(tsjava.language()))
            self.js_parser = Parser(Language(tsjs.language()))
        else:
            self.python_parser = None
            self.csharp_parser = None
            self.java_parser = None
            self.js_parser = None
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS (AST-BASED)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-MLA-01 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Local file-based logging (logging.FileHandler, basicConfig with filename)
        - Missing Azure Monitor/Application Insights integration
        - Console logging without centralized SIEM
        - Direct file writes for logging
        """
        findings = []
        lines = code.split('\n')
        
        if not self.python_parser:
            return self._analyze_python_fallback(code, file_path)
        
        tree = self.python_parser.parse(bytes(code, "utf8"))
        root_node = tree.root_node
        
        # Check for centralized logging integration (file-wide check)
        has_azure_monitor = self._check_for_centralized_logging_python(code)
        
        # Pattern 1: Detect logging.FileHandler() calls (HIGH severity if no centralized logging)
        file_handler_nodes = self._find_call_expressions(root_node, ["FileHandler"])
        for node in file_handler_nodes:
            line_num = node.start_point[0] + 1
            context = self._get_context_lines(lines, line_num, 15)
            
            # Check if Azure Monitor is configured in nearby context
            has_azure_in_context = re.search(
                r'(AzureLogHandler|azure\.monitor|opencensus\.ext\.azure|applicationinsights)',
                context,
                re.IGNORECASE
            )
            
            if not has_azure_monitor and not has_azure_in_context:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Local File Logging Without Centralized SIEM",
                    description=(
                        f"Local file-based logging (logging.FileHandler) at line {line_num} without "
                        f"centralized SIEM integration. FedRAMP requires tamper-resistant centralized "
                        f"logging for security events. Local files can be modified or deleted by attackers."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Integrate with Azure Monitor/Application Insights:\n"
                        "from opencensus.ext.azure.log_exporter import AzureLogHandler\n"
                        "logger.addHandler(AzureLogHandler(connection_string=os.getenv('APPLICATIONINSIGHTS_CONNECTION_STRING')))\n\n"
                        "Or use Azure SDK for Python with diagnostic settings:\n"
                        "pip install opencensus-ext-azure"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Detect logging.basicConfig with filename parameter (HIGH)
        basic_config_nodes = self._find_call_expressions(root_node, ["basicConfig"])
        for node in basic_config_nodes:
            line_num = node.start_point[0] + 1
            node_text = node.text.decode('utf8')
            
            if 'filename' in node_text:
                context = self._get_context_lines(lines, line_num, 15)
                has_azure_in_context = re.search(
                    r'(AzureLogHandler|azure\.monitor|opencensus\.ext\.azure)',
                    context,
                    re.IGNORECASE
                )
                
                if not has_azure_monitor and not has_azure_in_context:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="basicConfig File Logging Without Centralized SIEM",
                        description=(
                            f"logging.basicConfig with filename parameter at line {line_num} creates "
                            f"local file logging without centralized SIEM. FedRAMP requires tamper-resistant "
                            f"centralized logging system."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Replace local file logging with Azure Monitor:\n"
                            "from opencensus.ext.azure.log_exporter import AzureLogHandler\n"
                            "import logging\n"
                            "logger = logging.getLogger(__name__)\n"
                            "logger.addHandler(AzureLogHandler(connection_string='...'))"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 3: Detect open(..., 'w') for .log files (HIGH)
        open_call_nodes = self._find_call_expressions(root_node, ["open"])
        for node in open_call_nodes:
            line_num = node.start_point[0] + 1
            node_text = node.text.decode('utf8')
            
            # Check if opening a .log file for writing
            if re.search(r'\.log["\'].*["\'][wW]', node_text):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Direct File Write for Logging Without SIEM",
                    description=(
                        f"Direct file write to .log file at line {line_num} without centralized SIEM. "
                        f"FedRAMP requires tamper-resistant centralized logging. Manual file writes "
                        f"bypass centralized monitoring and audit controls."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use Azure Monitor for centralized logging:\n"
                        "from opencensus.ext.azure.log_exporter import AzureLogHandler\n"
                        "logger.addHandler(AzureLogHandler(connection_string='...'))\n"
                        "logger.info('Event message')  # Automatically sent to Azure Monitor"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 4: Import logging without Azure Monitor integration (MEDIUM)
        has_logging_import = self._check_for_import(root_node, "logging")
        if has_logging_import and not has_azure_monitor:
            line_num = self._find_import_line(lines, "logging")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Centralized Monitoring Integration",
                description=(
                    f"Application uses logging module at line {line_num} but lacks Azure Monitor or "
                    f"Application Insights integration. Centralized, tamper-resistant logging is "
                    f"required for audit and security event tracking."
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
    
    def _analyze_python_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis when tree-sitter unavailable."""
        findings = []
        lines = code.split('\n')
        
        # Check for centralized logging
        has_azure_monitor = re.search(
            r'(from\s+azure\.monitor|from\s+opencensus\.ext\.azure|applicationinsights|AzureLogHandler)',
            code
        )
        
        # Pattern 1: Local file logging
        file_logging_patterns = [
            r'logging\.FileHandler\s*\(',
            r'logging\.basicConfig\s*\([^)]*filename\s*=',
            r'open\s*\([^)]*\.log["\']\s*,\s*["\']w',
        ]
        
        for pattern in file_logging_patterns:
            match = re.search(pattern, code)
            if match and not has_azure_monitor:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Local File Logging Without Centralized SIEM",
                    description=(
                        f"Local file-based logging at line {line_num} without centralized SIEM integration. "
                        f"FedRAMP requires tamper-resistant centralized logging for security events."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Integrate with Azure Monitor/Application Insights.",
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Missing centralized monitoring
        has_logging = re.search(r'import\s+logging|from\s+logging\s+import', code)
        if has_logging and not has_azure_monitor:
            line_num = code[:has_logging.start()].count('\n') + 1
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Centralized Monitoring Integration",
                description=(
                    f"Application uses logging at line {line_num} but lacks Azure Monitor integration."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation="Add Azure Monitor/Application Insights.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-MLA-01 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - File-based logging (AddFile, FileLoggerProvider, Serilog WriteTo.File)
        - Missing Application Insights telemetry
        - No Azure Monitor integration
        - Local log storage without tamper protection
        """
        findings = []
        lines = code.split('\n')
        
        if not self.csharp_parser:
            return self._analyze_csharp_fallback(code, file_path)
        
        tree = self.csharp_parser.parse(bytes(code, "utf8"))
        root_node = tree.root_node
        
        # Check for centralized logging integration (file-wide)
        has_app_insights = self._check_for_app_insights_csharp(code)
        
        # Pattern 1: Detect AddFile() calls for file logging (HIGH)
        add_file_nodes = self._find_invocation_expressions(root_node, ["AddFile"])
        for node in add_file_nodes:
            line_num = node.start_point[0] + 1
            context = self._get_context_lines(lines, line_num, 15)
            
            # Check for Application Insights in nearby context
            has_ai_in_context = re.search(
                r'(ApplicationInsights|AddApplicationInsightsTelemetry|TelemetryClient|AzureMonitor)',
                context,
                re.IGNORECASE
            )
            
            if not has_app_insights and not has_ai_in_context:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="File Logging Without Centralized SIEM",
                    description=(
                        f"File-based logging (AddFile) at line {line_num} without centralized monitoring. "
                        f"FedRAMP requires tamper-resistant centralized logging. Local files are not "
                        f"tamper-resistant and don't provide the centralized visibility required for "
                        f"security operations."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Add Application Insights:\n"
                        "services.AddApplicationInsightsTelemetry();\n\n"
                        "Or use Azure Monitor with WorkspaceId and SharedKey configuration. "
                        "Configure diagnostic settings in Azure to send logs to Log Analytics."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Detect WriteTo.File() in Serilog configuration (HIGH)
        write_to_file_pattern = r'WriteTo\.File\s*\('
        for match in re.finditer(write_to_file_pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            context = self._get_context_lines(lines, line_num, 15)
            
            has_ai_in_context = re.search(
                r'(ApplicationInsights|AddApplicationInsightsTelemetry|AzureMonitor)',
                context,
                re.IGNORECASE
            )
            
            if not has_app_insights and not has_ai_in_context:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Serilog File Sink Without Centralized SIEM",
                    description=(
                        f"Serilog WriteTo.File at line {line_num} without centralized SIEM integration. "
                        f"FedRAMP requires tamper-resistant centralized logging. File sinks bypass "
                        f"centralized security monitoring."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Replace file sink with Application Insights:\n"
                        "Install-Package Serilog.Sinks.ApplicationInsights\n"
                        "Log.Logger = new LoggerConfiguration()\n"
                        "    .WriteTo.ApplicationInsights(telemetryConfiguration, TelemetryConverter.Traces)\n"
                        "    .CreateLogger();"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Logging usage without Application Insights (MEDIUM)
        has_logging = re.search(
            r'(ILogger|LoggerFactory|AddLogging)',
            code,
            re.IGNORECASE
        )
        
        if has_logging and not has_app_insights:
            line_num = code[:has_logging.start()].count('\n') + 1
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
                    "dotnet add package Microsoft.ApplicationInsights.AspNetCore\n"
                    "services.AddApplicationInsightsTelemetry();\n"
                    "Set APPLICATIONINSIGHTS_CONNECTION_STRING in configuration."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def _analyze_csharp_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis when tree-sitter unavailable."""
        findings = []
        lines = code.split('\n')
        
        # Check for Application Insights
        has_app_insights = re.search(
            r'(ApplicationInsights|AddApplicationInsightsTelemetry|TelemetryClient)',
            code,
            re.IGNORECASE
        )
        
        # Pattern 1: File logging patterns
        file_logging_patterns = [
            r'AddFile\s*\(',
            r'new\s+FileLoggerProvider',
            r'LoggerConfiguration.*WriteTo\.File',
        ]
        
        for pattern in file_logging_patterns:
            match = re.search(pattern, code)
            if match and not has_app_insights:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="File Logging Without Centralized SIEM",
                    description=(
                        f"File-based logging at line {line_num} without centralized monitoring."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Add Application Insights integration.",
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Missing Application Insights
        has_logging = re.search(r'(ILogger|LoggerFactory|AddLogging)', code, re.IGNORECASE)
        if has_logging and not has_app_insights:
            line_num = code[:has_logging.start()].count('\n') + 1
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Application Insights Integration",
                description=(
                    f"Application uses logging at line {line_num} but lacks Application Insights integration."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation="Add Application Insights telemetry.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-MLA-01 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Local file appenders (Log4j/Logback FileAppender, RollingFileAppender)
        - Missing Azure Monitor/Application Insights integration
        - No Micrometer or telemetry SDK configured
        - Direct file system logging without SIEM
        """
        findings = []
        lines = code.split('\n')
        
        if not self.java_parser:
            return self._analyze_java_fallback(code, file_path)
        
        tree = self.java_parser.parse(bytes(code, "utf8"))
        root_node = tree.root_node
        
        # Check for centralized logging integration (file-wide)
        has_azure_monitor = self._check_for_azure_monitor_java(code)
        
        # Pattern 1: Detect FileAppender references (HIGH)
        file_appender_pattern = r'(FileAppender|RollingFileAppender)'
        for match in re.finditer(file_appender_pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            context = self._get_context_lines(lines, line_num, 15)
            
            # Check for Azure Monitor in nearby context
            has_azure_in_context = re.search(
                r'(com\.microsoft\.azure.*applicationinsights|azure.*monitor|micrometer.*azure)',
                context
            )
            
            if not has_azure_monitor and not has_azure_in_context:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="File Appender Without Centralized SIEM",
                    description=(
                        f"File-based logging appender ({match.group(1)}) at line {line_num} without "
                        f"centralized monitoring. FedRAMP requires tamper-resistant centralized logging "
                        f"for security events. File-based logs can be tampered with or deleted."
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
                        "Configure connection string in application.properties:\n"
                        "azure.applicationinsights.connection-string=..."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Logging usage without centralized telemetry (MEDIUM)
        has_logging = re.search(
            r'(import.*slf4j|import.*log4j|import.*logback|@Slf4j)',
            code
        )
        
        if has_logging and not has_azure_monitor:
            line_num = code[:has_logging.start()].count('\n') + 1
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
    
    def _analyze_java_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis when tree-sitter unavailable."""
        findings = []
        lines = code.split('\n')
        
        # Check for Azure Monitor
        has_azure_monitor = re.search(
            r'(com\.microsoft\.azure.*applicationinsights|micrometer.*azure)',
            code
        )
        
        # Pattern 1: File appenders
        file_appender_patterns = [
            r'FileAppender',
            r'RollingFileAppender',
            r'<appender.*class=".*FileAppender',
        ]
        
        for pattern in file_appender_patterns:
            match = re.search(pattern, code)
            if match and not has_azure_monitor:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="File Appender Without Centralized SIEM",
                    description=(
                        f"File-based logging appender at line {line_num} without centralized monitoring."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Add Azure Application Insights integration.",
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Missing centralized telemetry
        has_logging = re.search(r'(import.*slf4j|import.*log4j|@Slf4j)', code)
        if has_logging and not has_azure_monitor:
            line_num = code[:has_logging.start()].count('\n') + 1
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Centralized Telemetry Integration",
                description=(
                    f"Application uses logging at line {line_num} but lacks Azure Monitor/Application Insights."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation="Add Application Insights dependency.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-MLA-01 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Console.log without centralized monitoring
        - File transport logging (Winston File transport, createWriteStream)
        - Missing Application Insights SDK
        - Local logging without tamper protection
        """
        findings = []
        lines = code.split('\n')
        
        if not self.js_parser:
            return self._analyze_typescript_fallback(code, file_path)
        
        tree = self.js_parser.parse(bytes(code, "utf8"))
        root_node = tree.root_node
        
        # Check for centralized logging integration (file-wide)
        has_app_insights = self._check_for_app_insights_js(code)
        
        # Pattern 1: Detect Winston File transport (HIGH)
        file_transport_patterns = [
            r'winston\..*File',
            r'new\s+transports\.File',
            r'createWriteStream.*\.log',
        ]
        
        for pattern in file_transport_patterns:
            match = re.search(pattern, code)
            if match:
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context_lines(lines, line_num, 15)
                
                # Check for Application Insights in nearby context
                has_ai_in_context = re.search(
                    r'(applicationinsights|@azure/monitor|@opentelemetry)',
                    context
                )
                
                if not has_app_insights and not has_ai_in_context:
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
        
        # Pattern 2: Console logging without centralized monitoring (MEDIUM)
        # Use regex since console.log is a member expression, not a simple call
        console_log_match = re.search(r'console\.(log|info|warn|error)', code)
        if console_log_match and not has_app_insights:
            line_num = code[:console_log_match.start()].count('\n') + 1
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
                    "appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING).start();"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def _analyze_typescript_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis when tree-sitter unavailable."""
        findings = []
        lines = code.split('\n')
        
        # Check for Application Insights
        has_app_insights = re.search(
            r'(applicationinsights|@azure/monitor|@opentelemetry)',
            code
        )
        
        # Pattern 1: File transport logging
        file_transport_patterns = [
            r'winston\..*File',
            r'new\s+transports\.File',
            r'createWriteStream.*\.log',
        ]
        
        for pattern in file_transport_patterns:
            match = re.search(pattern, code)
            if match and not has_app_insights:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="File Transport Logging Without Centralized SIEM",
                    description=(
                        f"File-based log transport at line {line_num} without centralized monitoring."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Integrate Application Insights.",
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Console logging
        has_console_log = re.search(r'console\.(log|info|warn|error)', code)
        if has_console_log and not has_app_insights:
            line_num = code[:has_console_log.start()].count('\n') + 1
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Console Logging Without Centralized Monitoring",
                description=(
                    f"Console logging at line {line_num} without Application Insights or centralized monitoring."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation="Add Application Insights integration.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (PATTERN-BASED)
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
            r"resource.*Microsoft\.OperationalInsights/workspaces",
            code
        )
        has_resources = re.search(r"resource\s+\w+\s+", code)
        
        if has_resources and not has_log_analytics:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Missing Log Analytics Workspace for Centralized Logging",
                description=(
                    "Infrastructure deploys Azure resources without a Log Analytics workspace. "
                    "FedRAMP requires centralized, tamper-resistant logging via Azure Monitor and Log Analytics. "
                    "All security events, activities, and changes must be logged to a SIEM."
                ),
                file_path=file_path,
                line_number=1,
                snippet="No Log Analytics workspace found in Bicep template",
                remediation=(
                    "Deploy Log Analytics workspace with FedRAMP-compliant retention:\n"
                    "resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {\n"
                    "  name: 'law-${uniqueString(resourceGroup().id)}'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    retentionInDays: 730  // FedRAMP 20x requires 2-year retention (KSI-MLA-01, KSI-MLA-02)\n"
                    "    sku: { name: 'PerGB2018' }\n"
                    "  }\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Resources without diagnostic settings (HIGH)
        resource_types = [
            "Microsoft.Web/sites",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.KeyVault/vaults",
            "Microsoft.Sql/servers",
            "Microsoft.Network/applicationGateways",
        ]
        
        for resource_type in resource_types:
            resource_match = re.search(rf"resource\s+\w+\s+'?{re.escape(resource_type)}", code)
            if resource_match:
                has_diagnostics = re.search(
                    r"resource.*Microsoft\.Insights/diagnosticSettings",
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
        
        # Pattern 3: Log Analytics workspace with insufficient retention (MEDIUM)
        retention_pattern = r"retentionInDays:\s*(\d+)"
        for match in re.finditer(retention_pattern, code):
            retention_days = int(match.group(1))
            if retention_days < 730:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Insufficient Log Retention Period",
                    description=(
                        f"Log Analytics workspace has {retention_days}-day retention at line {line_num}. "
                        f"FedRAMP 20x requires 730 days (2 years) retention for audit logs per AU-11. "
                        f"KSI-MLA-01 and KSI-MLA-02 mandate long-term tamper-resistant storage."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        f"Update retention to meet FedRAMP 20x requirements:\n"
                        f"properties: {{\n"
                        f"  retentionInDays: 730  // 2 years - FedRAMP minimum (KSI-MLA-01, AU-11)\n"
                        f"}}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
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
                    "FedRAMP requires centralized, tamper-resistant logging via Azure Monitor. "
                    "All security events and changes must be logged to a SIEM system."
                ),
                file_path=file_path,
                line_number=1,
                snippet="No azurerm_log_analytics_workspace found in configuration",
                remediation=(
                    "Add Log Analytics workspace with FedRAMP-compliant retention:\n"
                    "resource \"azurerm_log_analytics_workspace\" \"siem\" {\n"
                    "  name                = \"law-${var.project}-${var.environment}\"\n"
                    "  location            = azurerm_resource_group.main.location\n"
                    "  resource_group_name = azurerm_resource_group.main.name\n"
                    "  sku                 = \"PerGB2018\"\n"
                    "  retention_in_days   = 730  # FedRAMP 20x requires 2-year retention (KSI-MLA-01, KSI-MLA-02)\n"
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
        
        # Pattern 3: Log Analytics workspace with insufficient retention (MEDIUM)
        retention_pattern = r"retention_in_days\s*=\s*(\d+)"
        for match in re.finditer(retention_pattern, code):
            retention_days = int(match.group(1))
            if retention_days < 730:
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Insufficient Log Retention Period",
                    description=(
                        f"Log Analytics workspace has {retention_days}-day retention at line {line_num}. "
                        f"FedRAMP 20x requires 730 days (2 years) retention for audit logs per AU-11. "
                        f"KSI-MLA-01 and KSI-MLA-02 mandate long-term tamper-resistant storage."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        f"Update retention to meet FedRAMP 20x requirements:\n"
                        f"retention_in_days = 730  # 2 years - FedRAMP minimum (KSI-MLA-01, AU-11)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (NOT APPLICABLE)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """GitHub Actions workflow analysis not applicable for centralized logging."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Azure Pipelines YAML analysis not applicable for centralized logging."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """GitLab CI YAML analysis not applicable for centralized logging."""
        return []
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _check_for_centralized_logging_python(self, code: str) -> bool:
        """Check if Python code has Azure Monitor integration."""
        return bool(re.search(
            r'(from\s+azure\.monitor|from\s+opencensus\.ext\.azure|applicationinsights|AzureLogHandler)',
            code
        ))
    
    def _check_for_app_insights_csharp(self, code: str) -> bool:
        """Check if C# code has Application Insights integration."""
        return bool(re.search(
            r'(ApplicationInsights|AddApplicationInsightsTelemetry|TelemetryClient|AzureMonitor)',
            code,
            re.IGNORECASE
        ))
    
    def _check_for_azure_monitor_java(self, code: str) -> bool:
        """Check if Java code has Azure Monitor integration."""
        return bool(re.search(
            r'(com\.microsoft\.azure.*applicationinsights|azure.*monitor|micrometer.*azure)',
            code
        ))
    
    def _check_for_app_insights_js(self, code: str) -> bool:
        """Check if TypeScript/JavaScript code has Application Insights integration."""
        return bool(re.search(
            r'(applicationinsights|@azure/monitor|@opentelemetry)',
            code
        ))
    
    def _find_call_expressions(self, node: 'Node', function_names: List[str]) -> List['Node']:
        """Find call expression nodes matching function names."""
        results = []
        if not TREE_SITTER_AVAILABLE:
            return results
        
        def traverse(n):
            if n.type == 'call':
                func_node = n.child_by_field_name('function')
                if func_node:
                    func_text = func_node.text.decode('utf8')
                    for name in function_names:
                        if name in func_text:
                            results.append(n)
                            break
            for child in n.children:
                traverse(child)
        
        traverse(node)
        return results
    
    def _find_invocation_expressions(self, node: 'Node', method_names: List[str]) -> List['Node']:
        """Find invocation expression nodes matching method names (C#)."""
        results = []
        if not TREE_SITTER_AVAILABLE:
            return results
        
        def traverse(n):
            if n.type == 'invocation_expression':
                node_text = n.text.decode('utf8')
                for name in method_names:
                    if name in node_text:
                        results.append(n)
                        break
            for child in n.children:
                traverse(child)
        
        traverse(node)
        return results
    
    def _check_for_import(self, node: 'Node', module_name: str) -> bool:
        """Check if Python code imports a specific module."""
        if not TREE_SITTER_AVAILABLE:
            return False
        
        def traverse(n):
            if n.type in ['import_statement', 'import_from_statement']:
                import_text = n.text.decode('utf8')
                if module_name in import_text:
                    return True
            for child in n.children:
                if traverse(child):
                    return True
            return False
        
        return traverse(node)
    
    def _find_import_line(self, lines: List[str], module_name: str) -> int:
        """Find line number of import statement."""
        for i, line in enumerate(lines, 1):
            if re.search(rf'\bimport\s+{module_name}\b|from\s+{module_name}\s+import', line):
                return i
        return 1
    
    def _get_context_lines(self, lines: List[str], line_num: int, context: int = 15) -> str:
        """Get surrounding lines for context."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])
    

        """Get code snippet around line number."""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

