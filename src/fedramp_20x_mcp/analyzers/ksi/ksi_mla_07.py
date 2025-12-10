"""KSI-MLA-07 Enhanced: Event Types"""

import ast
import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_MLA_07_Analyzer(BaseKSIAnalyzer):
    """
    KSI-MLA-07: Event Types
    
    Maintain a list of information resources and event types that will be 
    monitored, logged, and audited, then do so.
    
    NIST: AU-2, AU-7.1, AU-12, SI-4.4, SI-4.5, AC-2.4, AC-6.9
    """
    
    KSI_ID = "KSI-MLA-07"
    KSI_NAME = "Event Types"
    KSI_STATEMENT = """Maintain a list of information resources and event types that will be monitored, logged, and audited, then do so."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging & Analysis"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-2.4", "Automated Audit Actions"),
        ("ac-6.9", "Log Use of Privileged Functions"),
        ("ac-17.1", "Monitoring and Control"),
        ("ac-20.1", "Limits on Authorized Use"),
        ("au-2", "Event Logging"),
        ("au-7.1", "Automatic Processing"),
        ("au-12", "Audit Record Generation"),
        ("si-4.4", "Inbound and Outbound Communications Traffic"),
        ("si-4.5", "System-generated Alerts"),
        ("si-7.7", "Integration of Detection and Response")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Python: Event types for auth, data, config changes (AST-based)"""
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
            
            # Pattern 1: Auth functions without logging in body
            auth_func_names = ['login', 'authenticate', 'logout', 'signin', 'sign_in', 'sign_out']
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_name_lower = node.name.lower()
                    
                    # Check if it's an auth function
                    is_auth_func = any(auth_name in func_name_lower for auth_name in auth_func_names)
                    
                    # Also check decorators for auth-related decorators
                    has_auth_decorator = False
                    for decorator in node.decorator_list:
                        if isinstance(decorator, ast.Name):
                            if 'login_required' in decorator.id.lower() or 'auth' in decorator.id.lower():
                                has_auth_decorator = True
                                break
                        elif isinstance(decorator, ast.Attribute):
                            if 'auth' in decorator.attr.lower():
                                has_auth_decorator = True
                                break
                    
                    if is_auth_func or has_auth_decorator:
                        # Check function body for logger calls
                        func_code = ast.unparse(node) if hasattr(ast, 'unparse') else ''
                        has_logger = bool(re.search(r'logger\.(info|warning|error|debug)', func_code, re.IGNORECASE))
                        
                        if not has_logger:
                            line_num = node.lineno
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title="Auth Function Without Event Logging",
                                description=(
                                    f"Authentication function '{node.name}' at line {line_num} missing event logging. "
                                    f"KSI-MLA-07 requires logging authentication events for audit trails (NIST AU-2, AU-12, AC-2.4). "
                                    f"Login/logout events must be logged with timestamps, user identifiers, and outcomes."
                                ),
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num),
                                remediation=(
                                    "Add event logging to authentication function:\n"
                                    "```python\n"
                                    "import logging\n"
                                    "logger = logging.getLogger(__name__)\n\n"
                                    "def login(username, password):\n"
                                    "    logger.info(f'Login attempt', extra={\n"
                                    "        'event_type': 'authentication',\n"
                                    "        'username': username,\n"
                                    "        'timestamp': datetime.now().isoformat()\n"
                                    "    })\n"
                                    "    user = authenticate(username, password)\n"
                                    "    if user:\n"
                                    "        logger.info(f'Login successful', extra={'user_id': user.id})\n"
                                    "    else:\n"
                                    "        logger.warning(f'Login failed', extra={'username': username})\n"
                                    "    return user\n"
                                    "```"
                                )
                            ))
            
            # Pattern 2: Data access operations without logging
            query_call_count = 0
            data_access_methods = ['query', 'get', 'filter', 'all', 'first', 'execute', 'executemany']
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        method_name = node.func.attr.lower()
                        if method_name in data_access_methods:
                            query_call_count += 1
            
            # Also check for SQL strings
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if re.search(r'SELECT\s+.*\s+FROM', node.value, re.IGNORECASE):
                        query_call_count += 1
            
            if query_call_count > 3:
                # Check if logger is imported or used anywhere
                has_logger = False
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        if any('logging' in alias.name for alias in node.names):
                            has_logger = True
                            break
                    elif isinstance(node, ast.ImportFrom):
                        if node.module and 'logging' in node.module:
                            has_logger = True
                            break
                    elif isinstance(node, ast.Attribute):
                        if 'logger' in (node.attr.lower() if hasattr(node, 'attr') else ''):
                            has_logger = True
                            break
                
                if not has_logger:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Data Access Operations Without Audit Logging",
                        description=(
                            f"File contains {query_call_count} data access operations without audit logging. "
                            f"KSI-MLA-07 requires logging data access events for compliance (NIST AU-2, AU-12, SI-4.4). "
                            f"Database queries, modifications, and API calls must be logged with user context."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=1,
                        code_snippet=f"{query_call_count} data access operations detected",
                        remediation=(
                            "Add comprehensive data access logging:\n"
                            "```python\n"
                            "import logging\n"
                            "logger = logging.getLogger(__name__)\n\n"
                            "def get_user_data(user_id):\n"
                            "    logger.info(f'Data access', extra={\n"
                            "        'event_type': 'data_access',\n"
                            "        'resource': 'user_data',\n"
                            "        'user_id': user_id,\n"
                            "        'action': 'read'\n"
                            "    })\n"
                            "    return User.query.filter_by(id=user_id).first()\n\n"
                            "def update_user(user_id, data):\n"
                            "    logger.info(f'Data modification', extra={\n"
                            "        'event_type': 'data_modification',\n"
                            "        'resource': 'user',\n"
                            "        'user_id': user_id,\n"
                            "        'action': 'update',\n"
                            "        'fields': list(data.keys())\n"
                            "    })\n"
                            "    user = User.query.get(user_id)\n"
                            "    user.update(data)\n"
                            "    return user\n"
                            "```"
                        )
                    ))
        
        except SyntaxError:
            # Fallback to regex if AST parsing fails
            findings.extend(self._python_regex_fallback(code, file_path, lines))
        
        return findings
    
    def _python_regex_fallback(self, code: str, file_path: str, lines: List[str]) -> List[Finding]:
        """Regex fallback for syntax errors"""
        findings = []
        
        # Check auth events
        auth_patterns = [
            r'def\s+(login|authenticate|logout|signin)\s*\(',
            r'@(login_required|auth\.|authenticate)',
        ]
        for pattern in auth_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'logger\.(info|warning|error)', context, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Auth event without logging (Regex Fallback)",
                        description=f"Authentication operation at line {line_num} missing event logging",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger.info with event_type='authentication'"
                    ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """C#: Event types for auth, data, config"""
        findings = []
        lines = code.split('\n')
        
        # Check auth operations
        auth_patterns = [
            r'SignInAsync\(',
            r'AuthenticateAsync\(',
            r'\[Authorize\]',
        ]
        for pattern in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'_logger\.(Log|Information)', context):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Auth operation without logging",
                        description=f"Authentication at line {line_num} missing event logging",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add _logger.LogInformation with eventType"
                    ))
        
        # Check database operations
        db_patterns = [
            r'_context\..*\.(Add|AddRange)\(',
            r'_context\..*\.(Update|UpdateRange)\(',
            r'_context\..*\.(Remove|RemoveRange)\(',
            r'ExecuteSqlRaw\(',
        ]
        
        # Count total operations
        total_ops = sum(len(list(re.finditer(p, code))) for p in db_patterns)
        
        if total_ops >= 3:
            has_logger = bool(re.search(r'ILogger|_logger', code))
            if not has_logger:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Data operations without logging",
                    description=f"Multiple data operations without audit logging",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="Multiple data operations found",
                    remediation="Add ILogger to track data changes (AU-2, AU-12)"
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Java: Event types for Spring Security, data access"""
        findings = []
        lines = code.split('\n')
        
        # Check auth events
        auth_patterns = [
            r'@PreAuthorize',
            r'@Secured',
            r'\.authenticate\(',
        ]
        for pattern in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'log\.(info|warn)', context):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Auth annotation without logging",
                        description=f"Authorization check at line {line_num} missing event logging",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add log.info with event type for AU-2 compliance"
                    ))
        
        # Check repository operations
        if re.search(r'@Repository|extends JpaRepository', code):
            has_logger = bool(re.search(r'Logger\s+log|private.*Logger', code))
            if not has_logger:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Repository without logging",
                    description="Repository class missing logger for data access events",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="Repository detected",
                    remediation="Add Logger to track data access patterns"
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """TypeScript: Event types for guards, interceptors"""
        findings = []
        lines = code.split('\n')
        
        # Check guards
        if re.search(r'implements CanActivate|@UseGuards', code):
            for match in re.finditer(r'(canActivate|@UseGuards)', code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'logger\.(log|info|warn)', context):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Guard without logging",
                        description=f"Authorization guard at line {line_num} missing event logging",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger to track authorization events"
                    ))
        
        # Check data services
        service_patterns = [
            r'\.save\(',
            r'\.update\(',
            r'\.delete\(',
            r'\.create\(',
        ]
        
        # Count total operations
        total_ops = sum(len(list(re.finditer(p, code))) for p in service_patterns)
        
        if total_ops > 3:
            has_logger = bool(re.search(r'import.*logger|this\.logger', code))
            if not has_logger:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Data operations without logging",
                    description="Multiple data operations without audit logging",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="Multiple data operations",
                    remediation="Add logger for data access events (AU-2)"
                ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Bicep: Diagnostic settings for event types"""
        findings = []
        lines = code.split('\n')
        
        # Resources requiring diagnostic settings
        resource_types = [
            r"'Microsoft\.KeyVault/vaults@",
            r"'Microsoft\.Storage/storageAccounts@",
            r"'Microsoft\.Web/sites@",
            r"'Microsoft\.Sql/servers@",
        ]
        
        for resource_type in resource_types:
            for match in re.finditer(resource_type, code):
                line_num = code[:match.start()].count('\n') + 1
                resource_name = self._extract_bicep_resource_name(lines, line_num)
                
                # Check for diagnostic settings
                diag_pattern = rf"scope:\s*{re.escape(resource_name)}|parent:\s*{re.escape(resource_name)}"
                has_diagnostics = bool(re.search(diag_pattern, code))
                
                if not has_diagnostics:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Resource missing diagnostic settings",
                        description=f"Resource '{resource_name}' at line {line_num} missing diagnostic settings for event logging",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation=f"Add Microsoft.Insights/diagnosticSettings for {resource_name} (AU-2, AU-12)"
                    ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Terraform: Monitor diagnostic settings"""
        findings = []
        lines = code.split('\n')
        
        # Resources requiring diagnostic settings
        resource_patterns = [
            r'resource\s+"azurerm_key_vault"\s+"(\w+)"',
            r'resource\s+"azurerm_storage_account"\s+"(\w+)"',
            r'resource\s+"azurerm_app_service"\s+"(\w+)"',
            r'resource\s+"azurerm_sql_server"\s+"(\w+)"',
        ]
        
        for pattern in resource_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                resource_name = match.group(1)
                
                # Check for diagnostic settings
                diag_pattern = rf'azurerm_monitor_diagnostic_setting.*target_resource_id.*{resource_name}'
                has_diagnostics = bool(re.search(diag_pattern, code, re.DOTALL))
                
                if not has_diagnostics:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Resource missing diagnostic settings",
                        description=f"Resource '{resource_name}' at line {line_num} missing monitor diagnostic settings",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation=f"Add azurerm_monitor_diagnostic_setting for {resource_name}"
                    ))
        
        return findings
    
    def _extract_bicep_resource_name(self, lines: List[str], start_line: int) -> str:
        """Extract resource symbolic name from Bicep resource declaration"""
        if start_line - 1 >= len(lines):
            return "unknown"
        
        line = lines[start_line - 1]
        match = re.search(r"resource\s+(\w+)", line)
        return match.group(1) if match else "unknown"
    

        """Get context around line"""
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        return '\n'.join(lines[start:end])
    

        """Get code snippet around line"""
        if not lines or line_num < 1:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-MLA-07.
        
        **KSI-MLA-07: Event Types**
        Maintain a list of information resources and event types that will be monitored, logged, and audited.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-MLA-07",
            "ksi_name": "Event Types",
            "azure_services": [
                {
                    "service": "Azure Monitor",
                    "purpose": "Comprehensive event type logging and monitoring configuration",
                    "capabilities": [
                        "Diagnostic settings for all resource types",
                        "Activity log event categories",
                        "Metric alerts for event monitoring",
                        "Log Analytics workspace event ingestion"
                    ]
                },
                {
                    "service": "Azure Sentinel",
                    "purpose": "Security event type collection and SIEM analysis",
                    "capabilities": [
                        "Data connectors for event ingestion",
                        "Analytics rules for event detection",
                        "Event taxonomy and classification",
                        "Incident correlation across event types"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Enforce diagnostic settings for event logging",
                    "capabilities": [
                        "Require diagnostic settings on all resources",
                        "Validate event log categories enabled",
                        "Audit non-compliant resources",
                        "Automated remediation for missing logs"
                    ]
                },
                {
                    "service": "Azure Resource Graph",
                    "purpose": "Inventory of resources and their logging configurations",
                    "capabilities": [
                        "Query diagnostic settings across subscriptions",
                        "List all resource types with logging",
                        "Identify resources without event logging",
                        "Export resource inventory for audit"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Event Type Inventory Documentation",
                    "description": "Maintain documented list of monitored event types per resource category",
                    "automation": "Export diagnostic settings and data collection rules",
                    "frequency": "Quarterly",
                    "evidence_produced": "Event type matrix showing resource types and logged events"
                },
                {
                    "method": "Diagnostic Settings Compliance Scan",
                    "description": "Verify all resources have appropriate diagnostic settings enabled",
                    "automation": "Azure Policy compliance scan",
                    "frequency": "Daily",
                    "evidence_produced": "Resource compliance report for event logging"
                },
                {
                    "method": "Log Ingestion Verification",
                    "description": "Confirm events are being ingested for all defined event types",
                    "automation": "KQL queries checking log ingestion per source",
                    "frequency": "Daily",
                    "evidence_produced": "Log ingestion health report"
                },
                {
                    "method": "Event Coverage Gap Analysis",
                    "description": "Identify resources or event types not being monitored",
                    "automation": "Resource Graph query for resources without logging",
                    "frequency": "Weekly",
                    "evidence_produced": "Gap analysis report with remediation plan"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["config-based", "log-based"],
            "implementation_guidance": {
                "quick_start": "Deploy Azure Policy for diagnostic settings, configure Log Analytics workspace, enable Sentinel data connectors, document event type taxonomy",
                "azure_well_architected": "Follows Azure WAF operational excellence and security pillars for comprehensive monitoring",
                "compliance_mapping": "Addresses NIST controls au-2, au-7.1, au-12, si-4.4, si-4.5, ac-2.4, ac-6.9"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-MLA-07 evidence.
        """
        return {
            "ksi_id": "KSI-MLA-07",
            "queries": [
                {
                    "name": "Resource Diagnostic Settings Inventory",
                    "type": "azure_resource_graph",
                    "query": """
                        resources
                        | join kind=leftouter (
                            resources
                            | where type == 'microsoft.insights/diagnosticsettings'
                            | extend targetResourceId = tolower(split(id, '/providers/microsoft.insights/')[0])
                            | project targetResourceId, diagnosticId=id
                        ) on $left.id == $right.targetResourceId
                        | where type !in ('microsoft.resources/subscriptions', 'microsoft.resources/resourcegroups')
                        | project name, type, resourceGroup, hasDiagnostics=isnotempty(diagnosticId)
                        | summarize Total=count(), WithDiagnostics=countif(hasDiagnostics) by type
                        | extend CoveragePercent = round((WithDiagnostics * 100.0) / Total, 2)
                        """,
                    "purpose": "Show event logging coverage across resource types",
                    "expected_result": "High coverage percentage with documented exceptions"
                },
                {
                    "name": "Log Ingestion Health by Event Type",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        union *
                        | where TimeGenerated > ago(24h)
                        | summarize EventCount = count() by $table, Type
                        | order by EventCount desc
                        """,
                    "purpose": "Verify events are being ingested across all event types",
                    "expected_result": "Active ingestion for all defined event types"
                },
                {
                    "name": "Sentinel Data Connectors Status",
                    "type": "kql",
                    "workspace": "Azure Sentinel workspace",
                    "query": """
                        SecurityEvent
                        | where TimeGenerated > ago(24h)
                        | summarize EventCount = count(), LastEvent = max(TimeGenerated) by Computer, EventID
                        | where EventCount > 0
                        | summarize ConnectedSources = dcount(Computer)
                        """,
                    "purpose": "Show active security event ingestion from all sources",
                    "expected_result": "All expected sources reporting events"
                },
                {
                    "name": "Activity Log Event Categories",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        AzureActivity
                        | where TimeGenerated > ago(7d)
                        | summarize EventCount = count() by CategoryValue, OperationNameValue
                        | order by EventCount desc
                        | take 50
                        """,
                    "purpose": "Show breadth of activity log event types being captured",
                    "expected_result": "Diverse event categories covering administrative, security, policy operations"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI or Managed Identity",
                "permissions_required": [
                    "Reader for Resource Graph queries",
                    "Log Analytics Reader for KQL queries",
                    "Sentinel Reader for data connector status"
                ],
                "automation_tools": [
                    "Azure CLI (az monitor, az graph)",
                    "PowerShell Az.Monitor and Az.ResourceGraph modules"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-MLA-07.
        """
        return {
            "ksi_id": "KSI-MLA-07",
            "artifacts": [
                {
                    "name": "Event Type Matrix",
                    "description": "Documented matrix of resource types and their monitored event categories",
                    "source": "Diagnostic settings configuration",
                    "format": "Excel or CSV matrix",
                    "collection_frequency": "Quarterly (or on change)",
                    "retention_period": "3 years",
                    "automation": "Resource Graph query with documentation template"
                },
                {
                    "name": "Diagnostic Settings Compliance Report",
                    "description": "Report showing diagnostic settings coverage across all resources",
                    "source": "Azure Policy compliance data",
                    "format": "CSV from Resource Graph",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "Scheduled Resource Graph query"
                },
                {
                    "name": "Log Ingestion Health Dashboard",
                    "description": "Real-time dashboard showing event ingestion status by type",
                    "source": "Log Analytics",
                    "format": "Azure Workbook",
                    "collection_frequency": "Continuous (real-time)",
                    "retention_period": "Persistent (configuration stored)",
                    "automation": "Azure Monitor Workbook"
                },
                {
                    "name": "Event Coverage Gap Analysis",
                    "description": "Quarterly analysis of resources or event types not being monitored",
                    "source": "Resource Graph and Log Analytics",
                    "format": "PDF report with remediation plan",
                    "collection_frequency": "Quarterly",
                    "retention_period": "3 years",
                    "automation": "Automated gap analysis with Power BI or custom script"
                },
                {
                    "name": "Sentinel Data Connector Configuration",
                    "description": "Export of all Sentinel data connectors and event collection rules",
                    "source": "Azure Sentinel configuration",
                    "format": "JSON configuration export",
                    "collection_frequency": "Monthly",
                    "retention_period": "3 years",
                    "automation": "Sentinel ARM template export"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["au-2", "au-7.1", "au-12", "si-4.4", "si-4.5", "ac-2.4", "ac-6.9"],
                "evidence_purpose": "Demonstrate comprehensive event type monitoring and logging"
            }
        }

