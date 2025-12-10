"""KSI-MLA-08 Enhanced: Log Data Access"""

import ast
import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_MLA_08_Analyzer(BaseKSIAnalyzer):
    """
    KSI-MLA-08: Log Data Access
    
    Use a least-privileged, role and attribute-based, and just-in-time access 
    authorization model for access to log data based on organizationally defined 
    data sensitivity.
    
    NIST: SI-11 (Error Handling)
    Focus: RBAC for logging infrastructure, secure log access patterns
    """
    
    KSI_ID = "KSI-MLA-08"
    KSI_NAME = "Log Data Access"
    KSI_STATEMENT = """Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data based on organizationally defined data sensitivity."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging & Analysis"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [("si-11", "Error Handling")]
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
        """Python: Log access patterns, Azure Monitor SDK (AST-based)"""
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
            
            # Pattern 1: Azure Monitor SDK usage without credential scoping
            has_monitor_import = False
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.module and 'azure.monitor.query' in node.module:
                        has_monitor_import = True
                        break
            
            if has_monitor_import:
                # Check for DefaultAzureCredential usage
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name) and node.func.id == 'DefaultAzureCredential':
                            # Check if scope or role is specified in nearby code
                            line_num = node.lineno
                            context = self._get_context(lines, line_num, 10)
                            has_scope = bool(re.search(r'scope\s*=|role\s*=', context))
                            
                            if not has_scope:
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title="Azure Monitor Query Without Explicit Scope",
                                    description=(
                                        f"Azure Monitor LogsQueryClient using DefaultAzureCredential at line {line_num} without role scoping. "
                                        f"KSI-MLA-08 requires least-privileged, role-based access for log data (NIST SI-11). "
                                        f"Use explicit credential scopes to limit access to log analytics workspaces."
                                    ),
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    remediation=(
                                        "Use least-privileged credentials with explicit scope:\n"
                                        "```python\n"
                                        "from azure.identity import DefaultAzureCredential\n"
                                        "from azure.monitor.query import LogsQueryClient\n\n"
                                        "# Use managed identity with Monitoring Reader role\n"
                                        "credential = DefaultAzureCredential()\n"
                                        "client = LogsQueryClient(credential)\n\n"
                                        "# Or use specific credential with limited scope\n"
                                        "from azure.identity import ManagedIdentityCredential\n"
                                        "credential = ManagedIdentityCredential(client_id='...')\n"
                                        "# Ensure identity has only Monitoring Reader role, not Log Analytics Contributor\n"
                                        "```"
                                    )
                                ))
            
            # Pattern 2: Direct log file access without authorization checks
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    is_file_open = False
                    filename_arg = None
                    
                    # Check for open() or with open()
                    if isinstance(node.func, ast.Name) and node.func.id == 'open':
                        is_file_open = True
                        if node.args:
                            filename_arg = node.args[0]
                    
                    if is_file_open and filename_arg:
                        # Check if filename contains .log
                        filename_str = ''
                        if isinstance(filename_arg, ast.Constant):
                            filename_str = str(filename_arg.value)
                        elif isinstance(filename_arg, ast.JoinedStr):  # f-string
                            filename_str = ast.unparse(filename_arg) if hasattr(ast, 'unparse') else ''
                        
                        if '.log' in filename_str.lower():
                            # Check for authorization in enclosing function
                            func_node = self._find_parent_function(node, tree)
                            has_authz = False
                            
                            if func_node:
                                # Check decorators for authorization
                                for decorator in func_node.decorator_list:
                                    dec_name = ''
                                    if isinstance(decorator, ast.Name):
                                        dec_name = decorator.id
                                    elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                                        dec_name = decorator.func.id
                                    
                                    if 'require' in dec_name.lower() or 'auth' in dec_name.lower():
                                        has_authz = True
                                        break
                                
                                # Check function body for authorization checks
                                if not has_authz:
                                    func_code = ast.unparse(func_node) if hasattr(ast, 'unparse') else ''
                                    has_authz = bool(re.search(r'check_permission|has_role|is_admin|@require', func_code, re.IGNORECASE))
                            
                            if not has_authz:
                                line_num = node.lineno
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title="Log File Access Without Authorization",
                                    description=(
                                        f"Direct log file access at line {line_num} without authorization check. "
                                        f"KSI-MLA-08 requires role-based access control for log data (NIST SI-11). "
                                        f"Administrative log access must verify user roles and permissions."
                                    ),
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    remediation=(
                                        "Add role-based authorization for log file access:\n"
                                        "```python\n"
                                        "from functools import wraps\n"
                                        "from flask import abort\n\n"
                                        "def require_admin_role(f):\n"
                                        "    @wraps(f)\n"
                                        "    def decorated_function(*args, **kwargs):\n"
                                        "        if not current_user.has_role('admin'):\n"
                                        "            abort(403)\n"
                                        "        return f(*args, **kwargs)\n"
                                        "    return decorated_function\n\n"
                                        "@app.route('/logs')\n"
                                        "@require_admin_role\n"
                                        "def view_logs():\n"
                                        "    with open('/var/log/app.log', 'r') as f:\n"
                                        "        return f.read()\n"
                                        "```"
                                    )
                                ))
        
        except SyntaxError:
            # Fallback to regex if AST parsing fails
            findings.extend(self._python_regex_fallback(code, file_path, lines))
        
        return findings
    
    def _find_parent_function(self, node, tree):
        """Find the parent function containing this node"""
        for potential_parent in ast.walk(tree):
            if isinstance(potential_parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(potential_parent):
                    if child is node:
                        return potential_parent
        return None
    
    def _python_regex_fallback(self, code: str, file_path: str, lines: List[str]) -> List[Finding]:
        """Regex fallback for syntax errors"""
        findings = []
        
        # Check for direct log file access without authz
        log_access_patterns = [
            r'open\([\'"].*\.log[\'"],',
            r'with\s+open\([\'"].*\.log[\'"]',
        ]
        for pattern in log_access_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 10)
                
                has_authz = bool(re.search(r'@require|check_permission|has_role', context))
                if not has_authz:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Log file access without authorization (Regex Fallback)",
                        description=f"Direct log file access at line {line_num} without authorization check",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add role-based access control for log file access"
                    ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """C#: Log access, Azure Monitor SDK"""
        findings = []
        lines = code.split('\n')
        
        # Check Azure Monitor usage
        if re.search(r'using Azure\.Monitor\.Query', code):
            if re.search(r'new\s+LogsQueryClient', code):
                # Check for explicit credential
                has_credential = bool(re.search(r'new\s+DefaultAzureCredential', code))
                if not has_credential:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Log query without explicit credential",
                        description="LogsQueryClient without explicit Azure credential",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=1,
                        code_snippet="LogsQueryClient detected",
                        remediation="Use DefaultAzureCredential with least-privileged role"
                    ))
        
        # Check log file access
        log_patterns = [
            r'File\.ReadAllText\([^)]*\.log',
            r'File\.Open\([^)]*\.log',
            r'StreamReader\([^)]*\.log',
        ]
        for pattern in log_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                # Check for class-level or method-level authorization
                has_authz = bool(re.search(r'\[Authorize[\(\]]|User\.IsInRole|ClaimsPrincipal', context))
                if not has_authz:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Log file access without authorization",
                        description=f"Log file read at line {line_num} without authorization check",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add [Authorize] or role check for log access"
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Java: Log access patterns"""
        findings = []
        lines = code.split('\n')
        
        # Check log file access
        log_patterns = [
            r'new\s+FileReader\([^)]*\.log',
            r'Files\.readAllLines\([^)]*\.log',
            r'Files\.lines\([^)]*\.log',
        ]
        for pattern in log_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 10)
                
                has_authz = bool(re.search(r'@PreAuthorize|@Secured|hasRole', context))
                if not has_authz:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Log file access without authorization",
                        description=f"Log file read at line {line_num} without authorization",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add @PreAuthorize or role check for log access"
                    ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """TypeScript: Log access patterns"""
        findings = []
        lines = code.split('\n')
        
        # Check log file access
        log_patterns = [
            r'fs\.readFileSync\([^)]*\.log',
            r'fs\.readFile\([^)]*\.log',
            r'createReadStream\([^)]*\.log',
        ]
        for pattern in log_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 10)
                
                has_authz = bool(re.search(r'@UseGuards|@Roles|canActivate', context))
                if not has_authz:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Log file access without authorization",
                        description=f"Log file read at line {line_num} without authorization",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add guard or role check for log access"
                    ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Bicep: RBAC for Log Analytics, Storage logs"""
        findings = []
        lines = code.split('\n')
        
        # Check Log Analytics without RBAC
        if re.search(r"Microsoft\.OperationalInsights/workspaces", code):
            has_rbac = bool(re.search(r"Microsoft\.Authorization/roleAssignments", code))
            if not has_rbac:
                result = self._find_line(lines, 'OperationalInsights/workspaces')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Log Analytics without RBAC",
                    description="Log Analytics workspace deployed without role assignments",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add roleAssignments with least-privileged roles (Monitoring Reader)"
                ))
        
        # Check Storage accounts with logs but no RBAC
        if re.search(r"Microsoft\.Storage/storageAccounts", code):
            has_blob = bool(re.search(r"blobServices|/logs/", code))
            has_rbac = bool(re.search(r"Microsoft\.Authorization/roleAssignments", code))
            if has_blob and not has_rbac:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Storage logs without RBAC",
                    description="Storage account with logs missing role assignments",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="Storage with logs detected",
                    remediation="Add Storage Blob Data Reader role for log access"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Terraform: RBAC for Log Analytics, Storage logs"""
        findings = []
        lines = code.split('\n')
        
        # Check Log Analytics without RBAC
        if re.search(r'azurerm_log_analytics_workspace', code):
            has_rbac = bool(re.search(r'azurerm_role_assignment', code))
            if not has_rbac:
                result = self._find_line(lines, 'azurerm_log_analytics_workspace')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Log Analytics without RBAC",
                    description="Log Analytics workspace without role assignments",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add azurerm_role_assignment with Monitoring Reader role"
                ))
        
        # Check Storage with logs but no RBAC
        if re.search(r'azurerm_storage_account', code):
            has_container = bool(re.search(r'azurerm_storage_container.*logs|container_name.*logs', code))
            has_rbac = bool(re.search(r'azurerm_role_assignment', code))
            if has_container and not has_rbac:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Storage logs without RBAC",
                    description="Storage account with log container missing role assignments",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="Storage logs detected",
                    remediation="Add Storage Blob Data Reader role assignment"
                ))
        
        return findings
    

        """Find line number containing pattern"""
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 1
    

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
        Get Azure-specific recommendations for automating evidence collection for KSI-MLA-08.
        
        **KSI-MLA-08: Log Data Access**
        Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-MLA-08",
            "ksi_name": "Log Data Access",
            "azure_services": [
                {
                    "service": "Azure RBAC",
                    "purpose": "Role-based access control for Log Analytics workspaces",
                    "capabilities": [
                        "Log Analytics Reader role assignment",
                        "Table-level access control",
                        "Custom roles for limited log access",
                        "Access review and audit trails"
                    ]
                },
                {
                    "service": "Azure AD Privileged Identity Management (PIM)",
                    "purpose": "Just-in-time access to sensitive log data",
                    "capabilities": [
                        "Time-bound access to Log Analytics",
                        "Approval workflows for log access",
                        "Access request justification",
                        "Audit of privileged log access"
                    ]
                },
                {
                    "service": "Azure Monitor Private Link",
                    "purpose": "Secure network access to log data",
                    "capabilities": [
                        "Private endpoint for Log Analytics",
                        "Network isolation for log queries",
                        "Azure Private Link Scope (AMPLS)",
                        "Prevent public access to logs"
                    ]
                },
                {
                    "service": "Azure Activity Log",
                    "purpose": "Audit log of log data access and queries",
                    "capabilities": [
                        "Track who accessed logs",
                        "Query history and patterns",
                        "Failed access attempts",
                        "Export to SIEM for monitoring"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Log Access RBAC Audit",
                    "description": "Export role assignments for Log Analytics workspaces showing least-privilege access",
                    "automation": "Azure RBAC API queries",
                    "frequency": "Monthly",
                    "evidence_produced": "RBAC assignment report for log data access"
                },
                {
                    "method": "PIM Log Access Requests",
                    "description": "Track just-in-time access requests to sensitive logs with approval evidence",
                    "automation": "PIM audit logs via Microsoft Graph API",
                    "frequency": "Monthly",
                    "evidence_produced": "PIM access request log with justifications"
                },
                {
                    "method": "Log Query Audit Trail",
                    "description": "Monitor and report who is querying log data",
                    "automation": "Azure Activity Log queries for Log Analytics operations",
                    "frequency": "Weekly",
                    "evidence_produced": "Log access activity report"
                },
                {
                    "method": "Private Link Configuration Validation",
                    "description": "Verify Log Analytics workspaces use private endpoints and deny public access",
                    "automation": "Resource Graph query for workspace network configuration",
                    "frequency": "Monthly",
                    "evidence_produced": "Network security configuration report for log access"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["config-based", "log-based"],
            "implementation_guidance": {
                "quick_start": "Configure RBAC with least-privilege roles, enable PIM for sensitive log access, deploy Private Link, monitor Activity Log for access patterns",
                "azure_well_architected": "Follows Azure WAF security pillar for least-privilege and zero trust principles",
                "compliance_mapping": "Addresses NIST control si-11 (Error Handling) and access control principles"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-MLA-08 evidence.
        """
        return {
            "ksi_id": "KSI-MLA-08",
            "queries": [
                {
                    "name": "Log Analytics Workspace RBAC Assignments",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
                    "method": "GET",
                    "purpose": "Show role-based access control for log data",
                    "expected_result": "Limited role assignments with least-privilege principles"
                },
                {
                    "name": "PIM Eligible Assignments for Log Access",
                    "type": "microsoft_graph",
                    "endpoint": "/privilegedAccess/azureResources/roleAssignments?$filter=resourceId eq '{workspaceId}'&$expand=subject,roleDefinition",
                    "method": "GET",
                    "purpose": "Show just-in-time access configuration for sensitive logs",
                    "expected_result": "PIM-managed access for elevated log data access"
                },
                {
                    "name": "Log Data Access Activity",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        AzureActivity
                        | where TimeGenerated > ago(30d)
                        | where ResourceProvider == 'Microsoft.OperationalInsights'
                        | where OperationNameValue contains 'query'
                        | summarize QueryCount = count(), LastQuery = max(TimeGenerated) by Caller, CallerIpAddress
                        | order by QueryCount desc
                        """,
                    "purpose": "Track who is accessing log data and query patterns",
                    "expected_result": "Authorized personnel with legitimate access patterns"
                },
                {
                    "name": "Log Analytics Private Link Configuration",
                    "type": "azure_resource_graph",
                    "query": """
                        resources
                        | where type == 'microsoft.operationalinsights/workspaces'
                        | extend publicNetworkAccess = tostring(properties.publicNetworkAccessForIngestion)
                        | extend hasPrivateLink = isnotempty(properties.privateLinkScopedResources)
                        | project name, resourceGroup, publicNetworkAccess, hasPrivateLink, location
                        | where publicNetworkAccess != 'Disabled' or hasPrivateLink == false
                        """,
                    "purpose": "Verify workspaces use private endpoints and restrict public access",
                    "expected_result": "All workspaces with private link and public access disabled"
                },
                {
                    "name": "Failed Log Access Attempts",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        AzureActivity
                        | where TimeGenerated > ago(7d)
                        | where ResourceProvider == 'Microsoft.OperationalInsights'
                        | where ActivityStatusValue == 'Failed'
                        | summarize FailedAttempts = count() by Caller, CallerIpAddress, OperationNameValue
                        | order by FailedAttempts desc
                        """,
                    "purpose": "Detect unauthorized access attempts to log data",
                    "expected_result": "Minimal or zero failed attempts with investigation of anomalies"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI or Managed Identity with appropriate permissions",
                "permissions_required": [
                    "Reader and User Access Administrator for RBAC queries",
                    "PrivilegedAccess.Read.AzureResources for PIM queries",
                    "Log Analytics Reader for activity queries",
                    "Reader for Resource Graph queries"
                ],
                "automation_tools": [
                    "Azure CLI (az role assignment list)",
                    "PowerShell Az.OperationalInsights and Az.Resources modules",
                    "Microsoft Graph PowerShell SDK for PIM"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-MLA-08.
        """
        return {
            "ksi_id": "KSI-MLA-08",
            "artifacts": [
                {
                    "name": "Log Access RBAC Configuration",
                    "description": "Complete inventory of role assignments for Log Analytics workspaces",
                    "source": "Azure RBAC API",
                    "format": "JSON role assignment export",
                    "collection_frequency": "Monthly",
                    "retention_period": "3 years",
                    "automation": "Azure CLI or PowerShell script"
                },
                {
                    "name": "PIM Access Request Log",
                    "description": "History of just-in-time access requests to sensitive log data",
                    "source": "Azure AD PIM audit logs",
                    "format": "CSV from Graph API query",
                    "collection_frequency": "Monthly",
                    "retention_period": "7 years (access audit)",
                    "automation": "Microsoft Graph API scheduled query"
                },
                {
                    "name": "Log Query Activity Report",
                    "description": "Report of log data access patterns showing who queried logs and when",
                    "source": "Azure Activity Log",
                    "format": "CSV from KQL query",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "Scheduled KQL query with export"
                },
                {
                    "name": "Private Link Configuration Evidence",
                    "description": "Network security configuration for Log Analytics workspaces",
                    "source": "Azure Resource Manager",
                    "format": "JSON configuration export",
                    "collection_frequency": "Quarterly",
                    "retention_period": "3 years",
                    "automation": "Resource Graph query"
                },
                {
                    "name": "Failed Access Attempts Report",
                    "description": "Log of failed attempts to access log data with investigation notes",
                    "source": "Azure Activity Log",
                    "format": "CSV with incident tracking",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "KQL query with alerting on anomalies"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["si-11", "ac-6", "au-9"],
                "evidence_purpose": "Demonstrate least-privilege, JIT access control for sensitive log data"
            }
        }

