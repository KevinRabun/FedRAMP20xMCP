"""KSI-CMT-01 Enhanced: Version Control and Change Logging"""

import ast
import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CMT_01_Analyzer(BaseKSIAnalyzer):
    """
    KSI-CMT-01: Version Control and Change Logging
    
    Log and monitor modifications to the cloud service offering.
    
    NIST: au-2, cm-3, cm-3.2, cm-4.2, cm-6, cm-8.3, ma-2
    Focus: Version control usage, change logging, audit trails
    """
    
    KSI_ID = "KSI-CMT-01"
    KSI_NAME = "Version Control and Change Logging"
    KSI_STATEMENT = "Log and monitor modifications to the cloud service offering."
    FAMILY = "CMT"
    FAMILY_NAME = "Change Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("au-2", "Event Logging"),
        ("cm-3", "Configuration Change Control"),
        ("cm-3.2", "Testing, Validation, and Documentation of Changes"),
        ("cm-4.2", "Verification of Controls"),
        ("cm-6", "Configuration Settings"),
        ("cm-8.3", "Automated Unauthorized Component Detection"),
        ("ma-2", "Controlled Maintenance")
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
        """Python: Direct file writes without version control, missing audit logs"""
        findings = []
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fall back to regex if AST parsing fails
            return self._python_regex_fallback(code, file_path)
        
        lines = code.split('\n')
        
        # Track logger usage in the code
        has_logging_import = False
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ['logging', 'logger']:
                            has_logging_import = True
                elif isinstance(node, ast.ImportFrom):
                    if node.module and 'log' in node.module.lower():
                        has_logging_import = True
        
        # Find file write operations
        for node in ast.walk(tree):
            # Pattern 1: open() with write mode
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'id') and node.func.id == 'open':
                    # Check if mode is 'w' or 'a' (write/append)
                    has_write_mode = False
                    for arg in node.args[1:]:  # Skip filename arg
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if 'w' in arg.value or 'a' in arg.value:
                                has_write_mode = True
                                break
                    
                    # Check keywords for mode
                    for keyword in node.keywords:
                        if keyword.arg == 'mode' and isinstance(keyword.value, ast.Constant):
                            if 'w' in keyword.value.value or 'a' in keyword.value.value:
                                has_write_mode = True
                                break
                    
                    if has_write_mode:
                        line_num = node.lineno
                        # Check context for logging
                        context_start = max(1, line_num - 3)
                        context_end = min(len(lines), line_num + 3)
                        context = '\n'.join(lines[context_start-1:context_end])
                        
                        has_audit = bool(re.search(r'log\.|logger\.|logging\.', context, re.IGNORECASE))
                        if not has_audit and not has_logging_import:
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title="File write operation without audit logging",
                                description=(
                                    f"open() with write mode at line {line_num} without audit trail. "
                                    "KSI-CMT-01 requires logging modifications to cloud service offering (AU-2, CM-3, CM-3.2). "
                                    "All file modifications should be logged for change tracking and compliance auditing."
                                ),
                                severity=Severity.MEDIUM,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num),
                                remediation=(
                                    "Add audit logging before file operations:\n"
                                    "import logging\n\n"
                                    "logger = logging.getLogger(__name__)\n\n"
                                    "# Log file modification\n"
                                    "logger.info(f'Writing to file: {filename}', extra={\n"
                                    "    'user': current_user,\n"
                                    "    'action': 'file_write',\n"
                                    "    'resource': filename,\n"
                                    "    'timestamp': datetime.utcnow()\n"
                                    "})\n\n"
                                    "with open(filename, 'w') as f:\n"
                                    "    f.write(data)\n\n"
                                    "NIST Controls: AU-2 (Audit Events), CM-3 (Change Control), CM-3.2 (Automated Change Control)\n"
                                )
                            ))
                
                # Pattern 2: shutil.copy, shutil.move
                if isinstance(node.func, ast.Attribute):
                    if hasattr(node.func.value, 'id') and node.func.value.id == 'shutil':
                        if node.func.attr in ['copy', 'copy2', 'move', 'copytree']:
                            line_num = node.lineno
                            context_start = max(1, line_num - 3)
                            context_end = min(len(lines), line_num + 3)
                            context = '\n'.join(lines[context_start-1:context_end])
                            
                            has_audit = bool(re.search(r'log\.|logger\.|logging\.', context, re.IGNORECASE))
                            if not has_audit:
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title=f"shutil.{node.func.attr}() without audit logging",
                                    description=(
                                        f"shutil.{node.func.attr}() at line {line_num} without audit trail. "
                                        "File copy/move operations must be logged for change tracking (CM-3)."
                                    ),
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    remediation=(
                                        "Add audit logging for file operations:\n"
                                        "logger.info(f'File operation: {operation}', extra={\n"
                                        "    'action': 'file_copy',\n"
                                        "    'source': source_path,\n"
                                        "    'destination': dest_path\n"
                                        "})\n"
                                        "shutil.copy(source, dest)\n\n"
                                        "NIST Controls: CM-3 (Change Control)\n"
                                    )
                                ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Direct file modifications without audit
        file_write_patterns = [
            (r'open\([^)]*,\s*[\'"]w', 'open() for writing'),
            (r'shutil\.copy', 'shutil.copy()'),
            (r'shutil\.move', 'shutil.move()'),
        ]
        
        for pattern, desc in file_write_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context_start = max(1, line_num - 3)
                context_end = min(len(lines), line_num + 3)
                context = '\n'.join(lines[context_start-1:context_end])
                
                # Check if audit logging present
                has_audit = bool(re.search(r'log\.|logger\.|audit', context, re.IGNORECASE))
                if not has_audit:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="File modification without audit logging (Regex Fallback)",
                        description=f"{desc} at line {line_num} without audit trail (detected via regex fallback)",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add audit logging before file operations (AU-2, CM-3)"
                    ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """C#: File operations, database changes without audit"""
        findings = []
        lines = code.split('\n')
        
        # File operations without logging
        file_ops = [
            (r'File\.Write', 'File.Write*'),
            (r'File\.Copy', 'File.Copy'),
            (r'File\.Move', 'File.Move'),
            (r'File\.Delete', 'File.Delete'),
        ]
        
        for pattern, desc in file_ops:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_logging = bool(re.search(r'ILogger|Log\.|_logger', context))
                if not has_logging:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="File operation without logging",
                        description=f"{desc} at line {line_num} without audit log",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Inject ILogger and log file operations (cm-3, au-2)"
                    ))
        
        # SaveChanges without audit
        if re.search(r'SaveChanges\(\)', code):
            for match in re.finditer(r'SaveChanges\(\)', code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_logging = bool(re.search(r'ILogger|Log\.|_logger', context))
                if not has_logging:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Database changes without audit",
                        description=f"SaveChanges at line {line_num} without audit logging",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Log entity changes before SaveChanges (au-2, cm-6)"
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Java: File I/O, JPA persist without audit"""
        findings = []
        lines = code.split('\n')
        
        # File operations
        file_patterns = [
            (r'FileWriter|FileOutputStream', 'File write operation'),
            (r'Files\.write', 'Files.write'),
            (r'Files\.copy', 'Files.copy'),
            (r'Files\.move', 'Files.move'),
        ]
        
        for pattern, desc in file_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_logger = bool(re.search(r'Logger|log\.|LOGGER', context))
                if not has_logger:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="File operation without logging",
                        description=f"{desc} at line {line_num} without audit",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add Logger and audit file operations (cm-3)"
                    ))
        
        # JPA/Hibernate operations
        persist_patterns = [
            (r'\.persist\(', 'EntityManager.persist'),
            (r'\.merge\(', 'EntityManager.merge'),
            (r'\.remove\(', 'EntityManager.remove'),
        ]
        
        for pattern, desc in persist_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_logger = bool(re.search(r'Logger|log\.|LOGGER', context))
                if not has_logger:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Database modification without audit",
                        description=f"{desc} at line {line_num} without logging",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Log entity changes before persist/merge (au-2)"
                    ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """TypeScript: fs operations, database writes without logging"""
        findings = []
        lines = code.split('\n')
        
        # File system operations
        fs_patterns = [
            (r'fs\.write\w*', 'fs.write*'),  # Match writeFile, writeFileSync, etc.
            (r'fs\.copy', 'fs.copy'),
            (r'fs\.move', 'fs.move'),
            (r'fs\.unlink', 'fs.unlink'),
        ]
        
        for pattern, desc in fs_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_logger = bool(re.search(r'logger\.|console\.log|winston', context, re.IGNORECASE))
                if not has_logger:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="File operation without logging",
                        description=f"{desc} at line {line_num} without audit",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger and audit file operations (cm-3)"
                    ))
        
        # Database operations
        db_patterns = [
            (r'\.save\(\)', 'save()'),
            (r'\.create\(', 'create()'),
            (r'\.update\(', 'update()'),
            (r'\.delete\(', 'delete()'),
        ]
        
        for pattern, desc in db_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_logger = bool(re.search(r'logger\.|console\.log|winston', context, re.IGNORECASE))
                if not has_logger:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Database modification without logging",
                        description=f"{desc} at line {line_num} without audit trail",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Log database changes before operations (au-2)"
                    ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Bicep: Missing Activity Log diagnostic settings, change tracking"""
        findings = []
        lines = code.split('\n')
        
        # Check for Activity Log diagnostic settings
        has_activity_log = bool(re.search(r'Microsoft\.Insights/diagnosticSettings', code))
        has_activity_log_category = bool(re.search(r'Administrative|Write|Delete', code))
        
        if not has_activity_log or not has_activity_log_category:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Activity Log diagnostic settings",
                description="No Activity Log forwarding for change monitoring (Administrative, Write, Delete)",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="Activity Log categories missing",
                remediation="Add diagnosticSettings for Activity Log with Administrative/Write/Delete categories (cm-3, au-2)"
            ))
        
        # Check for resources without diagnostic settings
        resource_types = [
            'Microsoft.KeyVault/vaults',
            'Microsoft.Storage/storageAccounts',
            'Microsoft.Web/sites',
        ]
        
        for resource_type in resource_types:
            if re.search(resource_type, code):
                # Check if diagnostic settings exist nearby
                has_diag = bool(re.search(rf'{resource_type}.*diagnosticSettings', code, re.DOTALL))
                if not has_diag:
                    result = self._find_line(lines, resource_type)

                    line_num = result['line_num'] if result else 0
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"{resource_type} without change tracking",
                        description=f"Resource at line {line_num} lacks diagnostic settings for change monitoring",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation=f"Add diagnosticSettings to track {resource_type} changes (cm-8.3)"
                    ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Terraform: Missing activity logs, change tracking"""
        findings = []
        lines = code.split('\n')
        
        # Check for activity log diagnostic settings
        has_monitor_diag = bool(re.search(r'azurerm_monitor_diagnostic_setting', code))
        has_activity_log = bool(re.search(r'log.*category.*Administrative|Write|Delete', code, re.DOTALL))
        
        if not has_monitor_diag or not has_activity_log:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Azure Monitor diagnostic settings",
                description="No activity log forwarding for change monitoring",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="Activity log categories missing",
                remediation="Add azurerm_monitor_diagnostic_setting with Administrative/Write/Delete logs (cm-3, au-2)"
            ))
        
        # Check resources without diagnostic settings
        resource_patterns = [
            (r'azurerm_key_vault', 'Key Vault'),
            (r'azurerm_storage_account', 'Storage Account'),
            (r'azurerm_app_service', 'App Service'),
        ]
        
        for pattern, name in resource_patterns:
            if re.search(pattern, code):
                # Look for diagnostic settings for this resource
                has_diag = bool(re.search(rf'{pattern}.*azurerm_monitor_diagnostic_setting', code, re.DOTALL))
                if not has_diag:
                    result = self._find_line(lines, pattern)

                    line_num = result['line_num'] if result else 0
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"{name} without change tracking",
                        description=f"Resource at line {line_num} lacks diagnostic settings",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation=f"Add azurerm_monitor_diagnostic_setting for {name} (cm-8.3)"
                    ))
        
        return findings
    
    def _get_snippet(self, lines: List[str], line_num: int, context: int = 3) -> str:
        """Get code snippet around line"""
        if not lines or line_num < 1:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-CMT-01.
        
        **KSI-CMT-01: Version Control and Change Logging**
        Log and monitor modifications to the cloud service offering.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-CMT-01",
            "ksi_name": "Version Control and Change Logging",
            "azure_services": [
                {
                    "service": "Azure DevOps / GitHub",
                    "purpose": "Version control for all infrastructure and application code",
                    "capabilities": [
                        "Git version control with commit history",
                        "Branch policies and approvals",
                        "Pull request reviews",
                        "Audit log of all changes"
                    ]
                },
                {
                    "service": "Azure Activity Log",
                    "purpose": "Audit trail of all Azure resource modifications",
                    "capabilities": [
                        "Resource create/update/delete logging",
                        "Who, what, when tracking",
                        "Long-term retention (up to 90 days default, unlimited with export)",
                        "Integration with Log Analytics"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Enforce version control and change management requirements",
                    "capabilities": [
                        "Require deployments via approved pipelines",
                        "Audit manual changes",
                        "Tag resources with change tracking metadata",
                        "Compliance reporting"
                    ]
                },
                {
                    "service": "Azure Automation Change Tracking",
                    "purpose": "Track configuration changes to VMs and software",
                    "capabilities": [
                        "File and registry change tracking",
                        "Software inventory changes",
                        "Service and daemon changes",
                        "Change history and rollback"
                    ]
                },
                {
                    "service": "Azure Monitor",
                    "purpose": "Comprehensive change monitoring and alerting",
                    "capabilities": [
                        "Configuration change alerts",
                        "Deployment history tracking",
                        "Change correlation and analytics",
                        "Integration with SIEM"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Git Commit History Export",
                    "description": "Export Git commit history showing all code changes with authors and timestamps",
                    "automation": "Azure DevOps/GitHub API",
                    "frequency": "Monthly",
                    "evidence_produced": "Git commit log with change descriptions"
                },
                {
                    "method": "Azure Resource Change History",
                    "description": "Track all resource configuration changes via Activity Log",
                    "automation": "Azure Activity Log queries",
                    "frequency": "Weekly",
                    "evidence_produced": "Resource change audit trail"
                },
                {
                    "method": "Deployment Pipeline Audit",
                    "description": "Log all deployments showing approved pipelines were used",
                    "automation": "Azure DevOps deployment history API",
                    "frequency": "Weekly",
                    "evidence_produced": "Deployment audit log with approval evidence"
                },
                {
                    "method": "Configuration Drift Detection",
                    "description": "Detect manual changes not tracked in version control",
                    "automation": "Azure Automation Change Tracking + Policy",
                    "frequency": "Daily",
                    "evidence_produced": "Configuration drift report with remediation"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["log-based", "config-based"],
            "implementation_guidance": {
                "quick_start": "Enforce Git for all code, enable Activity Log export to Log Analytics, configure Change Tracking, deploy Azure Policy for pipeline enforcement",
                "azure_well_architected": "Follows Azure WAF operational excellence for change management and version control",
                "compliance_mapping": "Addresses NIST controls au-2, cm-3, cm-3.2, cm-6 for change control and audit"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-CMT-01 evidence.
        """
        return {
            "ksi_id": "KSI-CMT-01",
            "queries": [
                {
                    "name": "Git Commit History",
                    "type": "azure_devops_api",
                    "endpoint": "https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/commits?api-version=7.1",
                    "method": "GET",
                    "purpose": "Show all code changes with commit messages and authors",
                    "expected_result": "Complete audit trail of code changes"
                },
                {
                    "name": "Azure Resource Modifications",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        AzureActivity
                        | where TimeGenerated > ago(30d)
                        | where OperationNameValue endswith '/WRITE' or OperationNameValue endswith '/DELETE'
                        | project TimeGenerated, Caller, OperationNameValue, ResourceGroup, ResourceId, ActivityStatusValue
                        | order by TimeGenerated desc
                        """,
                    "purpose": "Track all resource create/update/delete operations",
                    "expected_result": "Complete audit trail with who/what/when"
                },
                {
                    "name": "Deployment Pipeline History",
                    "type": "azure_devops_api",
                    "endpoint": "https://dev.azure.com/{org}/{project}/_apis/release/deployments?api-version=7.1",
                    "method": "GET",
                    "purpose": "Show all deployments via approved pipelines",
                    "expected_result": "100% of changes via version-controlled pipelines"
                },
                {
                    "name": "Configuration Change Tracking",
                    "type": "kql",
                    "workspace": "Log Analytics with Change Tracking",
                    "query": """
                        ConfigurationChange
                        | where TimeGenerated > ago(7d)
                        | summarize ChangeCount = count() by Computer, ConfigChangeType, ChangeCategory
                        | order by ChangeCount desc
                        """,
                    "purpose": "Detect configuration changes on VMs",
                    "expected_result": "All changes documented and authorized"
                },
                {
                    "name": "Manual vs Pipeline Changes",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        AzureActivity
                        | where TimeGenerated > ago(30d)
                        | where OperationNameValue endswith '/WRITE'
                        | extend DeploymentMethod = iff(Caller contains 'azuredevops' or Caller contains 'github', 'Pipeline', 'Manual')
                        | summarize ChangeCount = count() by DeploymentMethod
                        | extend Percentage = round((ChangeCount * 100.0) / toscalar(AzureActivity | where TimeGenerated > ago(30d) | where OperationNameValue endswith '/WRITE' | count()), 2)
                        """,
                    "purpose": "Verify changes come from version-controlled pipelines",
                    "expected_result": "Near 100% pipeline-driven changes"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI or Managed Identity",
                "permissions_required": [
                    "DevOps Project Reader for Git/pipeline data",
                    "Log Analytics Reader for activity/change tracking queries",
                    "Reader for Activity Log access"
                ],
                "automation_tools": [
                    "Azure DevOps CLI extension",
                    "Azure CLI (az monitor activity-log)",
                    "PowerShell Az.Monitor module"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-CMT-01.
        """
        return {
            "ksi_id": "KSI-CMT-01",
            "artifacts": [
                {
                    "name": "Git Commit History Report",
                    "description": "Complete version control history with commit messages, authors, and timestamps",
                    "source": "Azure DevOps / GitHub",
                    "format": "CSV or JSON export",
                    "collection_frequency": "Monthly",
                    "retention_period": "7 years",
                    "automation": "Git API scheduled export"
                },
                {
                    "name": "Azure Activity Log Archive",
                    "description": "Complete audit trail of all Azure resource modifications",
                    "source": "Azure Activity Log",
                    "format": "JSON or CSV from Log Analytics",
                    "collection_frequency": "Daily (continuous ingestion)",
                    "retention_period": "7 years",
                    "automation": "Log Analytics export"
                },
                {
                    "name": "Deployment Pipeline Audit Log",
                    "description": "Record of all deployments with approval and version control evidence",
                    "source": "Azure DevOps / GitHub Actions",
                    "format": "JSON deployment history",
                    "collection_frequency": "Weekly",
                    "retention_period": "7 years",
                    "automation": "DevOps API export"
                },
                {
                    "name": "Configuration Change Report",
                    "description": "VM and service configuration changes with change tracking",
                    "source": "Azure Automation Change Tracking",
                    "format": "CSV from Log Analytics",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "Change Tracking API"
                },
                {
                    "name": "Change Management Policy Configuration",
                    "description": "Azure Policy definitions enforcing version control and pipeline usage",
                    "source": "Azure Policy",
                    "format": "JSON policy export",
                    "collection_frequency": "Quarterly",
                    "retention_period": "3 years",
                    "automation": "Policy definition export"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["au-2", "cm-3", "cm-3.2", "cm-6", "cm-8.3"],
                "evidence_purpose": "Demonstrate all changes logged, version controlled, and tracked with complete audit trail"
            }
        }

