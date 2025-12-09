"""KSI-CMT-01 Enhanced: Version Control and Change Logging"""

import ast
import re
from typing import List
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
    

        """Get code snippet around line"""
        if not lines or line_num < 1:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])

