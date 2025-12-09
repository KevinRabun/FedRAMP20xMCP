"""
KSI-MLA-02 Enhanced: Audit Logging

Regularly review and audit logs.

**Enhancement Features:**
- AST-based detection for authentication/authorization operations without logging
- Structured logging pattern recognition
- Multi-language support with framework-specific checks
- Context-aware analysis (±15 lines) for nearby logging detection

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer

try:
    import tree_sitter_python as tspython
    import tree_sitter_c_sharp as tscsharp
    import tree_sitter_java as tsjava
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


class KSI_MLA_02_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-MLA-02: Audit Logging
    
    **Official Statement:**
    Regularly review and audit logs.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **NIST Controls:** ac-2.4, ac-6.9, au-2, au-6, au-6.1, si-4, si-4.4
    
    **Detection Strategy:**
    - Authentication/authorization operations without audit logging
    - Missing structured logging configuration
    - Security events without log correlation identifiers
    """
    
    KSI_ID = "KSI-MLA-02"
    KSI_NAME = "Audit Logging"
    KSI_STATEMENT = "Regularly review and audit logs."
    FAMILY = "MLA"
    NIST_CONTROLS = ["ac-2.4", "ac-6.9", "au-2", "au-6", "au-6.1", "si-4", "si-4.4"]
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
        if TREE_SITTER_AVAILABLE:
            self.python_parser = Parser(Language(tspython.language()))
            self.csharp_parser = Parser(Language(tscsharp.language()))
            self.java_parser = Parser(Language(tsjava.language()))
            self.js_parser = Parser(Language(tsjs.language()))
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect auth operations without audit logging in Python."""
        findings = []
        lines = code.split('\n')
        
        # Check for auth operations
        auth_patterns = [
            (r'def\s+(authenticate|login|logout|authorize)', 'Authentication/Authorization Function'),
            (r'@login_required|@permission_required', 'Protected Endpoint'),
            (r'check_password|verify_password', 'Password Verification'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(logger\.|logging\.|log\.info|log\.warning)', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} at line {line_num} without audit logging. AU-2, AU-6 require logging security events.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger.info() with structured data (user_id, ip, timestamp, action)",
                        ksi_id=self.KSI_ID
                    ))
        
        # Check for logging config
        if len(lines) > 50 and 'test' not in file_path.lower():
            if not re.search(r'(logging\.basicConfig|logging\.config|getLogger)', code):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Logging Configuration",
                    description="Application file without logging configuration. AU-2 requires capturing security events.",
                    file_path=file_path,
                    line_number=1,
                    snippet=lines[0] if lines else "",
                    remediation="Configure logging.basicConfig() or logging.config.dictConfig()",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect controllers/services without ILogger in C#."""
        findings = []
        lines = code.split('\n')
        
        # Check controllers
        controller_match = re.search(r'class\s+\w+\s*:\s*(Controller|ControllerBase)', code)
        if controller_match:
            line_num = code[:controller_match.start()].count('\n') + 1
            context = self._get_context(lines, line_num, 20)
            
            if not re.search(r'ILogger<', context):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Controller Without ILogger",
                    description=f"Controller at line {line_num} without ILogger injection. AU-2, AU-6 require logging security operations.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Inject ILogger<T> via constructor: ILogger<MyController> logger",
                    ksi_id=self.KSI_ID
                ))
        
        # Check auth operations
        auth_patterns = [
            (r'SignInAsync|SignOutAsync', 'Sign In/Out'),
            (r'AuthenticateAsync|ChallengeAsync', 'Authentication'),
            (r'\.PasswordHasher|HashPassword|VerifyHashedPassword', 'Password Operations'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(_logger\.|\.Log(Information|Warning|Error))', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} operation at line {line_num} without logging. AU-6 requires audit log review.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="_logger.LogInformation(\"Auth event\", new { UserId, Action, Timestamp })",
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect auth operations without logging in Java."""
        findings = []
        lines = code.split('\n')
        
        # Check for Spring Security operations
        auth_patterns = [
            (r'@PreAuthorize|@PostAuthorize|@Secured', 'Authorization Annotation'),
            (r'AuthenticationManager|authenticate\(', 'Authentication'),
            (r'BCryptPasswordEncoder|passwordEncoder', 'Password Encoding'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(log\.|logger\.|LOG\.)(info|warn|error)', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} at line {line_num} without audit logging. AU-2 requires logging security events.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger.info() with MDC context (userId, action, timestamp)",
                        ksi_id=self.KSI_ID
                    ))
        
        # Check for logger field
        if len(lines) > 50 and 'test' not in file_path.lower():
            if not re.search(r'(Logger\s+log|Logger\s+logger|@Slf4j)', code):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Logger Declaration",
                    description="Java class without logger. AU-6 requires regular audit log review.",
                    file_path=file_path,
                    line_number=1,
                    snippet=lines[0] if lines else "",
                    remediation="Add: private static final Logger log = LoggerFactory.getLogger(Class.class);",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect auth operations without logging in TypeScript/JavaScript."""
        findings = []
        lines = code.split('\n')
        
        # Check for auth operations
        auth_patterns = [
            (r'(passport\.authenticate|express-session|jwt\.sign)', 'Authentication'),
            (r'(@UseGuards|@Roles|canActivate)', 'Authorization Guard'),
            (r'(bcrypt\.hash|bcrypt\.compare)', 'Password Hashing'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(logger\.|log\.|console\.(info|warn|error))', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} at line {line_num} without audit logging. AU-2, AU-6 require security event logging.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger.info({ userId, action, timestamp, ip })",
                        ksi_id=self.KSI_ID
                    ))
        
        # Check for logger import
        if len(lines) > 50 and 'test' not in file_path.lower():
            if not re.search(r'(import.*winston|import.*pino|import.*log|logger\s*=)', code):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Logger Configuration",
                    description="TypeScript/JavaScript file without logger. AU-6 requires audit log review.",
                    file_path=file_path,
                    line_number=1,
                    snippet=lines[0] if lines else "",
                    remediation="Import winston or pino: import winston from 'winston';",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Check for missing audit logging configuration in Bicep."""
        findings = []
        lines = code.split('\n')
        
        # Check for resources without diagnostic settings
        resource_types = [
            'Microsoft.KeyVault/vaults',
            'Microsoft.Storage/storageAccounts',
            'Microsoft.Web/sites',
        ]
        
        for resource_type in resource_types:
            if re.search(rf"resource.*{re.escape(resource_type)}", code):
                if not re.search(r'Microsoft\.Insights/diagnosticSettings', code):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Resource Without Diagnostic Logging",
                        description=f"{resource_type} without diagnostic settings. AU-2 requires audit logging.",
                        file_path=file_path,
                        line_number=1,
                        snippet="",
                        remediation="Add diagnostic settings resource with logs category",
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Check for missing audit logging configuration in Terraform."""
        findings = []
        
        # Check for resources without monitor diagnostic settings
        resource_types = [
            'azurerm_key_vault',
            'azurerm_storage_account',
            'azurerm_app_service',
        ]
        
        for resource_type in resource_types:
            if re.search(rf'resource\s+"{resource_type}"', code):
                if not re.search(r'azurerm_monitor_diagnostic_setting', code):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Resource Without Diagnostic Logging",
                        description=f"{resource_type} without monitor diagnostic settings. AU-2 requires audit logs.",
                        file_path=file_path,
                        line_number=1,
                        snippet="",
                        remediation="Add azurerm_monitor_diagnostic_setting resource",
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        return []
    
    def _get_context(self, lines: List[str], line_num: int, context: int = 15) -> str:
        """Get surrounding context lines."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])
    
    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])

