"""
KSI-IAM-06: Suspicious Activity

Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_IAM_06_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-IAM-06: Suspicious Activity
    
    **Official Statement:**
    Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2: Account Management
    - ac-2.1: Automated System Account Management
    - ac-2.3: Disable Accounts
    - ac-2.13: Disable Accounts for High-risk Individuals
    - ac-7: Unsuccessful Logon Attempts
    - ps-4: Personnel Termination
    - ps-8: Personnel Sanctions
    
    **Detectability:** Code-Detectable (High Confidence)
    
    **Detection Strategy:**
    Look for:
    1. Failed login attempt monitoring and thresholds
    2. Account lockout configurations
    3. Automated account disabling mechanisms
    4. Integration with SIEM/monitoring for suspicious activity
    5. Privileged account specific protections
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: Not applicable for this KSI
    """
    
    KSI_ID = "KSI-IAM-06"
    KSI_NAME = "Suspicious Activity"
    KSI_STATEMENT = "Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity"
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-2", "ac-2.1", "ac-2.3", "ac-2.13", "ac-7", "ps-4", "ps-8"]
    RETIRED = False
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
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
        Analyze Python code for KSI-IAM-06: Suspicious Activity compliance.
        
        Frameworks: Flask, Django, FastAPI
        
        Patterns Detected:
        - Flask-Login failed attempt tracking
        - Django AXES (django-axes) failed login monitoring
        - Django settings: MAX_LOGIN_ATTEMPTS, ACCOUNT_LOCKOUT_*
        - Custom failed login handlers
        - Account lockout logic
        - Integration with monitoring systems
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Django AXES (automated account lockout)
        if 'django-axes' in code or 'axes' in code.lower():
            if not re.search(r'AXES_FAILURE_LIMIT\s*=\s*\d+', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing AXES_FAILURE_LIMIT configuration",
                    description="django-axes is present but AXES_FAILURE_LIMIT is not configured. This setting defines how many failed login attempts trigger account lockout.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'axes'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'axes')),
                    recommendation="Configure AXES_FAILURE_LIMIT (e.g., AXES_FAILURE_LIMIT = 5) in Django settings to automatically lock accounts after repeated failed login attempts."
                ))
        
        # Check for Django MAX_LOGIN_ATTEMPTS
        max_attempts_match = re.search(r'MAX_LOGIN_ATTEMPTS\s*=\s*(\d+)', code)
        if max_attempts_match:
            attempts = int(max_attempts_match.group(1))
            if attempts > 10:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Weak account lockout threshold",
                    description=f"MAX_LOGIN_ATTEMPTS is set to {attempts}, which is too high. FedRAMP recommends 5-10 failed attempts before lockout.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'MAX_LOGIN_ATTEMPTS'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'MAX_LOGIN_ATTEMPTS')),
                    recommendation="Set MAX_LOGIN_ATTEMPTS to 5-10 to comply with KSI-IAM-06 and NIST AC-7 (Unsuccessful Logon Attempts)."
                ))
        
        # Check for Flask-Login without lockout mechanism
        if 'flask_login' in code or 'from flask_login import' in code:
            has_lockout = bool(re.search(r'login_attempts|failed_login|account_locked', code, re.IGNORECASE))
            if not has_lockout:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing account lockout mechanism in Flask-Login",
                    description="Flask-Login is used but no failed login tracking or account lockout mechanism is detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'flask_login'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'flask_login')),
                    recommendation="Implement failed login tracking and automatic account lockout. Track failed_login_count and lock accounts after 5-10 attempts."
                ))
        
        # Check for monitoring/logging of failed logins
        has_failed_login_logging = bool(re.search(r'log.*failed.*login|login.*failed.*attempt', code, re.IGNORECASE))
        if not has_failed_login_logging and ('login' in code.lower() or 'authenticate' in code.lower()):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing failed login attempt logging",
                description="Authentication code detected but no logging of failed login attempts found.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                recommendation="Log all failed login attempts with timestamp, username, and source IP for monitoring suspicious activity per NIST AC-7."
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-06: Suspicious Activity compliance.
        
        Frameworks: ASP.NET Core Identity, Azure AD
        
        Patterns Detected:
        - SignInManager.MaxFailedAccessAttempts
        - LockoutEnabled configuration
        - DefaultLockoutTimeSpan
        - Failed sign-in attempt tracking
        - Azure AD Conditional Access integration
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Identity options
        if 'AddIdentity' in code or 'IdentityOptions' in code:
            # Check MaxFailedAccessAttempts
            max_failed_match = re.search(r'MaxFailedAccessAttempts\s*=\s*(\d+)', code)
            if max_failed_match:
                attempts = int(max_failed_match.group(1))
                if attempts > 10:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Weak MaxFailedAccessAttempts configuration",
                        description=f"MaxFailedAccessAttempts is set to {attempts}, which exceeds FedRAMP recommendations (5-10 attempts).",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=self._find_line(lines, 'MaxFailedAccessAttempts'),
                        code_snippet=self._get_snippet(lines, self._find_line(lines, 'MaxFailedAccessAttempts')),
                        recommendation="Set MaxFailedAccessAttempts to 5-10 to comply with NIST AC-7 requirements."
                    ))
            else:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="MaxFailedAccessAttempts not configured",
                    description="ASP.NET Core Identity is configured but MaxFailedAccessAttempts is not explicitly set.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'AddIdentity'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'AddIdentity')),
                    recommendation="Configure options.Lockout.MaxFailedAccessAttempts = 5 in Identity setup."
                ))
            
            # Check LockoutEnabled
            if 'LockoutEnabled' not in code or 'LockoutEnabled = false' in code:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Account lockout not enabled",
                    description="LockoutEnabled is not set to true, disabling automatic account lockout on failed attempts.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'Identity'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'Identity')),
                    recommendation="Set options.Lockout.AllowedForNewUsers = true and DefaultLockoutTimeSpan to enable account lockout."
                ))
            
            # Check DefaultLockoutTimeSpan
            if 'DefaultLockoutTimeSpan' not in code:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Lockout duration not configured",
                    description="DefaultLockoutTimeSpan is not configured, using default lockout duration.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'AddIdentity'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'AddIdentity')),
                    recommendation="Configure options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30) for adequate lockout duration."
                ))
        
        # Check for SignInManager usage without lockout handling
        if 'SignInManager' in code and 'PasswordSignInAsync' in code:
            has_lockout_check = bool(re.search(r'IsLockedOut|LockedOut|lockoutOnFailure:\s*true', code))
            if not has_lockout_check:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="SignInManager not configured for lockout on failure",
                    description="PasswordSignInAsync is used but lockoutOnFailure parameter not explicitly set to true.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'PasswordSignInAsync'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'PasswordSignInAsync')),
                    recommendation="Set lockoutOnFailure: true in PasswordSignInAsync calls to enable automatic lockout."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-06: Suspicious Activity compliance.
        
        Frameworks: Spring Security, Spring Boot
        
        Patterns Detected:
        - Spring Security failureHandler
        - AccountStatusException handling
        - LockedException handling
        - Custom authentication failure logic
        - Spring Session management
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Spring Security authentication failure handling
        if 'AuthenticationFailureHandler' in code or 'failureHandler' in code:
            has_lockout = bool(re.search(r'LockedException|DisabledException|account.*lock', code, re.IGNORECASE))
            if not has_lockout:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Authentication failure handler missing lockout logic",
                    description="Custom AuthenticationFailureHandler detected but no account lockout logic found.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'AuthenticationFailureHandler'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'AuthenticationFailureHandler')),
                    recommendation="Implement account lockout after repeated failed attempts. Track failures and throw LockedException when threshold is exceeded."
                ))
        
        # Check for UserDetailsService without lockout mechanism
        if 'UserDetailsService' in code or 'loadUserByUsername' in code:
            has_account_status = bool(re.search(r'isAccountNonLocked|accountNonLocked|locked', code))
            if not has_account_status:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="UserDetailsService missing account lock status",
                    description="Custom UserDetailsService detected but isAccountNonLocked() not implemented.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'UserDetailsService'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'UserDetailsService')),
                    recommendation="Implement isAccountNonLocked() to return account lock status and integrate with failed login tracking."
                ))
        
        # Check for @PreAuthorize without suspicious activity checks
        if '@PreAuthorize' in code and 'admin' in code.lower():
            has_monitoring = bool(re.search(r'audit|log|monitor', code.lower()))
            if not has_monitoring:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Privileged access without monitoring",
                    description="@PreAuthorize used for admin/privileged access but no audit logging detected.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, '@PreAuthorize'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, '@PreAuthorize')),
                    recommendation="Add audit logging for privileged account access to enable suspicious activity detection."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-06: Suspicious Activity compliance.
        
        Frameworks: Passport.js, Express, NestJS
        
        Patterns Detected:
        - Passport.js strategy configurations
        - Express-rate-limit for failed attempts
        - Custom lockout middleware
        - Account status checking
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Passport.js without rate limiting
        if 'passport' in code.lower() and ('local' in code.lower() or 'strategy' in code.lower()):
            has_rate_limit = bool(re.search(r'rateLimit|rate-limit|express-rate-limit', code, re.IGNORECASE))
            if not has_rate_limit:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Passport authentication without rate limiting",
                    description="Passport.js authentication detected but no rate limiting middleware found.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'passport'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'passport')),
                    recommendation="Add express-rate-limit or express-brute to limit failed login attempts and automatically lock accounts."
                ))
        
        # Check for login route without lockout mechanism
        if re.search(r'(app\.(post|use)|router\.(post|use)).*[\'\"](/login|/signin|/auth)', code):
            has_lockout = bool(re.search(r'locked|lockout|failed.*attempt|accountLocked', code, re.IGNORECASE))
            if not has_lockout:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Login endpoint missing account lockout",
                    description="Login/signin endpoint detected but no account lockout mechanism implemented.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, '/login'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, '/login')),
                    recommendation="Implement failed login tracking and automatic account lockout after 5-10 failed attempts."
                ))
        
        # Check for NestJS @UseGuards without throttle
        if '@UseGuards' in code and 'Auth' in code:
            has_throttle = bool(re.search(r'@Throttle|ThrottlerGuard', code))
            if not has_throttle:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="NestJS authentication without throttling",
                    description="@UseGuards authentication detected but no @Throttle or ThrottlerGuard configured.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, '@UseGuards'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, '@UseGuards')),
                    recommendation="Add @nestjs/throttler and configure ThrottlerGuard to limit login attempts."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-IAM-06: Suspicious Activity compliance.
        
        Resources Checked:
        - Azure Monitor alert rules for failed sign-ins
        - Log Analytics queries for suspicious activity
        - Azure AD Conditional Access policies
        - Application Insights availability tests
        
        Patterns Detected:
        - Alert rules for failed authentication
        - Conditional Access requiring MFA on suspicious activity
        - Sign-in risk policies
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Azure Monitor alert rules
        if 'Microsoft.Insights/scheduledQueryRules' in code or 'Microsoft.Insights/metricAlerts' in code:
            has_failed_signin_alert = bool(re.search(r'failed.*sign.*in|sign.*in.*fail|authentication.*fail', code, re.IGNORECASE))
            if not has_failed_signin_alert:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing alert rule for failed sign-ins",
                    description="Azure Monitor alerts configured but no alert for failed sign-in attempts detected.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'Insights'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'Insights')),
                    recommendation="Create scheduled query rule to monitor SigninLogs for ResultType != 0 (failed sign-ins) and alert on threshold exceeding 5 attempts."
                ))
        
        # Check for Log Analytics workspace without signin monitoring
        if 'Microsoft.OperationalInsights/workspaces' in code:
            has_signin_query = bool(re.search(r'SigninLogs|AuditLogs.*SignIn', code))
            if not has_signin_query:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Log Analytics workspace not configured for sign-in monitoring",
                    description="Log Analytics workspace deployed but no queries for monitoring sign-in activity.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'OperationalInsights'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'OperationalInsights')),
                    recommendation="Configure SigninLogs data source and create queries to detect repeated failed sign-in attempts."
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-IAM-06: Suspicious Activity compliance.
        
        Resources Checked:
        - azurerm_monitor_scheduled_query_rules_alert
        - azurerm_monitor_metric_alert
        - azurerm_log_analytics_workspace
        - Azure AD conditional access policies
        
        Patterns Detected:
        - Alert rules for failed authentication
        - Sign-in risk monitoring
        - Lockout automation
        """
        findings = []
        lines = code.split('\n')
        
        # Check for monitor alert rules
        if 'azurerm_monitor_scheduled_query_rules_alert' in code or 'azurerm_monitor_metric_alert' in code:
            has_failed_signin = bool(re.search(r'failed.*sign.*in|sign.*in.*fail|authentication.*fail', code, re.IGNORECASE))
            if not has_failed_signin:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Monitor alert missing failed sign-in detection",
                    description="Azure Monitor alert configured but does not monitor for failed sign-in attempts.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'azurerm_monitor'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'azurerm_monitor')),
                    recommendation="Add query to monitor SigninLogs for ResultType != 0 and trigger alert when threshold is exceeded (5+ failures)."
                ))
        
        # Check for Log Analytics workspace
        if 'azurerm_log_analytics_workspace' in code:
            # Look for corresponding alert rules
            has_alert = bool(re.search(r'azurerm_monitor.*alert', code))
            if not has_alert:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Log Analytics workspace without monitoring alerts",
                    description="Log Analytics workspace deployed but no associated alert rules for suspicious activity.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=self._find_line(lines, 'azurerm_log_analytics_workspace'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, 'azurerm_log_analytics_workspace')),
                    recommendation="Create scheduled query alert to monitor failed sign-ins and automatically respond to suspicious activity."
                ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
