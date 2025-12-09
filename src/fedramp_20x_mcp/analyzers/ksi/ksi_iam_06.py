"""
KSI-IAM-06: Suspicious Activity

Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity.

ENHANCED FEATURES:
- AST-based detection of account lockout configurations
- Failed login attempt threshold analysis
- Account disabling mechanism detection
- Integration with monitoring/SIEM detection
- Privileged account protection validation

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity, AnalysisResult
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_IAM_06_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-IAM-06: Suspicious Activity.
    
    **Official Statement:**
    Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:** Low: Yes, Moderate: Yes
    
    **NIST Controls:** ac-2, ac-2.1, ac-2.3, ac-2.13, ac-7, ps-4, ps-8
    
    **Detection Strategy:**
    - Application code: Detect account lockout configs, failed login tracking
    - IaC: Validate Azure AD/Entra ID lockout policies, Conditional Access
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    """
    
    KSI_ID = "KSI-IAM-06"
    KSI_NAME = "Suspicious Activity"
    KSI_STATEMENT = "Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity"
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-2", "Account Management"),
        ("ac-2.1", "Automated System Account Management"),
        ("ac-2.3", "Disable Accounts"),
        ("ac-2.13", "Disable Accounts for High-risk Individuals"),
        ("ac-7", "Unsuccessful Logon Attempts"),
        ("ps-4", "Personnel Termination"),
        ("ps-8", "Personnel Sanctions")
    ]
    
    # Framework-specific config keys
    LOCKOUT_CONFIGS = {
        "python": {
            "django": ["AXES_FAILURE_LIMIT", "MAX_LOGIN_ATTEMPTS", "ACCOUNT_LOCKOUT_THRESHOLD"],
            "flask": ["MAX_LOGIN_ATTEMPTS", "ACCOUNT_LOCKOUT_ATTEMPTS"]
        },
        "csharp": {
            "identity": ["MaxFailedAccessAttempts", "LockoutEnabled", "DefaultLockoutTimeSpan"]
        },
        "java": {
            "spring": ["maxAttempts", "lockoutDuration", "failureThreshold"]
        }
    }
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language

    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Python code for account lockout compliance."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Create parser
        parser = ASTParser(CodeLanguage.PYTHON)
        
        tree = parser.parse(code)
        if not tree:
            return findings
        
        # Check for django-axes framework
        has_axes = 'django-axes' in code or 'axes' in code.lower()
        has_flask_login = 'flask_login' in code
        
        # Find all assignments for lockout configuration
        assignments = parser.find_nodes_by_type(tree.root_node, "assignment")
        
        lockout_configs = {}
        for assign in assignments:
            assign_text = parser.get_node_text(assign, code_bytes)
            # Check for lockout configuration variables
            for config_key in ["AXES_FAILURE_LIMIT", "MAX_LOGIN_ATTEMPTS", "ACCOUNT_LOCKOUT_THRESHOLD"]:
                if config_key in assign_text:
                    # Extract the value
                    match = re.search(rf'{config_key}\s*=\s*(\d+)', assign_text)
                    if match:
                        lockout_configs[config_key] = int(match.group(1))
        
        # Validate Django AXES configuration
        if has_axes:
            if "AXES_FAILURE_LIMIT" not in lockout_configs:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing AXES_FAILURE_LIMIT Configuration",
                    description="django-axes is present but AXES_FAILURE_LIMIT is not configured. KSI-IAM-06 requires automatic account lockout after suspicious activity (NIST AC-7).",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_import_line(lines, "axes"),
                    code_snippet=self._get_snippet(lines, self._find_import_line(lines, "axes")),
                    recommendation=(
                        "Configure AXES_FAILURE_LIMIT in Django settings:\n"
                        "AXES_FAILURE_LIMIT = 5  # Lock after 5 failed attempts\n"
                        "AXES_COOLOFF_TIME = timedelta(minutes=30)  # 30-minute lockout\n"
                        "AXES_LOCKOUT_TEMPLATE = 'account_locked.html'"
                    )
                ))
            elif lockout_configs.get("AXES_FAILURE_LIMIT", 0) > 10:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Weak Account Lockout Threshold",
                    description=f"AXES_FAILURE_LIMIT is set to {lockout_configs['AXES_FAILURE_LIMIT']}, exceeding FedRAMP recommendations (5-10 attempts). Higher thresholds allow more brute-force attempts.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_config_line(lines, "AXES_FAILURE_LIMIT"),
                    code_snippet=self._get_snippet(lines, self._find_config_line(lines, "AXES_FAILURE_LIMIT")),
                    recommendation="Set AXES_FAILURE_LIMIT to 5-10 to comply with NIST AC-7 (Unsuccessful Logon Attempts)."
                ))
        
        # Check Flask-Login without lockout
        if has_flask_login:
            has_lockout_logic = any(key in lockout_configs for key in ["MAX_LOGIN_ATTEMPTS", "ACCOUNT_LOCKOUT_ATTEMPTS"])
            if not has_lockout_logic:
                # Check for custom failed login tracking
                has_custom_tracking = bool(re.search(r'failed_login|login_attempts|account_locked', code, re.IGNORECASE))
                if not has_custom_tracking:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Flask-Login Without Account Lockout",
                        description="Flask-Login is used but no account lockout mechanism detected. KSI-IAM-06 requires automatic disabling of accounts after suspicious activity.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=self._find_import_line(lines, "flask_login"),
                        code_snippet=self._get_snippet(lines, self._find_import_line(lines, "flask_login")),
                        recommendation=(
                            "Implement account lockout:\n"
                            "1. Track failed_login_count in User model\n"
                            "2. Lock account after 5-10 attempts\n"
                            "3. Set lockout duration (30+ minutes)\n"
                            "4. Log all failed attempts for monitoring"
                        )
                    ))
        
        # Check for failed login logging
        has_auth = bool(re.search(r'def\s+(login|authenticate)\s*\(', code))
        has_logging = bool(re.search(r'logger\.|logging\.|log\.', code))
        
        if has_auth and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Failed Login Logging",
                description="Authentication function detected but no logging configured. KSI-IAM-06 requires monitoring of suspicious activity (NIST AC-7, AU-2).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_function_line(lines, "login"),
                code_snippet=self._get_snippet(lines, self._find_function_line(lines, "login")),
                recommendation=(
                    "Add failed login logging:\n"
                    "import logging\n"
                    "logger = logging.getLogger(__name__)\n\n"
                    "if not authenticate(username, password):\n"
                    "    logger.warning(f'Failed login: {username} from {request.remote_addr}')"
                )
            ))
        
        return findings

    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# code for account lockout compliance."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Create parser
        parser = ASTParser(CodeLanguage.CSHARP)
        
        tree = parser.parse(code)
        if not tree:
            return findings
        
        # Check for ASP.NET Core Identity
        has_identity = 'AddIdentity' in code or 'IdentityOptions' in code
        
        if has_identity:
            # Find lockout configuration
            max_failed_match = re.search(r'MaxFailedAccessAttempts\s*=\s*(\d+)', code)
            lockout_enabled = bool(re.search(r'LockoutEnabled\s*=\s*true', code, re.IGNORECASE))
            
            if not max_failed_match:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="MaxFailedAccessAttempts Not Configured",
                    description="ASP.NET Core Identity is used but MaxFailedAccessAttempts is not explicitly set. KSI-IAM-06 requires automatic account lockout (NIST AC-7).",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_text_line(lines, "AddIdentity"),
                    code_snippet=self._get_snippet(lines, self._find_text_line(lines, "AddIdentity")),
                    recommendation=(
                        "Configure lockout in Startup.cs or Program.cs:\n"
                        "services.AddIdentity<ApplicationUser, IdentityRole>(options => {\n"
                        "    options.Lockout.MaxFailedAccessAttempts = 5;\n"
                        "    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);\n"
                        "    options.Lockout.AllowedForNewUsers = true;\n"
                        "});"
                    )
                ))
            elif int(max_failed_match.group(1)) > 10:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Weak MaxFailedAccessAttempts Threshold",
                    description=f"MaxFailedAccessAttempts is set to {max_failed_match.group(1)}, exceeding FedRAMP recommendations (5-10 attempts).",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_text_line(lines, "MaxFailedAccessAttempts"),
                    code_snippet=self._get_snippet(lines, self._find_text_line(lines, "MaxFailedAccessAttempts")),
                    recommendation="Set MaxFailedAccessAttempts to 5-10 per NIST AC-7 guidance."
                ))
            
            if not lockout_enabled:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Account Lockout Not Enabled",
                    description="MaxFailedAccessAttempts may be configured but LockoutEnabled is not set to true. Accounts will not be automatically locked.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_text_line(lines, "AddIdentity"),
                    code_snippet=self._get_snippet(lines, self._find_text_line(lines, "AddIdentity")),
                    recommendation="Enable lockout: options.Lockout.AllowedForNewUsers = true;"
                ))
        
        return findings

    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code for account lockout compliance."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Create parser
        parser = ASTParser(CodeLanguage.JAVA)
        
        tree = parser.parse(code)
        # Note: Continue with regex-based analysis even if AST parsing fails
        
        # Check for Spring Security UserDetailsService implementation
        has_user_details_service = bool(re.search(r'implements\s+UserDetailsService', code))
        
        if has_user_details_service:
            # Check if loadUserByUsername checks account lock status
            has_load_by_username = bool(re.search(r'loadUserByUsername\s*\(', code))
            
            if has_load_by_username:
                # Check if the method checks isAccountNonLocked or account lock status
                has_lock_check = bool(re.search(
                    r'(isAccountNonLocked|isLocked|accountLocked|lockoutEnd|getAccountNonLocked)',
                    code, re.IGNORECASE
                ))
                
                if not has_lock_check:
                    line_num = self._find_text_line(lines, "loadUserByUsername")
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Missing Account Lock Status Check",
                        description="UserDetailsService.loadUserByUsername() does not check account lock status. KSI-IAM-06 requires automatic account lockout after suspicious activity (NIST AC-7). Verify that user account is not locked before authentication.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Check account lock status in loadUserByUsername():\n\n"
                            "1. Add isAccountNonLocked() check:\n"
                            "   if (user.isLocked()) {\n"
                            "       throw new LockedException(\"Account is locked\");\n"
                            "   }\n\n"
                            "2. Return UserDetails with lock status:\n"
                            "   return new org.springframework.security.core.userdetails.User(\n"
                            "       user.getUsername(),\n"
                            "       user.getPassword(),\n"
                            "       user.isEnabled(),\n"
                            "       true, // accountNonExpired\n"
                            "       true, // credentialsNonExpired\n"
                            "       !user.isLocked(), // accountNonLocked\n"
                            "       getAuthorities(user)\n"
                            "   );"
                        )
                    ))
        
        # Check for Spring Security
        has_spring_security = 'springframework.security' in code or 'EnableWebSecurity' in code
        
        if has_spring_security:
            # Look for formLogin() usage
            has_form_login = bool(re.search(r'\.formLogin\s*\(', code))
            
            # Look for AuthenticationFailureHandler or lockout configuration
            # Exclude single-line comments
            code_without_comments = '\n'.join(
                line.split('//')[0] for line in lines
            )
            has_failure_handler = bool(re.search(
                r'(implements\s+AuthenticationFailureHandler|new\s+\w*AuthenticationFailureHandler|@Bean.*failureHandler|setMaximumAttempts|failureHandler\s*\()',
                code_without_comments
            ))
            
            # If using formLogin() without failure handler configuration, flag it
            if has_form_login and not has_failure_handler:
                # Find the best line number for the finding
                line_num = self._find_text_line(lines, "EnableWebSecurity")
                if line_num == 1:  # Not found
                    line_num = self._find_text_line(lines, "UserDetailsService")
                if line_num == 1:  # Still not found
                    line_num = self._find_text_line(lines, "springframework.security")
                
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing AuthenticationFailureHandler Configuration",
                    description="Spring Security formLogin() is configured without an AuthenticationFailureHandler. KSI-IAM-06 requires automatic account lockout after suspicious activity (NIST AC-7). Configure a failure handler to track failed login attempts and implement account lockout.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Implement account lockout mechanism:\n"
                        "1. Add failed_login_count and account_locked fields to User entity\n"
                        "2. Implement AuthenticationFailureHandler to track attempts\n"
                        "3. Check account lock status in UserDetailsService.loadUserByUsername()\n"
                        "4. Configure maxAttempts (5-10) and lockout duration (30+ minutes)"
                    )
                ))
        
        return findings

    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze JavaScript/TypeScript for account lockout compliance."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Create parser
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        
        tree = parser.parse(code)
        if not tree:
            # Fallback to regex if AST parsing fails
            tree = None
        
        # Check for Passport.js
        has_passport = 'passport' in code.lower()
        
        if has_passport:
            # Look for rate limiting or account lockout
            has_rate_limit = bool(re.search(r'express-rate-limit|rate-limiter|failed.*attempts', code, re.IGNORECASE))
            
            if not has_rate_limit:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Passport.js Without Rate Limiting",
                    description="Passport.js is used but no rate limiting or account lockout detected. KSI-IAM-06 requires protection against suspicious activity.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_text_line(lines, "passport"),
                    code_snippet=self._get_snippet(lines, self._find_text_line(lines, "passport")),
                    recommendation=(
                        "Add express-rate-limit:\n"
                        "const rateLimit = require('express-rate-limit');\n"
                        "const loginLimiter = rateLimit({\n"
                        "  windowMs: 15 * 60 * 1000, // 15 minutes\n"
                        "  max: 5 // limit each IP to 5 requests per windowMs\n"
                        "});\n"
                        "app.post('/login', loginLimiter, ...);"
                    )
                ))
        
        return findings

    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep IaC for account lockout compliance."""
        findings = []
        lines = code.split('\n')
        
        # Check for Log Analytics workspace without sign-in alerts
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        has_signin_alert = bool(re.search(r"(scheduledQueryRules|metricAlerts).*sign[-\s]*in", code, re.IGNORECASE))
        
        if has_log_analytics and not has_signin_alert:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Sign-In Monitoring Alerts",
                description="Log Analytics workspace configured without failed sign-in alerts. KSI-IAM-06 requires monitoring and automated response to suspicious activity (NIST AC-7).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_text_line(lines, "Microsoft.OperationalInsights"),
                code_snippet=self._get_snippet(lines, self._find_text_line(lines, "Microsoft.OperationalInsights")),
                recommendation=(
                    "Add alert rule for failed sign-ins:\n"
                    "resource signInAlert 'Microsoft.Insights/scheduledQueryRules@2021-08-01' = {\n"
                    "  name: 'FailedSignInAlert'\n"
                    "  location: resourceGroup().location\n"
                    "  properties: {\n"
                    "    scopes: [logAnalytics.id]\n"
                    "    criteria: { query: 'SigninLogs | where ResultType != 0' }\n"
                    "    actions: { actionGroups: [...] }\n"
                    "  }\n"
                    "}"
                )
            ))
        
        # IaC uses regex-based analysis (no tree-sitter parser for Bicep)
        # Check for Azure AD / Entra ID Conditional Access policies
        has_conditional_access = bool(re.search(r"Microsoft\.Authorization/conditionalAccessPolicies|'conditionalAccessPolicy'", code))
        
        if not has_conditional_access and not has_log_analytics:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Conditional Access Policy",
                description="No Azure AD Conditional Access policies detected. KSI-IAM-06 requires automated response to suspicious activity (NIST AC-7).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1),
                recommendation=(
                    "Deploy Conditional Access policy for account lockout:\n"
                    "resource conditionalAccessPolicy 'Microsoft.Authorization/conditionalAccessPolicies@2022-01-01' = {\n"
                    "  name: 'BlockFailedLogins'\n"
                    "  properties: {\n"
                    "    conditions: { signInRiskLevel: ['high', 'medium'] }\n"
                    "    grantControls: { operator: 'OR', builtInControls: ['block'] }\n"
                    "  }\n"
                    "}"
                )
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform IaC for account lockout compliance."""
        findings = []
        lines = code.split('\n')
        
        # Check for Log Analytics workspace without monitoring alerts
        has_log_analytics = bool(re.search(r'azurerm_log_analytics_workspace', code))
        has_signin_alert = bool(re.search(r'(azurerm_monitor_scheduled_query_rules_alert|azurerm_monitor_metric_alert).*sign[-\s]*in', code, re.IGNORECASE))
        
        if has_log_analytics and not has_signin_alert:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Sign-In Monitoring Alerts",
                description="Log Analytics workspace configured without failed sign-in alerts. KSI-IAM-06 requires monitoring and automated response to suspicious activity (NIST AC-7).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_text_line(lines, "azurerm_log_analytics_workspace"),
                code_snippet=self._get_snippet(lines, self._find_text_line(lines, "azurerm_log_analytics_workspace")),
                recommendation=(
                    "Add monitoring alert for failed sign-ins:\n"
                    "resource \"azurerm_monitor_scheduled_query_rules_alert\" \"failed_signin\" {\n"
                    "  name                = \"failed-signin-alert\"\n"
                    "  resource_group_name = azurerm_resource_group.main.name\n"
                    "  data_source_id      = azurerm_log_analytics_workspace.main.id\n"
                    "  query               = \"SigninLogs | where ResultType != 0\"\n"
                    "  frequency           = 5\n"
                    "  severity            = 2\n"
                    "}"
                )
            ))
        
        # IaC uses regex-based analysis (no tree-sitter parser for Terraform)
        # Check for Azure AD / Entra ID Conditional Access
        has_conditional_access = bool(re.search(r'azuread_conditional_access_policy|azuread_authentication_strength_policy', code))
        
        if not has_conditional_access and not has_log_analytics:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Conditional Access Policy",
                description="No Azure AD Conditional Access policies detected. KSI-IAM-06 requires automated account protection (NIST AC-7).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1),
                recommendation=(
                    "Add azuread_conditional_access_policy:\n"
                    "resource \"azuread_conditional_access_policy\" \"block_failed_logins\" {\n"
                    "  display_name = \"Block After Failed Logins\"\n"
                    "  state        = \"enabled\"\n"
                    "  conditions {\n"
                    "    sign_in_risk_levels = [\"high\", \"medium\"]\n"
                    "  }\n"
                    "  grant_controls {\n"
                    "    operator          = \"OR\"\n"
                    "    built_in_controls = [\"block\"]\n"
                    "  }\n"
                    "}"
                )
            ))
        
        return findings
    
    # Helper methods
    def _find_import_line(self, lines: List[str], keyword: str) -> int:
        """Find line with import containing keyword."""
        for i, line in enumerate(lines, 1):
            if 'import' in line.lower() and keyword.lower() in line.lower():
                return i
        return 1
    
    def _find_config_line(self, lines: List[str], keyword: str) -> int:
        """Find line with configuration keyword."""
        for i, line in enumerate(lines, 1):
            if keyword in line:
                return i
        return 1
    
    def _find_function_line(self, lines: List[str], func_name: str) -> int:
        """Find line with function definition."""
        for i, line in enumerate(lines, 1):
            if f'def {func_name}' in line or f'function {func_name}' in line:
                return i
        return 1
    
    def _find_text_line(self, lines: List[str], text: str) -> int:
        """Find line containing text."""
        for i, line in enumerate(lines, 1):
            if text in line:
                return i
        return 1
    
    def _get_snippet(self, lines: List[str], line_num: int, context: int = 3) -> str:
        """Get code snippet around line number."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = "→ " if i == line_num - 1 else "  "
            snippet_lines.append(f"{i+1:4d} {prefix}{lines[i]}")
        return "\n".join(snippet_lines)


def get_factory():
    """Get KSI analyzer factory instance."""
    from .factory import KSIAnalyzerFactory
    return KSIAnalyzerFactory()

