"""
Application code analyzers for FedRAMP 20x compliance.

Supports Python code analysis for security best practices.
"""

import re
from typing import Optional

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult


class PythonAnalyzer(BaseAnalyzer):
    """
    Analyzer for Python application code.
    
    Checks for FedRAMP 20x security compliance in Python applications.
    """
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze Python code for FedRAMP 20x compliance.
        
        Args:
            code: Python code content
            file_path: Path to the Python file
            
        Returns:
            AnalysisResult with findings
        """
        self.result = AnalysisResult()
        self.result.files_analyzed = 1
        
        # Check for authentication (KSI-IAM-01)
        self._check_authentication(code, file_path)
        
        # Check for hardcoded secrets (KSI-SVC-06)
        self._check_secrets_management(code, file_path)
        
        # Check for vulnerable dependencies (KSI-SVC-08)
        self._check_dependencies(code, file_path)
        
        # Check for PII handling (KSI-PIY-02)
        self._check_pii_handling(code, file_path)
        
        # Check for logging (KSI-MLA-05)
        self._check_logging(code, file_path)
        
        # Phase 2: Application Security
        self._check_service_account_management(code, file_path)
        self._check_microservices_security(code, file_path)
        
        # Phase 3: Secure Coding Practices
        self._check_error_handling(code, file_path)
        self._check_input_validation(code, file_path)
        self._check_secure_coding(code, file_path)
        self._check_data_classification(code, file_path)
        self._check_privacy_controls(code, file_path)
        self._check_service_mesh(code, file_path)
        self._check_least_privilege(code, file_path)
        self._check_session_management(code, file_path)
        
        # Phase 4: Monitoring & Observability
        self._check_security_monitoring(code, file_path)
        self._check_anomaly_detection(code, file_path)
        self._check_performance_monitoring(code, file_path)
        self._check_incident_response(code, file_path)
        
        # Phase 5: DevSecOps Automation
        self._check_configuration_management(code, file_path)
        self._check_version_control(code, file_path)
        self._check_automated_testing(code, file_path)
        self._check_audit_logging(code, file_path)
        self._check_log_integrity(code, file_path)
        self._check_key_management(code, file_path)
        
        return self.result
    
    def _check_authentication(self, code: str, file_path: str) -> None:
        """Check for proper authentication implementation (KSI-IAM-01)."""
        # Check for authentication-related imports
        has_auth_import = bool(re.search(
            r"from\s+(azure\.identity|msal|authlib|flask_login|django\.contrib\.auth)",
            code
        ))
        
        # Check for authentication decorators or middleware
        has_auth_decorator = bool(re.search(
            r"@(login_required|require_auth|authorize|authenticated)",
            code
        ))
        
        # Check for route/endpoint definitions without auth
        route_patterns = [
            r"@app\.route\(['\"].*['\"].*\)",
            r"@router\.(get|post|put|delete)\(['\"].*['\"].*\)",
            r"def\s+\w+\(request",
        ]
        
        has_routes = False
        for pattern in route_patterns:
            if re.search(pattern, code):
                has_routes = True
                break
        
        if has_routes and not (has_auth_import or has_auth_decorator):
            line_num = self.get_line_number(code, "@app.route") or \
                       self.get_line_number(code, "@router") or \
                       self.get_line_number(code, "def ")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.HIGH,
                title="API endpoints without authentication",
                description="Found route/endpoint definitions without authentication decorators. FedRAMP 20x requires authentication for all API endpoints.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add authentication using Azure AD/Entra ID:\n```python\nfrom azure.identity import DefaultAzureCredential\nfrom functools import wraps\nimport jwt\n\ndef require_auth(f):\n    @wraps(f)\n    def decorated_function(*args, **kwargs):\n        token = request.headers.get('Authorization', '').replace('Bearer ', '')\n        if not token:\n            return {'error': 'No token provided'}, 401\n        try:\n            # Validate JWT token with Azure AD\n            decoded = jwt.decode(token, options={'verify_signature': False})\n            request.user = decoded\n        except jwt.InvalidTokenError:\n            return {'error': 'Invalid token'}, 401\n        return f(*args, **kwargs)\n    return decorated_function\n\n@app.route('/api/data')\n@require_auth\ndef get_data():\n    return {'data': 'secure'}\n```\nSource: Azure AD authentication best practices (https://learn.microsoft.com/azure/active-directory/develop/authentication-vs-authorization)"
            ))
        elif has_auth_import and has_auth_decorator:
            line_num = self.get_line_number(code, "@login_required") or \
                       self.get_line_number(code, "@require_auth") or \
                       self.get_line_number(code, "azure.identity")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.INFO,
                title="Authentication properly implemented",
                description="API endpoints protected with authentication decorators.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure authentication tokens are validated and user permissions checked.",
                good_practice=True
            ))
    
    def _check_secrets_management(self, code: str, file_path: str) -> None:
        """Check for hardcoded secrets (KSI-SVC-06)."""
        # Patterns for potential secrets
        secret_patterns = [
            (r"password\s*=\s*['\"][^'\"]+['\"]", "password"),
            (r"api_key\s*=\s*['\"][^'\"]+['\"]", "API key"),
            (r"secret\s*=\s*['\"][^'\"]+['\"]", "secret"),
            (r"token\s*=\s*['\"][^'\"]+['\"]", "token"),
            (r"CONNECTION_STRING\s*=\s*['\"][^'\"]+['\"]", "connection string"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                
                # Skip if it's from environment or Key Vault
                if any(x in matched_text for x in ["os.environ", "os.getenv", "KeyVaultSecret", "SecretClient"]):
                    continue
                
                # Skip common non-secret values
                if any(x in matched_text.lower() for x in ["example", "test", "dummy", "placeholder", "***"]):
                    continue
                
                line_num = self.get_line_number(code, matched_text)
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-06",
                    severity=Severity.HIGH,
                    title=f"Potential hardcoded {secret_type} detected",
                    description=f"Found {secret_type} value in code. FedRAMP 20x requires secrets to be stored in Azure Key Vault.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=matched_text,
                    recommendation=f"Use Azure Key Vault to store {secret_type}:\n```python\nfrom azure.identity import DefaultAzureCredential\nfrom azure.keyvault.secrets import SecretClient\n\ncredential = DefaultAzureCredential()\nclient = SecretClient(\n    vault_url=\"https://your-vault.vault.azure.net\",\n    credential=credential\n)\n{secret_type.replace(' ', '_')} = client.get_secret(\"{secret_type.replace(' ', '-')}\").value\n```\nSource: Azure Key Vault best practices (https://learn.microsoft.com/azure/key-vault/general/best-practices)"
                ))
        
        # Check for good practices (Key Vault usage)
        if re.search(r"from azure\.keyvault\.secrets import SecretClient", code):
            if re.search(r"DefaultAzureCredential", code):
                line_num = self.get_line_number(code, "SecretClient")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-06",
                    severity=Severity.INFO,
                    title="Azure Key Vault with managed identity configured",
                    description="Secrets retrieved from Key Vault using DefaultAzureCredential (managed identity).",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure Key Vault access policies grant minimal required permissions.",
                    good_practice=True
                ))
    
    def _check_dependencies(self, code: str, file_path: str) -> None:
        """Check for potentially vulnerable dependencies (KSI-SVC-08)."""
        # Check for imports of dependencies with known vulnerabilities
        vulnerable_patterns = [
            (r"import\s+pickle", "pickle (insecure deserialization risk)"),
            (r"from\s+pickle\s+import", "pickle (insecure deserialization risk)"),
            (r"eval\(", "eval() (code injection risk)"),
            (r"exec\(", "exec() (code injection risk)"),
            (r"import\s+yaml(?!safe)", "yaml without safe_load (code execution risk)"),
        ]
        
        for pattern, issue in vulnerable_patterns:
            if re.search(pattern, code):
                line_num = self.get_line_number(code, pattern)
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-08",
                    severity=Severity.MEDIUM,
                    title=f"Potentially unsafe library usage: {issue}",
                    description=f"Using {issue}. FedRAMP 20x requires secure coding practices and dependency scanning.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use safer alternatives:\n- pickle → json or msgpack\n- eval/exec → ast.literal_eval or safe alternatives\n- yaml.load → yaml.safe_load\n\nRun dependency scanning:\n```bash\npip install safety bandit\nsafety check\nbandit -r .\n```\nSource: OWASP Secure Coding Practices (https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)"
                ))
        
        # Check for requirements.txt or pyproject.toml (good practice)
        if "requirements.txt" in file_path or "pyproject.toml" in file_path:
            # Check if versions are pinned
            if re.search(r"==\d+\.\d+", code):
                line_num = self.get_line_number(code, "==")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-08",
                    severity=Severity.INFO,
                    title="Dependencies pinned to specific versions",
                    description="Dependencies use exact version pinning for reproducibility.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Regularly update dependencies and run security scans (safety check, pip-audit).",
                    good_practice=True
                ))
    
    def _check_pii_handling(self, code: str, file_path: str) -> None:
        """Check for PII handling (KSI-PIY-02)."""
        # Check for fields that might contain PII
        pii_patterns = [
            (r"(ssn|social_security|social_security_number)", "Social Security Number"),
            (r"(email|email_address)", "email address"),
            (r"(phone|phone_number|telephone)", "phone number"),
            (r"(dob|date_of_birth|birthdate)", "date of birth"),
            (r"(address|street_address|home_address)", "physical address"),
        ]
        
        for pattern, pii_type in pii_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                # Check if there's encryption/masking nearby
                context_start = max(0, match.start() - 200)
                context_end = min(len(code), match.end() + 200)
                context = code[context_start:context_end]
                
                has_encryption = bool(re.search(r"(encrypt|hash|mask|redact|anonymize)", context, re.IGNORECASE))
                
                if not has_encryption:
                    line_num = self.get_line_number(code, match.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-PIY-02",
                        severity=Severity.MEDIUM,
                        title=f"Potential unencrypted PII: {pii_type}",
                        description=f"Field '{match.group(0)}' may contain {pii_type}. FedRAMP 20x requires PII to be encrypted at rest and in transit.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation=f"Encrypt {pii_type} before storing:\n```python\nfrom cryptography.fernet import Fernet\nimport os\n\n# Use Azure Key Vault for encryption key\nencryption_key = os.environ['ENCRYPTION_KEY']  # From Key Vault\nfernet = Fernet(encryption_key.encode())\n\n# Encrypt PII\nencrypted_value = fernet.encrypt({match.group(0)}.encode())\n\n# Decrypt when needed\ndecrypted_value = fernet.decrypt(encrypted_value).decode()\n```\nSource: NIST SP 800-122 (PII Protection)"
                    ))
    
    def _check_logging(self, code: str, file_path: str) -> None:
        """Check for proper logging implementation (KSI-MLA-05)."""
        # Check for logging imports
        has_logging = bool(re.search(r"import logging|from logging import", code))
        
        # Check for Azure Monitor/Application Insights
        has_azure_logging = bool(re.search(
            r"from (azure\.monitor|opencensus\.ext\.azure|applicationinsights)",
            code
        ))
        
        if has_logging or has_azure_logging:
            # Check if PII might be logged
            if re.search(r"logger\.(info|debug|error|warning)\([^)]*password[^)]*\)", code, re.IGNORECASE) or \
               re.search(r"logger\.(info|debug|error|warning)\([^)]*token[^)]*\)", code, re.IGNORECASE):
                line_num = self.get_line_number(code, "logger.")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.MEDIUM,
                    title="Potential sensitive data in logs",
                    description="Logging statements may include passwords, tokens, or PII. FedRAMP 20x requires logs must not contain sensitive data.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Sanitize log messages before logging:\n```python\nimport logging\n\ndef sanitize_log(message: str) -> str:\n    \"\"\"Remove sensitive data from log messages.\"\"\"\n    # Mask passwords, tokens, etc.\n    message = re.sub(r'password=[^&\\s]+', 'password=***', message, flags=re.IGNORECASE)\n    message = re.sub(r'token=[^&\\s]+', 'token=***', message, flags=re.IGNORECASE)\n    return message\n\nlogger.info(sanitize_log(f\"Request: {request_data}\"))\n```"
                ))
            
            if has_azure_logging:
                line_num = self.get_line_number(code, "azure.monitor") or \
                           self.get_line_number(code, "applicationinsights")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.INFO,
                    title="Azure Monitor/Application Insights configured",
                    description="Application uses Azure monitoring for centralized logging.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure log retention meets FedRAMP requirements (typically 90 days minimum).",
                    good_practice=True
                ))
        else:
            # No logging found
            # Only warn if this appears to be application code (has functions/classes)
            if re.search(r"def\s+\w+\(", code) and not file_path.endswith("__init__.py"):
                line_num = 1
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.LOW,
                    title="No logging implementation found",
                    description="Application code without logging statements. FedRAMP 20x requires audit logging for security events.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add logging to track security events:\n```python\nimport logging\nfrom opencensus.ext.azure.log_exporter import AzureLogHandler\n\nlogger = logging.getLogger(__name__)\nlogger.addHandler(AzureLogHandler(\n    connection_string='InstrumentationKey=your-key'\n))\n\nlogger.info('User authenticated', extra={'user_id': user_id})\nlogger.warning('Failed login attempt', extra={'ip': request.remote_addr})\n```\nSource: Azure Monitor best practices (https://learn.microsoft.com/azure/azure-monitor/logs/data-platform-logs)"
                ))
    
    # Phase 2: Application Security Methods
    
    def _check_service_account_management(self, code: str, file_path: str) -> None:
        """Check for service account and credential management (KSI-IAM-05)."""
        # Check for hardcoded credentials (anti-pattern)
        credential_patterns = [
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
            r"connection_string\s*=\s*['\"].*password=[^'\"]+['\"]",
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                line_num = self.get_line_number(code, pattern.split("=")[0])
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-05",
                    severity=Severity.HIGH,
                    title="Hardcoded credentials detected",
                    description="Credentials should NEVER be hardcoded in source code. FedRAMP 20x requires secure credential management using Azure Key Vault or Managed Identity.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use Azure Managed Identity or Key Vault:\n```python\nfrom azure.identity import DefaultAzureCredential\nfrom azure.keyvault.secrets import SecretClient\n\n# Option 1: Managed Identity (recommended)\ncredential = DefaultAzureCredential()\nclient = SomeClient(credential=credential)\n\n# Option 2: Key Vault for secrets\nkey_vault_url = os.environ['KEY_VAULT_URL']\nsecret_client = SecretClient(vault_url=key_vault_url, credential=credential)\napi_key = secret_client.get_secret('api-key').value\n```\nSource: Azure Managed Identity (https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/)"
                ))
                break
        
        # Check for proper credential management (good practice)
        has_managed_identity = bool(re.search(r"from\s+azure\.identity\s+import\s+(DefaultAzureCredential|ManagedIdentityCredential)", code))
        has_key_vault = bool(re.search(r"from\s+azure\.keyvault", code))
        
        if has_managed_identity or has_key_vault:
            line_num = self.get_line_number(code, "azure.identity") or \
                       self.get_line_number(code, "azure.keyvault")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-05",
                severity=Severity.INFO,
                title="Secure credential management implemented",
                description="Application uses Azure Managed Identity or Key Vault for credential management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure Managed Identity is assigned appropriate RBAC roles with least privilege.",
                good_practice=True
            ))
        else:
            # Check for environment variable usage (acceptable but not ideal)
            if re.search(r"os\.environ\[|os\.getenv\(", code):
                line_num = self.get_line_number(code, "os.environ")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-05",
                    severity=Severity.LOW,
                    title="Environment variables used for credentials",
                    description="Environment variables are better than hardcoded values but Managed Identity is preferred for Azure resources.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Consider migrating to Azure Managed Identity for better security and credential rotation."
                ))
    
    def _check_microservices_security(self, code: str, file_path: str) -> None:
        """Check for microservices security patterns (KSI-CNA-03)."""
        # Check if this appears to be a microservice (has HTTP client/server code)
        has_http_client = bool(re.search(r"import\s+(requests|httpx|aiohttp)|from\s+(requests|httpx|aiohttp)", code))
        has_http_server = bool(re.search(r"from\s+(flask|fastapi|django|starlette)", code))
        
        if has_http_client or has_http_server:
            issues = []
            
            # Check for service-to-service authentication
            has_service_auth = bool(re.search(
                r"DefaultAzureCredential|ClientSecretCredential|bearer.*token|Authorization.*Bearer",
                code,
                re.IGNORECASE
            ))
            
            if not has_service_auth:
                issues.append("No service-to-service authentication detected (OAuth/JWT required)")
            
            # Check for mTLS/certificate validation
            if has_http_client:
                # Check for verify=False (anti-pattern)
                if re.search(r"verify\s*=\s*False", code):
                    issues.append("SSL verification disabled (verify=False) - security risk")
                
                # Check for proper certificate handling
                has_mtls = bool(re.search(r"cert\s*=|client_cert|ssl_context", code))
                if not has_mtls:
                    issues.append("mTLS/client certificates not configured for service-to-service calls")
            
            # Check for API rate limiting (server-side)
            if has_http_server:
                has_rate_limiting = bool(re.search(r"limiter|ratelimit|throttle", code, re.IGNORECASE))
                if not has_rate_limiting:
                    issues.append("No rate limiting detected for API endpoints")
            
            if issues:
                line_num = self.get_line_number(code, "import")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-03",
                    severity=Severity.HIGH,
                    title="Microservices security controls missing",
                    description=f"Service communication security issues: {', '.join(issues)}. FedRAMP 20x requires secure service-to-service communication.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement microservices security:\n```python\n# Service-to-service authentication\nfrom azure.identity import DefaultAzureCredential\n\ncredential = DefaultAzureCredential()\ntoken = credential.get_token('https://yourapiscope/.default')\n\n# HTTPS with certificate validation\nimport requests\nresponse = requests.get(\n    'https://service-b.example.com/api',\n    headers={'Authorization': f'Bearer {token.token}'},\n    verify=True,  # Always verify SSL\n    cert=('/path/to/client.crt', '/path/to/client.key')  # mTLS\n)\n\n# Rate limiting (FastAPI example)\nfrom slowapi import Limiter\nlimiter = Limiter(key_func=lambda: request.headers.get('X-Forwarded-For'))\n\n@app.get('/api/endpoint')\n@limiter.limit('100/minute')\ndef endpoint():\n    pass\n```\nSource: Azure service-to-service auth (https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)"
                ))
            else:
                line_num = self.get_line_number(code, "DefaultAzureCredential") or \
                           self.get_line_number(code, "import")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-03",
                    severity=Severity.INFO,
                    title="Microservices security controls configured",
                    description="Service communication includes authentication and security controls.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure all inter-service calls use mutual TLS and token validation.",
                    good_practice=True
                ))
    
    # Phase 3: Secure Coding Practices Methods
    
    def _check_error_handling(self, code: str, file_path: str) -> None:
        """Check for proper error handling practices (KSI-SVC-01)."""
        # Check for bare except clauses (anti-pattern)
        if re.search(r"except\s*:", code):
            line_num = self.get_line_number(code, "except:")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-01",
                severity=Severity.MEDIUM,
                title="Bare except clause detected",
                description="Bare 'except:' catches all exceptions including system exits. This can hide bugs and make debugging difficult. FedRAMP 20x requires proper error handling.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use specific exception types:\n```python\n# Bad\ntry:\n    risky_operation()\nexcept:  # Too broad\n    pass\n\n# Good\ntry:\n    risky_operation()\nexcept (ValueError, KeyError) as e:\n    logger.error(f'Operation failed: {type(e).__name__}')\n    raise\n```"
            ))
        
        # Check for sensitive data in exception messages
        sensitive_in_errors = re.search(r"raise\s+\w+Exception\([^)]*(?:password|token|secret|key|credential)", code, re.IGNORECASE)
        if sensitive_in_errors:
            line_num = self.get_line_number(code, "raise")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-01",
                severity=Severity.HIGH,
                title="Sensitive data in exception message",
                description="Exception messages may contain sensitive information (passwords, tokens, etc.) that could be logged or displayed to users.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Sanitize exception messages:\n```python\n# Bad\nraise ValueError(f'Failed to authenticate with password: {password}')\n\n# Good\nraise ValueError('Authentication failed - check credentials')\nlogger.error('Auth failed', extra={'user_id': user_id})  # Log safely\n```"
            ))
        
        # Check for proper error logging
        has_try_except = bool(re.search(r"try:\s*\n.*?except", code, re.DOTALL))
        has_error_logging = bool(re.search(r"(logger|logging)\.(error|exception|critical)", code))
        
        if has_try_except and not has_error_logging:
            line_num = self.get_line_number(code, "except")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-01",
                severity=Severity.LOW,
                title="Exception handling without logging",
                description="Exceptions are caught but not logged. FedRAMP 20x requires error logging for security monitoring.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Log exceptions for monitoring:\n```python\nimport logging\nlogger = logging.getLogger(__name__)\n\ntry:\n    operation()\nexcept SpecificError as e:\n    logger.exception('Operation failed')  # Includes stack trace\n    raise  # Re-raise after logging\n```"
            ))
        elif has_error_logging:
            line_num = self.get_line_number(code, "logger.error") or self.get_line_number(code, "logger.exception")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-01",
                severity=Severity.INFO,
                title="Proper error logging implemented",
                description="Exceptions are being logged for monitoring and debugging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure error logs don't contain sensitive data.",
                good_practice=True
            ))
    
    def _check_input_validation(self, code: str, file_path: str) -> None:
        """Check for input validation and injection prevention (KSI-SVC-02)."""
        issues = []
        
        # Check for SQL injection risks
        sql_patterns = [
            r"execute\(['\"].*%s.*['\"].*%",  # String formatting in SQL
            r"query\s*=\s*f['\"]SELECT.*{.*}",  # F-string assigned to query variable
            r"cursor\.execute\([^)]*\+[^)]*\)",  # String concatenation in SQL
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, code):
                issues.append("SQL injection risk detected (string formatting/concatenation in queries)")
                line_num = self.get_line_number(code, "execute")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-02",
                    severity=Severity.HIGH,
                    title="SQL injection vulnerability",
                    description="SQL queries constructed with string formatting or concatenation are vulnerable to SQL injection attacks. FedRAMP 20x requires parameterized queries.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use parameterized queries:\n```python\n# Bad - SQL injection risk\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"  # Vulnerable!\ncursor.execute(query)\n\n# Good - Parameterized query\nquery = \"SELECT * FROM users WHERE id = %s\"\ncursor.execute(query, (user_id,))  # Safe\n\n# Or use ORM\nUser.objects.filter(id=user_id)  # SQLAlchemy/Django ORM\n```\nSource: OWASP SQL Injection Prevention (https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)"
                ))
                break
        
        # Check for parameterized queries (good practice)
        if re.search(r"execute\([^)]*,\s*\([^)]*\)\)", code):  # execute(query, (param,))
            line_num = self.get_line_number(code, "execute")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.INFO,
                title="Parameterized queries implemented",
                description="SQL queries use parameterized statements to prevent injection attacks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Continue using parameterized queries for all database operations.",
                good_practice=True
            ))
        
        # Check for command injection risks
        command_patterns = [
            r"os\.system\([^)]*\+",  # String concatenation in os.system
            r"subprocess\.(call|run|Popen)\([^)]*\+",  # String concatenation in subprocess
            r"subprocess\.(call|run|Popen)\(f['\"]",  # F-strings in subprocess
        ]
        
        for pattern in command_patterns:
            if re.search(pattern, code):
                issues.append("Command injection risk detected")
                line_num = self.get_line_number(code, "os.system") or self.get_line_number(code, "subprocess")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-02",
                    severity=Severity.HIGH,
                    title="Command injection vulnerability",
                    description="Shell commands constructed with user input are vulnerable to command injection attacks.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use subprocess with list arguments:\n```python\n# Bad - Command injection risk\nos.system(f'ls {user_input}')  # Vulnerable!\n\n# Good - Safe subprocess usage\nimport subprocess\nimport shlex\nsubprocess.run(['ls', user_input], check=True)  # Safe - no shell\n\n# If shell needed, sanitize input\nsafe_input = shlex.quote(user_input)\nsubprocess.run(f'ls {safe_input}', shell=True)  # Safer\n```"
                ))
                break
        
        # Check for path traversal risks
        if re.search(r"open\([^)]*\+|open\(f['\"].*{", code):
            issues.append("Path traversal risk detected")
            line_num = self.get_line_number(code, "open(")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.MEDIUM,
                title="Path traversal vulnerability",
                description="File paths constructed from user input without validation can lead to unauthorized file access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Validate and sanitize file paths:\n```python\nimport os\nfrom pathlib import Path\n\n# Bad\nfile_path = f'/data/{user_filename}'  # Vulnerable to ../../../etc/passwd\n\n# Good - Validate and resolve\nbase_dir = Path('/data')\nuser_path = Path(user_filename)\nfull_path = (base_dir / user_path).resolve()\n\nif not str(full_path).startswith(str(base_dir)):\n    raise ValueError('Invalid file path')\n\nwith open(full_path, 'r') as f:\n    content = f.read()\n```"
            ))
        
        # Check for input validation on API endpoints
        if re.search(r"@(app\.route|router\.(get|post|put|delete))", code):
            has_validation = bool(re.search(r"(pydantic|marshmallow|validator|validate_|isinstance\()", code))
            
            if not has_validation:
                line_num = self.get_line_number(code, "@app.route") or self.get_line_number(code, "@router")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-02",
                    severity=Severity.MEDIUM,
                    title="API endpoint without input validation",
                    description="API endpoints should validate all input data. FedRAMP 20x requires input validation to prevent injection attacks.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement input validation:\n```python\nfrom pydantic import BaseModel, validator, constr\n\nclass UserInput(BaseModel):\n    username: constr(min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')\n    email: constr(regex=r'^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$')\n    age: int\n    \n    @validator('age')\n    def validate_age(cls, v):\n        if not 0 <= v <= 150:\n            raise ValueError('Invalid age')\n        return v\n\n@app.post('/users')\ndef create_user(user: UserInput):  # FastAPI auto-validates\n    return {'user': user.dict()}\n```\nSource: OWASP Input Validation (https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)"
                ))
            else:
                line_num = self.get_line_number(code, "pydantic") or self.get_line_number(code, "validator")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-02",
                    severity=Severity.INFO,
                    title="Input validation implemented",
                    description="API endpoints include input validation using validation framework.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure all endpoints have comprehensive validation.",
                    good_practice=True
                ))
    
    def _check_secure_coding(self, code: str, file_path: str) -> None:
        """Check for secure coding practices (KSI-SVC-07)."""
        # Check for unsafe functions
        unsafe_functions = [
            (r"\beval\(", "eval() executes arbitrary code - major security risk"),
            (r"\bexec\(", "exec() executes arbitrary code - major security risk"),
            (r"\b__import__\(", "__import__() with user input can import malicious modules"),
            (r"\bcompile\(", "compile() with user input can execute arbitrary code"),
        ]
        
        for pattern, description in unsafe_functions:
            if re.search(pattern, code):
                line_num = self.get_line_number(code, pattern.replace("\\b", "").replace("\\(", ""))
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-07",
                    severity=Severity.HIGH,
                    title=f"Unsafe function detected: {pattern.replace(chr(92)+'b', '').replace(chr(92)+'(', '')}",
                    description=f"{description}. FedRAMP 20x prohibits unsafe code execution.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Avoid unsafe functions:\n```python\n# Bad\nuser_code = request.form['code']\neval(user_code)  # NEVER do this!\n\n# Good - Use safe alternatives\nimport ast\ntry:\n    parsed = ast.literal_eval(user_input)  # Only evaluates literals\nexcept (ValueError, SyntaxError):\n    raise ValueError('Invalid input')\n\n# Or use a safe parser for specific use cases\nimport json\ndata = json.loads(user_input)  # Safe for JSON\n```"
                ))
        
        # Check for insecure random number generation
        if re.search(r"import random\s|from random import", code):
            # Check if it's used (assume security purpose if random imported)
            if re.search(r"random\.(choice|randint|random|shuffle|choices)", code):
                line_num = self.get_line_number(code, "random")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-07",
                    severity=Severity.MEDIUM,
                    title="Insecure random number generator for security",
                    description="Python's 'random' module is not cryptographically secure. For security-sensitive operations (tokens, passwords, etc.), use 'secrets' module.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use cryptographically secure randomness:\n```python\n# Bad\nimport random\ntoken = ''.join(random.choice('abc123') for _ in range(32))  # Not secure!\n\n# Good\nimport secrets\ntoken = secrets.token_urlsafe(32)  # Cryptographically secure\nsession_id = secrets.token_hex(16)\nrandom_choice = secrets.choice(['a', 'b', 'c'])\n```\nSource: Python secrets module (https://docs.python.org/3/library/secrets.html)"
                ))
        
        # Check for secure randomness usage (good practice)
        if re.search(r"import secrets|from secrets import", code):
            line_num = self.get_line_number(code, "secrets")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.INFO,
                title="Cryptographically secure random generation",
                description="Code uses 'secrets' module for secure random number generation.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Continue using secrets module for security-sensitive operations.",
                good_practice=True
            ))
        
        # Check for hardcoded credentials (overlap with SVC-06 but worth double-checking)
        if re.search(r"(?:password|pwd|passwd)\s*=\s*['\"][^'\"]+['\"]", code, re.IGNORECASE):
            line_num = self.get_line_number(code, "password")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.HIGH,
                title="Hardcoded password detected",
                description="Passwords should never be hardcoded in source code.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use environment variables or Azure Key Vault for credentials."
            ))
    
    def _check_data_classification(self, code: str, file_path: str) -> None:
        """Check for data classification and tagging (KSI-PIY-01)."""
        # Check for PII fields without classification tags
        pii_patterns = [
            r"(?:first_?name|last_?name|full_?name|username)",
            r"(?:email|e_?mail)",
            r"(?:phone|telephone|mobile)",
            r"(?:ssn|social_?security)",
            r"(?:address|street|city|zip|postal)",
            r"(?:dob|date_?of_?birth|birthday)",
            r"(?:credit_?card|card_?number)",
        ]
        
        has_pii_fields = False
        for pattern in pii_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                has_pii_fields = True
                break
        
        if has_pii_fields:
            # Check for classification markers
            has_classification = bool(re.search(r"(classification|sensitivity|data_class|pii_level|confidential)", code, re.IGNORECASE))
            
            if not has_classification:
                line_num = self.get_line_number(code, "class") or 1
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-01",
                    severity=Severity.MEDIUM,
                    title="PII fields without classification tags",
                    description="Code contains PII fields but lacks data classification metadata. FedRAMP 20x requires data classification for sensitive information.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add data classification metadata:\n```python\nfrom enum import Enum\nfrom dataclasses import dataclass, field\n\nclass DataClassification(Enum):\n    PUBLIC = 'public'\n    INTERNAL = 'internal'\n    CONFIDENTIAL = 'confidential'\n    RESTRICTED = 'restricted'  # For PII, PHI, etc.\n\n@dataclass\nclass User:\n    username: str = field(metadata={'classification': DataClassification.INTERNAL})\n    email: str = field(metadata={'classification': DataClassification.CONFIDENTIAL})\n    ssn: str = field(metadata={'classification': DataClassification.RESTRICTED})\n    \n    def __post_init__(self):\n        # Validate classification-based access controls\n        for field_name, field_obj in self.__dataclass_fields__.items():\n            classification = field_obj.metadata.get('classification')\n            if classification == DataClassification.RESTRICTED:\n                # Apply additional security controls\n                pass\n```\nSource: NIST data classification guidance"
                ))
            else:
                line_num = self.get_line_number(code, "classification") or self.get_line_number(code, "sensitivity")
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-01",
                    severity=Severity.INFO,
                    title="Data classification implemented",
                    description="Code includes data classification metadata for sensitive fields.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure classification drives access control and encryption decisions.",
                    good_practice=True
                ))
    
    def _check_privacy_controls(self, code: str, file_path: str) -> None:
        """Check for privacy controls implementation (KSI-PIY-03)."""
        # Check for data retention policies
        has_retention = bool(re.search(r"(retention|expire|ttl|time_to_live|delete_after)", code, re.IGNORECASE))
        
        # Check for user data deletion capabilities
        has_deletion = bool(re.search(r"def\s+(delete_user|remove_user|purge_user|erase_user)", code, re.IGNORECASE))
        
        # Check for user consent mechanisms
        has_consent = bool(re.search(r"(consent|opt_in|agree|accept_terms|gdpr|privacy_policy)", code, re.IGNORECASE))
        
        # Check for data export capabilities (GDPR/privacy right)
        has_export = bool(re.search(r"def\s+(export_user|download_user|get_user_data)", code, re.IGNORECASE))
        
        # Check if this is a service class that should have deletion
        has_user_service = bool(re.search(r"class\s+\w*User\w*Service", code))
        has_get_or_update = bool(re.search(r"def\s+(get_user|update_user|create_user)", code))
        
        if has_user_service and has_get_or_update and not has_deletion:
            line_num = self.get_line_number(code, "class")
            self.add_finding(Finding(
                requirement_id="KSI-PIY-03",
                severity=Severity.MEDIUM,
                title="User service missing data deletion capability",
                description="Service manages user data but doesn't provide deletion methods. FedRAMP 20x and GDPR require data deletion capabilities (right to erasure).",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement secure user data deletion:\n```python\nclass UserService:\n    def get_user(self, user_id): ...\n    def update_user(self, user_id, data): ...\n    \n    async def delete_user(self, user_id: str, reason: str) -> None:\n        \"\"\"Delete user and all associated data (GDPR right to erasure)\"\"\"\n        # 1. Export for audit trail\n        await self.export_user_data(user_id)\n        \n        # 2. Delete from all related tables\n        await db.execute('DELETE FROM user_sessions WHERE user_id = %s', (user_id,))\n        await db.execute('DELETE FROM user_data WHERE user_id = %s', (user_id,))\n        await db.execute('DELETE FROM users WHERE id = %s', (user_id,))\n        \n        # 3. Log deletion\n        logger.info(f'User {user_id} deleted', extra={'reason': reason})\n```"
            ))
        
        if not has_retention and re.search(r"(user|customer|person|individual)", code, re.IGNORECASE):
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-PIY-03",
                severity=Severity.LOW,
                title="No data retention policy detected",
                description="Code handles user data but doesn't implement retention policies. FedRAMP 20x requires data lifecycle management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement data retention:\n```python\nfrom datetime import datetime, timedelta\n\nclass UserData:\n    created_at: datetime\n    retention_days: int = 365  # 1 year retention\n    \n    @property\n    def should_be_deleted(self) -> bool:\n        expiry = self.created_at + timedelta(days=self.retention_days)\n        return datetime.now() > expiry\n    \n    async def cleanup_expired_data(self):\n        \"\"\"Automated cleanup job\"\"\"\n        expired = [u for u in users if u.should_be_deleted]\n        for user in expired:\n            await user.secure_delete()\n```"
            ))
        
        if has_deletion and has_export:
            line_num = self.get_line_number(code, "delete_user") or self.get_line_number(code, "export_user")
            self.add_finding(Finding(
                requirement_id="KSI-PIY-03",
                severity=Severity.INFO,
                title="Privacy rights implemented (deletion and export)",
                description="Code implements user data deletion and export capabilities for privacy compliance.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure deletion is secure (overwrite, not just soft delete) and export includes all user data.",
                good_practice=True
            ))
        
        # Check for secure deletion (not just soft delete)
        if re.search(r"\.delete\(\)|DELETE FROM", code):
            has_secure_delete = bool(re.search(r"(overwrite|shred|secure_delete|wipe)", code, re.IGNORECASE))
            
            if not has_secure_delete:
                line_num = self.get_line_number(code, "delete")
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-03",
                    severity=Severity.MEDIUM,
                    title="Data deletion without secure overwrite",
                    description="Simple delete operations may not fully remove sensitive data. FedRAMP 20x requires secure data disposal for sensitive information.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement secure deletion for sensitive data:\n```python\nimport os\n\ndef secure_delete_file(filepath: str):\n    \"\"\"Overwrite file before deletion\"\"\"\n    if os.path.exists(filepath):\n        size = os.path.getsize(filepath)\n        # Overwrite with random data\n        with open(filepath, 'wb') as f:\n            f.write(os.urandom(size))\n        os.remove(filepath)\n\n# For database records\nasync def secure_delete_user(user_id: str):\n    # 1. Export for audit trail\n    await export_user_data(user_id)\n    # 2. Overwrite sensitive fields\n    await db.execute(\n        'UPDATE users SET email = %s, ssn = %s WHERE id = %s',\n        ('deleted@example.com', '000-00-0000', user_id)\n    )\n    # 3. Then delete\n    await db.execute('DELETE FROM users WHERE id = %s', (user_id,))\n```"
                ))
    
    def _check_service_mesh(self, code: str, file_path: str) -> None:
        """Check for service mesh configuration (KSI-CNA-07)."""
        # Check for Istio or Linkerd imports/configuration
        has_service_mesh = bool(re.search(r"(istio|linkerd|consul|envoy)", code, re.IGNORECASE))
        
        if has_service_mesh:
            # Check for mTLS configuration
            has_mtls = bool(re.search(r"(mtls|mutual_tls|peer_authentication)", code, re.IGNORECASE))
            
            # Check for authorization policies
            has_authz = bool(re.search(r"(authorization_policy|rbac|access_control)", code, re.IGNORECASE))
            
            issues = []
            if not has_mtls:
                issues.append("mTLS not configured")
            if not has_authz:
                issues.append("Authorization policies not defined")
            
            if issues:
                line_num = self.get_line_number(code, "istio") or self.get_line_number(code, "linkerd")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.HIGH,
                    title="Service mesh security controls missing",
                    description=f"Service mesh configuration incomplete: {', '.join(issues)}. FedRAMP 20x requires secure service-to-service communication.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure service mesh security:\n```yaml\n# Istio PeerAuthentication for mTLS\napiVersion: security.istio.io/v1beta1\nkind: PeerAuthentication\nmetadata:\n  name: default\n  namespace: production\nspec:\n  mtls:\n    mode: STRICT  # Require mTLS for all services\n\n---\n# Istio AuthorizationPolicy\napiVersion: security.istio.io/v1beta1\nkind: AuthorizationPolicy\nmetadata:\n  name: service-access\nspec:\n  action: ALLOW\n  rules:\n  - from:\n    - source:\n        principals: [\"cluster.local/ns/production/sa/frontend\"]\n    to:\n    - operation:\n        methods: [\"GET\", \"POST\"]\n        paths: [\"/api/*\"]\n```\nSource: Istio security best practices (https://istio.io/latest/docs/concepts/security/)"
                ))
            else:
                line_num = self.get_line_number(code, "mtls") or self.get_line_number(code, "authorization_policy")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.INFO,
                    title="Service mesh security configured",
                    description="Service mesh includes mTLS and authorization policies.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Regularly review and update authorization policies.",
                    good_practice=True
                ))
    
    def _check_least_privilege(self, code: str, file_path: str) -> None:
        """Check for least privilege access patterns (KSI-IAM-04)."""
        # Check for Azure IAM operations
        has_iam_operations = bool(re.search(r"(RoleAssignment|role_definition|assign_role|grant)", code, re.IGNORECASE))
        
        if has_iam_operations:
            # Check for wildcard permissions (anti-pattern)
            if re.search(r"['\"]actions['\"]:\s*\[['\"]?\*['\"]?\]|permissions.*\*|scope\s*=\s*['\"]?\*['\"]?", code):
                line_num = self.get_line_number(code, "actions") or self.get_line_number(code, "scope") or self.get_line_number(code, "*")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-04",
                    severity=Severity.HIGH,
                    title="Wildcard permissions detected",
                    description="IAM permissions use wildcard (*) which grants excessive access. FedRAMP 20x requires least privilege access.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use specific permissions:\n```python\n# Bad\ncustom_role = {\n    'actions': ['*'],  # Too broad!\n    'dataActions': ['*']\n}\n\n# Good - Specific permissions only\ncustom_role = {\n    'actions': [\n        'Microsoft.Storage/storageAccounts/read',\n        'Microsoft.Storage/storageAccounts/listKeys/action'\n    ],\n    'dataActions': [\n        'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'\n    ]\n}\n```\nSource: Azure RBAC best practices (https://learn.microsoft.com/azure/role-based-access-control/best-practices)"
                ))
            
            # Check for scope limitation
            if not re.search(r"scope\s*=|subscription|resource_group", code):
                line_num = self.get_line_number(code, "role")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-04",
                    severity=Severity.MEDIUM,
                    title="Role assignment without explicit scope",
                    description="Role assignments should be scoped to specific resources, not subscription-wide.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Limit scope to minimum required:\n```python\n# Bad - Subscription-wide\nrole_assignment = authorization_client.role_assignments.create(\n    scope=f'/subscriptions/{subscription_id}',  # Too broad\n    role_definition_id=role_id,\n    principal_id=principal_id\n)\n\n# Good - Resource-specific\nrole_assignment = authorization_client.role_assignments.create(\n    scope=f'/subscriptions/{subscription_id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{account}',\n    role_definition_id=role_id,\n    principal_id=principal_id\n)\n```"
                ))
            else:
                line_num = self.get_line_number(code, "scope")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-04",
                    severity=Severity.INFO,
                    title="Scoped role assignments implemented",
                    description="Role assignments include explicit scope limitation.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Regularly audit and review role assignments.",
                    good_practice=True
                ))
    
    def _check_session_management(self, code: str, file_path: str) -> None:
        """Check for secure session management (KSI-IAM-07)."""
        # Check for session/token usage
        has_sessions = bool(re.search(r"(session|token|jwt|cookie)", code, re.IGNORECASE))
        
        if has_sessions:
            issues = []
            
            # Check for session timeout
            has_timeout = bool(re.search(r"(timeout|expire|max_age|ttl|SESSION_LIFETIME|PERMANENT_SESSION_LIFETIME)", code, re.IGNORECASE))
            if not has_timeout:
                issues.append("No session timeout configured")
            
            # Check for secure cookie flags - match both set_cookie and Flask config
            has_cookie_config = bool(re.search(r"set_cookie|Cookie|SESSION_COOKIE", code))
            if has_cookie_config:
                has_secure = bool(re.search(r"secure\s*=\s*True|SESSION_COOKIE_SECURE.*=\s*True", code, re.IGNORECASE))
                has_httponly = bool(re.search(r"httponly\s*=\s*True|SESSION_COOKIE_HTTPONLY.*=\s*True", code, re.IGNORECASE))
                has_samesite = bool(re.search(r"samesite|SESSION_COOKIE_SAMESITE", code, re.IGNORECASE))
                
                if not has_secure:
                    issues.append("Cookies without 'secure' flag")
                if not has_httponly:
                    issues.append("Cookies without 'httpOnly' flag")
                if not has_samesite:
                    issues.append("Cookies without 'SameSite' attribute")
            
            # Check for token rotation (only if using JWT/tokens)
            uses_jwt = bool(re.search(r"\bjwt\b|\btoken\b", code, re.IGNORECASE))
            has_rotation = bool(re.search(r"(rotate|refresh|renew).*token", code, re.IGNORECASE))
            if uses_jwt and not has_rotation:
                issues.append("No token rotation mechanism")
            
            if issues:
                line_num = self.get_line_number(code, "session") or self.get_line_number(code, "token")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.HIGH,
                    title="Insecure session management",
                    description=f"Session management issues: {', '.join(issues)}. FedRAMP 20x requires secure session handling.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement secure session management:\n```python\nfrom flask import Flask, session\nfrom datetime import timedelta\n\napp = Flask(__name__)\napp.config.update(\n    SECRET_KEY=os.environ['SECRET_KEY'],  # From Key Vault\n    SESSION_COOKIE_SECURE=True,  # HTTPS only\n    SESSION_COOKIE_HTTPONLY=True,  # No JavaScript access\n    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection\n    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)  # 30-min timeout\n)\n\n# JWT with rotation\nimport jwt\nfrom datetime import datetime, timedelta\n\ndef create_token(user_id: str) -> dict:\n    access_token = jwt.encode({\n        'user_id': user_id,\n        'exp': datetime.utcnow() + timedelta(minutes=15),  # Short-lived\n        'type': 'access'\n    }, SECRET_KEY)\n    \n    refresh_token = jwt.encode({\n        'user_id': user_id,\n        'exp': datetime.utcnow() + timedelta(days=7),  # Longer-lived\n        'type': 'refresh'\n    }, SECRET_KEY)\n    \n    return {'access': access_token, 'refresh': refresh_token}\n```\nSource: OWASP Session Management (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)"
                ))
            else:
                line_num = self.get_line_number(code, "secure=True") or self.get_line_number(code, "timeout")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.INFO,
                    title="Secure session management implemented",
                    description="Session configuration includes timeout, secure cookies, and token rotation.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Monitor session activity for suspicious patterns.",
                    good_practice=True
                ))
    
    # =========================================================================
    # Phase 4: Monitoring & Observability
    # =========================================================================
    
    def _check_security_monitoring(self, code: str, file_path: str) -> None:
        """Check for security monitoring and alerting (KSI-MLA-03)."""
        # Check for monitoring framework imports
        has_app_insights = bool(re.search(r"from\s+applicationinsights|from\s+opencensus\.ext\.azure|import\s+applicationinsights", code))
        has_prometheus = bool(re.search(r"from\s+prometheus_client|import\s+prometheus_client", code))
        has_azure_monitor = bool(re.search(r"from\s+azure\.monitor|AzureMonitor", code))
        
        has_monitoring = has_app_insights or has_prometheus or has_azure_monitor
        
        if not has_monitoring:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.HIGH,
                title="Missing security monitoring integration",
                description="No Application Insights, Azure Monitor, or Prometheus integration detected. FedRAMP 20x requires real-time security monitoring.",
                file_path=file_path,
                line_number=1,
                recommendation="Integrate Application Insights for security monitoring:\n```python\nfrom applicationinsights import TelemetryClient\nfrom applicationinsights.requests import WSGIApplication\nimport logging\n\n# Initialize Application Insights\ntc = TelemetryClient(instrumentation_key=os.environ['APPINSIGHTS_KEY'])\n\n# Track custom security events\ndef track_security_event(event_name: str, properties: dict):\n    tc.track_event(event_name, properties)\n    tc.flush()\n\n# Example: Track authentication events\ndef login(username: str):\n    try:\n        user = authenticate(username)\n        track_security_event('UserLogin', {\n            'username': username,\n            'success': True,\n            'timestamp': datetime.utcnow().isoformat()\n        })\n        return user\n    except AuthenticationError as e:\n        track_security_event('UserLoginFailed', {\n            'username': username,\n            'success': False,\n            'error': str(e)\n        })\n        raise\n\n# Flask integration\nfrom flask import Flask\napp = Flask(__name__)\napp.wsgi_app = WSGIApplication(instrumentation_key=os.environ['APPINSIGHTS_KEY'], app=app.wsgi_app)\n```\nSource: Azure Application Insights (https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview)"
            ))
        else:
            # Check for security event tracking
            has_custom_events = bool(re.search(r"track_(event|metric|trace)|log_security|security_event", code, re.IGNORECASE))
            has_auth_logging = bool(re.search(r"track.*auth|log.*login|audit.*access", code, re.IGNORECASE))
            
            if has_custom_events and has_auth_logging:
                line_num = self.get_line_number(code, "track_event") or self.get_line_number(code, "TelemetryClient")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.INFO,
                    title="Security monitoring implemented",
                    description="Application Insights/Azure Monitor integrated with custom security event tracking.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure monitoring covers: authentication, authorization, data access, configuration changes, and error conditions.",
                    good_practice=True
                ))
            else:
                line_num = self.get_line_number(code, "applicationinsights") or self.get_line_number(code, "prometheus")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.MEDIUM,
                    title="Limited security event tracking",
                    description="Monitoring framework present but missing comprehensive security event tracking.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add custom tracking for authentication, authorization failures, data access, and suspicious patterns."
                ))
    
    def _check_anomaly_detection(self, code: str, file_path: str) -> None:
        """Check for anomaly detection configuration (KSI-MLA-04)."""
        # Check for anomaly detection or smart detection configuration
        has_smart_detection = bool(re.search(r"smart.?detection|anomaly.?detection|adaptive.?sampling", code, re.IGNORECASE))
        has_baseline_metrics = bool(re.search(r"baseline|threshold|metric.*alert|custom.*metric", code, re.IGNORECASE))
        has_auth_anomalies = bool(re.search(r"(unusual|suspicious|anomalous).*(login|auth|access)", code, re.IGNORECASE))
        
        # Check for Application Insights with smart detection APIs
        has_app_insights_config = bool(re.search(r"TelemetryConfiguration|ApplicationInsightsConfig", code))
        
        if not (has_smart_detection or has_baseline_metrics or has_auth_anomalies):
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.MEDIUM,
                title="Missing anomaly detection",
                description="No anomaly detection or smart detection configuration found. FedRAMP 20x recommends automated anomaly detection.",
                file_path=file_path,
                line_number=1,
                recommendation="Configure Application Insights Smart Detection and custom metrics:\n```python\nfrom applicationinsights import TelemetryClient\nfrom collections import Counter\nfrom datetime import datetime, timedelta\n\ntc = TelemetryClient()\n\n# Track authentication patterns for anomaly detection\nclass AuthAnomalyDetector:\n    def __init__(self):\n        self.login_attempts = Counter()\n        self.baseline_threshold = 5  # Normal login attempts per hour\n    \n    def track_login(self, user_id: str, ip_address: str, success: bool):\n        key = f\"{user_id}:{ip_address}\"\n        self.login_attempts[key] += 1\n        \n        # Custom metric for Application Insights\n        tc.track_metric('LoginAttempts', 1, properties={\n            'user_id': user_id,\n            'ip': ip_address,\n            'success': success\n        })\n        \n        # Detect anomalies\n        if self.login_attempts[key] > self.baseline_threshold:\n            tc.track_event('AnomalousLoginPattern', {\n                'user_id': user_id,\n                'ip': ip_address,\n                'attempts': self.login_attempts[key],\n                'threshold': self.baseline_threshold,\n                'severity': 'high'\n            })\n        \n        tc.flush()\n\n# Track performance anomalies\ndef track_request_duration(endpoint: str, duration_ms: float):\n    tc.track_metric('RequestDuration', duration_ms, properties={\n        'endpoint': endpoint\n    })\n    \n    # Alert on performance degradation\n    if duration_ms > 5000:  # 5 second threshold\n        tc.track_event('PerformanceDegradation', {\n            'endpoint': endpoint,\n            'duration_ms': duration_ms,\n            'severity': 'medium'\n        })\n```\nSource: Azure Monitor Smart Detection (https://learn.microsoft.com/azure/azure-monitor/app/proactive-diagnostics)"
            ))
        else:
            line_num = self.get_line_number(code, "anomaly") or self.get_line_number(code, "baseline") or self.get_line_number(code, "threshold")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.INFO,
                title="Anomaly detection configured",
                description="Smart detection or custom anomaly detection logic implemented.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure anomaly detection covers: authentication patterns, performance degradation, resource usage spikes, and API abuse.",
                good_practice=True
            ))
    
    def _check_performance_monitoring(self, code: str, file_path: str) -> None:
        """Check for performance monitoring (KSI-MLA-06)."""
        # Check for performance monitoring patterns
        has_timing = bool(re.search(r"(time\.|perf_counter|timeit|@timed|duration|elapsed)", code))
        has_profiling = bool(re.search(r"(cProfile|profile|line_profiler|memory_profiler)", code))
        has_request_tracking = bool(re.search(r"track_(request|dependency)|request.*duration|response.*time", code, re.IGNORECASE))
        has_db_monitoring = bool(re.search(r"(sql.*duration|query.*time|db.*performance|slow.*query)", code, re.IGNORECASE))
        has_resource_monitoring = bool(re.search(r"(cpu|memory|disk).*(usage|utilization|monitor)", code, re.IGNORECASE))
        
        has_monitoring = has_timing or has_request_tracking or has_db_monitoring or has_resource_monitoring
        
        if not has_monitoring:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.MEDIUM,
                title="Missing performance monitoring",
                description="No performance monitoring detected. FedRAMP 20x requires performance baseline tracking to detect attacks.",
                file_path=file_path,
                line_number=1,
                recommendation="Implement comprehensive performance monitoring:\n```python\nimport time\nimport psutil\nfrom applicationinsights import TelemetryClient\nfrom functools import wraps\n\ntc = TelemetryClient()\n\n# Request duration tracking\ndef track_performance(operation_name: str):\n    def decorator(func):\n        @wraps(func)\n        def wrapper(*args, **kwargs):\n            start = time.perf_counter()\n            try:\n                result = func(*args, **kwargs)\n                duration_ms = (time.perf_counter() - start) * 1000\n                \n                # Track in Application Insights\n                tc.track_metric('OperationDuration', duration_ms, properties={\n                    'operation': operation_name,\n                    'success': True\n                })\n                \n                # Alert on slow operations\n                if duration_ms > 1000:\n                    tc.track_event('SlowOperation', {\n                        'operation': operation_name,\n                        'duration_ms': duration_ms\n                    })\n                \n                return result\n            except Exception as e:\n                duration_ms = (time.perf_counter() - start) * 1000\n                tc.track_metric('OperationDuration', duration_ms, properties={\n                    'operation': operation_name,\n                    'success': False,\n                    'error': str(e)\n                })\n                raise\n            finally:\n                tc.flush()\n        return wrapper\n    return decorator\n\n# Resource utilization monitoring\ndef track_resource_usage():\n    cpu_percent = psutil.cpu_percent(interval=1)\n    memory = psutil.virtual_memory()\n    disk = psutil.disk_usage('/')\n    \n    tc.track_metric('CPUUsage', cpu_percent)\n    tc.track_metric('MemoryUsage', memory.percent)\n    tc.track_metric('DiskUsage', disk.percent)\n    \n    # Alert on high resource usage\n    if cpu_percent > 80 or memory.percent > 80:\n        tc.track_event('HighResourceUsage', {\n            'cpu': cpu_percent,\n            'memory': memory.percent,\n            'severity': 'high'\n        })\n\n# Database query monitoring\n@track_performance('database_query')\ndef execute_query(query: str):\n    # Your database logic here\n    pass\n```\nSource: Azure Monitor Performance (https://learn.microsoft.com/azure/azure-monitor/app/performance)"
            ))
        else:
            issues = []
            if not has_request_tracking:
                issues.append("HTTP request/response times")
            if not has_db_monitoring:
                issues.append("Database query performance")
            if not has_resource_monitoring:
                issues.append("CPU/memory utilization")
            
            if issues:
                line_num = self.get_line_number(code, "time.") or self.get_line_number(code, "track_")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.LOW,
                    title="Incomplete performance monitoring",
                    description=f"Performance monitoring present but missing: {', '.join(issues)}.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation=f"Add monitoring for: {', '.join(issues)}."
                ))
            else:
                line_num = self.get_line_number(code, "track_request") or self.get_line_number(code, "duration")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.INFO,
                    title="Comprehensive performance monitoring",
                    description="Request tracking, database monitoring, and resource utilization tracking implemented.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Set performance baselines and alerts for anomalies that may indicate attacks.",
                    good_practice=True
                ))
    
    def _check_incident_response(self, code: str, file_path: str) -> None:
        """Check for incident response automation (KSI-INR-01)."""
        # Check for incident response integrations
        has_pagerduty = bool(re.search(r"pagerduty|pypd", code, re.IGNORECASE))
        has_servicenow = bool(re.search(r"servicenow|pysnow", code, re.IGNORECASE))
        has_webhooks = bool(re.search(r"webhook|http.*post.*alert|incident.*notification", code, re.IGNORECASE))
        has_azure_alerts = bool(re.search(r"azure.*alert|action.*group|alert.*rule", code, re.IGNORECASE))
        has_email_alerts = bool(re.search(r"send.*email|smtp|alert.*email", code, re.IGNORECASE))
        has_slack = bool(re.search(r"slack|slack_sdk", code, re.IGNORECASE))
        
        has_integration = has_pagerduty or has_servicenow or has_webhooks or has_azure_alerts or has_slack
        
        if not has_integration:
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.MEDIUM,
                title="Missing incident response automation",
                description="No incident response system integration (PagerDuty, ServiceNow, webhooks). FedRAMP 20x requires automated incident response.",
                file_path=file_path,
                line_number=1,
                recommendation="Integrate with incident response system:\n```python\nimport requests\nimport json\nfrom datetime import datetime\nfrom enum import Enum\n\nclass IncidentSeverity(Enum):\n    CRITICAL = 'critical'\n    HIGH = 'high'\n    MEDIUM = 'medium'\n    LOW = 'low'\n\ndef create_incident(title: str, description: str, severity: IncidentSeverity):\n    \"\"\"Create incident in PagerDuty/ServiceNow via webhook.\"\"\"\n    webhook_url = os.environ['INCIDENT_WEBHOOK_URL']\n    \n    payload = {\n        'title': title,\n        'description': description,\n        'severity': severity.value,\n        'timestamp': datetime.utcnow().isoformat(),\n        'source': 'application',\n        'service': os.environ.get('SERVICE_NAME', 'unknown')\n    }\n    \n    try:\n        response = requests.post(\n            webhook_url,\n            json=payload,\n            headers={'Content-Type': 'application/json'},\n            timeout=10\n        )\n        response.raise_for_status()\n        return response.json()\n    except Exception as e:\n        # Log but don't fail - incident creation shouldn't break app\n        logger.error(f\"Failed to create incident: {e}\")\n        return None\n\n# Example: Auto-create incident on security event\ndef handle_security_event(event_type: str, details: dict):\n    if event_type == 'multiple_failed_logins':\n        create_incident(\n            title=f\"Suspicious Login Activity: {details['user_id']}\",\n            description=f\"Multiple failed login attempts detected. IP: {details['ip']}, Attempts: {details['count']}\",\n            severity=IncidentSeverity.HIGH\n        )\n    elif event_type == 'sql_injection_attempt':\n        create_incident(\n            title=f\"SQL Injection Attempt Blocked\",\n            description=f\"Potential SQL injection detected. Endpoint: {details['endpoint']}, IP: {details['ip']}\",\n            severity=IncidentSeverity.CRITICAL\n        )\n\n# Azure Monitor Action Group integration\nfrom azure.mgmt.monitor import MonitorManagementClient\nfrom azure.identity import DefaultAzureCredential\n\ndef configure_action_group():\n    credential = DefaultAzureCredential()\n    monitor_client = MonitorManagementClient(credential, subscription_id)\n    \n    # Create action group for critical alerts\n    action_group = {\n        'location': 'global',\n        'group_short_name': 'SecOps',\n        'enabled': True,\n        'webhook_receivers': [{\n            'name': 'incident_webhook',\n            'service_uri': os.environ['INCIDENT_WEBHOOK_URL']\n        }]\n    }\n```\nSource: Azure Monitor Action Groups (https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups)"
            ))
        else:
            # Check for critical event handling
            has_critical_alerts = bool(re.search(r"(critical|emergency|p0|sev0|severity.*1)", code, re.IGNORECASE))
            has_auto_escalation = bool(re.search(r"escalate|escalation|on-call", code, re.IGNORECASE))
            
            if has_critical_alerts or has_auto_escalation:
                line_num = self.get_line_number(code, "pagerduty") or self.get_line_number(code, "webhook") or self.get_line_number(code, "incident")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.INFO,
                    title="Incident response automation configured",
                    description="Incident response system integration with automated alerting for critical events.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure incident automation covers: authentication failures, authorization violations, data breaches, and system anomalies.",
                    good_practice=True
                ))
            else:
                line_num = self.get_line_number(code, "webhook") or self.get_line_number(code, "alert")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.LOW,
                    title="Basic incident notification configured",
                    description="Incident notification present but may lack severity-based auto-escalation.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Implement severity-based escalation for critical security events."
                ))
    
    # Phase 5: DevSecOps Automation Methods
    
    def _check_configuration_management(self, code: str, file_path: str) -> None:
        """Check for secure configuration management (KSI-CMT-01)."""
        # Check for hardcoded configuration values
        config_patterns = [
            (r"(api_url|endpoint|base_url)\s*=\s*['\"]https?://[^'\"]+['\"]", "API endpoint"),
            (r"(database_host|db_host|server)\s*=\s*['\"][^'\"]+['\"]", "Database host"),
            (r"(port|db_port)\s*=\s*\d+", "Port number"),
        ]
        
        hardcoded_configs = []
        for pattern, config_type in config_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            if matches:
                # Check if it's using environment variables or config service
                for match in matches:
                    context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                    if not re.search(r"(os\.environ|os\.getenv|config\.|settings\.|get_secret)", context):
                        hardcoded_configs.append((match, config_type))
        
        # Check for App Configuration or Key Vault integration
        has_app_config = bool(re.search(r"azure\.appconfiguration|AzureAppConfigurationClient", code))
        has_key_vault = bool(re.search(r"azure\.keyvault|SecretClient", code))
        has_env_vars = bool(re.search(r"os\.environ\[|os\.getenv\(", code))
        
        if hardcoded_configs:
            for match, config_type in hardcoded_configs[:3]:  # Report first 3
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-01",
                    severity=Severity.MEDIUM,
                    title=f"Hardcoded {config_type} configuration",
                    description=f"Configuration value hardcoded in source. FedRAMP 20x requires externalized, environment-specific configuration.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation=f"Use Azure App Configuration or environment variables:\n```python\nimport os\nfrom azure.appconfiguration import AzureAppConfigurationClient\nfrom azure.identity import DefaultAzureCredential\n\n# Option 1: Azure App Configuration (recommended for FedRAMP)\nconfig_client = AzureAppConfigurationClient(\n    base_url=os.environ['APPCONFIGURATION_ENDPOINT'],\n    credential=DefaultAzureCredential()\n)\n{config_type.lower().replace(' ', '_')} = config_client.get_configuration_setting(\n    key='{config_type.lower().replace(' ', '_')}'\n).value\n\n# Option 2: Environment variables (simpler but less secure)\n{config_type.lower().replace(' ', '_')} = os.environ['{config_type.upper().replace(' ', '_')}']\n```\nSource: Azure App Configuration (https://learn.microsoft.com/azure/azure-app-configuration/)"
                ))
        
        if has_app_config or has_key_vault:
            line_num = self.get_line_number(code, "appconfiguration") or self.get_line_number(code, "keyvault")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.INFO,
                title="Azure App Configuration or Key Vault integration",
                description="Application uses centralized configuration management service.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure all environment-specific values are externalized and production configs are access-controlled.",
                good_practice=True
            ))
        elif not hardcoded_configs and has_env_vars:
            line_num = self.get_line_number(code, "os.environ")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.LOW,
                title="Configuration uses environment variables",
                description="Environment variables used for configuration. Consider Azure App Configuration for centralized management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="For FedRAMP environments, migrate to Azure App Configuration for audit trails and access control.",
                good_practice=True
            ))
    
    def _check_version_control(self, code: str, file_path: str) -> None:
        """Check for version control enforcement (KSI-CMT-02)."""
        # This check is more about repository configuration, but we can check for deployment scripts
        
        # Check for direct production deployment patterns (anti-pattern)
        direct_deploy_patterns = [
            r"subprocess.*git\s+push.*production",
            r"os\.system.*git\s+push.*main",
            r"subprocess.*deploy.*production",
        ]
        
        has_direct_deploy = False
        for pattern in direct_deploy_patterns:
            match = re.search(pattern, code, re.IGNORECASE)
            if match:
                has_direct_deploy = True
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-02",
                    severity=Severity.HIGH,
                    title="Direct production deployment without approval",
                    description="Code performs direct deployment to production. FedRAMP 20x requires code review and approval workflows.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation="Use CI/CD pipelines with approval gates:\n1. Require pull request reviews before merge\n2. Configure branch protection on main/production branches\n3. Use Azure DevOps pipelines or GitHub Actions with approval steps\n4. Implement automated security checks before deployment\n\nExample Azure Pipeline approval:\n```yaml\nstages:\n- stage: Deploy_Production\n  dependsOn: Test\n  condition: succeeded()\n  jobs:\n  - deployment: DeployProd\n    environment: production  # Requires approval in Azure DevOps\n    strategy:\n      runOnce:\n        deploy:\n          steps:\n          - script: python deploy.py\n```\nSource: Azure DevOps Approvals (https://learn.microsoft.com/azure/devops/pipelines/process/approvals)"
                ))
                break
        
        # Check for CI/CD configuration references (good practice)
        has_cicd_config = bool(re.search(r"(\.github/workflows|azure-pipelines|\.gitlab-ci|jenkinsfile)", code, re.IGNORECASE))
        has_approval_check = bool(re.search(r"(approval|approve|review|gate)", code, re.IGNORECASE))
        
        if has_cicd_config or has_approval_check:
            line_num = self.get_line_number(code, "workflow") or self.get_line_number(code, "pipeline") or self.get_line_number(code, "approval")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-02",
                severity=Severity.INFO,
                title="CI/CD approval workflow referenced",
                description="Code references CI/CD approval processes.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Verify branch protection and approval requirements are enforced in repository settings.",
                good_practice=True
            ))
    
    def _check_automated_testing(self, code: str, file_path: str) -> None:
        """Check for automated security testing (KSI-CMT-03)."""
        # Check for test framework imports
        test_frameworks = [
            r"import\s+unittest",
            r"import\s+pytest",
            r"from\s+pytest",
            r"import\s+nose",
            r"from\s+django\.test",
        ]
        
        has_test_framework = False
        for pattern in test_frameworks:
            if re.search(pattern, code):
                has_test_framework = True
                break
        
        # Check for security-specific testing
        security_test_patterns = [
            r"(test.*security|test.*auth|test.*authorization|test.*encryption|test.*xss|test.*sql.*injection)",
            r"(pytest.*security|bandit|safety)",
        ]
        
        has_security_tests = False
        for pattern in security_test_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                has_security_tests = True
                break
        
        # Check for test coverage
        has_coverage = bool(re.search(r"(coverage|pytest-cov|--cov)", code, re.IGNORECASE))
        
        # Check if this is a test file
        is_test_file = bool(re.search(r"test_.*\.py$|.*_test\.py$", file_path))
        
        if not is_test_file and not has_test_framework:
            # Only report missing tests for non-test files in certain directories
            if re.search(r"(src/|app/|lib/|api/|views/|controllers/)", file_path, re.IGNORECASE):
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.MEDIUM,
                    title="No automated tests found",
                    description="Application code without corresponding test files. FedRAMP 20x requires automated security testing in CI/CD.",
                    file_path=file_path,
                    line_number=1,
                    recommendation="Create test files with security-focused tests:\n```python\nimport pytest\nfrom myapp import app, db\nfrom myapp.models import User\n\nclass TestSecurity:\n    def test_authentication_required(self):\n        \"\"\"Test that protected endpoints require authentication.\"\"\"\n        response = app.test_client().get('/api/protected')\n        assert response.status_code == 401\n    \n    def test_sql_injection_prevention(self):\n        \"\"\"Test that SQL injection is blocked.\"\"\"\n        malicious_input = \"'; DROP TABLE users; --\"\n        response = app.test_client().post('/search', data={'query': malicious_input})\n        # Should not execute malicious SQL\n        assert User.query.count() > 0  # Table still exists\n    \n    def test_xss_prevention(self):\n        \"\"\"Test that XSS payloads are escaped.\"\"\"\n        xss_payload = '<script>alert(\"XSS\")</script>'\n        response = app.test_client().post('/comment', data={'text': xss_payload})\n        assert b'<script>' not in response.data  # Should be escaped\n    \n    def test_authorization_enforcement(self):\n        \"\"\"Test that users can only access their own data.\"\"\"\n        user1_token = get_token_for_user('user1')\n        response = app.test_client().get(\n            '/api/users/user2/data',\n            headers={'Authorization': f'Bearer {user1_token}'}\n        )\n        assert response.status_code == 403  # Forbidden\n\n# Run with coverage:\n# pytest --cov=myapp --cov-report=html tests/\n```\n\nIntegrate security scanners in CI/CD:\n```yaml\n# .github/workflows/security.yml\nname: Security Tests\non: [push, pull_request]\njobs:\n  security:\n    runs-on: ubuntu-latest\n    steps:\n    - uses: actions/checkout@v3\n    - name: Run Bandit security scanner\n      run: |\n        pip install bandit\n        bandit -r src/ -f json -o bandit-report.json\n    - name: Run Safety dependency checker\n      run: |\n        pip install safety\n        safety check --json\n    - name: Run tests with coverage\n      run: |\n        pytest --cov=src --cov-report=xml\n```\nSource: OWASP Testing Guide (https://owasp.org/www-project-web-security-testing-guide/)"
                ))
        elif is_test_file and has_test_framework:
            if has_security_tests:
                line_num = self.get_line_number(code, "test.*security") or self.get_line_number(code, "test.*auth")
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.INFO,
                    title="Security tests implemented",
                    description="Test file includes security-focused test cases.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure tests cover: authentication, authorization, input validation, XSS, SQL injection, and CSRF.",
                    good_practice=True
                ))
            
            if has_coverage:
                line_num = self.get_line_number(code, "coverage") or self.get_line_number(code, "cov")
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.INFO,
                    title="Test coverage tracking configured",
                    description="Tests configured with code coverage measurement.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Set minimum coverage thresholds (80%+) and fail builds on regression.",
                    good_practice=True
                ))
    
    def _check_audit_logging(self, code: str, file_path: str) -> None:
        """Check for audit logging of security events (KSI-AFR-01)."""
        # Check for authentication/authorization functions
        has_auth_code = bool(re.search(r"(def.*login|def.*authenticate|def.*authorize|@login_required|@require_auth)", code, re.IGNORECASE))
        
        # Check for data access code
        has_data_access = bool(re.search(r"(\.query\.|\.filter\(|SELECT|INSERT|UPDATE|DELETE|db\.session)", code, re.IGNORECASE))
        
        # Check for logging in auth/data access contexts
        has_auth_logging = False
        has_data_logging = False
        
        if has_auth_code:
            # Look for logging near authentication code
            auth_matches = re.finditer(r"(def.*login|def.*authenticate|@login_required)", code, re.IGNORECASE)
            for match in auth_matches:
                context = code[match.start():min(len(code), match.end()+500)]
                if re.search(r"(logger\.|logging\.|log\.|track_event|track_trace)", context, re.IGNORECASE):
                    has_auth_logging = True
                    break
        
        if has_data_access:
            # Look for logging near data operations
            data_matches = re.finditer(r"(\.query\.|SELECT|INSERT|UPDATE|DELETE)", code, re.IGNORECASE)
            for match in data_matches:
                context = code[max(0, match.start()-200):min(len(code), match.end()+200)]
                if re.search(r"(logger\.|logging\.|log\.|track_event)", context, re.IGNORECASE):
                    has_data_logging = True
                    break
        
        # Report missing audit logging
        if has_auth_code and not has_auth_logging:
            line_num = self.get_line_number(code, "login") or self.get_line_number(code, "authenticate")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.HIGH,
                title="Authentication without audit logging",
                description="Authentication/authorization code missing audit logs. FedRAMP 20x requires logging of all security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add audit logging for authentication events:\n```python\nimport logging\nfrom datetime import datetime\nfrom azure.monitor.opentelemetry import configure_azure_monitor\nfrom opentelemetry import trace\n\n# Configure Azure Monitor (Application Insights)\nconfigure_azure_monitor(\n    connection_string=os.environ['APPLICATIONINSIGHTS_CONNECTION_STRING']\n)\ntracer = trace.get_tracer(__name__)\nlogger = logging.getLogger(__name__)\n\nclass SecurityAuditLogger:\n    @staticmethod\n    def log_authentication_attempt(user_id: str, ip_address: str, success: bool, method: str = 'password'):\n        event = {\n            'event_type': 'authentication_attempt',\n            'user_id': user_id,\n            'ip_address': ip_address,\n            'success': success,\n            'method': method,\n            'timestamp': datetime.utcnow().isoformat(),\n        }\n        \n        if success:\n            logger.info('Authentication success', extra=event)\n        else:\n            logger.warning('Authentication failed', extra=event)\n        \n        # Send to Application Insights\n        with tracer.start_as_current_span('auth_attempt') as span:\n            span.set_attributes(event)\n    \n    @staticmethod\n    def log_authorization_check(user_id: str, resource: str, action: str, allowed: bool):\n        event = {\n            'event_type': 'authorization_check',\n            'user_id': user_id,\n            'resource': resource,\n            'action': action,\n            'allowed': allowed,\n            'timestamp': datetime.utcnow().isoformat(),\n        }\n        \n        if not allowed:\n            logger.warning('Authorization denied', extra=event)\n        else:\n            logger.info('Authorization granted', extra=event)\n\n# Usage\n@app.route('/login', methods=['POST'])\ndef login():\n    username = request.form['username']\n    password = request.form['password']\n    \n    user = User.query.filter_by(username=username).first()\n    \n    if user and user.check_password(password):\n        SecurityAuditLogger.log_authentication_attempt(\n            user_id=user.id,\n            ip_address=request.remote_addr,\n            success=True,\n            method='password'\n        )\n        login_user(user)\n        return redirect('/dashboard')\n    else:\n        SecurityAuditLogger.log_authentication_attempt(\n            user_id=username,\n            ip_address=request.remote_addr,\n            success=False,\n            method='password'\n        )\n        return 'Invalid credentials', 401\n```\nSource: Azure Monitor audit logging (https://learn.microsoft.com/azure/azure-monitor/logs/data-security)"
            ))
        
        if has_data_access and not has_data_logging:
            line_num = self.get_line_number(code, "query") or self.get_line_number(code, "SELECT")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.MEDIUM,
                title="Data access without audit logging",
                description="Database operations missing audit trails. FedRAMP 20x requires logging of sensitive data access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Log sensitive data access:\n```python\ndef log_data_access(user_id: str, table: str, operation: str, record_id: str = None):\n    logger.info('Data access', extra={\n        'event_type': 'data_access',\n        'user_id': user_id,\n        'table': table,\n        'operation': operation,\n        'record_id': record_id,\n        'timestamp': datetime.utcnow().isoformat()\n    })\n\n# Usage\n@app.route('/api/user/<user_id>', methods=['GET'])\n@login_required\ndef get_user(user_id):\n    log_data_access(\n        user_id=current_user.id,\n        table='users',\n        operation='read',\n        record_id=user_id\n    )\n    user = User.query.get(user_id)\n    return jsonify(user.to_dict())\n```"
            ))
        
        # Good practice: audit logging present
        if (has_auth_code and has_auth_logging) or (has_data_access and has_data_logging):
            line_num = self.get_line_number(code, "logger") or self.get_line_number(code, "track_event")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.INFO,
                title="Audit logging implemented for security events",
                description="Security-relevant operations include audit logging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure audit logs include: user ID, timestamp, action, result, IP address, and resource accessed.",
                good_practice=True
            ))
    
    def _check_log_integrity(self, code: str, file_path: str) -> None:
        """Check for log integrity and protection (KSI-AFR-02)."""
        # Check for local file logging (anti-pattern for FedRAMP)
        local_logging_patterns = [
            r"FileHandler\(['\"].*\.log",
            r"open\(['\"].*\.log['\"],\s*['\"]w",
            r"with\s+open\(['\"].*\.log",
            r"logging\.basicConfig.*filename=",
        ]
        
        has_local_logging = False
        for pattern in local_logging_patterns:
            match = re.search(pattern, code, re.IGNORECASE)
            if match:
                has_local_logging = True
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-AFR-02",
                    severity=Severity.HIGH,
                    title="Logs written to local files (insecure)",
                    description="Application writes logs to local files. FedRAMP 20x requires logs streamed to immutable, centralized storage (SIEM).",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation="Stream logs to Azure Monitor (Application Insights):\n```python\nimport logging\nimport os\nfrom azure.monitor.opentelemetry import configure_azure_monitor\nfrom opentelemetry import trace\nfrom opentelemetry.sdk._logs import LoggingHandler\n\n# Configure Azure Monitor for centralized, immutable logging\nconfigure_azure_monitor(\n    connection_string=os.environ['APPLICATIONINSIGHTS_CONNECTION_STRING']\n)\n\n# Configure structured logging\nlogger = logging.getLogger(__name__)\nlogger.setLevel(logging.INFO)\n\n# DO NOT use FileHandler - logs must go to SIEM\n# handler = logging.FileHandler('app.log')  # WRONG\n\n# Instead, use Application Insights handler (logs are immutable)\nfrom opencensus.ext.azure.log_exporter import AzureLogHandler\nazure_handler = AzureLogHandler(\n    connection_string=os.environ['APPLICATIONINSIGHTS_CONNECTION_STRING']\n)\nlogger.addHandler(azure_handler)\n\n# All logs now sent to Azure Monitor (tamper-proof)\nlogger.info('Application started', extra={'version': '1.0.0'})\nlogger.warning('Security event detected', extra={'event_type': 'failed_login', 'user': 'john'})\n\n# For audit logs, use Azure Event Hubs for write-once storage\nfrom azure.eventhub import EventHubProducerClient, EventData\nfrom azure.identity import DefaultAzureCredential\n\nclass ImmutableAuditLogger:\n    def __init__(self):\n        self.producer = EventHubProducerClient(\n            fully_qualified_namespace=os.environ['EVENTHUB_NAMESPACE'],\n            eventhub_name='audit-logs',\n            credential=DefaultAzureCredential()\n        )\n    \n    def log_audit_event(self, event: dict):\n        \"\"\"Send audit log to Event Hubs (immutable, append-only).\"\"\"\n        event_data = EventData(json.dumps(event))\n        self.producer.send_event(event_data)\n\naudit_logger = ImmutableAuditLogger()\naudit_logger.log_audit_event({\n    'event_type': 'data_access',\n    'user_id': 'user123',\n    'resource': '/api/users/456',\n    'timestamp': datetime.utcnow().isoformat()\n})\n```\n\nConfigure log retention policies:\n```python\n# In Log Analytics workspace (via Bicep/ARM):\nresource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {\n  name: 'security-logs'\n  properties: {\n    retentionInDays: 90  # FedRAMP minimum\n    features: {\n      immediatePurgeDataOn30Days: false  # Prevent log deletion\n    }\n  }\n}\n```\nSource: Azure Monitor log integrity (https://learn.microsoft.com/azure/azure-monitor/logs/data-security)"
                ))
                break
        
        # Check for Application Insights or centralized logging
        has_app_insights = bool(re.search(r"(azure.*monitor|applicationinsights|opencensus.*azure|AzureLogHandler)", code, re.IGNORECASE))
        has_event_hub = bool(re.search(r"(eventhub|EventHubProducerClient)", code, re.IGNORECASE))
        has_syslog = bool(re.search(r"(syslog|SysLogHandler)", code, re.IGNORECASE))
        
        has_centralized = has_app_insights or has_event_hub or has_syslog
        
        if not has_local_logging and has_centralized:
            line_num = self.get_line_number(code, "applicationinsights") or self.get_line_number(code, "eventhub") or self.get_line_number(code, "syslog")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.INFO,
                title="Logs streamed to centralized SIEM",
                description="Application sends logs to Azure Monitor or Event Hubs (immutable storage).",
                file_path=file_path,
                line_number=line_num,
                recommendation="Verify log retention meets FedRAMP requirements (90+ days) and logs cannot be modified/deleted.",
                good_practice=True
            ))
    
    def _check_key_management(self, code: str, file_path: str) -> None:
        """Check for cryptographic key management (KSI-CED-01)."""
        # Check for hardcoded cryptographic keys/certificates
        key_patterns = [
            (r"(private_key|secret_key|encryption_key)\s*=\s*['\"][^'\"]{20,}['\"]", "encryption key"),
            (r"-----BEGIN\s+(PRIVATE|RSA|EC)\s+KEY-----", "private key"),
            (r"(cert|certificate)\s*=\s*['\"].*BEGIN\s+CERTIFICATE", "certificate"),
            (r"Fernet\(['\"].*['\"]", "Fernet key"),
            (r"AES\.new\(['\"].*['\"]", "AES key"),
        ]
        
        hardcoded_keys = []
        for pattern, key_type in key_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE | re.DOTALL))
            for match in matches:
                # Check if it's from Key Vault or environment (acceptable)
                context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                if not re.search(r"(get_secret|SecretClient|KeyVaultSecret|os\.environ)", context):
                    hardcoded_keys.append((match, key_type))
        
        # Check for local key generation without HSM
        key_generation_patterns = [
            r"Fernet\.generate_key\(\)",
            r"RSA\.generate\(",
            r"secrets\.token_bytes\(",
            r"os\.urandom\(",
        ]
        
        has_local_keygen = False
        for pattern in key_generation_patterns:
            match = re.search(pattern, code)
            if match:
                # Check if it's for HSM or Key Vault
                context = code[max(0, match.start()-200):min(len(code), match.end()+200)]
                if not re.search(r"(KeyVaultClient|CryptographyClient|create_key|import_key)", context, re.IGNORECASE):
                    has_local_keygen = True
                    line_num = self.get_line_number(code, match.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-CED-01",
                        severity=Severity.HIGH,
                        title="Local cryptographic key generation",
                        description="Application generates encryption keys locally. FedRAMP 20x requires keys managed in Azure Key Vault with HSM backing.",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=match.group(0),
                        recommendation="Use Azure Key Vault for key generation and storage:\n```python\nfrom azure.keyvault.keys import KeyClient\nfrom azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm\nfrom azure.identity import DefaultAzureCredential\nimport os\n\n# Key Vault client\nkey_vault_url = os.environ['KEY_VAULT_URL']\ncredential = DefaultAzureCredential()\nkey_client = KeyClient(vault_url=key_vault_url, credential=credential)\n\n# Generate key in Key Vault (HSM-backed)\nkey_name = 'data-encryption-key'\nkey = key_client.create_rsa_key(\n    name=key_name,\n    size=2048,\n    hardware_protected=True  # Use HSM\n)\n\nprint(f'Created key: {key.name} (ID: {key.id})')\n\n# Use key for encryption (key never leaves Key Vault)\ncrypto_client = CryptographyClient(key, credential=credential)\nplaintext = b'Sensitive data to encrypt'\nresult = crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep, plaintext)\nprint(f'Encrypted: {result.ciphertext.hex()}')\n\n# Decrypt\ndecrypt_result = crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep, result.ciphertext)\nprint(f'Decrypted: {decrypt_result.plaintext.decode()}')\n\n# Rotate keys regularly\ndef rotate_key(key_name: str):\n    # Create new version of key\n    new_key = key_client.create_rsa_key(\n        name=key_name,\n        size=2048,\n        hardware_protected=True\n    )\n    print(f'Rotated key to version: {new_key.properties.version}')\n    return new_key\n\n# For symmetric encryption with Key Vault\nfrom azure.keyvault.secrets import SecretClient\n\nsecret_client = SecretClient(vault_url=key_vault_url, credential=credential)\n\n# Store data encryption key (DEK) in Key Vault\nfrom cryptography.fernet import Fernet\n\n# Generate DEK locally (wrapped immediately)\ndek = Fernet.generate_key()\n\n# Encrypt DEK with Key Vault KEK (envelope encryption)\nkek_crypto = CryptographyClient(key, credential=credential)\nencrypted_dek = kek_crypto.encrypt(EncryptionAlgorithm.rsa_oaep, dek)\n\n# Store encrypted DEK\nsecret_client.set_secret('encrypted-dek', encrypted_dek.ciphertext.hex())\n\n# Use DEK for data encryption\nfernet = Fernet(dek)\nencrypted_data = fernet.encrypt(b'My sensitive data')\n```\nSource: Azure Key Vault cryptographic operations (https://learn.microsoft.com/azure/key-vault/keys/about-keys)"
                    ))
        
        # Report hardcoded keys
        if hardcoded_keys:
            for match, key_type in hardcoded_keys[:2]:  # Report first 2
                line_num = self.get_line_number(code, match.group(0))
                snippet = match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else '')
                self.add_finding(Finding(
                    requirement_id="KSI-CED-01",
                    severity=Severity.HIGH,
                    title=f"Hardcoded {key_type} in source code",
                    description=f"Cryptographic {key_type} hardcoded in application. FedRAMP 20x strictly prohibits keys in source code.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    recommendation=f"Store {key_type} in Azure Key Vault:\n```python\nfrom azure.keyvault.secrets import SecretClient\nfrom azure.identity import DefaultAzureCredential\nimport os\n\nkey_vault_url = os.environ['KEY_VAULT_URL']\ncredential = DefaultAzureCredential()\nsecret_client = SecretClient(vault_url=key_vault_url, credential=credential)\n\n# Retrieve {key_type} from Key Vault\n{key_type.replace(' ', '_')} = secret_client.get_secret('{key_type.replace(' ', '-')}').value\n\n# NEVER do this:\n# {key_type.replace(' ', '_')} = 'hardcoded-value'  # SECURITY VIOLATION\n```"
                ))
        
        # Check for Key Vault usage (good practice)
        has_key_vault = bool(re.search(r"(KeyClient|SecretClient|CryptographyClient|azure\.keyvault)", code))
        has_managed_identity = bool(re.search(r"DefaultAzureCredential|ManagedIdentityCredential", code))
        
        if has_key_vault and has_managed_identity:
            line_num = self.get_line_number(code, "KeyClient") or self.get_line_number(code, "SecretClient")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.INFO,
                title="Azure Key Vault integration with Managed Identity",
                description="Application retrieves cryptographic keys from Key Vault using Managed Identity (no credentials in code).",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure: 1) HSM-backed keys for sensitive operations, 2) Key rotation policies configured, 3) Access policies follow least privilege.",
                good_practice=True
            ))

