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
