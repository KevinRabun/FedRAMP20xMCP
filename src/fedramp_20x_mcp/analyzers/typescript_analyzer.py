"""
TypeScript/JavaScript application code analyzer for FedRAMP 20x compliance.

Supports TypeScript and JavaScript (Node.js, React, Angular, Vue) code analysis for security best practices.
"""

import re
from typing import Optional

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult


class TypeScriptAnalyzer(BaseAnalyzer):
    """
    Analyzer for TypeScript and JavaScript application code.
    
    Checks for FedRAMP 20x security compliance in TypeScript/JavaScript applications.
    """
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze TypeScript/JavaScript code for FedRAMP 20x compliance.
        
        Args:
            code: TypeScript/JavaScript code content
            file_path: Path to the TypeScript/JavaScript file
            
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
        
        # Phase 4: Monitoring and Observability
        self._check_security_monitoring(code, file_path)
        self._check_anomaly_detection(code, file_path)
        self._check_performance_monitoring(code, file_path)
        self._check_incident_response(code, file_path)
        
        return self.result
    
    def _check_authentication(self, code: str, file_path: str) -> None:
        """Check for proper authentication implementation (KSI-IAM-01)."""
        # Check for authentication libraries
        has_auth_library = bool(re.search(
            r"(from|import)\s+['\"](@azure/msal-|passport|jsonwebtoken|express-jwt|next-auth)",
            code
        ))
        
        # Check for authentication middleware
        has_auth_middleware = bool(re.search(
            r"(authenticate|isAuthenticated|requireAuth|authMiddleware|useAuth)",
            code
        ))
        
        # Check for API routes/endpoints
        has_routes = bool(re.search(
            r"(app\.(get|post|put|delete)|router\.(get|post|put|delete)|@(Get|Post|Put|Delete)|export.*async.*function.*(GET|POST))",
            code
        ))
        
        if has_routes and not (has_auth_library or has_auth_middleware):
            line_num = self.get_line_number(code, "app.get") or \
                       self.get_line_number(code, "router.") or \
                       self.get_line_number(code, "export")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.HIGH,
                title="API endpoints without authentication",
                description="Found route definitions without authentication middleware. FedRAMP 20x requires authentication for all API endpoints.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add authentication using Azure AD/MSAL:\n```typescript\n// Install: npm install @azure/msal-node\nimport { ConfidentialClientApplication } from '@azure/msal-node';\nimport { Request, Response, NextFunction } from 'express';\n\nconst msalConfig = {\n  auth: {\n    clientId: process.env.AZURE_CLIENT_ID!,\n    authority: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}`,\n    clientSecret: process.env.AZURE_CLIENT_SECRET!,\n  },\n};\n\nconst cca = new ConfidentialClientApplication(msalConfig);\n\n// Middleware to validate JWT token\nexport async function authenticateJWT(\n  req: Request,\n  res: Response,\n  next: NextFunction\n) {\n  const token = req.headers.authorization?.replace('Bearer ', '');\n  \n  if (!token) {\n    return res.status(401).json({ error: 'No token provided' });\n  }\n  \n  try {\n    // Validate token with Azure AD\n    const result = await cca.acquireTokenByClientCredential({\n      scopes: ['https://graph.microsoft.com/.default'],\n    });\n    next();\n  } catch (error) {\n    return res.status(401).json({ error: 'Invalid token' });\n  }\n}\n\n// Use in routes\napp.get('/api/data', authenticateJWT, (req, res) => {\n  res.json({ data: 'secure' });\n});\n```\nSource: MSAL Node.js (https://learn.microsoft.com/entra/identity-platform/quickstart-web-app-nodejs-msal)"
            ))
        elif has_auth_library and has_auth_middleware:
            line_num = self.get_line_number(code, "@azure/msal") or \
                       self.get_line_number(code, "passport") or \
                       self.get_line_number(code, "authenticate")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.INFO,
                title="Authentication properly implemented",
                description="API endpoints protected with authentication middleware and Azure AD integration.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure JWT token validation includes signature verification and expiration checks.",
                good_practice=True
            ))
    
    def _check_secrets_management(self, code: str, file_path: str) -> None:
        """Check for hardcoded secrets (KSI-SVC-06)."""
        # Patterns for potential secrets
        secret_patterns = [
            (r"(password|Password)\s*[:=]\s*['\"][^'\"]{3,}['\"]", "password"),
            (r"(apiKey|API_KEY|api_key)\s*[:=]\s*['\"][^'\"]{10,}['\"]", "API key"),
            (r"(secret|Secret|SECRET)\s*[:=]\s*['\"][^'\"]{10,}['\"]", "secret"),
            (r"(token|Token|TOKEN)\s*[:=]\s*['\"][^'\"]{10,}['\"]", "token"),
            (r"(connectionString|CONNECTION_STRING)\s*[:=]\s*['\"][^'\"]{10,}['\"]", "connection string"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                matched_text = match.group(0)
                
                # Skip if it's from environment variables or Key Vault
                if any(x in matched_text for x in ["process.env", "env.", "SecretClient", "getSecret", "${process.env"]):
                    continue
                
                # Skip common non-secret values
                if any(x in matched_text.lower() for x in ["example", "test", "dummy", "placeholder", "***", "your-", "enter-", "<"]):
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
                    recommendation=f"Use Azure Key Vault to store {secret_type}:\n```typescript\n// Install: npm install @azure/keyvault-secrets @azure/identity\nimport {{ DefaultAzureCredential }} from '@azure/identity';\nimport {{ SecretClient }} from '@azure/keyvault-secrets';\n\nconst credential = new DefaultAzureCredential();\nconst keyVaultUrl = process.env.KEY_VAULT_URL!;\nconst client = new SecretClient(keyVaultUrl, credential);\n\n// Retrieve secret\nasync function getSecret(secretName: string): Promise<string> {{\n  const secret = await client.getSecret(secretName);\n  return secret.value!;\n}}\n\nconst {secret_type.replace(' ', '')} = await getSecret('{secret_type.replace(' ', '-')}');\n\n// Or use environment variables loaded from Key Vault\nconst {secret_type.replace(' ', '')} = process.env.{secret_type.upper().replace(' ', '_')};\n```\nSource: Azure Key Vault for Node.js (https://learn.microsoft.com/azure/key-vault/secrets/quick-create-node)"
                ))
        
        # Check for good practices (Key Vault usage)
        if re.search(r"from\s+['\"]@azure/keyvault-secrets['\"]", code):
            if re.search(r"DefaultAzureCredential|ManagedIdentityCredential", code):
                line_num = self.get_line_number(code, "SecretClient") or self.get_line_number(code, "DefaultAzureCredential")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-06",
                    severity=Severity.INFO,
                    title="Azure Key Vault with managed identity configured",
                    description="Secrets retrieved from Key Vault using DefaultAzureCredential (managed identity).",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure Key Vault access policies grant minimal required permissions to managed identity.",
                    good_practice=True
                ))
    
    def _check_dependencies(self, code: str, file_path: str) -> None:
        """Check for potentially vulnerable dependencies (KSI-SVC-08)."""
        # Check for unsafe operations
        vulnerable_patterns = [
            (r"eval\s*\(", "eval() (code injection risk)"),
            (r"new\s+Function\s*\(", "Function constructor (code injection risk)"),
            (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML (XSS risk)"),
            (r"\.innerHTML\s*=", "innerHTML assignment (XSS risk)"),
            (r"exec\s*\(.*process\.env|child_process", "Command injection risk"),
        ]
        
        for pattern, issue in vulnerable_patterns:
            if re.search(pattern, code):
                line_num = self.get_line_number(code, pattern)
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-08",
                    severity=Severity.HIGH if "injection" in issue.lower() else Severity.MEDIUM,
                    title=f"Potentially unsafe code pattern: {issue}",
                    description=f"Using {issue}. FedRAMP 20x requires secure coding practices and vulnerability scanning.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use secure alternatives:\n- eval/Function → JSON.parse or safe alternatives\n- innerHTML → textContent or DOM methods\n- dangerouslySetInnerHTML → DOMPurify.sanitize()\n- child_process.exec → Validate/sanitize input\n\nRun dependency scanning:\n```bash\nnpm audit\nnpm install -g snyk\nsnyk test\n```\nSource: OWASP Node.js Security Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)"
                ))
        
        # Check for package.json (good practice if versions are pinned)
        if "package.json" in file_path:
            # Check if versions are exact (not ranges)
            if re.search(r'"[^"]+"\s*:\s*"\d+\.\d+\.\d+"', code):
                line_num = self.get_line_number(code, '"version"') or 1
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-08",
                    severity=Severity.INFO,
                    title="Dependencies pinned to exact versions",
                    description="Dependencies use exact version specifications for reproducibility.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Regularly update dependencies and run security scans (npm audit, snyk).",
                    good_practice=True
                ))
    
    def _check_pii_handling(self, code: str, file_path: str) -> None:
        """Check for PII handling (KSI-PIY-02)."""
        # Check for properties/fields that might contain PII
        pii_patterns = [
            (r"(ssn|socialSecurityNumber|SocialSecurityNumber)", "Social Security Number"),
            (r"(email|emailAddress|Email|EmailAddress)", "email address"),
            (r"(phone|phoneNumber|telephone|PhoneNumber)", "phone number"),
            (r"(dateOfBirth|dob|birthDate|DateOfBirth)", "date of birth"),
            (r"(address|streetAddress|homeAddress|Address)", "physical address"),
        ]
        
        for pattern, pii_type in pii_patterns:
            matches = re.finditer(r"(const|let|var|public|private)\s+\w*" + pattern, code, re.IGNORECASE)
            for match in matches:
                # Check if there's encryption nearby
                context_start = max(0, match.start() - 300)
                context_end = min(len(code), match.end() + 300)
                context = code[context_start:context_end]
                
                has_encryption = bool(re.search(r"(encrypt|cipher|crypto|hash|Hash)", context, re.IGNORECASE))
                
                if not has_encryption:
                    line_num = self.get_line_number(code, match.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-PIY-02",
                        severity=Severity.MEDIUM,
                        title=f"Potential unencrypted PII: {pii_type}",
                        description=f"Variable '{match.group(0)}' may contain {pii_type}. FedRAMP 20x requires PII to be encrypted at rest and in transit.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation=f"Encrypt {pii_type} before storing:\n```typescript\nimport {{ createCipheriv, createDecipheriv, randomBytes }} from 'crypto';\n\n// Get encryption key from Azure Key Vault\nconst ALGORITHM = 'aes-256-gcm';\nconst KEY = Buffer.from(await getSecret('encryption-key'), 'base64');\n\nfunction encryptPII(piiValue: string): string {{\n  const iv = randomBytes(16);\n  const cipher = createCipheriv(ALGORITHM, KEY, iv);\n  \n  let encrypted = cipher.update(piiValue, 'utf8', 'hex');\n  encrypted += cipher.final('hex');\n  \n  const authTag = cipher.getAuthTag();\n  return `${{iv.toString('hex')}}:${{encrypted}}:${{authTag.toString('hex')}}`;\n}}\n\nfunction decryptPII(encryptedValue: string): string {{\n  const [ivHex, encrypted, authTagHex] = encryptedValue.split(':');\n  const iv = Buffer.from(ivHex, 'hex');\n  const authTag = Buffer.from(authTagHex, 'hex');\n  \n  const decipher = createDecipheriv(ALGORITHM, KEY, iv);\n  decipher.setAuthTag(authTag);\n  \n  let decrypted = decipher.update(encrypted, 'hex', 'utf8');\n  decrypted += decipher.final('utf8');\n  return decrypted;\n}}\n\n// Use\nconst encryptedValue = encryptPII({match.group(0)});\n```\nSource: Node.js Crypto Module (https://nodejs.org/api/crypto.html)"
                    ))
    
    def _check_logging(self, code: str, file_path: str) -> None:
        """Check for proper logging implementation (KSI-MLA-05)."""
        # Check for logging libraries
        has_logging = bool(re.search(
            r"(console\.(log|error|warn|info)|winston|pino|bunyan|@azure/monitor|applicationinsights)",
            code
        ))
        
        # Check for Application Insights
        has_app_insights = bool(re.search(r"(applicationinsights|@azure/monitor-opentelemetry)", code))
        
        # Check for sensitive data in logs
        if has_logging:
            # Check for console.log with potential secrets
            log_statements = re.finditer(
                r'console\.(log|error|warn|info)\s*\([^)]*\)',
                code
            )
            
            for log_match in log_statements:
                context_start = max(0, log_match.start() - 200)
                context_end = min(len(code), log_match.end() + 200)
                context = code[context_start:context_end]
                
                if re.search(r"(password|token|secret|apikey)", context, re.IGNORECASE):
                    line_num = self.get_line_number(code, log_match.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-MLA-05",
                        severity=Severity.MEDIUM,
                        title="Potential sensitive data in logs",
                        description="Logging statement near sensitive data. Ensure secrets are not logged. FedRAMP 20x requires audit logs without exposing sensitive information.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Redact sensitive data before logging:\n```typescript\nfunction redact(sensitive: string): string {\n  if (!sensitive || sensitive.length < 4) {\n    return '***';\n  }\n  return `${sensitive.substring(0, 2)}***${sensitive.substring(sensitive.length - 2)}`;\n}\n\n// Use structured logging with redaction\nconsole.log('User login', { email: redact(userEmail) });\n```"
                    ))
        
        if not has_logging:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.MEDIUM,
                title="No logging implementation detected",
                description="No logging usage found. FedRAMP 20x requires comprehensive audit logging for security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement structured logging with Application Insights:\n```typescript\n// Install: npm install applicationinsights winston\nimport appInsights from 'applicationinsights';\nimport winston from 'winston';\n\n// Configure Application Insights\nappInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING)\n  .setAutoDependencyCorrelation(true)\n  .setAutoCollectRequests(true)\n  .setAutoCollectPerformance(true)\n  .setAutoCollectExceptions(true)\n  .setAutoCollectDependencies(true)\n  .start();\n\n// Create logger\nconst logger = winston.createLogger({\n  transports: [\n    new winston.transports.Console(),\n    new winston.transports.AzureApplicationInsights({\n      client: appInsights.defaultClient,\n    }),\n  ],\n});\n\n// Use in code\nlogger.info('Data access request', { userId: req.user?.id });\nlogger.error('Operation failed', { error: error.message });\n```\nSource: Application Insights for Node.js (https://learn.microsoft.com/azure/azure-monitor/app/nodejs)"
            ))
        elif has_app_insights:
            line_num = self.get_line_number(code, "applicationinsights") or self.get_line_number(code, "@azure/monitor")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.INFO,
                title="Application Insights logging configured",
                description="Application Insights telemetry enabled for centralized logging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure logs are sent to Log Analytics workspace and connected to Sentinel SIEM.",
                good_practice=True
            ))
    
    def _check_service_account_management(self, code: str, file_path: str) -> None:
        """Check for proper service account management (KSI-IAM-02)."""
        # Check for managed identity usage
        has_managed_identity = bool(re.search(r"(DefaultAzureCredential|ManagedIdentityCredential)", code))
        
        # Check for hardcoded credentials (anti-pattern)
        has_hardcoded_creds = bool(re.search(r'ClientSecretCredential.*["\'][a-zA-Z0-9]{30,}["\']', code))
        
        if has_hardcoded_creds:
            line_num = self.get_line_number(code, "ClientSecretCredential")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.HIGH,
                title="Hardcoded service principal credentials detected",
                description="Client secret appears to be hardcoded. FedRAMP 20x requires managed identities for service authentication.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use managed identities instead of service principals:\n```typescript\nimport { DefaultAzureCredential, ManagedIdentityCredential } from '@azure/identity';\n\n// Remove ClientSecretCredential with hardcoded secret\n// Use DefaultAzureCredential which automatically uses managed identity in Azure\nconst credential = new DefaultAzureCredential();\n\n// Or explicitly use managed identity\nconst credential = new ManagedIdentityCredential();\n\n// Works in Azure App Service, Azure Functions, AKS, VMs with system-assigned identity\n```\nSource: Azure Identity for JavaScript (https://learn.microsoft.com/javascript/api/overview/azure/identity-readme)"
            ))
        elif has_managed_identity:
            line_num = self.get_line_number(code, "DefaultAzureCredential") or self.get_line_number(code, "ManagedIdentityCredential")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.INFO,
                title="Managed identity authentication configured",
                description="Service uses DefaultAzureCredential or ManagedIdentityCredential for passwordless authentication.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure the managed identity has least-privilege RBAC assignments.",
                good_practice=True
            ))
    
    def _check_microservices_security(self, code: str, file_path: str) -> None:
        """Check for microservices security patterns (KSI-CNA-07)."""
        # Check for HTTP client libraries
        has_http_client = bool(re.search(r"(fetch\s*\(|axios|node-fetch|@azure/core-http)", code))
        
        if has_http_client:
            # Check for bearer token in headers
            has_auth_header = bool(re.search(r"(Authorization.*Bearer|headers.*authorization)", code, re.IGNORECASE))
            
            if not has_auth_header:
                line_num = self.get_line_number(code, "fetch") or self.get_line_number(code, "axios")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.MEDIUM,
                    title="HTTP client without authentication headers",
                    description="Service-to-service calls should use managed identity and bearer tokens. FedRAMP 20x requires authenticated service communication.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add authentication to HTTP client:\n```typescript\nimport { DefaultAzureCredential } from '@azure/identity';\n\nconst credential = new DefaultAzureCredential();\nconst scope = 'api://your-api-id/.default';\n\nasync function callService(url: string) {\n  const tokenResponse = await credential.getToken(scope);\n  \n  const response = await fetch(url, {\n    headers: {\n      'Authorization': `Bearer ${tokenResponse.token}`,\n      'Content-Type': 'application/json',\n    },\n  });\n  \n  return await response.json();\n}\n\n// Or use axios interceptor\nimport axios from 'axios';\n\nconst apiClient = axios.create({\n  baseURL: 'https://api.example.com',\n});\n\napiClient.interceptors.request.use(async (config) => {\n  const tokenResponse = await credential.getToken(scope);\n  config.headers.Authorization = `Bearer ${tokenResponse.token}`;\n  return config;\n});\n```"
                ))
            else:
                line_num = self.get_line_number(code, "Authorization") or self.get_line_number(code, "Bearer")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.INFO,
                    title="Service-to-service authentication configured",
                    description="HTTP client includes bearer token authentication headers.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure tokens use appropriate scopes and are refreshed automatically.",
                    good_practice=True
                ))
    
    def _check_error_handling(self, code: str, file_path: str) -> None:
        """Check for proper error handling (KSI-SVC-01)."""
        # Check for empty catch blocks
        empty_catch = re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", code)
        
        if empty_catch:
            line_num = self.get_line_number(code, empty_catch.group(0))
            self.add_finding(Finding(
                requirement_id="KSI-SVC-01",
                severity=Severity.MEDIUM,
                title="Empty catch block detected",
                description="Empty catch block swallows exceptions without logging. FedRAMP 20x requires error logging for audit trails.",
                file_path=file_path,
                line_number=line_num,
                code_snippet=empty_catch.group(0),
                recommendation="Log exceptions and handle appropriately:\n```typescript\ntry {\n  await riskyOperation();\n} catch (error) {\n  logger.error('Operation failed', { error: error.message });\n  throw error; // or handle gracefully\n}\n```"
            ))
        
        # Check for generic error handling without type checking
        generic_catch = re.search(r"catch\s*\(\s*e(rr|rror)?\s*\)\s*\{", code)
        
        if generic_catch:
            # Check if error is typed
            context_start = max(0, generic_catch.start() - 100)
            context_end = min(len(code), generic_catch.end() + 200)
            context = code[context_start:context_end]
            
            if "instanceof" not in context and "Error" not in context[:100]:
                line_num = self.get_line_number(code, generic_catch.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-01",
                    severity=Severity.LOW,
                    title="Untyped error handling detected",
                    description="Catch block doesn't check error type. Consider using typed errors or instanceof checks.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use typed error handling:\n```typescript\ntry {\n  await operation();\n} catch (error) {\n  if (error instanceof ValidationError) {\n    logger.warn('Validation failed', { error: error.message });\n    return res.status(400).json({ error: error.message });\n  } else if (error instanceof DatabaseError) {\n    logger.error('Database error', { error: error.message });\n    return res.status(500).json({ error: 'Internal server error' });\n  } else {\n    logger.error('Unexpected error', { error });\n    throw error;\n  }\n}\n```"
                ))
    
    def _check_input_validation(self, code: str, file_path: str) -> None:
        """Check for input validation (KSI-SVC-02)."""
        # Check for validation libraries
        has_validation = bool(re.search(
            r"(zod|joi|yup|express-validator|class-validator|@hapi/joi)",
            code
        ))
        
        # Check for req.body, req.query, req.params usage
        has_request_params = bool(re.search(
            r"req\.(body|query|params)",
            code
        ))
        
        if has_request_params and not has_validation:
            line_num = self.get_line_number(code, "req.body") or self.get_line_number(code, "req.query")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.MEDIUM,
                title="Request parameters without validation",
                description="Route accepts input without validation. FedRAMP 20x requires input validation to prevent injection attacks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add input validation with Zod or Joi:\n```typescript\n// Install: npm install zod\nimport { z } from 'zod';\n\n// Define schema\nconst CreateUserSchema = z.object({\n  username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_]+$/),\n  email: z.string().email(),\n  age: z.number().int().min(18).max(120).optional(),\n});\n\ntype CreateUserRequest = z.infer<typeof CreateUserSchema>;\n\n// Validate in route\napp.post('/users', async (req, res) => {\n  try {\n    const validatedData = CreateUserSchema.parse(req.body);\n    const user = await userService.create(validatedData);\n    return res.status(201).json(user);\n  } catch (error) {\n    if (error instanceof z.ZodError) {\n      return res.status(400).json({ errors: error.errors });\n    }\n    throw error;\n  }\n});\n\n// Or use middleware\nfunction validateRequest(schema: z.ZodSchema) {\n  return (req, res, next) => {\n    try {\n      req.body = schema.parse(req.body);\n      next();\n    } catch (error) {\n      return res.status(400).json({ errors: error.errors });\n    }\n  };\n}\n```\nSource: Zod documentation (https://zod.dev)"
            ))
        elif has_validation:
            line_num = self.get_line_number(code, "zod") or self.get_line_number(code, "joi") or self.get_line_number(code, "validator")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.INFO,
                title="Input validation properly configured",
                description="Application uses validation library for request data.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure all user inputs are validated, including query parameters and path variables.",
                good_practice=True
            ))
    
    def _check_secure_coding(self, code: str, file_path: str) -> None:
        """Check for secure coding practices (KSI-SVC-07)."""
        issues = []
        
        # Check for HTTPS enforcement (Express)
        if re.search(r"express\(\)|app\s*=.*express", code):
            if not re.search(r"(helmet|enforce\.HTTPS|requireHTTPS)", code):
                issues.append("Missing Helmet.js security middleware")
        
        # Check for CORS configuration
        if re.search(r"cors\(\s*\{.*origin:\s*['\"]?\*", code, re.DOTALL):
            line_num = self.get_line_number(code, "cors")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.MEDIUM,
                title="Overly permissive CORS policy",
                description="CORS allows all origins (*). FedRAMP 20x requires restricted cross-origin access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Restrict CORS to specific origins:\n```typescript\nimport cors from 'cors';\n\nconst corsOptions = {\n  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n  credentials: true,\n  optionsSuccessStatus: 200,\n};\n\napp.use(cors(corsOptions));\n```"
            ))
        
        if issues:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.HIGH,
                title="Missing security configurations",
                description=f"Security issues detected: {'; '.join(issues)}",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add security middleware:\n```typescript\nimport helmet from 'helmet';\nimport express from 'express';\n\nconst app = express();\n\n// Add Helmet for security headers\napp.use(helmet({\n  contentSecurityPolicy: {\n    directives: {\n      defaultSrc: [\"'self'\"],\n      styleSrc: [\"'self'\", \"'unsafe-inline'\"],\n    },\n  },\n  hsts: {\n    maxAge: 31536000,\n    includeSubDomains: true,\n  },\n}));\n\n// Enforce HTTPS in production\nif (process.env.NODE_ENV === 'production') {\n  app.use((req, res, next) => {\n    if (req.header('x-forwarded-proto') !== 'https') {\n      return res.redirect(`https://${req.header('host')}${req.url}`);\n    }\n    next();\n  });\n}\n```"
            ))
    
    def _check_data_classification(self, code: str, file_path: str) -> None:
        """Check for data classification (KSI-PIY-01)."""
        # Check for PII-related interfaces/types
        has_pii_types = bool(re.search(r"(email|phone|ssn|dateOfBirth|address)", code, re.IGNORECASE))
        
        # Check for data classification decorators/comments
        has_classification = bool(re.search(r"(@Sensitive|@Confidential|@PII|// PII:|// Sensitive:)", code))
        
        if has_pii_types and not has_classification:
            line_num = self.get_line_number(code, "email") or self.get_line_number(code, "phone")
            self.add_finding(Finding(
                requirement_id="KSI-PIY-01",
                severity=Severity.LOW,
                title="PII fields without data classification markers",
                description="Fields containing PII should be marked with classification comments or decorators for tracking.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add data classification markers:\n```typescript\nenum DataClassification {\n  PUBLIC = 'PUBLIC',\n  INTERNAL = 'INTERNAL',\n  CONFIDENTIAL = 'CONFIDENTIAL',\n  RESTRICTED = 'RESTRICTED',\n}\n\ninterface User {\n  id: string;\n  \n  // @DataClassification: RESTRICTED\n  ssn?: string;\n  \n  // @DataClassification: CONFIDENTIAL\n  email: string;\n  \n  // @DataClassification: PUBLIC\n  displayName: string;\n}\n\n// Or use decorators (with TypeScript experimental decorators)\nfunction Sensitive(classification: DataClassification) {\n  return function (target: any, propertyKey: string) {\n    Reflect.defineMetadata('classification', classification, target, propertyKey);\n  };\n}\n```"
            ))
    
    def _check_privacy_controls(self, code: str, file_path: str) -> None:
        """Check for privacy control implementation (KSI-PIY-03)."""
        # Check for consent tracking
        has_consent = bool(re.search(r"(consent|Consent|privacy|Privacy|gdpr|GDPR)", code))
        
        if not has_consent and re.search(r"(User|Customer|interface.*User|type.*User)", code):
            line_num = self.get_line_number(code, "interface User") or self.get_line_number(code, "type User")
            if line_num:
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-03",
                    severity=Severity.LOW,
                    title="User data without consent tracking",
                    description="User/customer types should track privacy consent for FedRAMP 20x compliance.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add consent tracking properties:\n```typescript\ninterface User {\n  id: string;\n  email: string;\n  \n  // Privacy consent tracking\n  marketingConsentGiven: boolean;\n  consentDate?: Date;\n  consentVersion: string;\n  dataSharingConsent: boolean;\n}\n\n// Consent management functions\nasync function updateConsent(\n  userId: string,\n  consent: ConsentUpdate\n): Promise<void> {\n  await db.users.update(userId, {\n    ...consent,\n    consentDate: new Date(),\n    consentVersion: '1.0',\n  });\n}\n```"
                ))
    
    def _check_service_mesh(self, code: str, file_path: str) -> None:
        """Check for service mesh security (KSI-CNA-07)."""
        # Already covered in _check_microservices_security
        pass
    
    def _check_least_privilege(self, code: str, file_path: str) -> None:
        """Check for least privilege implementation (KSI-IAM-04)."""
        # Check for authorization middleware
        has_auth_check = bool(re.search(
            r"(checkRole|requireRole|hasPermission|authorize|can\(|@Roles\()",
            code
        ))
        
        # Check for routes with authentication but no authorization
        if re.search(r"(authenticate|isAuthenticated)", code) and not has_auth_check:
            line_num = self.get_line_number(code, "authenticate")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.MEDIUM,
                title="Authentication without authorization checks",
                description="Routes use authentication but no role/permission checks. FedRAMP 20x requires least-privilege access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement role-based or permission-based authorization:\n```typescript\n// Define permissions\nenum Permission {\n  USER_READ = 'user:read',\n  USER_WRITE = 'user:write',\n  USER_DELETE = 'user:delete',\n}\n\n// Middleware to check permissions\nfunction requirePermission(...permissions: Permission[]) {\n  return (req: Request, res: Response, next: NextFunction) => {\n    const userPermissions = req.user?.permissions || [];\n    \n    const hasPermission = permissions.some(p => \n      userPermissions.includes(p)\n    );\n    \n    if (!hasPermission) {\n      return res.status(403).json({ error: 'Insufficient permissions' });\n    }\n    \n    next();\n  };\n}\n\n// Use in routes\napp.delete(\n  '/users/:id',\n  authenticateJWT,\n  requirePermission(Permission.USER_DELETE),\n  async (req, res) => {\n    await userService.delete(req.params.id);\n    res.status(204).send();\n  }\n);\n\n// Or use CASL for more complex authorization\nimport { AbilityBuilder, Ability } from '@casl/ability';\n```\nSource: CASL Authorization (https://casl.js.org/)"
            ))
        elif has_auth_check:
            line_num = self.get_line_number(code, "checkRole") or self.get_line_number(code, "hasPermission")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.INFO,
                title="Least privilege authorization implemented",
                description="Application uses role or permission checks for access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review authorization rules and ensure they follow least privilege principle.",
                good_practice=True
            ))
    
    def _check_session_management(self, code: str, file_path: str) -> None:
        """Check for secure session management (KSI-IAM-07)."""
        # Check for session middleware
        has_session = bool(re.search(r"(express-session|cookie-session|session\()", code))
        
        if has_session:
            # Check for secure cookie settings
            has_secure_cookies = bool(re.search(r"(httpOnly.*true|secure.*true|sameSite)", code, re.IGNORECASE))
            
            if not has_secure_cookies:
                line_num = self.get_line_number(code, "session")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.MEDIUM,
                    title="Session configuration without secure cookie flags",
                    description="Session management should use httpOnly, secure, and sameSite flags. FedRAMP 20x requires secure session handling.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure secure session management:\n```typescript\nimport session from 'express-session';\n\napp.use(session({\n  secret: process.env.SESSION_SECRET!,\n  resave: false,\n  saveUninitialized: false,\n  cookie: {\n    httpOnly: true,\n    secure: process.env.NODE_ENV === 'production', // HTTPS only in production\n    sameSite: 'strict',\n    maxAge: 20 * 60 * 1000, // 20 minutes\n  },\n  store: new RedisStore({  // Use persistent store in production\n    client: redisClient,\n  }),\n}));\n\n// For JWT tokens in cookies\nres.cookie('token', jwtToken, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  maxAge: 3600000, // 1 hour\n});\n```\nSource: Express Session Security (https://expressjs.com/en/advanced/best-practice-security.html)"
                ))
            else:
                line_num = self.get_line_number(code, "httpOnly") or self.get_line_number(code, "secure")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.INFO,
                    title="Secure session management configured",
                    description="Session cookies use httpOnly, secure, and sameSite flags.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure session timeout is configured appropriately (e.g., 20 minutes idle timeout).",
                    good_practice=True
                ))
    
    def _check_security_monitoring(self, code: str, file_path: str) -> None:
        """Check for security event monitoring (KSI-MLA-03)."""
        # Check for Application Insights or monitoring libraries
        has_monitoring = bool(re.search(
            r"(applicationinsights|@azure/monitor|winston|pino|bunyan)",
            code,
            re.IGNORECASE
        ))
        
        if has_monitoring:
            # Check for security event tracking
            has_security_tracking = bool(re.search(
                r"(trackEvent|trackException|logger\.(warn|error|info)|console\.(warn|error))",
                code
            ))
            
            if not has_security_tracking:
                line_num = self.get_line_number(code, "applicationinsights") or self.get_line_number(code, "winston")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.MEDIUM,
                    title="Limited security event tracking",
                    description="Monitoring framework is configured but not actively tracking security events. FedRAMP 20x requires comprehensive security monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track security-relevant events:\n```typescript\nimport * as appInsights from 'applicationinsights';\nimport winston from 'winston';\n\nclass SecurityMonitor {\n  private client: appInsights.TelemetryClient;\n  private logger: winston.Logger;\n  \n  constructor() {\n    appInsights.setup(process.env.APPINSIGHTS_CONNECTION_STRING).start();\n    this.client = appInsights.defaultClient;\n    \n    this.logger = winston.createLogger({\n      transports: [\n        new winston.transports.Console(),\n        new winston.transports.File({ filename: 'security.log' })\n      ]\n    });\n  }\n  \n  trackAuthenticationEvent(username: string, success: boolean, ipAddress: string): void {\n    const properties = {\n      username,\n      success: String(success),\n      ipAddress,\n      eventType: 'Authentication'\n    };\n    \n    this.client.trackEvent({ name: 'SecurityEvent', properties });\n    this.logger.warn(`Authentication attempt: ${username} from ${ipAddress} - ${success ? 'Success' : 'Failed'}`);\n  }\n  \n  trackAuthorizationFailure(username: string, resource: string): void {\n    this.client.trackEvent({\n      name: 'AuthorizationDenied',\n      properties: { username, resource }\n    });\n    this.logger.warn(`Authorization denied: ${username} attempted to access ${resource}`);\n  }\n}\n```\nSource: Application Insights for Node.js (https://learn.microsoft.com/azure/azure-monitor/app/nodejs)"
                ))
            else:
                line_num = self.get_line_number(code, "trackEvent") or self.get_line_number(code, "logger.warn")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.INFO,
                    title="Security monitoring implemented",
                    description="Application tracks security events using monitoring framework.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure all authentication, authorization, and data access events are logged.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.HIGH,
                title="No security monitoring framework detected",
                description="Application does not appear to use Application Insights or structured logging. FedRAMP 20x requires comprehensive security event monitoring.",
                file_path=file_path,
                recommendation="Implement Application Insights:\n```typescript\nimport * as appInsights from 'applicationinsights';\n\n// Initialize Application Insights\nappInsights.setup(process.env.APPINSIGHTS_CONNECTION_STRING)\n  .setAutoDependencyCorrelation(true)\n  .setAutoCollectRequests(true)\n  .setAutoCollectPerformance(true)\n  .setAutoCollectExceptions(true)\n  .setAutoCollectDependencies(true)\n  .setAutoCollectConsole(true)\n  .setUseDiskRetryCaching(true)\n  .start();\n```\nSource: Azure Monitor overview (https://learn.microsoft.com/azure/azure-monitor/overview)"
            ))
    
    def _check_anomaly_detection(self, code: str, file_path: str) -> None:
        """Check for anomaly detection configuration (KSI-MLA-04)."""
        # Check for metrics tracking
        has_metrics = bool(re.search(
            r"(trackMetric|prom-client|@opentelemetry/metrics)",
            code
        ))
        
        if has_metrics:
            # Check for custom metrics
            has_custom_metrics = bool(re.search(
                r"(trackMetric|Counter|Gauge|Histogram)",
                code
            ))
            
            if not has_custom_metrics:
                line_num = self.get_line_number(code, "prom-client")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-04",
                    severity=Severity.MEDIUM,
                    title="No custom metrics for anomaly detection",
                    description="Metrics framework is configured but not tracking custom metrics for anomaly detection. FedRAMP 20x requires baseline-based anomaly detection.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track custom metrics for anomaly detection:\n```typescript\nimport * as appInsights from 'applicationinsights';\nimport { Counter, Histogram } from 'prom-client';\n\nclass MetricsTracker {\n  private client: appInsights.TelemetryClient;\n  private loginAttempts: Counter;\n  private apiResponseTime: Histogram;\n  \n  constructor() {\n    this.client = appInsights.defaultClient;\n    \n    this.loginAttempts = new Counter({\n      name: 'security_login_attempts_total',\n      help: 'Total number of login attempts',\n      labelNames: ['ip_address', 'result']\n    });\n    \n    this.apiResponseTime = new Histogram({\n      name: 'api_response_time_seconds',\n      help: 'API response time in seconds',\n      labelNames: ['endpoint', 'method']\n    });\n  }\n  \n  trackLoginAttempt(ipAddress: string, success: boolean): void {\n    this.loginAttempts.inc({ ip_address: ipAddress, result: success ? 'success' : 'failed' });\n    this.client.trackMetric({ name: 'LoginAttempts', value: 1, properties: { ipAddress } });\n  }\n  \n  trackApiCallRate(endpoint: string, count: number): void {\n    this.client.trackMetric({ name: 'APICallRate', value: count, properties: { endpoint } });\n  }\n  \n  trackDataAccessVolume(username: string, bytes: number): void {\n    this.client.trackMetric({ name: 'DataAccessVolume', value: bytes, properties: { username } });\n  }\n}\n```\nEnable Smart Detection in Azure Portal for Application Insights.\n\nSource: Application Insights Smart Detection (https://learn.microsoft.com/azure/azure-monitor/alerts/proactive-diagnostics)"
                ))
            else:
                line_num = self.get_line_number(code, "trackMetric") or self.get_line_number(code, "Counter")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-04",
                    severity=Severity.INFO,
                    title="Metrics tracking configured",
                    description="Application tracks custom metrics that can be used for anomaly detection.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure Smart Detection is enabled in Azure Application Insights for automated anomaly detection.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.HIGH,
                title="No anomaly detection framework",
                description="Application does not track metrics for anomaly detection. FedRAMP 20x requires baseline-based anomaly detection.",
                file_path=file_path,
                recommendation="Implement metrics tracking with Application Insights (see KSI-MLA-03 recommendation)."
            ))
    
    def _check_performance_monitoring(self, code: str, file_path: str) -> None:
        """Check for performance monitoring (KSI-MLA-06)."""
        # Check for performance tracking
        has_perf_monitoring = bool(re.search(
            r"(applicationinsights|trackDependency|performance\.(now|measure)|perf_hooks)",
            code
        ))
        
        if has_perf_monitoring:
            # Check for dependency tracking
            has_dependency_tracking = bool(re.search(
                r"(trackDependency|measure|PerformanceObserver)",
                code
            ))
            
            if not has_dependency_tracking:
                line_num = self.get_line_number(code, "applicationinsights") or self.get_line_number(code, "performance")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.MEDIUM,
                    title="Limited performance monitoring",
                    description="Application has monitoring but doesn't track dependencies (database calls, external APIs). FedRAMP 20x requires comprehensive performance monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track dependencies for performance monitoring:\n```typescript\nimport * as appInsights from 'applicationinsights';\nimport { performance } from 'perf_hooks';\n\nclass PerformanceMonitor {\n  private client: appInsights.TelemetryClient;\n  \n  constructor() {\n    this.client = appInsights.defaultClient;\n  }\n  \n  async trackDependency<T>(\n    dependencyName: string,\n    target: string,\n    operation: () => Promise<T>\n  ): Promise<T> {\n    const startTime = new Date();\n    const startMark = performance.now();\n    let success = false;\n    \n    try {\n      const result = await operation();\n      success = true;\n      return result;\n    } catch (error) {\n      throw error;\n    } finally {\n      const duration = performance.now() - startMark;\n      \n      this.client.trackDependency({\n        dependencyTypeName: dependencyName,\n        target,\n        name: dependencyName,\n        data: target,\n        duration,\n        success,\n        resultCode: success ? 200 : 500,\n        time: startTime\n      });\n    }\n  }\n}\n\n// Usage\nconst monitor = new PerformanceMonitor();\nconst users = await monitor.trackDependency(\n  'Database',\n  'UserTable',\n  async () => await db.collection('users').find().toArray()\n);\n```\nSource: Application Insights dependency tracking (https://learn.microsoft.com/azure/azure-monitor/app/nodejs#track-dependencies)"
                ))
            else:
                line_num = self.get_line_number(code, "trackDependency") or self.get_line_number(code, "measure")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.INFO,
                    title="Comprehensive performance monitoring",
                    description="Application tracks dependencies and performance metrics.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure monitoring covers all critical dependencies and set up alerts for performance degradation.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.HIGH,
                title="No performance monitoring detected",
                description="Application does not implement performance monitoring. FedRAMP 20x requires tracking of request rates, response times, and resource utilization.",
                file_path=file_path,
                recommendation="Implement Application Insights for performance monitoring (see KSI-MLA-03 recommendation)."
            ))
    
    def _check_incident_response(self, code: str, file_path: str) -> None:
        """Check for automated incident response integration (KSI-INR-01)."""
        # Check for incident response integrations
        has_incident_integration = bool(re.search(
            r"(pagerduty|servicenow|opsgenie|webhook|axios|fetch|node-fetch)",
            code,
            re.IGNORECASE
        ))
        
        if has_incident_integration:
            # Check for error handling with alerting
            has_alert_on_error = bool(re.search(
                r"(trackException|logger\.error|console\.error).*(?:.*\n.*){0,5}.*(?:axios\.post|fetch|\.send)",
                code,
                re.DOTALL
            ))
            
            if not has_alert_on_error:
                line_num = self.get_line_number(code, "pagerduty") or self.get_line_number(code, "axios")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.MEDIUM,
                    title="Incident response integration not connected to errors",
                    description="Incident response tools are referenced but not integrated with error handling. FedRAMP 20x requires automated incident response.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Integrate incident response with error handling:\n```typescript\nimport axios from 'axios';\nimport winston from 'winston';\n\nclass IncidentResponseService {\n  private logger: winston.Logger;\n  private webhookUrl: string;\n  \n  constructor(webhookUrl: string) {\n    this.webhookUrl = webhookUrl;\n    this.logger = winston.createLogger({\n      transports: [new winston.transports.Console()]\n    });\n  }\n  \n  async triggerIncident(\n    error: Error,\n    severity: 'critical' | 'error' | 'warning',\n    context: Record<string, string>\n  ): Promise<void> {\n    const incident = {\n      routing_key: this.webhookUrl,\n      event_action: 'trigger',\n      payload: {\n        summary: error.message,\n        severity,\n        source: process.env.HOSTNAME || 'unknown',\n        timestamp: new Date().toISOString(),\n        custom_details: context\n      }\n    };\n    \n    try {\n      await axios.post('https://events.pagerduty.com/v2/enqueue', incident);\n      this.logger.info(`Incident triggered: ${error.constructor.name}`);\n    } catch (alertError) {\n      this.logger.error('Failed to trigger incident', alertError);\n    }\n  }\n}\n\n// Usage in error handler\napp.use((err: Error, req: Request, res: Response, next: NextFunction) => {\n  if (err.name === 'SecurityError') {\n    logger.error('Security breach detected', err);\n    incidentResponse.triggerIncident(err, 'critical', {\n      user: req.user?.username || 'anonymous',\n      ip: req.ip,\n      path: req.path\n    });\n  }\n  res.status(500).json({ error: 'Internal server error' });\n});\n```\nSource: Azure Monitor Action Groups (https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups)"
                ))
            else:
                line_num = self.get_line_number(code, "axios.post") or self.get_line_number(code, "trackException")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.INFO,
                    title="Automated incident response configured",
                    description="Application integrates incident response tools with error handling.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure incident response covers all critical errors and security events.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.HIGH,
                title="No incident response integration",
                description="Application does not integrate with incident response tools. FedRAMP 20x requires automated incident response for security events.",
                file_path=file_path,
                recommendation="Integrate with incident response system:\n1. Use Azure Monitor Action Groups for alerts\n2. Configure webhooks to PagerDuty, ServiceNow, or similar\n3. Implement automated alerting for critical errors\n\nSource: Azure Monitor alerting (https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-overview)"
            ))
