"""
C# application code analyzer for FedRAMP 20x compliance.

Supports C# (.NET) code analysis for security best practices.
"""

import re
from typing import Optional

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult


class CSharpAnalyzer(BaseAnalyzer):
    """
    Analyzer for C# application code.
    
    Checks for FedRAMP 20x security compliance in C#/.NET applications.
    """
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze C# code for FedRAMP 20x compliance.
        
        Args:
            code: C# code content
            file_path: Path to the C# file
            
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
        # Check for authentication-related usings
        has_auth_namespace = bool(re.search(
            r"using\s+(Microsoft\.Identity|Microsoft\.AspNetCore\.Authentication|Microsoft\.AspNetCore\.Authorization|Azure\.Identity)",
            code
        ))
        
        # Check for authentication attributes
        has_auth_attribute = bool(re.search(
            r"\[(Authorize|AllowAnonymous|RequireHttps)\]",
            code
        ))
        
        # Check for controller or endpoint definitions
        has_controller = bool(re.search(
            r"(class\s+\w+\s*:\s*Controller|class\s+\w+\s*:\s*ControllerBase|\[HttpGet\]|\[HttpPost\]|\[Route\()",
            code
        ))
        
        # Check for minimal API endpoints
        has_minimal_api = bool(re.search(
            r"app\.Map(Get|Post|Put|Delete)",
            code
        ))
        
        if (has_controller or has_minimal_api) and not (has_auth_namespace or has_auth_attribute):
            line_num = self.get_line_number(code, "Controller") or \
                       self.get_line_number(code, "app.Map") or \
                       self.get_line_number(code, "[Http")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.HIGH,
                title="API endpoints without authentication",
                description="Found controller or API endpoints without [Authorize] attribute. FedRAMP 20x requires authentication for all API endpoints.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add authentication using Azure AD/Entra ID:\n```csharp\nusing Microsoft.AspNetCore.Authorization;\nusing Microsoft.Identity.Web;\n\n// Add to Program.cs:\nbuilder.Services.AddMicrosoftIdentityWebApiAuthentication(configuration);\nbuilder.Services.AddAuthorization();\n\napp.UseAuthentication();\napp.UseAuthorization();\n\n// Protect controllers:\n[Authorize]\n[ApiController]\n[Route(\"api/[controller]\")]\npublic class DataController : ControllerBase\n{\n    [HttpGet]\n    public IActionResult GetData()\n    {\n        return Ok(new { data = \"secure\" });\n    }\n}\n```\nSource: Azure AD authentication for ASP.NET Core (https://learn.microsoft.com/azure/active-directory/develop/quickstart-web-api-aspnet-core-protect-api)"
            ))
        elif has_auth_namespace and has_auth_attribute:
            line_num = self.get_line_number(code, "[Authorize]") or \
                       self.get_line_number(code, "Microsoft.Identity")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.INFO,
                title="Authentication properly implemented",
                description="API endpoints protected with [Authorize] attribute and Azure AD integration.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure JWT token validation is configured and role-based access control (RBAC) is implemented.",
                good_practice=True
            ))
    
    def _check_secrets_management(self, code: str, file_path: str) -> None:
        """Check for hardcoded secrets (KSI-SVC-06)."""
        # Patterns for potential secrets
        secret_patterns = [
            (r'(password|Password)\s*=\s*"[^"]{3,}"', "password"),
            (r'(apiKey|ApiKey|API_KEY)\s*=\s*"[^"]{10,}"', "API key"),
            (r'(secret|Secret)\s*=\s*"[^"]{10,}"', "secret"),
            (r'(token|Token)\s*=\s*"[^"]{10,}"', "token"),
            (r'(connectionString|ConnectionString)\s*=\s*"[^"]{10,}"', "connection string"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                
                # Skip if it's from configuration or Key Vault
                if any(x in matched_text for x in ["Configuration[", "GetSecret", "SecretClient", "Environment.GetEnvironmentVariable"]):
                    continue
                
                # Skip common non-secret values
                if any(x in matched_text.lower() for x in ["example", "test", "dummy", "placeholder", "***", "your-", "enter-"]):
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
                    recommendation=f"Use Azure Key Vault to store {secret_type}:\n```csharp\nusing Azure.Identity;\nusing Azure.Security.KeyVault.Secrets;\n\nvar keyVaultUrl = new Uri(\"https://your-vault.vault.azure.net\");\nvar credential = new DefaultAzureCredential();\nvar client = new SecretClient(keyVaultUrl, credential);\n\n// Retrieve secret\nKeyVaultSecret secret = await client.GetSecretAsync(\"{secret_type.replace(' ', '-')}\");\nstring secretValue = secret.Value;\n\n// Or use configuration:\nbuilder.Configuration.AddAzureKeyVault(keyVaultUrl, credential);\nstring secretValue = builder.Configuration[\"{secret_type.replace(' ', '-')}\"];\n```\nSource: Azure Key Vault with ASP.NET Core (https://learn.microsoft.com/azure/key-vault/general/tutorial-net-create-vault-azure-web-app)"
                ))
        
        # Check for good practices (Key Vault usage)
        if re.search(r"using\s+Azure\.Security\.KeyVault\.Secrets", code):
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
        # Check for unsafe deserialization
        vulnerable_patterns = [
            (r"BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter", "Insecure deserialization (use System.Text.Json)"),
            (r"Process\.Start\([^)]*user", "Command injection risk in Process.Start"),
            (r"SqlCommand.*CommandText.*\+", "Potential SQL injection (use parameterized queries)"),
            (r"Response\.Write\([^)]*Request\[", "Cross-site scripting (XSS) risk"),
        ]
        
        for pattern, issue in vulnerable_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                line_num = self.get_line_number(code, pattern)
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-08",
                    severity=Severity.HIGH if "injection" in issue.lower() else Severity.MEDIUM,
                    title=f"Potentially unsafe code pattern: {issue}",
                    description=f"Using {issue}. FedRAMP 20x requires secure coding practices and vulnerability scanning.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Use secure alternatives:\n- BinaryFormatter → System.Text.Json.JsonSerializer\n- SqlCommand string concat → SqlParameter\n- Response.Write(user input) → HtmlEncoder.Encode()\n\nRun dependency scanning:\n```bash\ndotnet list package --vulnerable\ndotnet tool install --global Microsoft.CST.OAT.VelocityRaptor\n```\nSource: OWASP Top 10 for .NET (https://owasp.org/www-project-top-ten/)"
                ))
        
        # Check for .csproj file (good practice if versions are specified)
        if file_path.endswith(".csproj"):
            # Check if PackageReference has Version attribute
            if re.search(r'<PackageReference.*Version="[\d\.]+"', code):
                line_num = self.get_line_number(code, "PackageReference")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-08",
                    severity=Severity.INFO,
                    title="NuGet packages pinned to specific versions",
                    description="Dependencies use explicit version specifications for reproducibility.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Regularly update packages and scan for vulnerabilities using 'dotnet list package --vulnerable'.",
                    good_practice=True
                ))
    
    def _check_pii_handling(self, code: str, file_path: str) -> None:
        """Check for PII handling (KSI-PIY-02)."""
        # Check for properties/fields that might contain PII
        pii_patterns = [
            (r"(Ssn|SocialSecurityNumber|SSN)", "Social Security Number"),
            (r"(Email|EmailAddress)", "email address"),
            (r"(Phone|PhoneNumber|Telephone)", "phone number"),
            (r"(DateOfBirth|DOB|BirthDate)", "date of birth"),
            (r"(Address|StreetAddress|HomeAddress)", "physical address"),
        ]
        
        for pattern, pii_type in pii_patterns:
            matches = re.finditer(r"(public|private|protected)\s+\w+\s+" + pattern, code, re.IGNORECASE)
            for match in matches:
                # Check if there's encryption/data protection nearby
                context_start = max(0, match.start() - 300)
                context_end = min(len(code), match.end() + 300)
                context = code[context_start:context_end]
                
                has_protection = bool(re.search(r"(Encrypt|Protect|IDataProtector|AES|Hash|Redact)", context, re.IGNORECASE))
                
                if not has_protection:
                    line_num = self.get_line_number(code, match.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-PIY-02",
                        severity=Severity.MEDIUM,
                        title=f"Potential unprotected PII: {pii_type}",
                        description=f"Property '{match.group(0)}' may contain {pii_type}. FedRAMP 20x requires PII to be encrypted at rest and in transit.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation=f"Use ASP.NET Core Data Protection API to encrypt {pii_type}:\n```csharp\nusing Microsoft.AspNetCore.DataProtection;\n\npublic class UserService\n{{\n    private readonly IDataProtector _protector;\n    \n    public UserService(IDataProtectionProvider provider)\n    {{\n        _protector = provider.CreateProtector(\"PII.Protection\");\n    }}\n    \n    public string EncryptPII(string piiValue)\n    {{\n        return _protector.Protect(piiValue);\n    }}\n    \n    public string DecryptPII(string encryptedValue)\n    {{\n        return _protector.Unprotect(encryptedValue);\n    }}\n}}\n\n// Store encryption keys in Azure Key Vault\nbuilder.Services.AddDataProtection()\n    .PersistKeysToAzureBlobStorage(blobUri)\n    .ProtectKeysWithAzureKeyVault(keyId, credential);\n```\nSource: ASP.NET Core Data Protection (https://learn.microsoft.com/aspnet/core/security/data-protection/)"
                    ))
    
    def _check_logging(self, code: str, file_path: str) -> None:
        """Check for proper logging implementation (KSI-MLA-05)."""
        # Check for logging usage
        has_logging = bool(re.search(r"(ILogger<|_logger\.|LogInformation|LogError|LogWarning)", code))
        
        # Check for Application Insights
        has_app_insights = bool(re.search(r"(TelemetryClient|AddApplicationInsightsTelemetry)", code))
        
        # Check for potentially sensitive data in logs
        if has_logging:
            sensitive_in_logs = re.search(
                r'(LogInformation|LogError|LogWarning).*\(.*\{.*\}.*\)',
                code
            )
            
            if sensitive_in_logs:
                # Check if nearby code handles passwords, tokens, etc.
                context_start = max(0, sensitive_in_logs.start() - 200)
                context_end = min(len(code), sensitive_in_logs.end() + 200)
                context = code[context_start:context_end]
                
                if re.search(r"(password|token|secret|apikey)", context, re.IGNORECASE):
                    line_num = self.get_line_number(code, sensitive_in_logs.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-MLA-05",
                        severity=Severity.MEDIUM,
                        title="Potential sensitive data in logs",
                        description="Logging statement near sensitive data. Ensure secrets are not logged. FedRAMP 20x requires audit logs without exposing sensitive information.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Redact sensitive data before logging:\n```csharp\npublic static string Redact(string sensitive)\n{\n    if (string.IsNullOrEmpty(sensitive) || sensitive.Length < 4)\n        return \"***\";\n    return $\"{sensitive.Substring(0, 2)}***{sensitive.Substring(sensitive.Length - 2)}\";\n}\n\n// Use structured logging with redaction\n_logger.LogInformation(\"User login: {{Email}}\", Redact(userEmail));\n```"
                    ))
        
        if not has_logging:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.MEDIUM,
                title="No logging implementation detected",
                description="No ILogger usage found. FedRAMP 20x requires comprehensive audit logging for security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement structured logging with Application Insights:\n```csharp\n// Program.cs\nbuilder.Logging.AddApplicationInsights();\nbuilder.Services.AddApplicationInsightsTelemetry();\n\n// Controller\npublic class ApiController : ControllerBase\n{\n    private readonly ILogger<ApiController> _logger;\n    \n    public ApiController(ILogger<ApiController> logger)\n    {\n        _logger = logger;\n    }\n    \n    [HttpGet]\n    public IActionResult GetData()\n    {\n        _logger.LogInformation(\"Data access request from {{User}}\", User.Identity?.Name);\n        return Ok();\n    }\n}\n```\nSource: Azure Application Insights for .NET (https://learn.microsoft.com/azure/azure-monitor/app/asp-net-core)"
            ))
        elif has_app_insights:
            line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "TelemetryClient")
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
        # Check for service principal or managed identity usage
        has_managed_identity = bool(re.search(r"DefaultAzureCredential|ManagedIdentityCredential|ChainedTokenCredential", code))
        
        # Check for hardcoded credentials (anti-pattern)
        has_hardcoded_creds = bool(re.search(r'ClientSecretCredential.*"[a-zA-Z0-9]{30,}"', code))
        
        if has_hardcoded_creds:
            line_num = self.get_line_number(code, "ClientSecretCredential")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.HIGH,
                title="Hardcoded service principal credentials detected",
                description="Client secret appears to be hardcoded. FedRAMP 20x requires managed identities for service authentication.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use managed identities instead of service principals:\n```csharp\n// Remove ClientSecretCredential with hardcoded secret\n// Use DefaultAzureCredential which automatically uses managed identity in Azure\nvar credential = new DefaultAzureCredential();\n\n// Or explicitly use managed identity\nvar credential = new ManagedIdentityCredential();\n\n// Works in Azure App Service, Azure Functions, AKS, VMs with system-assigned identity\n```\nSource: Azure Managed Identities (https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview)"
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
        # Check for service-to-service authentication
        has_dapr = bool(re.search(r"Dapr\.|DaprClient|AddDapr", code))
        has_http_client = bool(re.search(r"HttpClient|IHttpClientFactory", code))
        
        if has_http_client and not has_dapr:
            # Check if DefaultAzureCredential is used for service calls
            has_auth_handler = bool(re.search(r"(AddHttpMessageHandler|DelegatingHandler|Bearer.*token)", code, re.IGNORECASE))
            
            if not has_auth_handler:
                line_num = self.get_line_number(code, "HttpClient")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.MEDIUM,
                    title="HttpClient without authentication handler",
                    description="Service-to-service calls should use managed identity and bearer tokens. FedRAMP 20x requires authenticated service communication.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add authentication to HttpClient:\n```csharp\n// Add Azure AD authentication to HttpClient\nservices.AddHttpClient<IMyService, MyService>(client =>\n{\n    client.BaseAddress = new Uri(\"https://api.example.com\");\n})\n.AddHttpMessageHandler<AuthenticationDelegatingHandler>();\n\n// Implement delegating handler\npublic class AuthenticationDelegatingHandler : DelegatingHandler\n{\n    private readonly TokenCredential _credential;\n    \n    protected override async Task<HttpResponseMessage> SendAsync(\n        HttpRequestMessage request, CancellationToken cancellationToken)\n    {\n        var token = await _credential.GetTokenAsync(\n            new TokenRequestContext(new[] { \"api://your-api/.default\" }));\n        request.Headers.Authorization = \n            new AuthenticationHeaderValue(\"Bearer\", token.Token);\n        return await base.SendAsync(request, cancellationToken);\n    }\n}\n```"
                ))
        elif has_dapr:
            line_num = self.get_line_number(code, "Dapr")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-07",
                severity=Severity.INFO,
                title="Dapr service mesh configured",
                description="Using Dapr for service-to-service communication with built-in security.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure Dapr mTLS is enabled and service invocation uses access control policies.",
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
                recommendation="Log exceptions and handle appropriately:\n```csharp\ntry\n{\n    // operation\n}\ncatch (Exception ex)\n{\n    _logger.LogError(ex, \"Operation failed: {{Operation}}\", \"operationName\");\n    throw; // or handle gracefully\n}\n```"
            ))
        
        # Check for generic exception catching
        generic_catch = re.search(r"catch\s*\(\s*Exception\s+\w+\s*\)", code)
        
        if generic_catch:
            # Check if it's near the top-level (acceptable for global error handling)
            context_before = code[:generic_catch.start()]
            if "Program" not in context_before and "Startup" not in context_before and "Middleware" not in context_before:
                line_num = self.get_line_number(code, generic_catch.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-01",
                    severity=Severity.LOW,
                    title="Generic exception handler detected",
                    description="Catching generic Exception hides specific error types. Consider catching specific exceptions.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Catch specific exceptions when possible:\n```csharp\ntry\n{\n    await database.SaveAsync();\n}\ncatch (DbUpdateException ex)\n{\n    _logger.LogError(ex, \"Database update failed\");\n    return StatusCode(500, \"Database error\");\n}\ncatch (ValidationException ex)\n{\n    _logger.LogWarning(ex, \"Validation failed\");\n    return BadRequest(ex.Message);\n}\n```"
                ))
    
    def _check_input_validation(self, code: str, file_path: str) -> None:
        """Check for input validation (KSI-SVC-02)."""
        # Check for data annotations
        has_validation = bool(re.search(r"\[(Required|StringLength|Range|RegularExpression|MaxLength|MinLength)\]", code))
        
        # Check for model binding in controllers
        has_model_binding = bool(re.search(r"\[FromBody\]|\[FromQuery\]|\[FromRoute\]", code))
        
        # Check for model state validation
        has_model_state_check = bool(re.search(r"ModelState\.IsValid", code))
        
        if has_model_binding and not (has_validation or has_model_state_check):
            line_num = self.get_line_number(code, "[FromBody]") or self.get_line_number(code, "[FromQuery]")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.MEDIUM,
                title="Model binding without validation",
                description="Controller accepts input without validation attributes or ModelState check. FedRAMP 20x requires input validation to prevent injection attacks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add data annotations and validate ModelState:\n```csharp\npublic class CreateUserRequest\n{\n    [Required(ErrorMessage = \"Username is required\")]\n    [StringLength(50, MinimumLength = 3)]\n    [RegularExpression(@\"^[a-zA-Z0-9_]+$\", ErrorMessage = \"Invalid characters\")]\n    public string Username { get; set; }\n    \n    [Required]\n    [EmailAddress]\n    public string Email { get; set; }\n}\n\n[HttpPost]\npublic IActionResult CreateUser([FromBody] CreateUserRequest request)\n{\n    if (!ModelState.IsValid)\n    {\n        return BadRequest(ModelState);\n    }\n    // Process validated input\n}\n```\nSource: ASP.NET Core Model Validation (https://learn.microsoft.com/aspnet/core/mvc/models/validation)"
            ))
        elif has_validation and has_model_state_check:
            line_num = self.get_line_number(code, "[Required]") or self.get_line_number(code, "ModelState.IsValid")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.INFO,
                title="Input validation properly configured",
                description="Models use data annotations and controllers validate ModelState.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Consider using FluentValidation for complex validation scenarios.",
                good_practice=True
            ))
    
    def _check_secure_coding(self, code: str, file_path: str) -> None:
        """Check for secure coding practices (KSI-SVC-07)."""
        issues = []
        
        # Check for HTTPS redirection
        if re.search(r"(UseHsts|UseHttpsRedirection)", code):
            line_num = self.get_line_number(code, "UseHttpsRedirection") or self.get_line_number(code, "UseHsts")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.INFO,
                title="HTTPS enforcement configured",
                description="Application enforces HTTPS with HSTS.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure HSTS max-age is set to at least 1 year (31536000 seconds).",
                good_practice=True
            ))
        elif re.search(r"(WebApplication\.Create|CreateBuilder)", code):
            line_num = self.get_line_number(code, "WebApplication")
            issues.append("Missing app.UseHttpsRedirection() and app.UseHsts()")
        
        # Check for CORS configuration
        if re.search(r"UseCors\(.*\*", code):
            line_num = self.get_line_number(code, "UseCors")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.MEDIUM,
                title="Overly permissive CORS policy",
                description="CORS allows all origins (*). FedRAMP 20x requires restricted cross-origin access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Restrict CORS to specific origins:\n```csharp\nbuilder.Services.AddCors(options =>\n{\n    options.AddPolicy(\"AllowedOrigins\", policy =>\n    {\n        policy.WithOrigins(\"https://yourdomain.com\")\n              .AllowAnyHeader()\n              .AllowAnyMethod()\n              .AllowCredentials();\n    });\n});\n\napp.UseCors(\"AllowedOrigins\");\n```"
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
                recommendation="Add security middleware in Program.cs:\n```csharp\nvar app = builder.Build();\n\nif (!app.Environment.IsDevelopment())\n{\n    app.UseHsts();\n}\n\napp.UseHttpsRedirection();\napp.UseAuthentication();\napp.UseAuthorization();\n```"
            ))
    
    def _check_data_classification(self, code: str, file_path: str) -> None:
        """Check for data classification attributes (KSI-PIY-01)."""
        # Check for custom data classification attributes
        has_classification = bool(re.search(r"\[(Sensitive|Confidential|Internal|Public)Data\]", code))
        
        # Check for PII-related properties
        has_pii_properties = bool(re.search(r"(Email|Phone|SSN|DateOfBirth|Address)", code))
        
        if has_pii_properties and not has_classification:
            line_num = self.get_line_number(code, "Email") or self.get_line_number(code, "Phone")
            self.add_finding(Finding(
                requirement_id="KSI-PIY-01",
                severity=Severity.LOW,
                title="PII properties without data classification attributes",
                description="Properties containing PII should be marked with data classification attributes for tracking and compliance.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Create and use data classification attributes:\n```csharp\n[AttributeUsage(AttributeTargets.Property)]\npublic class SensitiveDataAttribute : Attribute\n{\n    public DataClassification Classification { get; set; }\n}\n\npublic enum DataClassification\n{\n    Public,\n    Internal,\n    Confidential,\n    Restricted\n}\n\npublic class User\n{\n    [SensitiveData(Classification = DataClassification.Restricted)]\n    public string SSN { get; set; }\n    \n    [SensitiveData(Classification = DataClassification.Confidential)]\n    public string Email { get; set; }\n}\n```"
            ))
    
    def _check_privacy_controls(self, code: str, file_path: str) -> None:
        """Check for privacy control implementation (KSI-PIY-03)."""
        # Check for data anonymization/pseudonymization
        has_anonymization = bool(re.search(r"(Anonymize|Pseudonymize|Hash|Redact)", code))
        
        # Check for consent tracking
        has_consent = bool(re.search(r"(Consent|UserConsent|PrivacyAgreement)", code))
        
        if not has_consent and re.search(r"(User|Customer|Person)", code):
            line_num = self.get_line_number(code, "class.*User") or self.get_line_number(code, "class.*Customer")
            if line_num:
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-03",
                    severity=Severity.LOW,
                    title="User data without consent tracking",
                    description="User/customer entities should track privacy consent for FedRAMP 20x compliance.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add consent tracking properties:\n```csharp\npublic class User\n{\n    public bool MarketingConsentGiven { get; set; }\n    public DateTime? ConsentDate { get; set; }\n    public string ConsentVersion { get; set; }\n    public bool DataSharingConsent { get; set; }\n}\n```"
                ))
    
    def _check_service_mesh(self, code: str, file_path: str) -> None:
        """Check for service mesh security (KSI-CNA-07)."""
        # Already covered in _check_microservices_security
        pass
    
    def _check_least_privilege(self, code: str, file_path: str) -> None:
        """Check for least privilege implementation (KSI-IAM-04)."""
        # Check for role-based authorization
        has_role_auth = bool(re.search(r'\[Authorize\(Roles\s*=|Policy\s*=', code))
        
        # Check for resource-based authorization
        has_resource_auth = bool(re.search(r"IAuthorizationService|AuthorizeAsync", code))
        
        if re.search(r"\[Authorize\]", code) and not (has_role_auth or has_resource_auth):
            line_num = self.get_line_number(code, "[Authorize]")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.MEDIUM,
                title="Authorization without role or policy checks",
                description="Using [Authorize] without Roles or Policy allows any authenticated user. FedRAMP 20x requires least-privilege access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement role-based or policy-based authorization:\n```csharp\n// Role-based\n[Authorize(Roles = \"Admin,Manager\")]\npublic IActionResult DeleteUser(int id) { }\n\n// Policy-based (recommended)\nservices.AddAuthorization(options =>\n{\n    options.AddPolicy(\"CanDeleteUser\", policy =>\n        policy.RequireClaim(\"permission\", \"user.delete\"));\n});\n\n[Authorize(Policy = \"CanDeleteUser\")]\npublic IActionResult DeleteUser(int id) { }\n\n// Resource-based (most granular)\npublic async Task<IActionResult> Edit(int id)\n{\n    var resource = await _repository.GetAsync(id);\n    var authResult = await _authService.AuthorizeAsync(\n        User, resource, \"CanEdit\");\n    if (!authResult.Succeeded)\n        return Forbid();\n}\n```\nSource: ASP.NET Core Authorization (https://learn.microsoft.com/aspnet/core/security/authorization/)"
            ))
        elif has_role_auth or has_resource_auth:
            line_num = self.get_line_number(code, "Policy =") or self.get_line_number(code, "Roles =") or self.get_line_number(code, "AuthorizeAsync")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.INFO,
                title="Least privilege authorization implemented",
                description="Application uses role-based or policy-based authorization for access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review authorization policies and ensure they follow least privilege principle.",
                good_practice=True
            ))
    
    def _check_session_management(self, code: str, file_path: str) -> None:
        """Check for secure session management (KSI-IAM-07)."""
        # Check for session configuration
        has_session_config = bool(re.search(r"AddSession|UseSession", code))
        
        if has_session_config:
            # Check for secure cookie settings
            has_secure_cookies = bool(re.search(r"Cookie\s*=\s*new.*HttpOnly\s*=\s*true.*Secure\s*=\s*true", code, re.DOTALL))
            
            if not has_secure_cookies:
                line_num = self.get_line_number(code, "AddSession") or self.get_line_number(code, "UseSession")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.MEDIUM,
                    title="Session cookies without security flags",
                    description="Session management should use HttpOnly and Secure flags. FedRAMP 20x requires secure session handling.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure secure session cookies:\n```csharp\nbuilder.Services.AddSession(options =>\n{\n    options.Cookie.HttpOnly = true;\n    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n    options.Cookie.SameSite = SameSiteMode.Strict;\n    options.IdleTimeout = TimeSpan.FromMinutes(20);\n});\n\n// For authentication cookies\nbuilder.Services.ConfigureApplicationCookie(options =>\n{\n    options.Cookie.HttpOnly = true;\n    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n    options.Cookie.SameSite = SameSiteMode.Strict;\n    options.ExpireTimeSpan = TimeSpan.FromHours(1);\n    options.SlidingExpiration = true;\n});\n```\nSource: ASP.NET Core Security best practices (https://learn.microsoft.com/aspnet/core/security/)"
                ))
            else:
                line_num = self.get_line_number(code, "HttpOnly")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.INFO,
                    title="Secure session management configured",
                    description="Session cookies use HttpOnly, Secure, and SameSite flags.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure session timeout is configured appropriately (e.g., 20 minutes idle timeout).",
                    good_practice=True
                ))
    
    def _check_security_monitoring(self, code: str, file_path: str) -> None:
        """Check for security event monitoring (KSI-MLA-03)."""
        # Check for Application Insights telemetry
        has_app_insights = bool(re.search(r"(Microsoft\.ApplicationInsights|TelemetryClient|ILogger)", code))
        
        if has_app_insights:
            # Check for security event tracking
            has_security_tracking = bool(re.search(
                r"(TrackEvent|TrackException|TrackTrace|LogWarning|LogError|LogCritical)",
                code
            ))
            
            if not has_security_tracking:
                line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "ILogger")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.MEDIUM,
                    title="Limited security event tracking",
                    description="Application Insights or ILogger is configured but not actively tracking security events. FedRAMP 20x requires comprehensive security monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track security-relevant events:\n```csharp\nusing Microsoft.ApplicationInsights;\nusing Microsoft.Extensions.Logging;\n\npublic class SecurityMonitor\n{\n    private readonly TelemetryClient _telemetry;\n    private readonly ILogger<SecurityMonitor> _logger;\n    \n    public void TrackAuthenticationEvent(string username, bool success, string ipAddress)\n    {\n        var properties = new Dictionary<string, string>\n        {\n            { \"Username\", username },\n            { \"Success\", success.ToString() },\n            { \"IPAddress\", ipAddress },\n            { \"EventType\", \"Authentication\" }\n        };\n        \n        _telemetry.TrackEvent(\"SecurityEvent\", properties);\n        _logger.LogWarning(\"Authentication attempt: {Username} from {IP} - {Result}\",\n            username, ipAddress, success ? \"Success\" : \"Failed\");\n    }\n    \n    public void TrackAuthorizationFailure(string username, string resource)\n    {\n        _telemetry.TrackEvent(\"AuthorizationDenied\", new Dictionary<string, string>\n        {\n            { \"Username\", username },\n            { \"Resource\", resource }\n        });\n        _logger.LogWarning(\"Authorization denied: {Username} attempted to access {Resource}\",\n            username, resource);\n    }\n}\n```\nSource: Azure Monitor Application Insights (https://learn.microsoft.com/azure/azure-monitor/app/api-custom-events-metrics)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackEvent") or self.get_line_number(code, "LogWarning")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.INFO,
                    title="Security monitoring implemented",
                    description="Application tracks security events using Application Insights or ILogger.",
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
                recommendation="Implement Application Insights:\n```csharp\n// Program.cs\nbuilder.Services.AddApplicationInsightsTelemetry(options =>\n{\n    options.ConnectionString = builder.Configuration[\"ApplicationInsights:ConnectionString\"];\n});\n\n// Add structured logging\nbuilder.Logging.AddApplicationInsights();\nbuilder.Logging.AddConsole();\nbuilder.Logging.AddAzureWebAppDiagnostics();\n```\nSource: Azure Monitor overview (https://learn.microsoft.com/azure/azure-monitor/overview)"
            ))
    
    def _check_anomaly_detection(self, code: str, file_path: str) -> None:
        """Check for anomaly detection configuration (KSI-MLA-04)."""
        # Check for Application Insights smart detection
        has_app_insights = bool(re.search(r"Microsoft\.ApplicationInsights", code))
        
        if has_app_insights:
            # Check for metrics tracking
            has_metrics = bool(re.search(r"(TrackMetric|GetMetric|TelemetryClient)", code))
            
            if not has_metrics:
                line_num = self.get_line_number(code, "ApplicationInsights")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-04",
                    severity=Severity.MEDIUM,
                    title="No custom metrics for anomaly detection",
                    description="Application Insights is configured but not tracking custom metrics for anomaly detection. FedRAMP 20x requires baseline-based anomaly detection.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track custom metrics for anomaly detection:\n```csharp\npublic class MetricsTracker\n{\n    private readonly TelemetryClient _telemetry;\n    \n    public void TrackLoginAttempts(int count, string ipAddress)\n    {\n        _telemetry.GetMetric(\"LoginAttempts\", \"IPAddress\").TrackValue(count, ipAddress);\n    }\n    \n    public void TrackApiCallRate(int count, string endpoint)\n    {\n        _telemetry.GetMetric(\"APICallRate\", \"Endpoint\").TrackValue(count, endpoint);\n    }\n    \n    public void TrackDataAccessVolume(long bytes, string username)\n    {\n        _telemetry.GetMetric(\"DataAccessVolume\", \"User\").TrackValue(bytes, username);\n    }\n}\n```\nEnable Smart Detection in Azure Portal:\n1. Navigate to Application Insights resource\n2. Go to Smart Detection settings\n3. Enable anomaly detection alerts\n\nSource: Application Insights Smart Detection (https://learn.microsoft.com/azure/azure-monitor/alerts/proactive-diagnostics)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackMetric") or self.get_line_number(code, "GetMetric")
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
                description="Application does not use Application Insights for anomaly detection. FedRAMP 20x requires baseline-based anomaly detection.",
                file_path=file_path,
                recommendation="Implement Application Insights with Smart Detection (see KSI-MLA-03 recommendation)."
            ))
    
    def _check_performance_monitoring(self, code: str, file_path: str) -> None:
        """Check for performance monitoring (KSI-MLA-06)."""
        # Check for performance tracking
        has_perf_monitoring = bool(re.search(
            r"(ApplicationInsights|ILogger|TrackDependency|TrackRequest|Stopwatch)",
            code
        ))
        
        if has_perf_monitoring:
            # Check for dependency tracking
            has_dependency_tracking = bool(re.search(r"TrackDependency", code))
            
            if not has_dependency_tracking:
                line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "Stopwatch")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.MEDIUM,
                    title="Limited performance monitoring",
                    description="Application has monitoring but doesn't track dependencies (database calls, external APIs). FedRAMP 20x requires comprehensive performance monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track dependencies for performance monitoring:\n```csharp\npublic class PerformanceMonitor\n{\n    private readonly TelemetryClient _telemetry;\n    \n    public async Task<T> TrackDependencyAsync<T>(string dependencyName, string target, Func<Task<T>> operation)\n    {\n        var startTime = DateTime.UtcNow;\n        var timer = Stopwatch.StartNew();\n        bool success = false;\n        \n        try\n        {\n            var result = await operation();\n            success = true;\n            return result;\n        }\n        finally\n        {\n            timer.Stop();\n            _telemetry.TrackDependency(\n                dependencyTypeName: dependencyName,\n                target: target,\n                dependencyName: dependencyName,\n                data: target,\n                startTime: startTime,\n                duration: timer.Elapsed,\n                resultCode: success ? \"200\" : \"500\",\n                success: success\n            );\n        }\n    }\n}\n\n// Usage\nawait _monitor.TrackDependencyAsync(\"SQL\", \"UserDatabase\",\n    async () => await _dbContext.Users.ToListAsync());\n```\nSource: Application Insights dependency tracking (https://learn.microsoft.com/azure/azure-monitor/app/asp-net-dependencies)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackDependency")
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
            r"(PagerDuty|ServiceNow|Opsgenie|webhook|Alert|Notification|SendGrid|Twilio)",
            code,
            re.IGNORECASE
        ))
        
        if has_incident_integration:
            # Check for error handling with alerting
            has_alert_on_error = bool(re.search(
                r"(TrackException|LogError|LogCritical).*(?:.*\n.*){0,5}.*(?:SendAsync|PostAsync|Alert|Notify)",
                code,
                re.DOTALL
            ))
            
            if not has_alert_on_error:
                line_num = self.get_line_number(code, "PagerDuty") or self.get_line_number(code, "webhook")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.MEDIUM,
                    title="Incident response integration not connected to errors",
                    description="Incident response tools are referenced but not integrated with error handling. FedRAMP 20x requires automated incident response.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Integrate incident response with error handling:\n```csharp\npublic class IncidentResponseService\n{\n    private readonly HttpClient _client;\n    private readonly ILogger<IncidentResponseService> _logger;\n    private readonly string _webhookUrl;\n    \n    public async Task TriggerIncidentAsync(Exception ex, string severity, Dictionary<string, string> context)\n    {\n        var incident = new\n        {\n            routing_key = _webhookUrl,\n            event_action = \"trigger\",\n            payload = new\n            {\n                summary = ex.Message,\n                severity = severity,\n                source = Environment.MachineName,\n                timestamp = DateTime.UtcNow,\n                custom_details = context\n            }\n        };\n        \n        try\n        {\n            var response = await _client.PostAsJsonAsync(\n                \"https://events.pagerduty.com/v2/enqueue\",\n                incident\n            );\n            response.EnsureSuccessStatusCode();\n            _logger.LogInformation(\"Incident triggered: {ExceptionType}\", ex.GetType().Name);\n        }\n        catch (Exception alertEx)\n        {\n            _logger.LogError(alertEx, \"Failed to trigger incident\");\n        }\n    }\n}\n\n// Usage in exception handler\ncatch (SecurityException ex)\n{\n    _logger.LogCritical(ex, \"Security breach detected\");\n    await _incidentResponse.TriggerIncidentAsync(ex, \"critical\", new Dictionary<string, string>\n    {\n        { \"user\", User.Identity.Name },\n        { \"ip\", HttpContext.Connection.RemoteIpAddress.ToString() }\n    });\n}\n```\nSource: Azure Monitor Action Groups (https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackException") or self.get_line_number(code, "PostAsync")
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
    
    # Phase 5: DevSecOps Automation Methods
    
    def _check_configuration_management(self, code: str, file_path: str) -> None:
        """Check for secure configuration management (KSI-CMT-01)."""
        # Check for hardcoded configuration values
        config_patterns = [
            (r'(ApiUrl|BaseUrl|Endpoint)\s*=\s*"https?://[^"]+";', "API endpoint"),
            (r'(ConnectionString|DbConnection)\s*=\s*"[^"]+";', "Connection string"),
            (r'(Port|DbPort)\s*=\s*\d+;', "Port number"),
        ]
        
        hardcoded_configs = []
        for pattern, config_type in config_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            if matches:
                for match in matches:
                    context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                    if not re.search(r'(Configuration\[|GetValue<|GetSection|IConfiguration|Environment\.GetEnvironmentVariable)', context):
                        hardcoded_configs.append((match, config_type))
        
        # Check for Azure App Configuration integration
        has_app_config = bool(re.search(r'(Azure\.AppConfiguration|ConfigurationClient|AzureAppConfigurationOptions)', code))
        has_key_vault = bool(re.search(r'(Azure\.KeyVault|SecretClient)', code))
        has_iconfiguration = bool(re.search(r'IConfiguration', code))
        
        if hardcoded_configs:
            for match, config_type in hardcoded_configs[:3]:
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-01",
                    severity=Severity.MEDIUM,
                    title=f"Hardcoded {config_type} configuration",
                    description=f"Configuration value hardcoded in source. FedRAMP 20x requires externalized configuration.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation=f"Use Azure App Configuration:\n```csharp\n// Program.cs\nvar builder = WebApplication.CreateBuilder(args);\n\n// Add Azure App Configuration\nbuilder.Configuration.AddAzureAppConfiguration(options =>\n{{\n    options.Connect(\n        new Uri(builder.Configuration[\"AppConfig:Endpoint\"]),\n        new DefaultAzureCredential()\n    )\n    .ConfigureKeyVault(kv =>\n    {{\n        kv.SetCredential(new DefaultAzureCredential());\n    }});\n}});\n\n// Service configuration\npublic class MyService\n{{\n    private readonly IConfiguration _configuration;\n    \n    public MyService(IConfiguration configuration)\n    {{\n        _configuration = configuration;\n    }}\n    \n    public string Get{config_type.replace(' ', '')}()\n    {{\n        return _configuration[\"{config_type.replace(' ', '')}\"];\n    }}\n}}\n```\nSource: Azure App Configuration (https://learn.microsoft.com/azure/azure-app-configuration/quickstart-dotnet-core-app)"
                ))
        
        if has_app_config or has_key_vault:
            line_num = self.get_line_number(code, "AppConfiguration") or self.get_line_number(code, "KeyVault")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.INFO,
                title="Azure App Configuration or Key Vault integration",
                description="Application uses centralized configuration management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure all environment-specific values are externalized.",
                good_practice=True
            ))
        elif not hardcoded_configs and has_iconfiguration:
            line_num = self.get_line_number(code, "IConfiguration")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.LOW,
                title="Configuration uses IConfiguration",
                description="Environment variables/appsettings.json used. Consider Azure App Configuration for centralized management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Migrate to Azure App Configuration for FedRAMP audit trails.",
                good_practice=True
            ))
    
    def _check_version_control(self, code: str, file_path: str) -> None:
        """Check for version control enforcement (KSI-CMT-02)."""
        # Check for direct production deployment (anti-pattern)
        direct_deploy_patterns = [
            r'Process\.Start.*git\s+push.*production',
            r'ProcessStartInfo.*deploy.*production',
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
                    description="Code performs direct production deployment. FedRAMP 20x requires approval workflows.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation="Use Azure DevOps pipelines with approval gates or GitHub Actions with environment protection rules."
                ))
                break
        
        has_cicd_config = bool(re.search(r'(azure-pipelines|\.github/workflows)', code, re.IGNORECASE))
        if has_cicd_config:
            line_num = self.get_line_number(code, "pipeline")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-02",
                severity=Severity.INFO,
                title="CI/CD configuration referenced",
                description="Code references CI/CD pipelines.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Verify branch protection and approval requirements.",
                good_practice=True
            ))
    
    def _check_automated_testing(self, code: str, file_path: str) -> None:
        """Check for automated security testing (KSI-CMT-03)."""
        # Check for test frameworks
        test_frameworks = [
            r'using\s+Xunit',
            r'using\s+NUnit',
            r'using\s+Microsoft\.VisualStudio\.TestTools',
        ]
        
        has_test_framework = False
        for pattern in test_frameworks:
            if re.search(pattern, code):
                has_test_framework = True
                break
        
        # Check for security tests
        has_security_tests = bool(re.search(
            r'(Test.*Security|Test.*Auth|Test.*Sql.*Injection|Test.*Xss)',
            code,
            re.IGNORECASE
        ))
        
        is_test_file = bool(re.search(r'Tests?\.cs$', file_path))
        
        if not is_test_file and not has_test_framework:
            if re.search(r'(Controllers|Services|Repositories)', file_path, re.IGNORECASE):
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.MEDIUM,
                    title="No automated tests found",
                    description="Application code without tests. FedRAMP 20x requires automated security testing.",
                    file_path=file_path,
                    line_number=1,
                    recommendation="Create test project with security tests:\n```csharp\nusing Xunit;\nusing Microsoft.AspNetCore.Mvc.Testing;\n\npublic class SecurityTests : IClassFixture<WebApplicationFactory<Program>>\n{\n    private readonly HttpClient _client;\n    \n    [Fact]\n    public async Task ProtectedEndpoint_RequiresAuthentication()\n    {\n        var response = await _client.GetAsync(\"/api/protected\");\n        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);\n    }\n    \n    [Theory]\n    [InlineData(\"'; DROP TABLE Users; --\")]\n    [InlineData(\"<script>alert('XSS')</script>\")]\n    public async Task InputValidation_BlocksMaliciousInput(string maliciousInput)\n    {\n        var response = await _client.PostAsJsonAsync(\"/api/search\",\n            new { query = maliciousInput });\n        \n        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);\n    }\n    \n    [Fact]\n    public async Task Authorization_EnforcesAccessControl()\n    {\n        var token = GetTokenForUser(\"user1\");\n        _client.DefaultRequestHeaders.Authorization =\n            new AuthenticationHeaderValue(\"Bearer\", token);\n        \n        var response = await _client.GetAsync(\"/api/users/user2/data\");\n        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);\n    }\n}\n```"
                ))
        elif is_test_file and has_test_framework:
            if has_security_tests:
                line_num = self.get_line_number(code, "Security") or self.get_line_number(code, "Auth")
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.INFO,
                    title="Security tests implemented",
                    description="Test file includes security-focused tests.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure coverage: authentication, authorization, input validation, XSS, SQL injection.",
                    good_practice=True
                ))
    
    def _check_audit_logging(self, code: str, file_path: str) -> None:
        """Check for audit logging of security events (KSI-AFR-01)."""
        has_auth_code = bool(re.search(
            r'(Authenticate|Login|SignIn|Authorize|ClaimsPrincipal)',
            code,
            re.IGNORECASE
        ))
        
        has_data_access = bool(re.search(
            r'(DbContext|IQueryable|FromSql|ExecuteSql)',
            code,
            re.IGNORECASE
        ))
        
        has_logging = bool(re.search(r'(ILogger|Log\.|TrackEvent|TelemetryClient)', code))
        
        if has_auth_code and not has_logging:
            line_num = self.get_line_number(code, "Authenticate") or self.get_line_number(code, "Login")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.HIGH,
                title="Authentication without audit logging",
                description="Authentication code missing audit logs. FedRAMP 20x requires logging of all security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add audit logging:\n```csharp\npublic class SecurityAuditLogger\n{\n    private readonly ILogger<SecurityAuditLogger> _logger;\n    private readonly TelemetryClient _telemetry;\n    \n    public void LogAuthenticationAttempt(\n        string userId,\n        string ipAddress,\n        bool success,\n        string method = \"password\")\n    {\n        var properties = new Dictionary<string, string>\n        {\n            [\"UserId\"] = userId,\n            [\"IpAddress\"] = ipAddress,\n            [\"Success\"] = success.ToString(),\n            [\"Method\"] = method,\n            [\"Timestamp\"] = DateTime.UtcNow.ToString(\"O\")\n        };\n        \n        _telemetry.TrackEvent(\"AuthenticationAttempt\", properties);\n        _logger.Log(\n            success ? LogLevel.Information : LogLevel.Warning,\n            \"Authentication {Result} for user {UserId} from {IpAddress}\",\n            success ? \"success\" : \"failed\",\n            userId,\n            ipAddress\n        );\n    }\n    \n    public void LogAuthorizationCheck(\n        string userId,\n        string resource,\n        string action,\n        bool allowed)\n    {\n        _logger.Log(\n            allowed ? LogLevel.Information : LogLevel.Warning,\n            \"Authorization {Result}: {UserId} attempted {Action} on {Resource}\",\n            allowed ? \"granted\" : \"denied\",\n            userId,\n            action,\n            resource\n        );\n    }\n}\n```"
            ))
        
        if has_data_access and not has_logging:
            line_num = self.get_line_number(code, "DbContext")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.MEDIUM,
                title="Data access without audit logging",
                description="Database operations missing audit trails.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Log sensitive data access operations."
            ))
        
        if (has_auth_code or has_data_access) and has_logging:
            line_num = self.get_line_number(code, "ILogger") or self.get_line_number(code, "TrackEvent")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.INFO,
                title="Audit logging implemented",
                description="Security operations include audit logging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure logs include: user ID, timestamp, action, result, IP, resource.",
                good_practice=True
            ))
    
    def _check_log_integrity(self, code: str, file_path: str) -> None:
        """Check for log integrity and protection (KSI-AFR-02)."""
        # Check for local file logging
        local_logging = bool(re.search(
            r'(FileAppender|File.*Logger|StreamWriter.*\.log)',
            code,
            re.IGNORECASE
        ))
        
        if local_logging:
            line_num = self.get_line_number(code, "File")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.HIGH,
                title="Logs written to local files (insecure)",
                description="Application writes logs locally. FedRAMP 20x requires centralized, immutable logging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Stream logs to Azure Monitor:\n```csharp\nusing Microsoft.ApplicationInsights;\nusing Azure.Messaging.EventHubs;\n\n// Configure Application Insights\nservices.AddApplicationInsightsTelemetry(\n    builder.Configuration[\"ApplicationInsights:ConnectionString\"]\n);\n\n// For immutable audit logs, use Event Hubs\npublic class ImmutableAuditLogger\n{\n    private readonly EventHubProducerClient _producer;\n    \n    public async Task LogAuditEventAsync(object auditEvent)\n    {\n        var eventData = new EventData(\n            JsonSerializer.SerializeToUtf8Bytes(auditEvent)\n        );\n        await _producer.SendAsync(new[] { eventData });\n    }\n}\n```"
            ))
        
        has_app_insights = bool(re.search(r'(ApplicationInsights|TelemetryClient)', code))
        has_event_hub = bool(re.search(r'EventHub', code))
        
        if not local_logging and (has_app_insights or has_event_hub):
            line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "EventHub")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.INFO,
                title="Logs streamed to centralized SIEM",
                description="Application sends logs to Azure Monitor or Event Hubs.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Verify log retention meets FedRAMP requirements (90+ days).",
                good_practice=True
            ))
    
    def _check_key_management(self, code: str, file_path: str) -> None:
        """Check for cryptographic key management (KSI-CED-01)."""
        # Check for hardcoded keys
        key_patterns = [
            (r'(privateKey|secretKey|encryptionKey)\s*=\s*"[^"]{20,}";', "encryption key"),
            (r'-----BEGIN\s+(PRIVATE|RSA)\s+KEY-----', "private key"),
            (r'new\s+AesManaged\(\).*Key\s*=\s*', "AES key"),
        ]
        
        hardcoded_keys = []
        for pattern, key_type in key_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE | re.DOTALL))
            for match in matches:
                context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                if not re.search(r'(SecretClient|GetSecretAsync|KeyVaultSecret)', context):
                    hardcoded_keys.append((match, key_type))
        
        # Check for local key generation
        key_generation = bool(re.search(
            r'(Aes\.Create|RSA\.Create|RNGCryptoServiceProvider)(?!.*KeyVault)',
            code,
            re.DOTALL
        ))
        
        if key_generation:
            line_num = self.get_line_number(code, "Aes.Create") or self.get_line_number(code, "RSA.Create")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.HIGH,
                title="Local cryptographic key generation",
                description="Application generates keys locally. FedRAMP 20x requires Azure Key Vault with HSM.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use Azure Key Vault:\n```csharp\nusing Azure.Security.KeyVault.Keys;\nusing Azure.Security.KeyVault.Keys.Cryptography;\n\nvar keyClient = new KeyClient(\n    new Uri(configuration[\"KeyVault:Url\"]),\n    new DefaultAzureCredential()\n);\n\n// Generate key in Key Vault\nvar key = await keyClient.CreateRsaKeyAsync(\n    new CreateRsaKeyOptions(\"data-encryption-key\")\n    {\n        KeySize = 2048,\n        HardwareProtected = true  // Use HSM\n    }\n);\n\n// Use for encryption\nvar cryptoClient = new CryptographyClient(key.Value.Id, new DefaultAzureCredential());\nvar result = await cryptoClient.EncryptAsync(\n    EncryptionAlgorithm.RsaOaep,\n    plaintext\n);\n```"
            ))
        
        if hardcoded_keys:
            for match, key_type in hardcoded_keys[:2]:
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CED-01",
                    severity=Severity.HIGH,
                    title=f"Hardcoded {key_type} in source",
                    description=f"Cryptographic {key_type} hardcoded. FedRAMP 20x prohibits keys in source.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation=f"Store {key_type} in Azure Key Vault and retrieve at runtime."
                ))
        
        has_key_vault = bool(re.search(r'(KeyClient|SecretClient|KeyVault)', code))
        has_managed_identity = bool(re.search(r'DefaultAzureCredential|ManagedIdentityCredential', code))
        
        if has_key_vault and has_managed_identity:
            line_num = self.get_line_number(code, "KeyClient") or self.get_line_number(code, "SecretClient")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.INFO,
                title="Azure Key Vault integration with Managed Identity",
                description="Application retrieves keys from Key Vault using Managed Identity.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure HSM-backed keys and key rotation policies configured.",
                good_practice=True
            ))

