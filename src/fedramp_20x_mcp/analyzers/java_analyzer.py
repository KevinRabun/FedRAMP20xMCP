"""
Java application code analyzer for FedRAMP 20x compliance.

Supports Java (Spring Boot, Jakarta EE) code analysis for security best practices.
"""

import re
from typing import Optional

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult


class JavaAnalyzer(BaseAnalyzer):
    """
    Analyzer for Java application code.
    
    Checks for FedRAMP 20x security compliance in Java/Spring Boot applications.
    """
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze Java code for FedRAMP 20x compliance.
        
        Args:
            code: Java code content
            file_path: Path to the Java file
            
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
        # Check for Spring Security imports
        has_spring_security = bool(re.search(
            r"import\s+org\.springframework\.security\.(config|oauth2|web)",
            code
        ))
        
        # Check for security annotations
        has_security_annotations = bool(re.search(
            r"@(PreAuthorize|PostAuthorize|Secured|RolesAllowed)",
            code
        ))
        
        # Check for REST controller or request mapping
        has_endpoints = bool(re.search(
            r"@(RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)",
            code
        ))
        
        if has_endpoints and not (has_spring_security or has_security_annotations):
            line_num = self.get_line_number(code, "@RestController") or \
                       self.get_line_number(code, "@Controller") or \
                       self.get_line_number(code, "@GetMapping")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.HIGH,
                title="API endpoints without authentication",
                description="Found REST endpoints without @PreAuthorize or Spring Security configuration. FedRAMP 20x requires authentication for all API endpoints.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Spring Security with Azure AD authentication:\n```java\n// pom.xml or build.gradle\n<dependency>\n    <groupId>com.azure.spring</groupId>\n    <artifactId>spring-cloud-azure-starter-active-directory</artifactId>\n</dependency>\n\n// SecurityConfig.java\n@Configuration\n@EnableWebSecurity\n@EnableMethodSecurity\npublic class SecurityConfig {\n    @Bean\n    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n        http.authorizeHttpRequests(auth -> auth\n            .requestMatchers(\"/public/**\").permitAll()\n            .anyRequest().authenticated()\n        )\n        .oauth2ResourceServer(oauth2 -> oauth2.jwt());\n        return http.build();\n    }\n}\n\n// Controller\n@RestController\n@RequestMapping(\"/api\")\npublic class DataController {\n    @GetMapping(\"/data\")\n    @PreAuthorize(\"isAuthenticated()\")\n    public ResponseEntity<Data> getData() {\n        return ResponseEntity.ok(data);\n    }\n}\n```\nSource: Azure AD with Spring Boot (https://learn.microsoft.com/azure/developer/java/spring-framework/configure-spring-boot-starter-java-app-with-azure-active-directory)"
            ))
        elif has_spring_security and has_security_annotations:
            line_num = self.get_line_number(code, "@PreAuthorize") or \
                       self.get_line_number(code, "springframework.security")
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.INFO,
                title="Authentication properly implemented",
                description="API endpoints protected with Spring Security and @PreAuthorize annotations.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure JWT token validation is configured and role-based access control is implemented.",
                good_practice=True
            ))
    
    def _check_secrets_management(self, code: str, file_path: str) -> None:
        """Check for hardcoded secrets (KSI-SVC-06)."""
        # Patterns for potential secrets
        secret_patterns = [
            (r'(password|Password)\s*=\s*"[^"]{3,}"', "password"),
            (r'(apiKey|API_KEY)\s*=\s*"[^"]{10,}"', "API key"),
            (r'(secret|Secret|SECRET)\s*=\s*"[^"]{10,}"', "secret"),
            (r'(token|Token|TOKEN)\s*=\s*"[^"]{10,}"', "token"),
            (r'(connectionString|connection-string)\s*=\s*"[^"]{10,}"', "connection string"),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                matched_text = match.group(0)
                
                # Skip if it's from environment or Key Vault
                if any(x in matched_text for x in ["System.getenv", "Environment.getProperty", "secretClient", "${", "@Value"]):
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
                    recommendation=f"Use Azure Key Vault to store {secret_type}:\n```java\n// Add dependency\n<dependency>\n    <groupId>com.azure</groupId>\n    <artifactId>azure-security-keyvault-secrets</artifactId>\n</dependency>\n<dependency>\n    <groupId>com.azure</groupId>\n    <artifactId>azure-identity</artifactId>\n</dependency>\n\n// Retrieve secret with managed identity\nimport com.azure.identity.DefaultAzureCredentialBuilder;\nimport com.azure.security.keyvault.secrets.SecretClient;\nimport com.azure.security.keyvault.secrets.SecretClientBuilder;\n\npublic class SecretManager {{\n    private final SecretClient secretClient;\n    \n    public SecretManager() {{\n        secretClient = new SecretClientBuilder()\n            .vaultUrl(\"https://your-vault.vault.azure.net\")\n            .credential(new DefaultAzureCredentialBuilder().build())\n            .buildClient();\n    }}\n    \n    public String getSecret(String secretName) {{\n        return secretClient.getSecret(secretName).getValue();\n    }}\n}}\n\n// Or use Spring Boot integration\n@Value(\"${{azure.keyvault.secret.{secret_type.replace(' ', '-')}}}\")\nprivate String secretValue;\n```\nSource: Azure Key Vault with Java (https://learn.microsoft.com/azure/key-vault/secrets/quick-create-java)"
                ))
        
        # Check for good practices (Key Vault usage)
        if re.search(r"import\s+com\.azure\.security\.keyvault\.secrets", code):
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
            (r"ObjectInputStream|readObject|XMLDecoder", "Insecure deserialization (use JSON libraries)"),
            (r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder.*user", "Command injection risk"),
            (r"Statement\.execute\(.*\+|createStatement\(\).*\+", "SQL injection risk (use PreparedStatement)"),
            (r"eval\(|ScriptEngine", "Code injection risk"),
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
                    recommendation="Use secure alternatives:\n- ObjectInputStream → Jackson/Gson JSON serialization\n- Statement → PreparedStatement with parameterized queries\n- Runtime.exec(user input) → Validate/sanitize input, use ProcessBuilder safely\n- ScriptEngine → Avoid evaluating user input\n\nRun dependency scanning:\n```bash\n# Maven\nmvn dependency-check:check\n\n# Gradle\ngradle dependencyCheckAnalyze\n\n# OWASP Dependency-Check\n```\nSource: OWASP Secure Coding Practices (https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)"
                ))
        
        # Check for pom.xml or build.gradle (good practice if versions are specified)
        if "pom.xml" in file_path or "build.gradle" in file_path:
            # Check if versions are specified
            if re.search(r"<version>[\d\.]+</version>|version\s*=\s*['\"][\d\.]+['\"]", code):
                line_num = self.get_line_number(code, "version")
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-08",
                    severity=Severity.INFO,
                    title="Dependencies pinned to specific versions",
                    description="Dependencies use explicit version specifications for reproducibility.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Regularly update dependencies and run security scans (OWASP Dependency-Check, Snyk).",
                    good_practice=True
                ))
    
    def _check_pii_handling(self, code: str, file_path: str) -> None:
        """Check for PII handling (KSI-PIY-02)."""
        # Check for fields that might contain PII
        pii_patterns = [
            (r"(ssn|socialSecurityNumber|SocialSecurityNumber)", "Social Security Number"),
            (r"(email|emailAddress|Email|EmailAddress)", "email address"),
            (r"(phone|phoneNumber|telephone|PhoneNumber)", "phone number"),
            (r"(dateOfBirth|dob|birthDate|DateOfBirth)", "date of birth"),
            (r"(address|streetAddress|homeAddress|Address)", "physical address"),
        ]
        
        for pattern, pii_type in pii_patterns:
            matches = re.finditer(r"(private|protected|public)\s+\w+\s+" + pattern, code)
            for match in matches:
                # Check if there's encryption nearby
                context_start = max(0, match.start() - 300)
                context_end = min(len(code), match.end() + 300)
                context = code[context_start:context_end]
                
                has_encryption = bool(re.search(r"(encrypt|Cipher|AES|hash|Hash|@Encrypted)", context, re.IGNORECASE))
                
                if not has_encryption:
                    line_num = self.get_line_number(code, match.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-PIY-02",
                        severity=Severity.MEDIUM,
                        title=f"Potential unencrypted PII: {pii_type}",
                        description=f"Field '{match.group(0)}' may contain {pii_type}. FedRAMP 20x requires PII to be encrypted at rest and in transit.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation=f"Encrypt {pii_type} before storing:\n```java\nimport javax.crypto.Cipher;\nimport javax.crypto.SecretKey;\nimport javax.crypto.spec.SecretKeySpec;\nimport java.util.Base64;\n\npublic class PiiEncryption {{\n    // Get encryption key from Azure Key Vault\n    private final SecretKey key;\n    \n    public PiiEncryption(String keyFromKeyVault) {{\n        byte[] decodedKey = Base64.getDecoder().decode(keyFromKeyVault);\n        this.key = new SecretKeySpec(decodedKey, 0, decodedKey.length, \"AES\");\n    }}\n    \n    public String encrypt(String piiValue) throws Exception {{\n        Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n        cipher.init(Cipher.ENCRYPT_MODE, key);\n        byte[] encrypted = cipher.doFinal(piiValue.getBytes());\n        return Base64.getEncoder().encodeToString(encrypted);\n    }}\n    \n    public String decrypt(String encryptedValue) throws Exception {{\n        Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n        cipher.init(Cipher.DECRYPT_MODE, key);\n        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));\n        return new String(decrypted);\n    }}\n}}\n\n// JPA entity with encryption\n@Entity\npublic class User {{\n    @Convert(converter = PiiEncryptionConverter.class)\n    private String {match.group(0).split()[-1]};\n}}\n```\nSource: NIST SP 800-122 (PII Protection)"
                    ))
    
    def _check_logging(self, code: str, file_path: str) -> None:
        """Check for proper logging implementation (KSI-MLA-05)."""
        # Check for logging frameworks
        has_logging = bool(re.search(
            r"(import\s+(org\.slf4j|java\.util\.logging|org\.apache\.log4j|ch\.qos\.logback)|Logger\s+\w+\s*=|@Slf4j)",
            code
        ))
        
        # Check for Application Insights
        has_app_insights = bool(re.search(r"(TelemetryClient|applicationinsights)", code))
        
        # Check for sensitive data in logs
        if has_logging:
            log_statements = re.finditer(
                r'(log|logger)\.(info|error|warn|debug)\s*\([^)]*\)',
                code,
                re.IGNORECASE
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
                        recommendation="Redact sensitive data before logging:\n```java\npublic class LogSanitizer {\n    public static String redact(String sensitive) {\n        if (sensitive == null || sensitive.length() < 4) {\n            return \"***\";\n        }\n        return sensitive.substring(0, 2) + \"***\" + \n               sensitive.substring(sensitive.length() - 2);\n    }\n}\n\n// Use structured logging with redaction\nlogger.info(\"User login: email={}\", LogSanitizer.redact(userEmail));\n```"
                    ))
        
        if not has_logging:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.MEDIUM,
                title="No logging implementation detected",
                description="No Logger usage found. FedRAMP 20x requires comprehensive audit logging for security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement structured logging with Application Insights:\n```java\n// Add dependencies (Maven)\n<dependency>\n    <groupId>com.microsoft.azure</groupId>\n    <artifactId>applicationinsights-spring-boot-starter</artifactId>\n</dependency>\n<dependency>\n    <groupId>org.slf4j</groupId>\n    <artifactId>slf4j-api</artifactId>\n</dependency>\n\n// Use in code\nimport org.slf4j.Logger;\nimport org.slf4j.LoggerFactory;\n\npublic class DataController {\n    private static final Logger logger = LoggerFactory.getLogger(DataController.class);\n    \n    @GetMapping(\"/data\")\n    public ResponseEntity<Data> getData() {\n        logger.info(\"Data access request from user: {}\", \n            SecurityContextHolder.getContext().getAuthentication().getName());\n        return ResponseEntity.ok(data);\n    }\n}\n\n// Or use Lombok\n@Slf4j\npublic class DataService {\n    public void process() {\n        log.info(\"Processing data\");\n    }\n}\n```\nSource: Azure Application Insights for Java (https://learn.microsoft.com/azure/azure-monitor/app/java-in-process-agent)"
            ))
        elif has_app_insights:
            line_num = self.get_line_number(code, "TelemetryClient") or self.get_line_number(code, "applicationinsights")
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
                recommendation="Use managed identities instead of service principals:\n```java\nimport com.azure.identity.DefaultAzureCredential;\nimport com.azure.identity.DefaultAzureCredentialBuilder;\n\n// Remove ClientSecretCredential with hardcoded secret\n// Use DefaultAzureCredential which automatically uses managed identity in Azure\nTokenCredential credential = new DefaultAzureCredentialBuilder().build();\n\n// Or explicitly use managed identity\nTokenCredential credential = new ManagedIdentityCredentialBuilder().build();\n\n// Works in Azure App Service, Azure Functions, AKS, VMs with system-assigned identity\n```\nSource: Azure Managed Identities for Java (https://learn.microsoft.com/azure/developer/java/sdk/identity)"
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
        # Check for RestTemplate or WebClient
        has_http_client = bool(re.search(r"(RestTemplate|WebClient|RestClient)", code))
        
        # Check for service-to-service authentication
        has_feign = bool(re.search(r"@FeignClient", code))
        
        if has_http_client or has_feign:
            # Check for bearer token interceptor
            has_auth_interceptor = bool(re.search(r"(ClientHttpRequestInterceptor|ExchangeFilterFunction|RequestInterceptor|Bearer)", code))
            
            if not has_auth_interceptor:
                line_num = self.get_line_number(code, "RestTemplate") or self.get_line_number(code, "WebClient")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.MEDIUM,
                    title="HTTP client without authentication interceptor",
                    description="Service-to-service calls should use managed identity and bearer tokens. FedRAMP 20x requires authenticated service communication.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add authentication interceptor to HTTP client:\n```java\nimport com.azure.identity.DefaultAzureCredential;\nimport com.azure.core.credential.TokenRequestContext;\n\n@Configuration\npublic class RestTemplateConfig {\n    @Bean\n    public RestTemplate restTemplate() {\n        RestTemplate restTemplate = new RestTemplate();\n        restTemplate.getInterceptors().add(new BearerTokenInterceptor());\n        return restTemplate;\n    }\n}\n\npublic class BearerTokenInterceptor implements ClientHttpRequestInterceptor {\n    private final DefaultAzureCredential credential;\n    private final String scope;\n    \n    public BearerTokenInterceptor() {\n        this.credential = new DefaultAzureCredentialBuilder().build();\n        this.scope = \"api://your-api-id/.default\";\n    }\n    \n    @Override\n    public ClientHttpResponse intercept(HttpRequest request, byte[] body, \n                                        ClientHttpRequestExecution execution) throws IOException {\n        TokenRequestContext context = new TokenRequestContext().addScopes(scope);\n        String token = credential.getToken(context).block().getToken();\n        request.getHeaders().setBearerAuth(token);\n        return execution.execute(request, body);\n    }\n}\n```\nSource: Spring Boot REST API security (https://spring.io/guides/tutorials/rest)"
                ))
            else:
                line_num = self.get_line_number(code, "Interceptor") or self.get_line_number(code, "Bearer")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.INFO,
                    title="Service-to-service authentication configured",
                    description="HTTP client uses authentication interceptor for bearer tokens.",
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
                recommendation="Log exceptions and handle appropriately:\n```java\ntry {\n    // operation\n} catch (Exception ex) {\n    logger.error(\"Operation failed: {}\", operationName, ex);\n    throw ex; // or handle gracefully\n}\n```"
            ))
        
        # Check for catching Exception or Throwable
        generic_catch = re.search(r"catch\s*\(\s*(Exception|Throwable)\s+\w+\s*\)", code)
        
        if generic_catch:
            line_num = self.get_line_number(code, generic_catch.group(0))
            self.add_finding(Finding(
                requirement_id="KSI-SVC-01",
                severity=Severity.LOW,
                title="Generic exception handler detected",
                description="Catching generic Exception or Throwable hides specific error types. Consider catching specific exceptions.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Catch specific exceptions when possible:\n```java\ntry {\n    repository.save(entity);\n} catch (DataAccessException ex) {\n    logger.error(\"Database error\", ex);\n    throw new ServiceException(\"Failed to save data\", ex);\n} catch (ValidationException ex) {\n    logger.warn(\"Validation failed\", ex);\n    throw ex;\n}\n```"
            ))
    
    def _check_input_validation(self, code: str, file_path: str) -> None:
        """Check for input validation (KSI-SVC-02)."""
        # Check for validation annotations
        has_validation = bool(re.search(
            r"@(NotNull|NotEmpty|NotBlank|Size|Min|Max|Email|Pattern|Valid)",
            code
        ))
        
        # Check for request body or request parameters
        has_request_mapping = bool(re.search(
            r"@(RequestBody|RequestParam|PathVariable)",
            code
        ))
        
        if has_request_mapping and not has_validation:
            line_num = self.get_line_number(code, "@RequestBody") or self.get_line_number(code, "@RequestParam")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.MEDIUM,
                title="Request parameters without validation",
                description="Controller accepts input without validation annotations. FedRAMP 20x requires input validation to prevent injection attacks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add Bean Validation (JSR-380) annotations:\n```java\nimport javax.validation.Valid;\nimport javax.validation.constraints.*;\n\npublic class CreateUserRequest {\n    @NotBlank(message = \"Username is required\")\n    @Size(min = 3, max = 50)\n    @Pattern(regexp = \"^[a-zA-Z0-9_]+$\", message = \"Invalid characters\")\n    private String username;\n    \n    @NotNull\n    @Email(message = \"Invalid email format\")\n    private String email;\n}\n\n@RestController\npublic class UserController {\n    @PostMapping(\"/users\")\n    public ResponseEntity<User> createUser(@Valid @RequestBody CreateUserRequest request) {\n        // Spring automatically validates and returns 400 if invalid\n        return ResponseEntity.ok(userService.create(request));\n    }\n}\n```\nSource: Spring Boot Validation (https://spring.io/guides/gs/validating-form-input/)"
            ))
        elif has_validation:
            line_num = self.get_line_number(code, "@Valid") or self.get_line_number(code, "@NotNull")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.INFO,
                title="Input validation properly configured",
                description="Request models use Bean Validation annotations.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure custom validators are implemented for complex business rules.",
                good_practice=True
            ))
    
    def _check_secure_coding(self, code: str, file_path: str) -> None:
        """Check for secure coding practices (KSI-SVC-07)."""
        issues = []
        
        # Check for HTTPS/HSTS configuration
        if re.search(r"(requiresSecure|setSecure\(true\)|REQUIRE_HTTPS)", code):
            line_num = self.get_line_number(code, "Secure")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.INFO,
                title="HTTPS enforcement configured",
                description="Application enforces HTTPS for secure communication.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure HSTS headers are configured with max-age of at least 1 year.",
                good_practice=True
            ))
        elif re.search(r"@Configuration|@SpringBootApplication", code):
            issues.append("Missing HTTPS enforcement configuration")
        
        # Check for CORS configuration
        if re.search(r"addAllowedOrigin\(\"[\*]", code):
            line_num = self.get_line_number(code, "addAllowedOrigin")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.MEDIUM,
                title="Overly permissive CORS policy",
                description="CORS allows all origins (*). FedRAMP 20x requires restricted cross-origin access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Restrict CORS to specific origins:\n```java\n@Configuration\npublic class WebConfig implements WebMvcConfigurer {\n    @Override\n    public void addCorsMappings(CorsRegistry registry) {\n        registry.addMapping(\"/api/**\")\n            .allowedOrigins(\"https://yourdomain.com\")\n            .allowedMethods(\"GET\", \"POST\", \"PUT\", \"DELETE\")\n            .allowCredentials(true)\n            .maxAge(3600);\n    }\n}\n```"
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
                recommendation="Add security configuration:\n```java\n@Configuration\npublic class SecurityConfig {\n    @Bean\n    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n        http\n            .requiresChannel(channel -> channel\n                .anyRequest().requiresSecure())\n            .headers(headers -> headers\n                .httpStrictTransportSecurity(hsts -> hsts\n                    .maxAgeInSeconds(31536000)\n                    .includeSubDomains(true)));\n        return http.build();\n    }\n}\n```"
            ))
    
    def _check_data_classification(self, code: str, file_path: str) -> None:
        """Check for data classification attributes (KSI-PIY-01)."""
        # Check for custom annotations
        has_classification = bool(re.search(r"@(Sensitive|Confidential|Internal|Public)Data", code))
        
        # Check for PII-related fields
        has_pii_fields = bool(re.search(r"(email|phone|ssn|dateOfBirth|address)", code, re.IGNORECASE))
        
        if has_pii_fields and not has_classification:
            line_num = self.get_line_number(code, "email") or self.get_line_number(code, "phone")
            self.add_finding(Finding(
                requirement_id="KSI-PIY-01",
                severity=Severity.LOW,
                title="PII fields without data classification annotations",
                description="Fields containing PII should be marked with data classification annotations for tracking and compliance.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Create and use data classification annotations:\n```java\n@Retention(RetentionPolicy.RUNTIME)\n@Target(ElementType.FIELD)\npublic @interface SensitiveData {\n    DataClassification value();\n}\n\npublic enum DataClassification {\n    PUBLIC,\n    INTERNAL,\n    CONFIDENTIAL,\n    RESTRICTED\n}\n\n@Entity\npublic class User {\n    @SensitiveData(DataClassification.RESTRICTED)\n    private String ssn;\n    \n    @SensitiveData(DataClassification.CONFIDENTIAL)\n    private String email;\n}\n```"
            ))
    
    def _check_privacy_controls(self, code: str, file_path: str) -> None:
        """Check for privacy control implementation (KSI-PIY-03)."""
        # Check for consent tracking
        has_consent = bool(re.search(r"(consent|Consent|privacyAgreement|PrivacyAgreement)", code))
        
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
                    recommendation="Add consent tracking fields:\n```java\n@Entity\npublic class User {\n    private Boolean marketingConsentGiven;\n    private LocalDateTime consentDate;\n    private String consentVersion;\n    private Boolean dataSharingConsent;\n}\n```"
                ))
    
    def _check_service_mesh(self, code: str, file_path: str) -> None:
        """Check for service mesh security (KSI-CNA-07)."""
        # Already covered in _check_microservices_security
        pass
    
    def _check_least_privilege(self, code: str, file_path: str) -> None:
        """Check for least privilege implementation (KSI-IAM-04)."""
        # Check for role-based authorization
        has_role_auth = bool(re.search(r"(@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed)", code))
        
        if re.search(r"@PreAuthorize\(['\"]isAuthenticated\(\)['\"]", code) and not re.search(r"hasRole|hasAuthority", code):
            line_num = self.get_line_number(code, "@PreAuthorize")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.MEDIUM,
                title="Authorization without role checks",
                description="Using @PreAuthorize('isAuthenticated()') without role checks allows any authenticated user. FedRAMP 20x requires least-privilege access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement role-based or permission-based authorization:\n```java\n// Role-based\n@PreAuthorize(\"hasAnyRole('ADMIN', 'MANAGER')\")\n@DeleteMapping(\"/users/{id}\")\npublic ResponseEntity<Void> deleteUser(@PathVariable Long id) {\n    return ResponseEntity.noContent().build();\n}\n\n// Permission-based (recommended)\n@PreAuthorize(\"hasAuthority('user:delete')\")\n@DeleteMapping(\"/users/{id}\")\npublic ResponseEntity<Void> deleteUser(@PathVariable Long id) {\n    return ResponseEntity.noContent().build();\n}\n\n// Method-level with business logic\n@PostAuthorize(\"returnObject.owner == authentication.name\")\n@GetMapping(\"/documents/{id}\")\npublic Document getDocument(@PathVariable Long id) {\n    return documentService.findById(id);\n}\n```\nSource: Spring Security Method Security (https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)"
            ))
        elif has_role_auth and re.search(r"(hasRole|hasAuthority|@Secured|@RolesAllowed)", code):
            line_num = self.get_line_number(code, "hasRole") or self.get_line_number(code, "hasAuthority")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.INFO,
                title="Least privilege authorization implemented",
                description="Application uses role-based or permission-based authorization for access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review authorization rules and ensure they follow least privilege principle.",
                good_practice=True
            ))
    
    def _check_session_management(self, code: str, file_path: str) -> None:
        """Check for secure session management (KSI-IAM-07)."""
        # Check for session configuration
        has_session_config = bool(re.search(r"(sessionManagement|SessionCreationPolicy|session-timeout)", code))
        
        if has_session_config:
            # Check for secure cookie settings
            has_secure_cookies = bool(re.search(r"(httpOnly|secure|sameSite)", code, re.IGNORECASE))
            
            if not has_secure_cookies:
                line_num = self.get_line_number(code, "session")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.MEDIUM,
                    title="Session configuration without secure cookie flags",
                    description="Session management should use HttpOnly, Secure, and SameSite flags. FedRAMP 20x requires secure session handling.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure secure session management:\n```java\n// application.properties\nserver.servlet.session.cookie.http-only=true\nserver.servlet.session.cookie.secure=true\nserver.servlet.session.cookie.same-site=strict\nserver.servlet.session.timeout=20m\n\n// SecurityConfig.java\n@Bean\npublic SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n    http\n        .sessionManagement(session -> session\n            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)\n            .maximumSessions(1)\n            .expiredUrl(\"/login?expired\"))\n        .rememberMe(remember -> remember\n            .alwaysRemember(false)\n            .tokenValiditySeconds(1209600)); // 14 days\n    return http.build();\n}\n```\nSource: Spring Security Session Management (https://docs.spring.io/spring-security/reference/servlet/authentication/session-management.html)"
                ))
            else:
                line_num = self.get_line_number(code, "httpOnly") or self.get_line_number(code, "secure")
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
        # Check for Application Insights for Java
        has_monitoring = bool(re.search(
            r"(com\.microsoft\.applicationinsights|io\.micrometer|org\.slf4j\.Logger)",
            code
        ))
        
        if has_monitoring:
            # Check for security event logging
            has_security_logging = bool(re.search(
                r"(logger\.(warn|error|info)|trackEvent|trackException)",
                code
            ))
            
            if not has_security_logging:
                line_num = self.get_line_number(code, "applicationinsights") or self.get_line_number(code, "Logger")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.MEDIUM,
                    title="Limited security event tracking",
                    description="Monitoring framework is configured but not actively tracking security events. FedRAMP 20x requires comprehensive security monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track security-relevant events:\n```java\nimport com.microsoft.applicationinsights.TelemetryClient;\nimport org.slf4j.Logger;\nimport org.slf4j.LoggerFactory;\n\n@Service\npublic class SecurityMonitor {\n    private static final Logger logger = LoggerFactory.getLogger(SecurityMonitor.class);\n    private final TelemetryClient telemetryClient;\n    \n    public void trackAuthenticationEvent(String username, boolean success, String ipAddress) {\n        Map<String, String> properties = new HashMap<>();\n        properties.put(\"Username\", username);\n        properties.put(\"Success\", String.valueOf(success));\n        properties.put(\"IPAddress\", ipAddress);\n        properties.put(\"EventType\", \"Authentication\");\n        \n        telemetryClient.trackEvent(\"SecurityEvent\", properties, null);\n        logger.warn(\"Authentication attempt: {} from {} - {}\",\n            username, ipAddress, success ? \"Success\" : \"Failed\");\n    }\n    \n    public void trackAuthorizationFailure(String username, String resource) {\n        Map<String, String> properties = new HashMap<>();\n        properties.put(\"Username\", username);\n        properties.put(\"Resource\", resource);\n        \n        telemetryClient.trackEvent(\"AuthorizationDenied\", properties, null);\n        logger.warn(\"Authorization denied: {} attempted to access {}\",\n            username, resource);\n    }\n}\n```\nSource: Application Insights for Java (https://learn.microsoft.com/azure/azure-monitor/app/java-in-process-agent)"
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
                recommendation="Implement Application Insights for Java:\n```xml\n<!-- pom.xml -->\n<dependency>\n    <groupId>com.microsoft.azure</groupId>\n    <artifactId>applicationinsights-spring-boot-starter</artifactId>\n    <version>3.4.19</version>\n</dependency>\n```\n\n```yaml\n# application.yml\nazure:\n  application-insights:\n    instrumentation-key: ${APPINSIGHTS_INSTRUMENTATIONKEY}\n```\nSource: Azure Monitor Java overview (https://learn.microsoft.com/azure/azure-monitor/app/java-get-started)"
            ))
    
    def _check_anomaly_detection(self, code: str, file_path: str) -> None:
        """Check for anomaly detection configuration (KSI-MLA-04)."""
        # Check for metrics tracking
        has_metrics = bool(re.search(
            r"(MeterRegistry|Counter|Timer|Gauge|trackMetric)",
            code
        ))
        
        if has_metrics:
            # Check for custom metrics
            has_custom_metrics = bool(re.search(
                r"(counter\(|timer\(|gauge\(|trackMetric)",
                code
            ))
            
            if not has_custom_metrics:
                line_num = self.get_line_number(code, "MeterRegistry")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-04",
                    severity=Severity.MEDIUM,
                    title="No custom metrics for anomaly detection",
                    description="Metrics framework is configured but not tracking custom metrics for anomaly detection. FedRAMP 20x requires baseline-based anomaly detection.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track custom metrics for anomaly detection:\n```java\nimport io.micrometer.core.instrument.MeterRegistry;\nimport io.micrometer.core.instrument.Counter;\nimport io.micrometer.core.instrument.Timer;\n\n@Service\npublic class MetricsTracker {\n    private final MeterRegistry registry;\n    private final Counter loginAttempts;\n    private final Timer apiResponseTime;\n    \n    public MetricsTracker(MeterRegistry registry) {\n        this.registry = registry;\n        this.loginAttempts = Counter.builder(\"security.login.attempts\")\n            .tag(\"type\", \"authentication\")\n            .register(registry);\n        this.apiResponseTime = Timer.builder(\"api.response.time\")\n            .tag(\"type\", \"performance\")\n            .register(registry);\n    }\n    \n    public void trackLoginAttempt(String ipAddress) {\n        Counter.builder(\"security.login.attempts\")\n            .tag(\"ip\", ipAddress)\n            .register(registry)\n            .increment();\n    }\n    \n    public void trackDataAccessVolume(String username, long bytes) {\n        registry.counter(\"security.data.access\",\n            \"user\", username).increment(bytes);\n    }\n}\n```\nEnable Smart Detection in Azure Portal for Application Insights.\n\nSource: Micrometer metrics (https://micrometer.io/docs/concepts)"
                ))
            else:
                line_num = self.get_line_number(code, "counter(") or self.get_line_number(code, "trackMetric")
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
                recommendation="Implement Micrometer with Application Insights (see KSI-MLA-03 recommendation)."
            ))
    
    def _check_performance_monitoring(self, code: str, file_path: str) -> None:
        """Check for performance monitoring (KSI-MLA-06)."""
        # Check for performance tracking
        has_perf_monitoring = bool(re.search(
            r"(MeterRegistry|Timer|trackDependency|@Timed|StopWatch)",
            code
        ))
        
        if has_perf_monitoring:
            # Check for dependency tracking
            has_dependency_tracking = bool(re.search(
                r"(trackDependency|@Timed|Timer\.record)",
                code
            ))
            
            if not has_dependency_tracking:
                line_num = self.get_line_number(code, "MeterRegistry") or self.get_line_number(code, "StopWatch")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.MEDIUM,
                    title="Limited performance monitoring",
                    description="Application has monitoring but doesn't track dependencies (database calls, external APIs). FedRAMP 20x requires comprehensive performance monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track dependencies for performance monitoring:\n```java\nimport io.micrometer.core.instrument.MeterRegistry;\nimport io.micrometer.core.instrument.Timer;\n\n@Service\npublic class PerformanceMonitor {\n    private final MeterRegistry registry;\n    \n    public <T> T trackDependency(String dependencyName, String target, Supplier<T> operation) {\n        Timer.Sample sample = Timer.start(registry);\n        boolean success = false;\n        \n        try {\n            T result = operation.get();\n            success = true;\n            return result;\n        } finally {\n            sample.stop(Timer.builder(\"dependency.call\")\n                .tag(\"dependency\", dependencyName)\n                .tag(\"target\", target)\n                .tag(\"success\", String.valueOf(success))\n                .register(registry));\n        }\n    }\n}\n\n// Usage\n@Service\npublic class UserService {\n    private final PerformanceMonitor monitor;\n    private final UserRepository repository;\n    \n    public List<User> getUsers() {\n        return monitor.trackDependency(\"Database\", \"UserRepository\",\n            () -> repository.findAll());\n    }\n}\n```\nSource: Spring Boot Actuator metrics (https://docs.spring.io/spring-boot/reference/actuator/metrics.html)"
                ))
            else:
                line_num = self.get_line_number(code, "@Timed") or self.get_line_number(code, "trackDependency")
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
                recommendation="Implement Micrometer for performance monitoring (see KSI-MLA-03 recommendation)."
            ))
    
    def _check_incident_response(self, code: str, file_path: str) -> None:
        """Check for automated incident response integration (KSI-INR-01)."""
        # Check for incident response integrations
        has_incident_integration = bool(re.search(
            r"(PagerDuty|ServiceNow|Opsgenie|webhook|RestTemplate|WebClient)",
            code,
            re.IGNORECASE
        ))
        
        if has_incident_integration:
            # Check for error handling with alerting
            has_alert_on_error = bool(re.search(
                r"(logger\.error|trackException).*(?:.*\n.*){0,5}.*(?:postForEntity|post|exchange)",
                code,
                re.DOTALL
            ))
            
            if not has_alert_on_error:
                line_num = self.get_line_number(code, "PagerDuty") or self.get_line_number(code, "RestTemplate")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.MEDIUM,
                    title="Incident response integration not connected to errors",
                    description="Incident response tools are referenced but not integrated with error handling. FedRAMP 20x requires automated incident response.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Integrate incident response with error handling:\n```java\nimport org.springframework.web.client.RestTemplate;\nimport org.slf4j.Logger;\nimport org.slf4j.LoggerFactory;\n\n@Service\npublic class IncidentResponseService {\n    private static final Logger logger = LoggerFactory.getLogger(IncidentResponseService.class);\n    private final RestTemplate restTemplate;\n    \n    @Value(\"${pagerduty.integration.key}\")\n    private String integrationKey;\n    \n    public void triggerIncident(Exception ex, String severity, Map<String, String> context) {\n        Map<String, Object> incident = Map.of(\n            \"routing_key\", integrationKey,\n            \"event_action\", \"trigger\",\n            \"payload\", Map.of(\n                \"summary\", ex.getMessage(),\n                \"severity\", severity,\n                \"source\", InetAddress.getLocalHost().getHostName(),\n                \"timestamp\", Instant.now().toString(),\n                \"custom_details\", context\n            )\n        );\n        \n        try {\n            restTemplate.postForEntity(\n                \"https://events.pagerduty.com/v2/enqueue\",\n                incident,\n                String.class\n            );\n            logger.info(\"Incident triggered: {}\", ex.getClass().getSimpleName());\n        } catch (Exception alertEx) {\n            logger.error(\"Failed to trigger incident\", alertEx);\n        }\n    }\n}\n\n// Usage in exception handler\n@ControllerAdvice\npublic class GlobalExceptionHandler {\n    private final IncidentResponseService incidentResponse;\n    \n    @ExceptionHandler(SecurityException.class)\n    public ResponseEntity<String> handleSecurityException(SecurityException ex, HttpServletRequest request) {\n        logger.error(\"Security breach detected\", ex);\n        incidentResponse.triggerIncident(ex, \"critical\", Map.of(\n            \"user\", request.getUserPrincipal().getName(),\n            \"ip\", request.getRemoteAddr()\n        ));\n        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(\"Access denied\");\n    }\n}\n```\nSource: Azure Monitor Action Groups (https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups)"
                ))
            else:
                line_num = self.get_line_number(code, "postForEntity") or self.get_line_number(code, "logger.error")
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
            (r'(apiUrl|baseUrl|endpoint)\s*=\s*"https?://[^"]+";', "API endpoint"),
            (r'(connectionString|jdbcUrl)\s*=\s*"[^"]+";', "Connection string"),
            (r'(port|dbPort)\s*=\s*\d+;', "Port number"),
        ]
        
        hardcoded_configs = []
        for pattern, config_type in config_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            if matches:
                for match in matches:
                    context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                    if not re.search(r'(@Value|Environment\.getProperty|ConfigurationProperties|System\.getenv)', context):
                        hardcoded_configs.append((match, config_type))
        
        has_app_config = bool(re.search(r'(azure\.data\.appconfiguration|AppConfigurationClient)', code))
        has_key_vault = bool(re.search(r'(azure\.security\.keyvault|SecretClient)', code))
        has_spring_config = bool(re.search(r'(@Value|@ConfigurationProperties|Environment)', code))
        
        if hardcoded_configs:
            for match, config_type in hardcoded_configs[:3]:
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-01",
                    severity=Severity.MEDIUM,
                    title=f"Hardcoded {config_type} configuration",
                    description=f"Configuration hardcoded in source. FedRAMP 20x requires externalized configuration.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation=f"Use Azure App Configuration:\n```java\n// pom.xml\n<dependency>\n    <groupId>com.azure.spring</groupId>\n    <artifactId>spring-cloud-azure-starter-appconfiguration</artifactId>\n</dependency>\n\n// application.properties\nspring.cloud.azure.appconfiguration.stores[0].endpoint=${{APPCONFIGURATION_ENDPOINT}}\n\n// Configuration class\n@Configuration\npublic class AppConfig {{\n    @Value(\"${{{config_type.replace(' ', '.').lower()}}}\")\n    private String {config_type.replace(' ', '')};\n    \n    public String get{config_type.replace(' ', '')}() {{\n        return {config_type.replace(' ', '')};\n    }}\n}}\n```\nSource: Azure App Configuration for Spring (https://learn.microsoft.com/azure/developer/java/spring-framework/configure-spring-boot-starter-java-app-with-azure-app-configuration)"
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
        elif not hardcoded_configs and has_spring_config:
            line_num = self.get_line_number(code, "@Value")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.LOW,
                title="Configuration uses Spring properties",
                description="application.properties used. Consider Azure App Configuration for centralized management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Migrate to Azure App Configuration for FedRAMP audit trails.",
                good_practice=True
            ))
    
    def _check_version_control(self, code: str, file_path: str) -> None:
        """Check for version control enforcement (KSI-CMT-02)."""
        direct_deploy = bool(re.search(
            r'(Runtime\.exec|ProcessBuilder).*git\s+push.*production',
            code,
            re.IGNORECASE
        ))
        
        if direct_deploy:
            line_num = self.get_line_number(code, "git push")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-02",
                severity=Severity.HIGH,
                title="Direct production deployment",
                description="Code performs direct production deployment. FedRAMP 20x requires approval workflows.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use Azure DevOps or GitHub Actions with approval gates."
            ))
        
        has_cicd = bool(re.search(r'(azure-pipelines|Jenkinsfile)', code, re.IGNORECASE))
        if has_cicd:
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
        test_frameworks = [
            r'import\s+org\.junit',
            r'import\s+org\.testng',
            r'@Test',
        ]
        
        has_test_framework = any(re.search(p, code) for p in test_frameworks)
        has_security_tests = bool(re.search(
            r'(test.*Security|test.*Auth|test.*Sql.*Injection|test.*Xss)',
            code,
            re.IGNORECASE
        ))
        
        is_test_file = bool(re.search(r'Test\.java$', file_path))
        
        if not is_test_file and not has_test_framework:
            if re.search(r'(Controller|Service|Repository)', file_path, re.IGNORECASE):
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.MEDIUM,
                    title="No automated tests found",
                    description="Application code without tests. FedRAMP 20x requires automated security testing.",
                    file_path=file_path,
                    line_number=1,
                    recommendation="Create security tests:\n```java\nimport org.junit.jupiter.api.Test;\nimport org.springframework.boot.test.context.SpringBootTest;\nimport static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;\n\n@SpringBootTest\nclass SecurityTests {\n    @Test\n    void protectedEndpoint_RequiresAuthentication() throws Exception {\n        mockMvc.perform(get(\"/api/protected\"))\n            .andExpect(status().isUnauthorized());\n    }\n    \n    @Test\n    void inputValidation_BlocksSqlInjection() throws Exception {\n        String maliciousInput = \"'; DROP TABLE users; --\";\n        mockMvc.perform(post(\"/api/search\")\n            .param(\"query\", maliciousInput)\n            .with(csrf()))\n            .andExpect(status().isOk());\n        // Verify table still exists\n        assertNotNull(userRepository.findAll());\n    }\n}\n```"
                ))
        elif is_test_file and has_test_framework and has_security_tests:
            line_num = self.get_line_number(code, "Security") or self.get_line_number(code, "Auth")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-03",
                severity=Severity.INFO,
                title="Security tests implemented",
                description="Test file includes security-focused tests.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure coverage: authentication, authorization, input validation.",
                good_practice=True
            ))
    
    def _check_audit_logging(self, code: str, file_path: str) -> None:
        """Check for audit logging of security events (KSI-AFR-01)."""
        has_auth_code = bool(re.search(
            r'(authenticate|login|UserDetails|SecurityContext)',
            code,
            re.IGNORECASE
        ))
        
        has_data_access = bool(re.search(
            r'(JpaRepository|@Query|EntityManager)',
            code,
            re.IGNORECASE
        ))
        
        has_logging = bool(re.search(r'(Logger|log\.|trackEvent|telemetryClient)', code))
        
        if has_auth_code and not has_logging:
            line_num = self.get_line_number(code, "authenticate") or self.get_line_number(code, "login")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.HIGH,
                title="Authentication without audit logging",
                description="Authentication code missing audit logs. FedRAMP 20x requires logging of all security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add audit logging:\n```java\nimport org.slf4j.Logger;\nimport org.slf4j.LoggerFactory;\nimport com.microsoft.applicationinsights.TelemetryClient;\n\n@Component\npublic class SecurityAuditLogger {\n    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditLogger.class);\n    private final TelemetryClient telemetry;\n    \n    public void logAuthenticationAttempt(\n        String userId, String ipAddress, boolean success, String method) {\n        \n        Map<String, String> properties = Map.of(\n            \"userId\", userId,\n            \"ipAddress\", ipAddress,\n            \"success\", String.valueOf(success),\n            \"method\", method,\n            \"timestamp\", Instant.now().toString()\n        );\n        \n        telemetry.trackEvent(\"AuthenticationAttempt\", properties, null);\n        \n        if (success) {\n            logger.info(\"Authentication success: user={}, ip={}\", userId, ipAddress);\n        } else {\n            logger.warn(\"Authentication failed: user={}, ip={}\", userId, ipAddress);\n        }\n    }\n}\n```"
            ))
        
        if has_data_access and not has_logging:
            line_num = self.get_line_number(code, "Repository")
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
            line_num = self.get_line_number(code, "Logger") or self.get_line_number(code, "trackEvent")
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
        local_logging = bool(re.search(
            r'(FileAppender|FileHandler|FileWriter.*\.log)',
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
                recommendation="Stream logs to Azure Monitor:\n```java\n// pom.xml\n<dependency>\n    <groupId>com.microsoft.azure</groupId>\n    <artifactId>applicationinsights-spring-boot-starter</artifactId>\n</dependency>\n\n// application.properties\nazure.application-insights.instrumentation-key=${APPINSIGHTS_KEY}\n\n// For immutable audit logs\nimport com.azure.messaging.eventhubs.EventHubProducerClient;\nimport com.fasterxml.jackson.databind.ObjectMapper;\n\n@Service\npublic class ImmutableAuditLogger {\n    private final EventHubProducerClient producer;\n    private final ObjectMapper mapper;\n    \n    public void logAuditEvent(Object event) {\n        EventData eventData = new EventData(\n            mapper.writeValueAsBytes(event)\n        );\n        producer.send(Collections.singletonList(eventData));\n    }\n}\n```"
            ))
        
        has_app_insights = bool(re.search(r'(applicationinsights|TelemetryClient)', code))
        has_event_hub = bool(re.search(r'EventHub', code))
        
        if not local_logging and (has_app_insights or has_event_hub):
            line_num = self.get_line_number(code, "applicationinsights") or self.get_line_number(code, "EventHub")
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
        key_patterns = [
            (r'(privateKey|secretKey|encryptionKey)\s*=\s*"[^"]{20,}";', "encryption key"),
            (r'-----BEGIN\s+(PRIVATE|RSA)\s+KEY-----', "private key"),
            (r'KeyGenerator\.getInstance', "generated key"),
        ]
        
        hardcoded_keys = []
        for pattern, key_type in key_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE | re.DOTALL))
            for match in matches:
                context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                if not re.search(r'(SecretClient|KeyClient|getSecret)', context):
                    hardcoded_keys.append((match, key_type))
        
        key_generation = bool(re.search(
            r'(KeyGenerator\.getInstance|KeyPairGenerator\.getInstance)(?!.*KeyVault)',
            code,
            re.DOTALL
        ))
        
        if key_generation:
            line_num = self.get_line_number(code, "KeyGenerator")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.HIGH,
                title="Local cryptographic key generation",
                description="Application generates keys locally. FedRAMP 20x requires Azure Key Vault with HSM.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use Azure Key Vault:\n```java\nimport com.azure.security.keyvault.keys.KeyClient;\nimport com.azure.security.keyvault.keys.cryptography.CryptographyClient;\nimport com.azure.identity.DefaultAzureCredential;\n\nKeyClient keyClient = new KeyClientBuilder()\n    .vaultUrl(vaultUrl)\n    .credential(new DefaultAzureCredential())\n    .buildClient();\n\n// Generate key in Key Vault\nKeyVaultKey key = keyClient.createRsaKey(\n    new CreateRsaKeyOptions(\"data-encryption-key\")\n        .setKeySize(2048)\n        .setHardwareProtected(true)  // Use HSM\n);\n\n// Use for encryption\nCryptographyClient cryptoClient = new CryptographyClientBuilder()\n    .credential(new DefaultAzureCredential())\n    .keyIdentifier(key.getId())\n    .buildClient();\n\nEncryptResult result = cryptoClient.encrypt(\n    EncryptionAlgorithm.RSA_OAEP,\n    plaintext\n);\n```"
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
                    recommendation=f"Store {key_type} in Azure Key Vault."
                ))
        
        has_key_vault = bool(re.search(r'(KeyClient|SecretClient|azure\.security\.keyvault)', code))
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

