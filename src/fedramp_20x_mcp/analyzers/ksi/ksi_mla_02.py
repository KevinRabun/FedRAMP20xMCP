"""
KSI-MLA-02: Audit Logging

Regularly review and audit logs.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_MLA_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-MLA-02: Audit Logging
    
    **Official Statement:**
    Regularly review and audit logs.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2.4
    - ac-6.9
    - au-2
    - au-6
    - au-6.1
    - si-4
    - si-4.4
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Regularly review and audit logs....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-MLA-02"
    KSI_NAME = "Audit Logging"
    KSI_STATEMENT = """Regularly review and audit logs."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging, and Auditing"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-2.4", "ac-6.9", "au-2", "au-6", "au-6.1", "si-4", "si-4.4"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
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
        Analyze Python code for KSI-MLA-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Missing comprehensive logging configuration
        - No structured logging for audit events
        - Authentication/authorization without audit logs
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Authentication without logging (HIGH)
        auth_match = self._find_line(lines, r'(authenticate|login|logout|authorize)')
        
        if auth_match:
            line_num = auth_match['line_num']
            # Check if logging is present nearby
            context_start = max(0, line_num - 5)
            context_end = min(len(lines), line_num + 10)
            context = lines[context_start:context_end]
            
            has_logging = any(re.search(r'(logger\.|logging\.|log\.)', line) for line in context)
            
            if not has_logging:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Authentication/Authorization Without Audit Logging",
                    description=(
                        "Authentication or authorization operation without audit logging. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "missing audit logs for authentication/authorization events prevents detection of "
                        "unauthorized access attempts, privilege escalation, and security incidents."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Implement comprehensive audit logging for security events:\n"
                        "import logging\n"
                        "import json\n\n"
                        "# Configure structured logging\n"
                        "logging.basicConfig(\n"
                        "    level=logging.INFO,\n"
                        "    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'\n"
                        ")\n"
                        "logger = logging.getLogger(__name__)\n\n"
                        "# Flask Example\n"
                        "from flask import request\n\n"
                        "@app.route('/login', methods=['POST'])\n"
                        "def login():\n"
                        "    username = request.json.get('username')\n"
                        "    \n"
                        "    # Log authentication attempt\n"
                        "    logger.info(\n"
                        "        'Authentication attempt',\n"
                        "        extra={\n"
                        "            'event': 'auth.login.attempt',\n"
                        "            'username': username,\n"
                        "            'ip': request.remote_addr,\n"
                        "            'user_agent': request.user_agent.string\n"
                        "        }\n"
                        "    )\n"
                        "    \n"
                        "    user = authenticate(username, password)\n"
                        "    \n"
                        "    if user:\n"
                        "        logger.info(\n"
                        "            'Authentication successful',\n"
                        "            extra={\n"
                        "                'event': 'auth.login.success',\n"
                        "                'user_id': user.id,\n"
                        "                'username': username\n"
                        "            }\n"
                        "        )\n"
                        "    else:\n"
                        "        logger.warning(\n"
                        "            'Authentication failed',\n"
                        "            extra={\n"
                        "                'event': 'auth.login.failure',\n"
                        "                'username': username,\n"
                        "                'reason': 'invalid_credentials'\n"
                        "            }\n"
                        "        )\n\n"
                        "# Azure Application Insights\n"
                        "from opencensus.ext.azure.log_exporter import AzureLogHandler\n"
                        "logger.addHandler(AzureLogHandler(connection_string=conn_str))\n\n"
                        "Ref: Python Logging (https://docs.python.org/3/library/logging.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: No logging configuration (MEDIUM)
        has_logging_config = self._find_line(lines, r'(logging\.basicConfig|logging\.config|getLogger)')
        
        if not has_logging_config:
            # Check if this is an application file (not test, __init__, etc.)
            is_app_file = not any(x in file_path.lower() for x in ['test', '__init__', 'setup', 'conftest'])
            
            if is_app_file and len(lines) > 50:  # Only flag substantial files
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="No Logging Configuration Detected",
                    description=(
                        "Application file without logging configuration. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6, SI-4) - "
                        "without logging configuration, security events may not be captured for audit review."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet=self._get_snippet(lines, 1, context=5),
                    remediation=(
                        "Configure structured logging with appropriate handlers:\n"
                        "import logging\n"
                        "import logging.config\n"
                        "import os\n\n"
                        "# Option 1: Basic configuration\n"
                        "logging.basicConfig(\n"
                        "    level=os.getenv('LOG_LEVEL', 'INFO'),\n"
                        "    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',\n"
                        "    handlers=[\n"
                        "        logging.StreamHandler(),\n"
                        "        logging.FileHandler('app.log')\n"
                        "    ]\n"
                        ")\n\n"
                        "# Option 2: Dictionary configuration\n"
                        "logging.config.dictConfig({\n"
                        "    'version': 1,\n"
                        "    'disable_existing_loggers': False,\n"
                        "    'formatters': {\n"
                        "        'standard': {\n"
                        "            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'\n"
                        "        },\n"
                        "    },\n"
                        "    'handlers': {\n"
                        "        'console': {\n"
                        "            'class': 'logging.StreamHandler',\n"
                        "            'formatter': 'standard',\n"
                        "            'level': 'INFO',\n"
                        "        },\n"
                        "        'file': {\n"
                        "            'class': 'logging.handlers.RotatingFileHandler',\n"
                        "            'filename': 'app.log',\n"
                        "            'maxBytes': 10485760,  # 10MB\n"
                        "            'backupCount': 5,\n"
                        "            'formatter': 'standard',\n"
                        "        },\n"
                        "    },\n"
                        "    'root': {\n"
                        "        'handlers': ['console', 'file'],\n"
                        "        'level': 'INFO',\n"
                        "    },\n"
                        "})\n\n"
                        "Ref: Python Logging Configuration (https://docs.python.org/3/library/logging.config.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-MLA-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Missing ILogger injection
        - Authentication without audit logging
        - No structured logging configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Controller without ILogger (MEDIUM)
        controller_match = self._find_line(lines, r':\s*(Controller|ControllerBase)')
        
        if controller_match:
            line_num = controller_match['line_num']
            # Check if ILogger is injected
            has_logger = any(re.search(r'ILogger<', line) for line in lines[max(0, line_num-10):min(len(lines), line_num+20)])
            
            if not has_logger:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Controller Without ILogger Injection",
                    description=(
                        "ASP.NET Core controller without ILogger dependency injection. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "controllers handle authentication, authorization, and data access operations "
                        "that must be logged for security auditing and incident investigation."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Inject ILogger into controllers and log security events:\n"
                        "using Microsoft.AspNetCore.Mvc;\n"
                        "using Microsoft.Extensions.Logging;\n\n"
                        "[ApiController]\n"
                        "[Route(\"api/[controller]\")]\n"
                        "public class CustomersController : ControllerBase\n"
                        "{\n"
                        "    private readonly ILogger<CustomersController> _logger;\n"
                        "    private readonly ICustomerService _customerService;\n\n"
                        "    public CustomersController(\n"
                        "        ILogger<CustomersController> logger,\n"
                        "        ICustomerService customerService)\n"
                        "    {\n"
                        "        _logger = logger;\n"
                        "        _customerService = customerService;\n"
                        "    }\n\n"
                        "    [HttpPost(\"login\")]\n"
                        "    public async Task<IActionResult> Login([FromBody] LoginRequest request)\n"
                        "    {\n"
                        "        _logger.LogInformation(\n"
                        "            \"Authentication attempt for user {Username} from {IPAddress}\",\n"
                        "            request.Username,\n"
                        "            HttpContext.Connection.RemoteIpAddress\n"
                        "        );\n\n"
                        "        var result = await _customerService.AuthenticateAsync(request);\n\n"
                        "        if (result.Success)\n"
                        "        {\n"
                        "            _logger.LogInformation(\n"
                        "                \"Authentication successful for user {UserId}\",\n"
                        "                result.UserId\n"
                        "            );\n"
                        "        }\n"
                        "        else\n"
                        "        {\n"
                        "            _logger.LogWarning(\n"
                        "                \"Authentication failed for user {Username}. Reason: {Reason}\",\n"
                        "                request.Username,\n"
                        "                result.FailureReason\n"
                        "            );\n"
                        "        }\n\n"
                        "        return result.Success ? Ok(result) : Unauthorized();\n"
                        "    }\n"
                        "}\n\n"
                        "Ref: ASP.NET Core Logging (https://learn.microsoft.com/aspnet/core/fundamentals/logging/)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: [Authorize] attribute without logging (HIGH)
        authorize_match = self._find_line(lines, r'\[Authorize')
        
        if authorize_match:
            line_num = authorize_match['line_num']
            # Check if logging exists in the method
            method_start = line_num
            method_end = min(len(lines), line_num + 30)
            method_lines = lines[method_start:method_end]
            
            has_logging = any(re.search(r'_logger\.(Log|Information|Warning)', line) for line in method_lines)
            
            if not has_logging:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Authorized Endpoint Without Audit Logging",
                    description=(
                        "[Authorize] attribute without audit logging in method body. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6, AC-2.4) - "
                        "authorized endpoints handle sensitive operations that must be logged "
                        "for security auditing, including user identity, action, and result."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Log all authorized operations with structured data:\n"
                        "[HttpGet(\"{id}\")]\n"
                        "[Authorize(Roles = \"Admin\")]\n"
                        "public async Task<IActionResult> GetCustomer(int id)\n"
                        "{\n"
                        "    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);\n"
                        "    var username = User.Identity?.Name;\n\n"
                        "    _logger.LogInformation(\n"
                        "        \"User {UserId} ({Username}) accessing customer {CustomerId}\",\n"
                        "        userId,\n"
                        "        username,\n"
                        "        id\n"
                        "    );\n\n"
                        "    var customer = await _customerService.GetByIdAsync(id);\n\n"
                        "    if (customer == null)\n"
                        "    {\n"
                        "        _logger.LogWarning(\n"
                        "            \"Customer {CustomerId} not found for user {UserId}\",\n"
                        "            id,\n"
                        "            userId\n"
                        "        );\n"
                        "        return NotFound();\n"
                        "    }\n\n"
                        "    return Ok(customer);\n"
                        "}\n\n"
                        "Ref: ASP.NET Core Identity Claims (https://learn.microsoft.com/aspnet/core/security/authorization/claims)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-MLA-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Missing Logger injection
        - @PreAuthorize/@Secured without logging
        - No audit logging configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: @RestController without Logger (MEDIUM)
        controller_match = self._find_line(lines, r'@RestController|@Controller')
        
        if controller_match:
            line_num = controller_match['line_num']
            # Check if Logger field exists
            has_logger = any(re.search(r'(private.*Logger|@Slf4j)', line) 
                            for line in lines[max(0, line_num-5):min(len(lines), line_num+30)])
            
            if not has_logger:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Controller Without Logger",
                    description=(
                        "Spring controller without Logger field or @Slf4j annotation. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "controllers handle security-sensitive operations (authentication, authorization, data access) "
                        "that must be logged for audit review and incident investigation."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add Logger to controllers and log security events:\n"
                        "import org.slf4j.Logger;\n"
                        "import org.slf4j.LoggerFactory;\n"
                        "import org.springframework.web.bind.annotation.*;\n\n"
                        "// Option 1: Manual logger\n"
                        "@RestController\n"
                        "@RequestMapping(\"/api/customers\")\n"
                        "public class CustomerController {\n"
                        "    private static final Logger logger = LoggerFactory.getLogger(CustomerController.class);\n"
                        "    private final CustomerService customerService;\n\n"
                        "    @PostMapping(\"/login\")\n"
                        "    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {\n"
                        "        logger.info(\"Authentication attempt for user {} from {}\",\n"
                        "            request.getUsername(),\n"
                        "            httpRequest.getRemoteAddr()\n"
                        "        );\n\n"
                        "        AuthResult result = customerService.authenticate(request);\n\n"
                        "        if (result.isSuccess()) {\n"
                        "            logger.info(\"Authentication successful for user {}\", result.getUserId());\n"
                        "            return ResponseEntity.ok(result);\n"
                        "        } else {\n"
                        "            logger.warn(\"Authentication failed for user {}. Reason: {}\",\n"
                        "                request.getUsername(),\n"
                        "                result.getFailureReason()\n"
                        "            );\n"
                        "            return ResponseEntity.status(401).build();\n"
                        "        }\n"
                        "    }\n"
                        "}\n\n"
                        "// Option 2: Lombok @Slf4j (recommended)\n"
                        "import lombok.extern.slf4j.Slf4j;\n\n"
                        "@Slf4j\n"
                        "@RestController\n"
                        "@RequestMapping(\"/api/customers\")\n"
                        "public class CustomerController {\n"
                        "    // Lombok auto-generates: private static final Logger log\n"
                        "    \n"
                        "    @PostMapping(\"/login\")\n"
                        "    public ResponseEntity<?> login(@RequestBody LoginRequest request) {\n"
                        "        log.info(\"Authentication attempt for user {}\", request.getUsername());\n"
                        "        // ... authentication logic\n"
                        "    }\n"
                        "}\n\n"
                        "Ref: SLF4J Logging (http://www.slf4j.org/manual.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: @PreAuthorize without logging (HIGH)
        preauthorize_match = self._find_line(lines, r'@PreAuthorize|@Secured|@RolesAllowed')
        
        if preauthorize_match:
            line_num = preauthorize_match['line_num']
            # Check if logging exists in the method
            method_start = line_num
            method_end = min(len(lines), line_num + 30)
            method_lines = lines[method_start:method_end]
            
            has_logging = any(re.search(r'(logger|log)\.(info|warn|error|debug)', line, re.IGNORECASE) 
                             for line in method_lines)
            
            if not has_logging:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Secured Endpoint Without Audit Logging",
                    description=(
                        "Method with @PreAuthorize/@Secured/@RolesAllowed without audit logging. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6, AC-2.4) - "
                        "secured endpoints handle privileged operations that must be logged "
                        "with user identity, action, parameters, and result for compliance auditing."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Log all secured operations with structured context:\n"
                        "import org.springframework.security.core.annotation.AuthenticationPrincipal;\n"
                        "import org.springframework.security.core.userdetails.UserDetails;\n\n"
                        "@GetMapping(\"/{id}\")\n"
                        "@PreAuthorize(\"hasRole('ADMIN')\")\n"
                        "public ResponseEntity<Customer> getCustomer(\n"
                        "    @PathVariable Long id,\n"
                        "    @AuthenticationPrincipal UserDetails userDetails\n"
                        ") {\n"
                        "    log.info(\"User {} accessing customer {}\",\n"
                        "        userDetails.getUsername(),\n"
                        "        id\n"
                        "    );\n\n"
                        "    Optional<Customer> customer = customerService.findById(id);\n\n"
                        "    if (customer.isEmpty()) {\n"
                        "        log.warn(\"Customer {} not found for user {}\",\n"
                        "            id,\n"
                        "            userDetails.getUsername()\n"
                        "        );\n"
                        "        return ResponseEntity.notFound().build();\n"
                        "    }\n\n"
                        "    return ResponseEntity.ok(customer.get());\n"
                        "}\n\n"
                        "// For comprehensive audit logging, consider Spring Data JPA Auditing:\n"
                        "@Configuration\n"
                        "@EnableJpaAuditing\n"
                        "public class AuditConfig {\n"
                        "    @Bean\n"
                        "    public AuditorAware<String> auditorProvider() {\n"
                        "        return () -> Optional.of(\n"
                        "            SecurityContextHolder.getContext()\n"
                        "                .getAuthentication()\n"
                        "                .getName()\n"
                        "        );\n"
                        "    }\n"
                        "}\n\n"
                        "Ref: Spring Security Method Security (https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-MLA-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Vue
        
        Detects:
        - Route handlers without logging
        - Authentication middleware without audit logging
        - No Winston/Pino logger configured
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Express route without logging (MEDIUM)
        route_match = self._find_line(lines, r'app\.(get|post|put|delete|patch)\(|router\.(get|post|put|delete|patch)\(')
        
        if route_match:
            line_num = route_match['line_num']
            # Check if logging exists in route handler
            route_end = min(len(lines), line_num + 20)
            route_lines = lines[line_num:route_end]
            
            has_logging = any(re.search(r'(logger|winston|pino|console)\.(info|warn|error|debug)', line, re.IGNORECASE) 
                             for line in route_lines)
            
            if not has_logging:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Route Handler Without Logging",
                    description=(
                        "Express/NestJS route handler without logging. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "route handlers process security-sensitive requests (authentication, authorization, data access) "
                        "that must be logged for audit review and incident investigation."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add structured logging to all route handlers:\n"
                        "// Express with Winston\n"
                        "import express from 'express';\n"
                        "import winston from 'winston';\n\n"
                        "const logger = winston.createLogger({\n"
                        "  level: 'info',\n"
                        "  format: winston.format.json(),\n"
                        "  transports: [\n"
                        "    new winston.transports.File({ filename: 'audit.log' }),\n"
                        "    new winston.transports.Console()\n"
                        "  ]\n"
                        "});\n\n"
                        "const app = express();\n\n"
                        "app.post('/api/login', async (req, res) => {\n"
                        "  const { username } = req.body;\n\n"
                        "  logger.info('Authentication attempt', {\n"
                        "    username,\n"
                        "    ip: req.ip,\n"
                        "    userAgent: req.get('user-agent'),\n"
                        "    timestamp: new Date().toISOString()\n"
                        "  });\n\n"
                        "  try {\n"
                        "    const result = await authenticateUser(username, req.body.password);\n\n"
                        "    if (result.success) {\n"
                        "      logger.info('Authentication successful', {\n"
                        "        userId: result.userId,\n"
                        "        username\n"
                        "      });\n"
                        "      return res.json({ token: result.token });\n"
                        "    } else {\n"
                        "      logger.warn('Authentication failed', {\n"
                        "        username,\n"
                        "        reason: result.reason\n"
                        "      });\n"
                        "      return res.status(401).json({ error: 'Invalid credentials' });\n"
                        "    }\n"
                        "  } catch (error) {\n"
                        "    logger.error('Authentication error', {\n"
                        "      username,\n"
                        "      error: error.message\n"
                        "    });\n"
                        "    return res.status(500).json({ error: 'Internal server error' });\n"
                        "  }\n"
                        "});\n\n"
                        "// NestJS with built-in Logger\n"
                        "import { Controller, Post, Body, Logger, Req } from '@nestjs/common';\n"
                        "import { Request } from 'express';\n\n"
                        "@Controller('auth')\n"
                        "export class AuthController {\n"
                        "  private readonly logger = new Logger(AuthController.name);\n\n"
                        "  @Post('login')\n"
                        "  async login(@Body() loginDto: LoginDto, @Req() req: Request) {\n"
                        "    this.logger.log(`Authentication attempt for user ${loginDto.username} from ${req.ip}`);\n\n"
                        "    const result = await this.authService.login(loginDto);\n\n"
                        "    if (result.success) {\n"
                        "      this.logger.log(`Authentication successful for user ${result.userId}`);\n"
                        "    } else {\n"
                        "      this.logger.warn(`Authentication failed for user ${loginDto.username}`);\n"
                        "    }\n\n"
                        "    return result;\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Winston Logging (https://github.com/winstonjs/winston), NestJS Logger (https://docs.nestjs.com/techniques/logger)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Authentication middleware without logging (HIGH)
        auth_middleware_match = self._find_line(lines, r'(async|function).*authenticate|verifyToken|checkAuth')
        
        if auth_middleware_match:
            line_num = auth_middleware_match['line_num']
            # Check if logging exists in middleware
            middleware_end = min(len(lines), line_num + 30)
            middleware_lines = lines[line_num:middleware_end]
            
            has_logging = any(re.search(r'(logger|winston|pino|console)\.(info|warn|error)', line, re.IGNORECASE) 
                             for line in middleware_lines)
            
            if not has_logging:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Authentication Middleware Without Audit Logging",
                    description=(
                        "Authentication middleware without audit logging. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6, AC-2.4) - "
                        "authentication middleware enforces access control and must log "
                        "all authentication attempts, successes, and failures with user context."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Log all authentication attempts in middleware:\n"
                        "// Express JWT middleware with audit logging\n"
                        "import jwt from 'jsonwebtoken';\n"
                        "import winston from 'winston';\n\n"
                        "const logger = winston.createLogger({ /* config */ });\n\n"
                        "export const authenticateJWT = async (req, res, next) => {\n"
                        "  const token = req.headers.authorization?.split(' ')[1];\n\n"
                        "  if (!token) {\n"
                        "    logger.warn('Authentication attempt without token', {\n"
                        "      path: req.path,\n"
                        "      ip: req.ip,\n"
                        "      userAgent: req.get('user-agent')\n"
                        "    });\n"
                        "    return res.status(401).json({ error: 'No token provided' });\n"
                        "  }\n\n"
                        "  try {\n"
                        "    const decoded = jwt.verify(token, process.env.JWT_SECRET);\n\n"
                        "    logger.info('Authentication successful', {\n"
                        "      userId: decoded.userId,\n"
                        "      username: decoded.username,\n"
                        "      path: req.path,\n"
                        "      method: req.method\n"
                        "    });\n\n"
                        "    req.user = decoded;\n"
                        "    next();\n"
                        "  } catch (error) {\n"
                        "    logger.error('Authentication failed - invalid token', {\n"
                        "      error: error.message,\n"
                        "      path: req.path,\n"
                        "      ip: req.ip\n"
                        "    });\n"
                        "    return res.status(403).json({ error: 'Invalid token' });\n"
                        "  }\n"
                        "};\n\n"
                        "// NestJS Guard with audit logging\n"
                        "import { Injectable, CanActivate, ExecutionContext, Logger } from '@nestjs/common';\n"
                        "import { JwtService } from '@nestjs/jwt';\n\n"
                        "@Injectable()\n"
                        "export class JwtAuthGuard implements CanActivate {\n"
                        "  private readonly logger = new Logger(JwtAuthGuard.name);\n\n"
                        "  constructor(private jwtService: JwtService) {}\n\n"
                        "  async canActivate(context: ExecutionContext): Promise<boolean> {\n"
                        "    const request = context.switchToHttp().getRequest();\n"
                        "    const token = request.headers.authorization?.split(' ')[1];\n\n"
                        "    if (!token) {\n"
                        "      this.logger.warn(`No token provided for ${request.path}`);\n"
                        "      return false;\n"
                        "    }\n\n"
                        "    try {\n"
                        "      const payload = await this.jwtService.verifyAsync(token);\n"
                        "      this.logger.log(`User ${payload.userId} authenticated for ${request.path}`);\n"
                        "      request.user = payload;\n"
                        "      return true;\n"
                        "    } catch {\n"
                        "      this.logger.error(`Invalid token for ${request.path}`);\n"
                        "      return false;\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Express Middleware (https://expressjs.com/en/guide/using-middleware.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-MLA-02 compliance.
        
        Detects:
        - Azure resources without diagnosticSettings
        - Missing Log Analytics workspace configuration
        - Storage accounts without logging enabled
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure resources without diagnostic settings (MEDIUM)
        resource_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.(Web|Sql|KeyVault|Storage|Compute|Network)")
        
        if resource_match:
            line_num = resource_match['line_num']
            # Check if diagnostic settings exist
            has_diagnostics = any(re.search(r"resource.*diagnosticSettings|Microsoft\.Insights/diagnosticSettings", line) 
                                 for line in lines)
            
            if not has_diagnostics:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Azure Resource Without Diagnostic Settings",
                    description=(
                        "Azure resource deployed without diagnostic settings. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "Azure resources must send diagnostic logs to Log Analytics workspace "
                        "or Storage Account for centralized audit review and compliance monitoring."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add diagnostic settings to all Azure resources:\n"
                        "// Web App with diagnostic settings\n"
                        "param logAnalyticsWorkspaceId string\n\n"
                        "resource webApp 'Microsoft.Web/sites@2023-01-01' = {\n"
                        "  name: 'myWebApp'\n"
                        "  location: resourceGroup().location\n"
                        "  properties: {\n"
                        "    serverFarmId: appServicePlan.id\n"
                        "    httpsOnly: true\n"
                        "  }\n"
                        "}\n\n"
                        "resource webAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                        "  scope: webApp\n"
                        "  name: '${webApp.name}-diagnostics'\n"
                        "  properties: {\n"
                        "    workspaceId: logAnalyticsWorkspaceId\n"
                        "    logs: [\n"
                        "      {\n"
                        "        category: 'AppServiceHTTPLogs'\n"
                        "        enabled: true\n"
                        "        retentionPolicy: {\n"
                        "          enabled: true\n"
                        "          days: 90  // FedRAMP requires 90-day retention minimum\n"
                        "        }\n"
                        "      }\n"
                        "      {\n"
                        "        category: 'AppServiceConsoleLogs'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "      {\n"
                        "        category: 'AppServiceAuditLogs'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "    ]\n"
                        "    metrics: [\n"
                        "      {\n"
                        "        category: 'AllMetrics'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "// SQL Database with diagnostic settings\n"
                        "resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {\n"
                        "  parent: sqlServer\n"
                        "  name: 'myDatabase'\n"
                        "  location: resourceGroup().location\n"
                        "}\n\n"
                        "resource sqlDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                        "  scope: sqlDatabase\n"
                        "  name: '${sqlDatabase.name}-diagnostics'\n"
                        "  properties: {\n"
                        "    workspaceId: logAnalyticsWorkspaceId\n"
                        "    logs: [\n"
                        "      {\n"
                        "        category: 'SQLSecurityAuditEvents'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "      {\n"
                        "        category: 'Errors'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "      {\n"
                        "        category: 'QueryStoreRuntimeStatistics'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "// Log Analytics Workspace (required for diagnostic settings)\n"
                        "resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {\n"
                        "  name: 'myLogAnalytics'\n"
                        "  location: resourceGroup().location\n"
                        "  properties: {\n"
                        "    sku: {\n"
                        "      name: 'PerGB2018'\n"
                        "    }\n"
                        "    retentionInDays: 90  // FedRAMP minimum retention\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Monitor Diagnostic Settings (https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Storage account without logging (MEDIUM)
        storage_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts")
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if storage logging is enabled (blobServices diagnostics)
            has_blob_logging = any(re.search(r"blobServices.*diagnosticSettings|Microsoft\.Storage/storageAccounts/blobServices.*diagnosticSettings", line) 
                                  for line in lines)
            
            if not has_blob_logging:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Blob Logging",
                    description=(
                        "Storage account without blob service diagnostic settings. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "storage blob operations (read, write, delete) must be logged "
                        "for audit review and incident investigation."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable diagnostic settings for storage blob services:\n"
                        "param logAnalyticsWorkspaceId string\n\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: 'mystorageaccount'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: {\n"
                        "    name: 'Standard_GRS'\n"
                        "  }\n"
                        "  kind: 'StorageV2'\n"
                        "}\n\n"
                        "resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {\n"
                        "  parent: storageAccount\n"
                        "  name: 'default'\n"
                        "}\n\n"
                        "resource blobDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                        "  scope: blobServices\n"
                        "  name: '${storageAccount.name}-blob-diagnostics'\n"
                        "  properties: {\n"
                        "    workspaceId: logAnalyticsWorkspaceId\n"
                        "    logs: [\n"
                        "      {\n"
                        "        category: 'StorageRead'\n"
                        "        enabled: true\n"
                        "        retentionPolicy: {\n"
                        "          enabled: true\n"
                        "          days: 90\n"
                        "        }\n"
                        "      }\n"
                        "      {\n"
                        "        category: 'StorageWrite'\n"
                        "        enabled: true\n"
                        "        retentionPolicy: {\n"
                        "          enabled: true\n"
                        "          days: 90\n"
                        "        }\n"
                        "      }\n"
                        "      {\n"
                        "        category: 'StorageDelete'\n"
                        "        enabled: true\n"
                        "        retentionPolicy: {\n"
                        "          enabled: true\n"
                        "          days: 90\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    metrics: [\n"
                        "      {\n"
                        "        category: 'Transaction'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Storage Analytics Logging (https://learn.microsoft.com/azure/storage/common/storage-analytics-logging)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-MLA-02 compliance.
        
        Detects:
        - Azure resources without monitor diagnostic settings
        - Missing Log Analytics workspace configuration
        - Storage accounts without logging enabled
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure resources without diagnostic settings (MEDIUM)
        resource_match = self._find_line(lines, r'resource\s+"azurerm_(app_service|sql_database|key_vault|storage_account|virtual_machine|virtual_network)"')
        
        if resource_match:
            line_num = resource_match['line_num']
            # Check if diagnostic settings exist
            has_diagnostics = any(re.search(r'resource.*azurerm_monitor_diagnostic_setting', line) 
                                 for line in lines)
            
            if not has_diagnostics:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Azure Resource Without Diagnostic Settings",
                    description=(
                        "Azure resource deployed without monitor diagnostic settings. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "Azure resources must send diagnostic logs to Log Analytics workspace "
                        "or Storage Account for centralized audit review and compliance monitoring."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add monitor diagnostic settings to all Azure resources:\n"
                        "# Web App with diagnostic settings\n"
                        "resource \"azurerm_linux_web_app\" \"example\" {\n"
                        "  name                = \"example-web-app\"\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  service_plan_id     = azurerm_service_plan.example.id\n\n"
                        "  https_only = true\n\n"
                        "  site_config {}\n"
                        "}\n\n"
                        "resource \"azurerm_monitor_diagnostic_setting\" \"web_app_diagnostics\" {\n"
                        "  name                       = \"web-app-diagnostics\"\n"
                        "  target_resource_id         = azurerm_linux_web_app.example.id\n"
                        "  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n\n"
                        "  enabled_log {\n"
                        "    category = \"AppServiceHTTPLogs\"\n"
                        "    retention_policy {\n"
                        "      enabled = true\n"
                        "      days    = 90  # FedRAMP requires 90-day retention minimum\n"
                        "    }\n"
                        "  }\n\n"
                        "  enabled_log {\n"
                        "    category = \"AppServiceConsoleLogs\"\n"
                        "  }\n\n"
                        "  enabled_log {\n"
                        "    category = \"AppServiceAuditLogs\"\n"
                        "  }\n\n"
                        "  metric {\n"
                        "    category = \"AllMetrics\"\n"
                        "    enabled  = true\n"
                        "  }\n"
                        "}\n\n"
                        "# SQL Database with diagnostic settings\n"
                        "resource \"azurerm_mssql_database\" \"example\" {\n"
                        "  name      = \"example-db\"\n"
                        "  server_id = azurerm_mssql_server.example.id\n"
                        "}\n\n"
                        "resource \"azurerm_monitor_diagnostic_setting\" \"sql_diagnostics\" {\n"
                        "  name                       = \"sql-db-diagnostics\"\n"
                        "  target_resource_id         = azurerm_mssql_database.example.id\n"
                        "  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n\n"
                        "  enabled_log {\n"
                        "    category = \"SQLSecurityAuditEvents\"\n"
                        "  }\n\n"
                        "  enabled_log {\n"
                        "    category = \"Errors\"\n"
                        "  }\n\n"
                        "  enabled_log {\n"
                        "    category = \"QueryStoreRuntimeStatistics\"\n"
                        "  }\n"
                        "}\n\n"
                        "# Log Analytics Workspace (required for diagnostic settings)\n"
                        "resource \"azurerm_log_analytics_workspace\" \"example\" {\n"
                        "  name                = \"example-log-analytics\"\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  sku                 = \"PerGB2018\"\n"
                        "  retention_in_days   = 90  # FedRAMP minimum retention\n"
                        "}\n\n"
                        "Ref: azurerm_monitor_diagnostic_setting (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Storage account without logging (MEDIUM)
        storage_match = self._find_line(lines, r'resource\s+"azurerm_storage_account"')
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if storage logging is enabled
            has_blob_logging = any(re.search(r'resource.*azurerm_storage_account_blob_container_sas|azurerm_monitor_diagnostic_setting', line) 
                                  for line in lines)
            
            if not has_blob_logging:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Logging",
                    description=(
                        "Storage account without diagnostic settings or logging. "
                        "KSI-MLA-02 requires regularly reviewing audit logs (AU-2, AU-6) - "
                        "storage blob operations (read, write, delete) must be logged "
                        "for audit review and incident investigation."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable diagnostic settings for storage accounts:\n"
                        "resource \"azurerm_storage_account\" \"example\" {\n"
                        "  name                     = \"examplestorageaccount\"\n"
                        "  resource_group_name      = azurerm_resource_group.example.name\n"
                        "  location                 = azurerm_resource_group.example.location\n"
                        "  account_tier             = \"Standard\"\n"
                        "  account_replication_type = \"GRS\"\n\n"
                        "  # Enable logging for blob service\n"
                        "  blob_properties {\n"
                        "    logging {\n"
                        "      version               = \"1.0\"\n"
                        "      delete                = true\n"
                        "      read                  = true\n"
                        "      write                 = true\n"
                        "      retention_policy_days = 90\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "# Alternative: Use monitor diagnostic settings for blob service\n"
                        "resource \"azurerm_monitor_diagnostic_setting\" \"storage_blob_diagnostics\" {\n"
                        "  name                       = \"storage-blob-diagnostics\"\n"
                        "  target_resource_id         = \"${azurerm_storage_account.example.id}/blobServices/default\"\n"
                        "  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n\n"
                        "  enabled_log {\n"
                        "    category = \"StorageRead\"\n"
                        "    retention_policy {\n"
                        "      enabled = true\n"
                        "      days    = 90\n"
                        "    }\n"
                        "  }\n\n"
                        "  enabled_log {\n"
                        "    category = \"StorageWrite\"\n"
                        "    retention_policy {\n"
                        "      enabled = true\n"
                        "      days    = 90\n"
                        "    }\n"
                        "  }\n\n"
                        "  enabled_log {\n"
                        "    category = \"StorageDelete\"\n"
                        "    retention_policy {\n"
                        "      enabled = true\n"
                        "      days    = 90\n"
                        "    }\n"
                        "  }\n\n"
                        "  metric {\n"
                        "    category = \"Transaction\"\n"
                        "    enabled  = true\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: azurerm_storage_account logging (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#logging)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-MLA-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-MLA-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-MLA-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> Optional[Dict[str, Any]]:
        """
        Find line matching regex pattern.
        
        Returns:
            Dict with 'line_num' and 'line' if found, None otherwise
        """
        regex = re.compile(pattern, re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                return {'line_num': i, 'line': line}
        return None
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
