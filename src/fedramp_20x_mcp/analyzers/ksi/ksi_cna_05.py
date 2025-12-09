"""
KSI-CNA-05: Unwanted Activity

Protect against denial of service attacks and other unwanted activity.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import ast
import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_05_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced Analyzer for KSI-CNA-05: Unwanted Activity
    
    **Official Statement:**
    Protect against denial of service attacks and other unwanted activity.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - sc-5
    - si-8
    - si-8.2
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-05"
    KSI_NAME = "Unwanted Activity"
    KSI_STATEMENT = """Protect against denial of service attacks and other unwanted activity."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("sc-5", "Denial-of-service Protection"),
        ("si-8", "Spam Protection"),
        ("si-8.2", "Automatic Updates")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-CNA-05 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Missing rate limiting middleware/decorators
        - Flask apps without Flask-Limiter
        - Django apps without rate limiting middleware
        - FastAPI apps without rate limiting dependencies
        """
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self._python_regex_fallback(code, lines, file_path)
        
        # Pattern 1: Flask app without rate limiter
        has_flask = False
        has_limiter = False
        flask_app_line = 0
        
        for node in ast.walk(tree):
            # Check for Flask import
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    if any('flask' in alias.name.lower() for alias in node.names):
                        has_flask = True
                elif isinstance(node, ast.ImportFrom):
                    if node.module and 'flask' in node.module.lower():
                        has_flask = True
                    # Check for Flask-Limiter
                    if node.module and 'flask_limiter' in node.module.lower():
                        has_limiter = True
            
            # Check for Flask app creation
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'Flask':
                    flask_app_line = node.lineno
        
        if has_flask and not has_limiter and flask_app_line > 0:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Flask Application Without Rate Limiting",
                description=(
                    f"Flask application at line {flask_app_line} missing rate limiting. "
                    f"KSI-CNA-05 requires protection against DoS attacks (SC-5) - "
                    f"Flask apps should use Flask-Limiter or similar middleware to prevent abuse."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=flask_app_line,
                code_snippet=self._get_snippet(lines, flask_app_line, context=3),
                remediation=(
                    "Add Flask-Limiter for rate limiting:\n\n"
                    "from flask import Flask\n"
                    "from flask_limiter import Limiter\n"
                    "from flask_limiter.util import get_remote_address\n\n"
                    "app = Flask(__name__)\n\n"
                    "# Rate limiter for DoS protection (SC-5, SI-8)\n"
                    "limiter = Limiter(\n"
                    "    app=app,\n"
                    "    key_func=get_remote_address,\n"
                    "    default_limits=['200 per day', '50 per hour'],\n"
                    "    storage_uri='redis://localhost:6379'  # Distributed rate limiting\n"
                    ")\n\n"
                    "@app.route('/api/data')\n"
                    "@limiter.limit('10 per minute')  # Per-endpoint limit\n"
                    "def get_data():\n"
                    "    return {'data': 'value'}\n\n"
                    "Ref: Flask-Limiter (https://flask-limiter.readthedocs.io/)"
                )
            ))
        
        # Pattern 2: Django settings without throttling
        has_django = 'django' in code.lower() or 'INSTALLED_APPS' in code
        has_throttle = 'throttle' in code.lower() or 'ratelimit' in code.lower()
        
        if has_django and not has_throttle:
            # Look for settings.py indicators
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id in ['MIDDLEWARE', 'REST_FRAMEWORK']:
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title="Django Application Without Rate Limiting",
                                description=(
                                    f"Django configuration at line {node.lineno} missing rate limiting middleware. "
                                    f"KSI-CNA-05 requires DoS protection (SC-5) - "
                                    f"Django REST Framework should include throttling classes."
                                ),
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno, context=3),
                                remediation=(
                                    "Add Django REST Framework throttling:\n\n"
                                    "# settings.py\n"
                                    "REST_FRAMEWORK = {\n"
                                    "    'DEFAULT_THROTTLE_CLASSES': [\n"
                                    "        'rest_framework.throttling.AnonRateThrottle',  # Anonymous users\n"
                                    "        'rest_framework.throttling.UserRateThrottle',  # Authenticated users\n"
                                    "    ],\n"
                                    "    'DEFAULT_THROTTLE_RATES': {\n"
                                    "        'anon': '100/day',  # SC-5 DoS protection\n"
                                    "        'user': '1000/day',\n"
                                    "    }\n"
                                    "}\n\n"
                                    "# Or use django-ratelimit for function-based views:\n"
                                    "from django_ratelimit.decorators import ratelimit\n\n"
                                    "@ratelimit(key='ip', rate='10/m', method='GET')\n"
                                    "def my_view(request):\n"
                                    "    return JsonResponse({'data': 'value'})\n\n"
                                    "Ref: Django REST Framework Throttling (https://www.django-rest-framework.org/api-guide/throttling/)"
                                )
                            ))
                            break
        
        # Pattern 3: FastAPI app without rate limiting dependency
        has_fastapi = False
        has_slowapi = False
        fastapi_app_line = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom):
                    if node.module and 'fastapi' in node.module.lower():
                        has_fastapi = True
                    if node.module and 'slowapi' in node.module.lower():
                        has_slowapi = True
            
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'FastAPI':
                    fastapi_app_line = node.lineno
        
        if has_fastapi and not has_slowapi and fastapi_app_line > 0:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="FastAPI Application Without Rate Limiting",
                description=(
                    f"FastAPI application at line {fastapi_app_line} missing rate limiting. "
                    f"KSI-CNA-05 requires DoS protection (SC-5) - "
                    f"FastAPI apps should use SlowAPI or similar middleware for rate limiting."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=fastapi_app_line,
                code_snippet=self._get_snippet(lines, fastapi_app_line, context=3),
                remediation=(
                    "Add SlowAPI rate limiting middleware:\n\n"
                    "from fastapi import FastAPI, Request\n"
                    "from slowapi import Limiter, _rate_limit_exceeded_handler\n"
                    "from slowapi.util import get_remote_address\n"
                    "from slowapi.errors import RateLimitExceeded\n\n"
                    "# Rate limiter for DoS protection (SC-5)\n"
                    "limiter = Limiter(key_func=get_remote_address)\n"
                    "app = FastAPI()\n"
                    "app.state.limiter = limiter\n"
                    "app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)\n\n"
                    "@app.get('/api/data')\n"
                    "@limiter.limit('10/minute')  # Per-endpoint rate limit\n"
                    "async def get_data(request: Request):\n"
                    "    return {'data': 'value'}\n\n"
                    "Ref: SlowAPI (https://github.com/laurentS/slowapi)"
                )
            ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        # Check for Flask without limiter
        if 'flask' in code.lower() and 'flask_limiter' not in code.lower() and 'limiter' not in code.lower():
            line_match = self._find_line(lines, r'Flask\s*\(', use_regex=True)
            if line_match:
                line_num = line_match['line_num']
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Flask Application Without Rate Limiting (Regex Fallback)",
                    description=f"Flask app at line {line_num} may be missing rate limiting.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add Flask-Limiter for rate limiting"
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-05 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - ASP.NET Core apps without rate limiting middleware
        - Missing AspNetCoreRateLimit or similar packages
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: ASP.NET Core without rate limiting middleware
        has_aspnetcore = re.search(r'using\s+Microsoft\.AspNetCore', code) or re.search(r'WebApplication\.', code)
        has_ratelimit = re.search(r'AspNetCoreRateLimit|RateLimitMiddleware|UseRateLimiting', code, re.IGNORECASE)
        
        if has_aspnetcore and not has_ratelimit:
            # Look for Program.cs or Startup.cs patterns
            for i, line in enumerate(lines, 1):
                if re.search(r'WebApplication\.CreateBuilder|builder\.Build\(\)', line):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="ASP.NET Core Application Without Rate Limiting",
                        description=(
                            f"ASP.NET Core app at line {i} missing rate limiting middleware. "
                            f"KSI-CNA-05 requires DoS protection (SC-5) - "
                            f"add AspNetCoreRateLimit or built-in rate limiting."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, context=3),
                        remediation=(
                            "Add ASP.NET Core rate limiting middleware:\n\n"
                            "// Program.cs\n"
                            "using AspNetCoreRateLimit;\n\n"
                            "var builder = WebApplication.CreateBuilder(args);\n\n"
                            "// Rate limiting for DoS protection (SC-5, SI-8)\n"
                            "builder.Services.AddMemoryCache();\n"
                            "builder.Services.Configure<IpRateLimitOptions>(options =>\n"
                            "{\n"
                            "    options.EnableEndpointRateLimiting = true;\n"
                            "    options.StackBlockedRequests = false;\n"
                            "    options.GeneralRules = new List<RateLimitRule>\n"
                            "    {\n"
                            "        new RateLimitRule\n"
                            "        {\n"
                            "            Endpoint = \"*\",\n"
                            "            Period = \"1m\",\n"
                            "            Limit = 100  // Max 100 requests per minute\n"
                            "        }\n"
                            "    };\n"
                            "});\n\n"
                            "builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();\n"
                            "builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();\n"
                            "builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();\n\n"
                            "var app = builder.Build();\n\n"
                            "app.UseIpRateLimiting();  // Enable rate limiting middleware\n\n"
                            "Ref: AspNetCoreRateLimit (https://github.com/stefanprodan/AspNetCoreRateLimit)"
                        )
                    ))
                    break
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-05 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Spring Boot apps without rate limiting (Bucket4j, Resilience4j)
        - Missing @RateLimiter annotations
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Spring Boot without rate limiting
        has_springboot = re.search(r'import.*springframework\.boot', code) or re.search(r'@SpringBootApplication', code)
        has_ratelimit = re.search(r'Bucket4j|RateLimiter|@RateLimiter|resilience4j', code, re.IGNORECASE)
        
        if has_springboot and not has_ratelimit:
            for i, line in enumerate(lines, 1):
                if re.search(r'@SpringBootApplication|@RestController', line):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Spring Boot Application Without Rate Limiting",
                        description=(
                            f"Spring Boot app at line {i} missing rate limiting. "
                            f"KSI-CNA-05 requires DoS protection (SC-5) - "
                            f"add Bucket4j or Resilience4j for rate limiting."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, context=3),
                        remediation=(
                            "Add Resilience4j rate limiting:\n\n"
                            "// Maven dependency\n"
                            "// <dependency>\n"
                            "//   <groupId>io.github.resilience4j</groupId>\n"
                            "//   <artifactId>resilience4j-spring-boot2</artifactId>\n"
                            "// </dependency>\n\n"
                            "import io.github.resilience4j.ratelimiter.annotation.RateLimiter;\n"
                            "import org.springframework.web.bind.annotation.*;\n\n"
                            "@RestController\n"
                            "@RequestMapping(\"/api\")\n"
                            "public class ApiController {\n\n"
                            "    @GetMapping(\"/data\")\n"
                            "    @RateLimiter(name = \"apiLimiter\")  // DoS protection (SC-5)\n"
                            "    public ResponseEntity<String> getData() {\n"
                            "        return ResponseEntity.ok(\"data\");\n"
                            "    }\n"
                            "}\n\n"
                            "// application.yml\n"
                            "// resilience4j.ratelimiter:\n"
                            "//   instances:\n"
                            "//     apiLimiter:\n"
                            "//       limitForPeriod: 10  # Max 10 requests\n"
                            "//       limitRefreshPeriod: 1m  # Per minute\n"
                            "//       timeoutDuration: 0s\n\n"
                            "Ref: Resilience4j Rate Limiter (https://resilience4j.readme.io/docs/ratelimiter)"
                        )
                    ))
                    break
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-05 compliance (AST-first).
        
        Frameworks: Express, NestJS, Next.js
        
        Detects:
        - Express apps without express-rate-limit
        - NestJS apps without @nestjs/throttler
        """
        # Try AST-based analysis first
        from ..ast_utils import ASTParser, CodeLanguage
        parser = ASTParser(CodeLanguage.JAVASCRIPT)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser, tree) -> List[Finding]:
        """AST-based TypeScript/JavaScript analysis for rate limiting."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Check for framework imports
        import_nodes = parser.find_nodes_by_type(tree.root_node, 'import_statement')
        has_express = False
        has_nestjs = False
        has_ratelimit = False
        has_throttler = False
        
        for import_node in import_nodes:
            import_text = parser.get_node_text(import_node, code_bytes)
            if 'express' in import_text and 'express-rate-limit' not in import_text:
                has_express = True
            if 'express-rate-limit' in import_text or 'rateLimit' in import_text or 'RateLimiterMiddleware' in import_text or 'RateLimiter' in import_text:
                has_ratelimit = True
            if '@nestjs/common' in import_text or '@nestjs/core' in import_text:
                has_nestjs = True
            if '@nestjs/throttler' in import_text or 'ThrottlerModule' in import_text:
                has_throttler = True
        
        # Pattern 1: Express without rate limiting via call_expression (HIGH)
        if has_express and not has_ratelimit:
            call_nodes = parser.find_nodes_by_type(tree.root_node, 'call_expression')
            for call_node in call_nodes:
                call_text = parser.get_node_text(call_node, code_bytes)
                # Check for express() or new Express()
                if 'express()' in call_text or 'Express()' in call_text:
                    line_num = code[:call_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Express Application Without Rate Limiting",
                        description=(
                            f"Express app at line {line_num} missing rate limiting middleware. "
                            f"KSI-CNA-05 requires DoS protection (SC-5) - "
                            f"add express-rate-limit middleware."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            "Add express-rate-limit middleware:\n\n"
                            "import express from 'express';\n"
                            "import rateLimit from 'express-rate-limit';\n\n"
                            "const app = express();\n\n"
                            "// Rate limiter for DoS protection (SC-5, SI-8)\n"
                            "const limiter = rateLimit({\n"
                            "  windowMs: 1 * 60 * 1000,  // 1 minute\n"
                            "  max: 100,  // Max 100 requests per window\n"
                            "  standardHeaders: true,  // Return rate limit info in headers\n"
                            "  legacyHeaders: false,\n"
                            "  message: 'Too many requests, please try again later'\n"
                            "});\n\n"
                            "// Apply to all routes\n"
                            "app.use(limiter);\n\n"
                            "// Or apply to specific routes\n"
                            "app.get('/api/data', limiter, (req, res) => {\n"
                            "  res.json({ data: 'value' });\n"
                            "});\n\n"
                            "Ref: express-rate-limit (https://github.com/express-rate-limit/express-rate-limit)"
                        )
                    ))
                    break
        
        # Pattern 2: NestJS without throttler via decorator_call_expression (HIGH)
        if has_nestjs and not has_throttler:
            # Look for @Module or @Controller decorators
            decorator_nodes = parser.find_nodes_by_type(tree.root_node, 'decorator')
            for decorator_node in decorator_nodes:
                decorator_text = parser.get_node_text(decorator_node, code_bytes)
                if '@Module' in decorator_text or '@Controller' in decorator_text:
                    line_num = code[:decorator_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="NestJS Application Without Rate Limiting",
                        description=(
                            f"NestJS app at line {line_num} missing rate limiting. "
                            f"KSI-CNA-05 requires DoS protection (SC-5) - "
                            f"add @nestjs/throttler module."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            "Add NestJS Throttler module:\n\n"
                            "// app.module.ts\n"
                            "import { Module } from '@nestjs/common';\n"
                            "import { ThrottlerModule } from '@nestjs/throttler';\n\n"
                            "@Module({\n"
                            "  imports: [\n"
                            "    // Rate limiting for DoS protection (SC-5)\n"
                            "    ThrottlerModule.forRoot({\n"
                            "      ttl: 60,  // Time window in seconds\n"
                            "      limit: 100,  // Max requests per window\n"
                            "    }),\n"
                            "  ],\n"
                            "})\n"
                            "export class AppModule {}\n\n"
                            "// Use @Throttle() decorator on controllers/routes\n"
                            "import { Throttle } from '@nestjs/throttler';\n\n"
                            "@Controller('api')\n"
                            "export class ApiController {\n"
                            "  @Get('data')\n"
                            "  @Throttle(10, 60)  // 10 requests per 60 seconds\n"
                            "  getData() {\n"
                            "    return { data: 'value' };\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: NestJS Throttler (https://docs.nestjs.com/security/rate-limiting)"
                        )
                    ))
                    break
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for TypeScript/JavaScript rate limiting analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Express without rate limiting
        has_express = re.search(r'import.*express|require\(["\']express["\']\)', code)
        has_ratelimit = re.search(r'express-rate-limit|rateLimit|RateLimiterMiddleware', code, re.IGNORECASE)
        
        if has_express and not has_ratelimit:
            for i, line in enumerate(lines, 1):
                if re.search(r'express\(\)|new\s+Express\(\)', line):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Express Application Without Rate Limiting",
                        description=(
                            f"Express app at line {i} missing rate limiting middleware. "
                            f"KSI-CNA-05 requires DoS protection (SC-5) - "
                            f"add express-rate-limit middleware."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, context=3),
                        remediation=(
                            "Add express-rate-limit middleware:\n\n"
                            "import express from 'express';\n"
                            "import rateLimit from 'express-rate-limit';\n\n"
                            "const app = express();\n\n"
                            "// Rate limiter for DoS protection (SC-5, SI-8)\n"
                            "const limiter = rateLimit({\n"
                            "  windowMs: 1 * 60 * 1000,  // 1 minute\n"
                            "  max: 100,  // Max 100 requests per window\n"
                            "  standardHeaders: true,  // Return rate limit info in headers\n"
                            "  legacyHeaders: false,\n"
                            "  message: 'Too many requests, please try again later'\n"
                            "});\n\n"
                            "// Apply to all routes\n"
                            "app.use(limiter);\n\n"
                            "// Or apply to specific routes\n"
                            "app.get('/api/data', limiter, (req, res) => {\n"
                            "  res.json({ data: 'value' });\n"
                            "});\n\n"
                            "Ref: express-rate-limit (https://github.com/express-rate-limit/express-rate-limit)"
                        )
                    ))
                    break
        
        # Pattern 2: NestJS without throttler
        has_nestjs = re.search(r'@nestjs/common|@Module\(|@Controller\(', code)
        has_throttler = re.search(r'@nestjs/throttler|@Throttle\(|ThrottlerModule', code)
        
        if has_nestjs and not has_throttler:
            for i, line in enumerate(lines, 1):
                if re.search(r'@Module\(|@Controller\(', line):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="NestJS Application Without Rate Limiting",
                        description=(
                            f"NestJS app at line {i} missing rate limiting. "
                            f"KSI-CNA-05 requires DoS protection (SC-5) - "
                            f"add @nestjs/throttler module."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, context=3),
                        remediation=(
                            "Add NestJS Throttler module:\n\n"
                            "// app.module.ts\n"
                            "import { Module } from '@nestjs/common';\n"
                            "import { ThrottlerModule } from '@nestjs/throttler';\n\n"
                            "@Module({\n"
                            "  imports: [\n"
                            "    // Rate limiting for DoS protection (SC-5)\n"
                            "    ThrottlerModule.forRoot({\n"
                            "      ttl: 60,  // Time window in seconds\n"
                            "      limit: 100,  // Max requests per window\n"
                            "    }),\n"
                            "  ],\n"
                            "})\n"
                            "export class AppModule {}\n\n"
                            "// Use @Throttle() decorator on controllers/routes\n"
                            "import { Throttle } from '@nestjs/throttler';\n\n"
                            "@Controller('api')\n"
                            "export class ApiController {\n"
                            "  @Get('data')\n"
                            "  @Throttle(10, 60)  // 10 requests per 60 seconds\n"
                            "  getData() {\n"
                            "    return { data: 'value' };\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: NestJS Throttler (https://docs.nestjs.com/security/rate-limiting)"
                        )
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-05 compliance.
        
        Detects:
        - Web apps without Azure Front Door/DDoS protection
        - API Management without rate limiting policies
        - Application Gateway without WAF
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Web App/App Service without DDoS protection (HIGH)
        webapp_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Web/sites")
        
        if webapp_match:
            line_num = webapp_match['line_num']
            # Check if protected by Front Door or DDoS plan
            has_frontdoor = any(re.search(r"Microsoft\.Network/(frontDoors|FrontDoorWebApplicationFirewallPolicies)", line) 
                              for line in lines)
            has_ddos = any(re.search(r"Microsoft\.Network/ddosProtectionPlans", line) 
                         for line in lines)
            
            if not (has_frontdoor or has_ddos):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Web App Without DDoS Protection",
                    description=(
                        "Web App deployed without DDoS protection or Azure Front Door. "
                        "KSI-CNA-05 requires protecting against DoS attacks (SC-5) - "
                        "public-facing web applications must be protected by Azure Front Door, "
                        "Azure DDoS Protection, or equivalent service to mitigate volumetric attacks, "
                        "protocol attacks, and resource-layer attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add Azure Front Door with WAF for DDoS protection:\n"
                        "// Azure Front Door with DDoS protection and rate limiting\n"
                        "param wafPolicyId string\n\n"
                        "resource frontDoor 'Microsoft.Network/frontDoors@2021-06-01' = {\n"
                        "  name: 'myFrontDoor'\n"
                        "  location: 'Global'\n"
                        "  properties: {\n"
                        "    enabledState: 'Enabled'\n"
                        "    frontendEndpoints: [\n"
                        "      {\n"
                        "        name: 'frontendEndpoint1'\n"
                        "        properties: {\n"
                        "          hostName: '${frontDoorName}.azurefd.net'\n"
                        "          sessionAffinityEnabledState: 'Disabled'\n"
                        "          // WAF policy for DDoS protection\n"
                        "          webApplicationFirewallPolicyLink: {\n"
                        "            id: wafPolicyId\n"
                        "          }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    backendPools: [\n"
                        "      {\n"
                        "        name: 'backendPool1'\n"
                        "        properties: {\n"
                        "          backends: [\n"
                        "            {\n"
                        "              address: webApp.properties.defaultHostName\n"
                        "              backendHostHeader: webApp.properties.defaultHostName\n"
                        "              httpPort: 80\n"
                        "              httpsPort: 443\n"
                        "              weight: 50\n"
                        "              priority: 1\n"
                        "              enabledState: 'Enabled'\n"
                        "            }\n"
                        "          ]\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    routingRules: [\n"
                        "      {\n"
                        "        name: 'routingRule1'\n"
                        "        properties: {\n"
                        "          frontendEndpoints: [\n"
                        "            { id: resourceId('Microsoft.Network/frontDoors/frontendEndpoints', frontDoorName, 'frontendEndpoint1') }\n"
                        "          ]\n"
                        "          acceptedProtocols: ['Https']\n"
                        "          patternsToMatch: ['/*']\n"
                        "          routeConfiguration: {\n"
                        "            '@odata.type': '#Microsoft.Azure.FrontDoor.Models.FrontdoorForwardingConfiguration'\n"
                        "            forwardingProtocol: 'HttpsOnly'\n"
                        "            backendPool: { id: resourceId('Microsoft.Network/frontDoors/backendPools', frontDoorName, 'backendPool1') }\n"
                        "          }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "// WAF Policy with DDoS protection rules\n"
                        "resource wafPolicy 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2022-05-01' = {\n"
                        "  name: 'myWafPolicy'\n"
                        "  location: 'Global'\n"
                        "  sku: {\n"
                        "    name: 'Premium_AzureFrontDoor'  // Required for advanced DDoS\n"
                        "  }\n"
                        "  properties: {\n"
                        "    policySettings: {\n"
                        "      enabledState: 'Enabled'\n"
                        "      mode: 'Prevention'\n"
                        "      // Rate limiting for DoS protection (SC-5)\n"
                        "      requestBodyCheck: 'Enabled'\n"
                        "      maxRequestBodySizeInKb: 128\n"
                        "    }\n"
                        "    customRules: {\n"
                        "      rules: [\n"
                        "        {\n"
                        "          name: 'RateLimitRule'\n"
                        "          priority: 1\n"
                        "          ruleType: 'RateLimitRule'\n"
                        "          rateLimitThreshold: 100  // Max requests per minute\n"
                        "          rateLimitDurationInMinutes: 1\n"
                        "          matchConditions: [\n"
                        "            {\n"
                        "              matchVariable: 'RequestUri'\n"
                        "              operator: 'Contains'\n"
                        "              matchValue: ['/api/']\n"
                        "            }\n"
                        "          ]\n"
                        "          action: 'Block'\n"
                        "        }\n"
                        "      ]\n"
                        "    }\n"
                        "    managedRules: {\n"
                        "      managedRuleSets: [\n"
                        "        {\n"
                        "          ruleSetType: 'Microsoft_DefaultRuleSet'\n"
                        "          ruleSetVersion: '2.1'\n"
                        "        }\n"
                        "        {\n"
                        "          ruleSetType: 'Microsoft_BotManagerRuleSet'\n"
                        "          ruleSetVersion: '1.0'\n"
                        "        }\n"
                        "      ]\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Front Door DDoS Protection (https://learn.microsoft.com/azure/frontdoor/front-door-ddos)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: API Management without rate limiting (HIGH)
        apim_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.ApiManagement/service")
        
        if apim_match:
            line_num = apim_match['line_num']
            # Check if rate limit policy exists
            has_rate_limit = any(re.search(r"rate-limit|quota|throttle", line, re.IGNORECASE) 
                               for line in lines)
            
            if not has_rate_limit:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="API Management Without Rate Limiting",
                    description=(
                        "API Management service without rate limiting policies. "
                        "KSI-CNA-05 requires protecting against DoS attacks and unwanted activity (SC-5, SI-8) - "
                        "APIs must implement rate limiting, quota policies, and throttling "
                        "to prevent abuse and resource exhaustion attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add rate limiting policies to API Management:\n"
                        "// API Management with rate limiting\n"
                        "resource apiManagement 'Microsoft.ApiManagement/service@2023-03-01-preview' = {\n"
                        "  name: 'myApiManagement'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: {\n"
                        "    name: 'Standard'\n"
                        "    capacity: 1\n"
                        "  }\n"
                        "  properties: {\n"
                        "    publisherEmail: 'admin@example.com'\n"
                        "    publisherName: 'My Company'\n"
                        "  }\n"
                        "}\n\n"
                        "// Global rate limit policy (DoS protection)\n"
                        "resource rateLimitPolicy 'Microsoft.ApiManagement/service/policies@2023-03-01-preview' = {\n"
                        "  parent: apiManagement\n"
                        "  name: 'policy'\n"
                        "  properties: {\n"
                        "    value: '''\n"
                        "      <policies>\n"
                        "        <inbound>\n"
                        "          <!-- Rate limit by IP address (SC-5) -->\n"
                        "          <rate-limit-by-key calls=\"100\" renewal-period=\"60\" \n"
                        "                            counter-key=\"@(context.Request.IpAddress)\" />\n"
                        "          \n"
                        "          <!-- Quota limit per subscription -->\n"
                        "          <quota-by-key calls=\"10000\" renewal-period=\"86400\" \n"
                        "                        counter-key=\"@(context.Subscription.Id)\" />\n"
                        "          \n"
                        "          <!-- Throttle concurrent requests -->\n"
                        "          <limit-concurrency key=\"@(context.Request.IpAddress)\" max-count=\"10\" />\n"
                        "          \n"
                        "          <!-- Block suspicious user agents (SI-8) -->\n"
                        "          <choose>\n"
                        "            <when condition=\"@(context.Request.Headers.GetValueOrDefault('User-Agent','').Contains('bot'))\">\n"
                        "              <return-response>\n"
                        "                <set-status code=\"403\" reason=\"Forbidden\" />\n"
                        "              </return-response>\n"
                        "            </when>\n"
                        "          </choose>\n"
                        "          \n"
                        "          <!-- Check request size limits -->\n"
                        "          <check-header name=\"Content-Length\" failed-check-httpcode=\"413\" \n"
                        "                        failed-check-error-message=\"Request too large\">\n"
                        "            <value>1048576</value> <!-- 1 MB max -->\n"
                        "          </check-header>\n"
                        "        </inbound>\n"
                        "      </policies>\n"
                        "    '''\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: API Management Rate Limiting (https://learn.microsoft.com/azure/api-management/api-management-howto-rate-limit)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Application Gateway without WAF (MEDIUM)
        appgw_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Network/applicationGateways")
        
        if appgw_match:
            line_num = appgw_match['line_num']
            # Check if WAF is enabled
            appgw_end = min(len(lines), line_num + 100)
            appgw_lines = lines[line_num:appgw_end]
            
            has_waf = any(re.search(r"sku.*WAF|firewallPolicy", line, re.IGNORECASE) 
                        for line in appgw_lines)
            
            if not has_waf:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Application Gateway Without WAF",
                    description=(
                        "Application Gateway deployed without Web Application Firewall (WAF). "
                        "KSI-CNA-05 requires protecting against unwanted activity (SC-5, SI-8.2) - "
                        "Application Gateway should use WAF SKU or WAF policy "
                        "to protect against common web exploits, bot traffic, and application-layer DDoS attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use Application Gateway with WAF:\n"
                        "// Application Gateway with WAF for DoS protection\n"
                        "resource applicationGateway 'Microsoft.Network/applicationGateways@2023-06-01' = {\n"
                        "  name: 'myAppGateway'\n"
                        "  location: resourceGroup().location\n"
                        "  properties: {\n"
                        "    sku: {\n"
                        "      name: 'WAF_v2'  // WAF-enabled SKU\n"
                        "      tier: 'WAF_v2'\n"
                        "      capacity: 2\n"
                        "    }\n"
                        "    // WAF configuration for DDoS protection\n"
                        "    webApplicationFirewallConfiguration: {\n"
                        "      enabled: true\n"
                        "      firewallMode: 'Prevention'  // Block malicious traffic\n"
                        "      ruleSetType: 'OWASP'\n"
                        "      ruleSetVersion: '3.2'\n"
                        "      // Rate limiting and request limits\n"
                        "      requestBodyCheck: true\n"
                        "      maxRequestBodySizeInKb: 128\n"
                        "      fileUploadLimitInMb: 100\n"
                        "    }\n"
                        "    gatewayIPConfigurations: [\n"
                        "      {\n"
                        "        name: 'appGatewayIpConfig'\n"
                        "        properties: {\n"
                        "          subnet: { id: subnet.id }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    frontendIPConfigurations: [\n"
                        "      {\n"
                        "        name: 'appGatewayFrontendIP'\n"
                        "        properties: {\n"
                        "          publicIPAddress: { id: publicIP.id }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    frontendPorts: [\n"
                        "      {\n"
                        "        name: 'port_443'\n"
                        "        properties: { port: 443 }\n"
                        "      }\n"
                        "    ]\n"
                        "    // Additional configuration...\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Application Gateway WAF (https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-05 compliance.
        
        Detects:
        - Web apps without Azure Front Door/DDoS protection
        - API Management without rate limiting policies
        - Application Gateway without WAF
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: App Service without DDoS protection (HIGH)
        webapp_match = self._find_line(lines, r'resource\s+"azurerm_(linux|windows)_web_app"')
        
        if webapp_match:
            line_num = webapp_match['line_num']
            # Check if protected by Front Door
            has_frontdoor = any(re.search(r'resource\s+"azurerm_cdn_frontdoor', line) 
                              for line in lines)
            has_ddos = any(re.search(r'resource\s+"azurerm_network_ddos_protection_plan"', line) 
                         for line in lines)
            
            if not (has_frontdoor or has_ddos):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Web App Without DDoS Protection",
                    description=(
                        "Web App deployed without DDoS protection or Azure Front Door. "
                        "KSI-CNA-05 requires protecting against DoS attacks (SC-5) - "
                        "public-facing web applications must be protected by Azure Front Door, "
                        "Azure DDoS Protection, or equivalent service to mitigate volumetric attacks, "
                        "protocol attacks, and resource-layer attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add Azure Front Door with WAF for DDoS protection:\n"
                        "# Azure Front Door with DDoS protection\n"
                        "resource \"azurerm_cdn_frontdoor_profile\" \"example\" {\n"
                        "  name                = \"my-frontdoor\"\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  sku_name            = \"Premium_AzureFrontDoor\"  # Required for advanced DDoS\n"
                        "}\n\n"
                        "resource \"azurerm_cdn_frontdoor_endpoint\" \"example\" {\n"
                        "  name                     = \"my-endpoint\"\n"
                        "  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.example.id\n"
                        "}\n\n"
                        "# WAF Policy with DDoS protection rules\n"
                        "resource \"azurerm_cdn_frontdoor_firewall_policy\" \"example\" {\n"
                        "  name                              = \"mywafpolicy\"\n"
                        "  resource_group_name               = azurerm_resource_group.example.name\n"
                        "  sku_name                          = azurerm_cdn_frontdoor_profile.example.sku_name\n"
                        "  enabled                           = true\n"
                        "  mode                              = \"Prevention\"\n"
                        "  request_body_check_enabled        = true\n"
                        "  # Rate limiting for DoS protection (SC-5)\n"
                        "  custom_rule {\n"
                        "    name                           = \"RateLimitRule\"\n"
                        "    enabled                        = true\n"
                        "    priority                       = 1\n"
                        "    rate_limit_duration_in_minutes = 1\n"
                        "    rate_limit_threshold           = 100  # Max requests per minute\n"
                        "    type                           = \"RateLimitRule\"\n"
                        "    action                         = \"Block\"\n\n"
                        "    match_condition {\n"
                        "      match_variable     = \"RequestUri\"\n"
                        "      operator           = \"Contains\"\n"
                        "      match_values       = [\"/api/\"]\n"
                        "    }\n"
                        "  }\n\n"
                        "  # Managed rules for OWASP and bot protection\n"
                        "  managed_rule {\n"
                        "    type    = \"Microsoft_DefaultRuleSet\"\n"
                        "    version = \"2.1\"\n"
                        "    action  = \"Block\"\n"
                        "  }\n\n"
                        "  managed_rule {\n"
                        "    type    = \"Microsoft_BotManagerRuleSet\"\n"
                        "    version = \"1.0\"\n"
                        "    action  = \"Block\"\n"
                        "  }\n"
                        "}\n\n"
                        "# Associate WAF with endpoint\n"
                        "resource \"azurerm_cdn_frontdoor_security_policy\" \"example\" {\n"
                        "  name                     = \"my-security-policy\"\n"
                        "  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.example.id\n\n"
                        "  security_policies {\n"
                        "    firewall {\n"
                        "      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.example.id\n\n"
                        "      association {\n"
                        "        domain {\n"
                        "          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.example.id\n"
                        "        }\n"
                        "      }\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: azurerm_cdn_frontdoor_firewall_policy (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_firewall_policy)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    

        """Find line number and content matching regex pattern."""
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                return {'line_num': i, 'line': line}
        return None
    

        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

