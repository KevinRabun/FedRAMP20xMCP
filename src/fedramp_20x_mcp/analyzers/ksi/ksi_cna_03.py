"""
KSI-CNA-03: Enforce Traffic Flow

Use logical networking and related capabilities to enforce traffic flow controls.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CNA-03: Enforce Traffic Flow
    
    **Official Statement:**
    Use logical networking and related capabilities to enforce traffic flow controls.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-12
    - ac-17.3
    - ca-9
    - sc-4
    - sc-7
    - sc-7.7
    - sc-8
    - sc-10
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Use logical networking and related capabilities to enforce traffic flow controls....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-03"
    KSI_NAME = "Enforce Traffic Flow"
    KSI_STATEMENT = """Use logical networking and related capabilities to enforce traffic flow controls."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-12", "ac-17.3", "ca-9", "sc-4", "sc-7", "sc-7.7", "sc-8", "sc-10"]
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
        Analyze Python code for KSI-CNA-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Flask apps without allowed hosts configuration
        - CORS allowing all origins
        - No IP allowlist/denylist for admin endpoints
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: CORS allowing all origins (HIGH)
        cors_match = self._find_line(lines, r'CORS\(.*origins=\["?\*"?\]|CORSMiddleware.*allow_origins=\["?\*"?\]')
        
        if cors_match:
            line_num = cors_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="CORS Allowing All Origins",
                description=(
                    "CORS middleware configured to allow all origins (*). "
                    "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                    "allowing all origins defeats cross-origin security protections and enables "
                    "attacks from untrusted websites."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Configure CORS with specific allowed origins:\n"
                    "# Flask-CORS\n"
                    "from flask import Flask\n"
                    "from flask_cors import CORS\n\n"
                    "app = Flask(__name__)\n"
                    "# Specify allowed origins explicitly\n"
                    "CORS(app, origins=[\n"
                    "    'https://app.example.com',\n"
                    "    'https://admin.example.com'\n"
                    "])\n\n"
                    "# FastAPI with CORSMiddleware\n"
                    "from fastapi import FastAPI\n"
                    "from fastapi.middleware.cors import CORSMiddleware\n\n"
                    "app = FastAPI()\n"
                    "app.add_middleware(\n"
                    "    CORSMiddleware,\n"
                    "    allow_origins=[\n"
                    "        'https://app.example.com',\n"
                    "        'https://admin.example.com'\n"
                    "    ],\n"
                    "    allow_credentials=True,\n"
                    "    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\n"
                    "    allow_headers=['*'],\n"
                    ")\n\n"
                    "# Django settings.py\n"
                    "CORS_ALLOWED_ORIGINS = [\n"
                    "    'https://app.example.com',\n"
                    "    'https://admin.example.com',\n"
                    "]\n"
                    "CORS_ALLOW_CREDENTIALS = True\n\n"
                    "Ref: CORS Best Practices (https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: No IP allowlist for admin endpoints (MEDIUM)
        admin_route_match = self._find_line(lines, r'@app\.route\([\'"]\/admin|@router\.(get|post)\([\'"]\/admin')
        
        if admin_route_match:
            line_num = admin_route_match['line_num']
            # Check if IP filtering exists
            route_end = min(len(lines), line_num + 20)
            route_lines = lines[line_num:route_end]
            
            has_ip_filtering = any(re.search(r'request\.remote_addr|request\.client\.host|IP_WHITELIST|IP_ALLOWLIST', line, re.IGNORECASE) 
                                  for line in route_lines)
            
            if not has_ip_filtering:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Admin Endpoint Without IP Filtering",
                    description=(
                        "Admin endpoint without IP allowlist filtering. "
                        "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7, AC-17.3) - "
                        "administrative interfaces should restrict access to trusted IP ranges "
                        "to prevent unauthorized access attempts."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Add IP allowlist filtering for administrative endpoints:\n"
                        "# Flask decorator for IP filtering\n"
                        "from flask import request, abort\n"
                        "from functools import wraps\n\n"
                        "ALLOWED_ADMIN_IPS = [\n"
                        "    '10.0.0.0/8',      # Internal network\n"
                        "    '192.168.1.0/24',  # VPN range\n"
                        "]\n\n"
                        "def require_admin_ip(f):\n"
                        "    @wraps(f)\n"
                        "    def decorated_function(*args, **kwargs):\n"
                        "        client_ip = request.remote_addr\n"
                        "        if not any(ipaddress.ip_address(client_ip) in ipaddress.ip_network(allowed)\n"
                        "                  for allowed in ALLOWED_ADMIN_IPS):\n"
                        "            abort(403)\n"
                        "        return f(*args, **kwargs)\n"
                        "    return decorated_function\n\n"
                        "@app.route('/admin/dashboard')\n"
                        "@require_admin_ip\n"
                        "def admin_dashboard():\n"
                        "    return render_template('admin/dashboard.html')\n\n"
                        "# FastAPI dependency for IP filtering\n"
                        "from fastapi import Request, HTTPException, Depends\n"
                        "import ipaddress\n\n"
                        "async def verify_admin_ip(request: Request):\n"
                        "    client_ip = request.client.host\n"
                        "    if not any(ipaddress.ip_address(client_ip) in ipaddress.ip_network(allowed)\n"
                        "              for allowed in ALLOWED_ADMIN_IPS):\n"
                        "        raise HTTPException(status_code=403, detail='Access denied')\n\n"
                        "@app.get('/admin/dashboard', dependencies=[Depends(verify_admin_ip)])\n"
                        "async def admin_dashboard():\n"
                        "    return {'message': 'Admin dashboard'}\n\n"
                        "Ref: Network Security Controls (https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - CORS allowing all origins
        - No IP filtering on administrative controllers
        - Missing request throttling
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: CORS allowing all origins (HIGH)
        cors_match = self._find_line(lines, r'WithOrigins\("?\*"?\)|AllowAnyOrigin\(\)')
        
        if cors_match:
            line_num = cors_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="CORS Allowing All Origins",
                description=(
                    "CORS policy configured to allow all origins. "
                    "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                    "allowing all origins defeats cross-origin security protections and enables "
                    "attacks from untrusted websites."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Configure CORS with specific allowed origins:\n"
                    "// Program.cs or Startup.cs\n"
                    "var builder = WebApplication.CreateBuilder(args);\n\n"
                    "// Define specific CORS policy\n"
                    "builder.Services.AddCors(options =>\n"
                    "{\n"
                    "    options.AddPolicy(\"AllowedOrigins\", policy =>\n"
                    "    {\n"
                    "        policy.WithOrigins(\n"
                    "            \"https://app.example.com\",\n"
                    "            \"https://admin.example.com\"\n"
                    "        )\n"
                    "        .AllowCredentials()\n"
                    "        .WithMethods(\"GET\", \"POST\", \"PUT\", \"DELETE\")\n"
                    "        .WithHeaders(\"Content-Type\", \"Authorization\");\n"
                    "    });\n"
                    "});\n\n"
                    "var app = builder.Build();\n"
                    "app.UseCors(\"AllowedOrigins\");\n\n"
                    "// Load origins from configuration (preferred)\n"
                    "builder.Services.AddCors(options =>\n"
                    "{\n"
                    "    var allowedOrigins = builder.Configuration\n"
                    "        .GetSection(\"Cors:AllowedOrigins\")\n"
                    "        .Get<string[]>();\n\n"
                    "    options.AddPolicy(\"ConfiguredOrigins\", policy =>\n"
                    "    {\n"
                    "        policy.WithOrigins(allowedOrigins)\n"
                    "              .AllowCredentials();\n"
                    "    });\n"
                    "});\n\n"
                    "// appsettings.json:\n"
                    "{\n"
                    "  \"Cors\": {\n"
                    "    \"AllowedOrigins\": [\n"
                    "      \"https://app.example.com\",\n"
                    "      \"https://admin.example.com\"\n"
                    "    ]\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: ASP.NET Core CORS (https://learn.microsoft.com/aspnet/core/security/cors)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Admin controller without IP filtering (MEDIUM)
        admin_controller_match = self._find_line(lines, r'\[Route\(["\']admin|\[ApiController\].*Admin')
        
        if admin_controller_match:
            line_num = admin_controller_match['line_num']
            # Check if IP filtering exists
            controller_end = min(len(lines), line_num + 30)
            controller_lines = lines[line_num:controller_end]
            
            has_ip_filtering = any(re.search(r'HttpContext\.Connection\.RemoteIpAddress|AllowedIPAttribute|IPAddressFilter', line, re.IGNORECASE) 
                                  for line in controller_lines)
            
            if not has_ip_filtering:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Admin Controller Without IP Filtering",
                    description=(
                        "Administrative controller without IP allowlist filtering. "
                        "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7, AC-17.3) - "
                        "administrative interfaces should restrict access to trusted IP ranges "
                        "to prevent unauthorized access attempts."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Add IP allowlist filtering for administrative controllers:\n"
                        "// Create IP filter attribute\n"
                        "using Microsoft.AspNetCore.Mvc;\n"
                        "using Microsoft.AspNetCore.Mvc.Filters;\n"
                        "using System.Net;\n\n"
                        "public class AllowedIPAttribute : ActionFilterAttribute\n"
                        "{\n"
                        "    private readonly string[] _allowedIPs;\n\n"
                        "    public AllowedIPAttribute(params string[] allowedIPs)\n"
                        "    {\n"
                        "        _allowedIPs = allowedIPs;\n"
                        "    }\n\n"
                        "    public override void OnActionExecuting(ActionExecutingContext context)\n"
                        "    {\n"
                        "        var remoteIp = context.HttpContext.Connection.RemoteIpAddress;\n"
                        "        var isAllowed = _allowedIPs.Any(ip =>\n"
                        "        {\n"
                        "            var network = IPNetwork.Parse(ip);\n"
                        "            return network.Contains(remoteIp);\n"
                        "        });\n\n"
                        "        if (!isAllowed)\n"
                        "        {\n"
                        "            context.Result = new StatusCodeResult((int)HttpStatusCode.Forbidden);\n"
                        "        }\n"
                        "    }\n"
                        "}\n\n"
                        "// Apply to admin controller\n"
                        "[ApiController]\n"
                        "[Route(\"admin\")]\n"
                        "[AllowedIP(\"10.0.0.0/8\", \"192.168.1.0/24\")]\n"
                        "public class AdminController : ControllerBase\n"
                        "{\n"
                        "    [HttpGet(\"dashboard\")]\n"
                        "    public IActionResult Dashboard()\n"
                        "    {\n"
                        "        return Ok(new { message = \"Admin dashboard\" });\n"
                        "    }\n"
                        "}\n\n"
                        "// Load from configuration (preferred)\n"
                        "// appsettings.json:\n"
                        "{\n"
                        "  \"AdminIPAllowList\": [\n"
                        "    \"10.0.0.0/8\",\n"
                        "    \"192.168.1.0/24\"\n"
                        "  ]\n"
                        "}\n\n"
                        "Ref: ASP.NET Core IP Filtering (https://learn.microsoft.com/aspnet/core/security/ip-safelist)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - CORS allowing all origins
        - No IP filtering on administrative controllers
        - Missing request origin validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: CORS allowing all origins (HIGH)
        cors_match = self._find_line(lines, r'allowedOrigins\("?\*"?\)|setAllowedOrigins.*\*')
        
        if cors_match:
            line_num = cors_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="CORS Allowing All Origins",
                description=(
                    "CORS configuration allowing all origins (*). "
                    "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                    "allowing all origins defeats cross-origin security protections and enables "
                    "attacks from untrusted websites."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Configure CORS with specific allowed origins:\n"
                    "import org.springframework.context.annotation.Bean;\n"
                    "import org.springframework.context.annotation.Configuration;\n"
                    "import org.springframework.web.servlet.config.annotation.CorsRegistry;\n"
                    "import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;\n\n"
                    "@Configuration\n"
                    "public class WebConfig implements WebMvcConfigurer {\n\n"
                    "    @Override\n"
                    "    public void addCorsMappings(CorsRegistry registry) {\n"
                    "        registry.addMapping(\"/api/**\")\n"
                    "            .allowedOrigins(\n"
                    "                \"https://app.example.com\",\n"
                    "                \"https://admin.example.com\"\n"
                    "            )\n"
                    "            .allowedMethods(\"GET\", \"POST\", \"PUT\", \"DELETE\")\n"
                    "            .allowedHeaders(\"Content-Type\", \"Authorization\")\n"
                    "            .allowCredentials(true)\n"
                    "            .maxAge(3600);\n"
                    "    }\n"
                    "}\n\n"
                    "// Load from application.properties (preferred)\n"
                    "// application.properties:\n"
                    "cors.allowed-origins=https://app.example.com,https://admin.example.com\n\n"
                    "// Configuration class:\n"
                    "@Configuration\n"
                    "public class CorsConfig implements WebMvcConfigurer {\n\n"
                    "    @Value(\"${cors.allowed-origins}\")\n"
                    "    private String[] allowedOrigins;\n\n"
                    "    @Override\n"
                    "    public void addCorsMappings(CorsRegistry registry) {\n"
                    "        registry.addMapping(\"/api/**\")\n"
                    "            .allowedOrigins(allowedOrigins)\n"
                    "            .allowCredentials(true);\n"
                    "    }\n"
                    "}\n\n"
                    "Ref: Spring CORS Configuration (https://docs.spring.io/spring-framework/reference/web/webmvc-cors.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Admin controller without IP filtering (MEDIUM)
        admin_controller_match = self._find_line(lines, r'@RequestMapping\(.*/admin|@RestController.*Admin')
        
        if admin_controller_match:
            line_num = admin_controller_match['line_num']
            # Check if IP filtering exists
            controller_end = min(len(lines), line_num + 30)
            controller_lines = lines[line_num:controller_end]
            
            has_ip_filtering = any(re.search(r'HttpServletRequest.*getRemoteAddr|IPAddressFilter|@PreAuthorize.*hasIpAddress', line, re.IGNORECASE) 
                                  for line in controller_lines)
            
            if not has_ip_filtering:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Admin Controller Without IP Filtering",
                    description=(
                        "Administrative controller without IP allowlist filtering. "
                        "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7, AC-17.3) - "
                        "administrative interfaces should restrict access to trusted IP ranges "
                        "to prevent unauthorized access attempts."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Add IP allowlist filtering for administrative controllers:\n"
                        "// Create IP filter interceptor\n"
                        "import javax.servlet.http.HttpServletRequest;\n"
                        "import javax.servlet.http.HttpServletResponse;\n"
                        "import org.springframework.beans.factory.annotation.Value;\n"
                        "import org.springframework.stereotype.Component;\n"
                        "import org.springframework.web.servlet.HandlerInterceptor;\n"
                        "import inet.ipaddr.*;\n\n"
                        "@Component\n"
                        "public class IPAddressInterceptor implements HandlerInterceptor {\n\n"
                        "    @Value(\"${admin.allowed-ips}\")\n"
                        "    private String[] allowedIPs;\n\n"
                        "    @Override\n"
                        "    public boolean preHandle(HttpServletRequest request,\n"
                        "                            HttpServletResponse response,\n"
                        "                            Object handler) throws Exception {\n"
                        "        String remoteAddr = request.getRemoteAddr();\n"
                        "        IPAddress remoteIP = new IPAddressString(remoteAddr).getAddress();\n\n"
                        "        boolean isAllowed = Arrays.stream(allowedIPs)\n"
                        "            .anyMatch(allowed -> {\n"
                        "                IPAddress network = new IPAddressString(allowed).getAddress();\n"
                        "                return network.contains(remoteIP);\n"
                        "            });\n\n"
                        "        if (!isAllowed) {\n"
                        "            response.setStatus(HttpServletResponse.SC_FORBIDDEN);\n"
                        "            return false;\n"
                        "        }\n"
                        "        return true;\n"
                        "    }\n"
                        "}\n\n"
                        "// Register interceptor for admin paths\n"
                        "@Configuration\n"
                        "public class WebMvcConfig implements WebMvcConfigurer {\n\n"
                        "    @Autowired\n"
                        "    private IPAddressInterceptor ipAddressInterceptor;\n\n"
                        "    @Override\n"
                        "    public void addInterceptors(InterceptorRegistry registry) {\n"
                        "        registry.addInterceptor(ipAddressInterceptor)\n"
                        "            .addPathPatterns(\"/admin/**\");\n"
                        "    }\n"
                        "}\n\n"
                        "// application.properties:\n"
                        "admin.allowed-ips=10.0.0.0/8,192.168.1.0/24\n\n"
                        "Ref: Spring Interceptors (https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-config/interceptors.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Vue
        
        Detects:
        - CORS allowing all origins
        - No IP filtering on admin routes
        - Missing origin validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: CORS allowing all origins (HIGH)
        cors_match = self._find_line(lines, r'cors\(\)|origin:\s*["\']?\*["\']?|origin:\s*true')
        
        if cors_match:
            line_num = cors_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="CORS Allowing All Origins",
                description=(
                    "CORS middleware configured to allow all origins. "
                    "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                    "allowing all origins defeats cross-origin security protections and enables "
                    "attacks from untrusted websites."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Configure CORS with specific allowed origins:\n"
                    "// Express with cors middleware\n"
                    "import express from 'express';\n"
                    "import cors from 'cors';\n\n"
                    "const app = express();\n\n"
                    "// Specify allowed origins\n"
                    "const corsOptions = {\n"
                    "  origin: [\n"
                    "    'https://app.example.com',\n"
                    "    'https://admin.example.com'\n"
                    "  ],\n"
                    "  credentials: true,\n"
                    "  methods: ['GET', 'POST', 'PUT', 'DELETE'],\n"
                    "  allowedHeaders: ['Content-Type', 'Authorization']\n"
                    "};\n"
                    "app.use(cors(corsOptions));\n\n"
                    "// Dynamic origin validation (for subdomains)\n"
                    "const corsOptions = {\n"
                    "  origin: function(origin, callback) {\n"
                    "    const allowedOrigins = [\n"
                    "      'https://app.example.com',\n"
                    "      'https://admin.example.com'\n"
                    "    ];\n"
                    "    if (!origin || allowedOrigins.includes(origin)) {\n"
                    "      callback(null, true);\n"
                    "    } else {\n"
                    "      callback(new Error('Not allowed by CORS'));\n"
                    "    }\n"
                    "  },\n"
                    "  credentials: true\n"
                    "};\n\n"
                    "// NestJS\n"
                    "import { NestFactory } from '@nestjs/core';\n"
                    "import { AppModule } from './app.module';\n\n"
                    "async function bootstrap() {\n"
                    "  const app = await NestFactory.create(AppModule);\n"
                    "  app.enableCors({\n"
                    "    origin: [\n"
                    "      'https://app.example.com',\n"
                    "      'https://admin.example.com'\n"
                    "    ],\n"
                    "    credentials: true,\n"
                    "  });\n"
                    "  await app.listen(3000);\n"
                    "}\n\n"
                    "Ref: CORS Configuration (https://expressjs.com/en/resources/middleware/cors.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Admin route without IP filtering (MEDIUM)
        admin_route_match = self._find_line(lines, r'(app|router)\.(get|post|put|delete)\(["\']\/admin')
        
        if admin_route_match:
            line_num = admin_route_match['line_num']
            # Check if IP filtering exists
            route_end = min(len(lines), line_num + 20)
            route_lines = lines[line_num:route_end]
            
            has_ip_filtering = any(re.search(r'req\.(ip|connection\.remoteAddress)|IP_WHITELIST|IP_ALLOWLIST|ipfilter', line, re.IGNORECASE) 
                                  for line in route_lines)
            
            if not has_ip_filtering:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Admin Route Without IP Filtering",
                    description=(
                        "Administrative route without IP allowlist filtering. "
                        "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7, AC-17.3) - "
                        "administrative interfaces should restrict access to trusted IP ranges "
                        "to prevent unauthorized access attempts."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Add IP allowlist filtering for administrative routes:\n"
                        "// Express middleware for IP filtering\n"
                        "import express from 'express';\n"
                        "import ipaddr from 'ipaddr.js';\n\n"
                        "const ALLOWED_ADMIN_IPS = [\n"
                        "  '10.0.0.0/8',\n"
                        "  '192.168.1.0/24'\n"
                        "];\n\n"
                        "function checkAdminIP(req, res, next) {\n"
                        "  const clientIP = req.ip || req.connection.remoteAddress;\n"
                        "  const parsedIP = ipaddr.parse(clientIP);\n\n"
                        "  const isAllowed = ALLOWED_ADMIN_IPS.some(range => {\n"
                        "    const [network, bits] = range.split('/');\n"
                        "    const parsedRange = ipaddr.parse(network);\n"
                        "    return parsedIP.match(parsedRange, parseInt(bits));\n"
                        "  });\n\n"
                        "  if (!isAllowed) {\n"
                        "    return res.status(403).json({ error: 'Access denied' });\n"
                        "  }\n"
                        "  next();\n"
                        "}\n\n"
                        "// Apply to admin routes\n"
                        "const adminRouter = express.Router();\n"
                        "adminRouter.use(checkAdminIP);\n\n"
                        "adminRouter.get('/dashboard', (req, res) => {\n"
                        "  res.json({ message: 'Admin dashboard' });\n"
                        "});\n\n"
                        "app.use('/admin', adminRouter);\n\n"
                        "// NestJS Guard for IP filtering\n"
                        "import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';\n"
                        "import * as ipaddr from 'ipaddr.js';\n\n"
                        "@Injectable()\n"
                        "export class IPFilterGuard implements CanActivate {\n"
                        "  private readonly allowedIPs = [\n"
                        "    '10.0.0.0/8',\n"
                        "    '192.168.1.0/24'\n"
                        "  ];\n\n"
                        "  canActivate(context: ExecutionContext): boolean {\n"
                        "    const request = context.switchToHttp().getRequest();\n"
                        "    const clientIP = request.ip;\n"
                        "    const parsedIP = ipaddr.parse(clientIP);\n\n"
                        "    return this.allowedIPs.some(range => {\n"
                        "      const [network, bits] = range.split('/');\n"
                        "      const parsedRange = ipaddr.parse(network);\n"
                        "      return parsedIP.match(parsedRange, parseInt(bits));\n"
                        "    });\n"
                        "  }\n"
                        "}\n\n"
                        "// Apply to controller\n"
                        "@Controller('admin')\n"
                        "@UseGuards(IPFilterGuard)\n"
                        "export class AdminController {\n"
                        "  @Get('dashboard')\n"
                        "  getDashboard() {\n"
                        "    return { message: 'Admin dashboard' };\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: IP Filtering with ipaddr.js (https://www.npmjs.com/package/ipaddr.js)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-03 compliance.
        
        Detects:
        - Virtual Networks without Network Security Groups
        - Subnets allowing all inbound traffic
        - Missing service endpoints
        - No traffic flow restrictions
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Subnet without NSG (HIGH)
        subnet_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Network/virtualNetworks.*subnets")
        
        if subnet_match:
            line_num = subnet_match['line_num']
            # Check if NSG is configured
            subnet_end = min(len(lines), line_num + 20)
            subnet_lines = lines[line_num:subnet_end]
            
            has_nsg = any(re.search(r'networkSecurityGroup|nsgId', line, re.IGNORECASE) 
                         for line in subnet_lines)
            
            if not has_nsg:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Subnet Without Network Security Group",
                    description=(
                        "Subnet configured without Network Security Group (NSG). "
                        "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                        "every subnet must have an NSG to filter and restrict network traffic "
                        "based on least privilege principles."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Attach NSG to all subnets:\n"
                        "// Network Security Group\n"
                        "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {\n"
                        "  name: 'app-nsg'\n"
                        "  location: resourceGroup().location\n"
                        "  properties: {\n"
                        "    securityRules: [\n"
                        "      {\n"
                        "        name: 'AllowHTTPS'\n"
                        "        properties: {\n"
                        "          protocol: 'Tcp'\n"
                        "          sourcePortRange: '*'\n"
                        "          destinationPortRange: '443'\n"
                        "          sourceAddressPrefix: 'Internet'\n"
                        "          destinationAddressPrefix: '*'\n"
                        "          access: 'Allow'\n"
                        "          priority: 100\n"
                        "          direction: 'Inbound'\n"
                        "        }\n"
                        "      }\n"
                        "      {\n"
                        "        name: 'DenyAllInbound'\n"
                        "        properties: {\n"
                        "          protocol: '*'\n"
                        "          sourcePortRange: '*'\n"
                        "          destinationPortRange: '*'\n"
                        "          sourceAddressPrefix: '*'\n"
                        "          destinationAddressPrefix: '*'\n"
                        "          access: 'Deny'\n"
                        "          priority: 4096\n"
                        "          direction: 'Inbound'\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "// Virtual Network with subnet\n"
                        "resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {\n"
                        "  name: 'app-vnet'\n"
                        "  location: resourceGroup().location\n"
                        "  properties: {\n"
                        "    addressSpace: {\n"
                        "      addressPrefixes: [\n"
                        "        '10.0.0.0/16'\n"
                        "      ]\n"
                        "    }\n"
                        "    subnets: [\n"
                        "      {\n"
                        "        name: 'app-subnet'\n"
                        "        properties: {\n"
                        "          addressPrefix: '10.0.1.0/24'\n"
                        "          networkSecurityGroup: {\n"
                        "            id: nsg.id  // Attach NSG to subnet\n"
                        "          }\n"
                        "          serviceEndpoints: [\n"
                        "            {\n"
                        "              service: 'Microsoft.Storage'\n"
                        "            }\n"
                        "            {\n"
                        "              service: 'Microsoft.Sql'\n"
                        "            }\n"
                        "          ]\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure NSG (https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: NSG rule allowing all traffic (HIGH)
        nsg_rule_match = self._find_line(lines, r"securityRules.*sourceAddressPrefix.*\*.*destinationPortRange.*\*.*access.*Allow")
        
        if nsg_rule_match:
            line_num = nsg_rule_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="NSG Rule Allowing All Traffic",
                description=(
                    "Network Security Group rule allowing traffic from any source to any destination port. "
                    "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                    "NSG rules must follow least privilege and only allow necessary traffic."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=5),
                remediation=(
                    "Configure NSG rules with specific source/destination restrictions:\n"
                    "resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {\n"
                    "  name: 'restrictive-nsg'\n"
                    "  location: resourceGroup().location\n"
                    "  properties: {\n"
                    "    securityRules: [\n"
                    "      {\n"
                    "        name: 'AllowHTTPSFromSpecificIP'\n"
                    "        properties: {\n"
                    "          protocol: 'Tcp'\n"
                    "          sourcePortRange: '*'\n"
                    "          destinationPortRange: '443'\n"
                    "          sourceAddressPrefix: '203.0.113.0/24'  // Specific IP range\n"
                    "          destinationAddressPrefix: '*'\n"
                    "          access: 'Allow'\n"
                    "          priority: 100\n"
                    "          direction: 'Inbound'\n"
                    "        }\n"
                    "      }\n"
                    "      {\n"
                    "        name: 'AllowManagementFromBastion'\n"
                    "        properties: {\n"
                    "          protocol: 'Tcp'\n"
                    "          sourcePortRange: '*'\n"
                    "          destinationPortRanges: ['22', '3389']  // Specific ports\n"
                    "          sourceAddressPrefix: 'VirtualNetwork'  // From VNet only\n"
                    "          destinationAddressPrefix: '*'\n"
                    "          access: 'Allow'\n"
                    "          priority: 200\n"
                    "          direction: 'Inbound'\n"
                    "        }\n"
                    "      }\n"
                    "      {\n"
                    "        name: 'DenyAllInbound'\n"
                    "        properties: {\n"
                    "          protocol: '*'\n"
                    "          sourcePortRange: '*'\n"
                    "          destinationPortRange: '*'\n"
                    "          sourceAddressPrefix: '*'\n"
                    "          destinationAddressPrefix: '*'\n"
                    "          access: 'Deny'\n"
                    "          priority: 4096\n"
                    "          direction: 'Inbound'\n"
                    "        }\n"
                    "      }\n"
                    "    ]\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure NSG Rules (https://learn.microsoft.com/azure/virtual-network/network-security-group-how-it-works)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-03 compliance.
        
        Detects:
        - Subnets without Network Security Groups
        - NSG rules allowing all traffic
        - Missing service endpoints
        - No traffic flow restrictions
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Subnet without NSG association (HIGH)
        subnet_match = self._find_line(lines, r'resource\s+"azurerm_subnet"')
        
        if subnet_match:
            line_num = subnet_match['line_num']
            # Check if NSG association exists
            has_nsg_association = any(re.search(r'resource.*azurerm_subnet_network_security_group_association', line) 
                                     for line in lines)
            
            if not has_nsg_association:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Subnet Without Network Security Group",
                    description=(
                        "Subnet configured without Network Security Group (NSG) association. "
                        "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                        "every subnet must have an NSG to filter and restrict network traffic "
                        "based on least privilege principles."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Associate NSG with subnets:\n"
                        "# Network Security Group\n"
                        "resource \"azurerm_network_security_group\" \"app_nsg\" {\n"
                        "  name                = \"app-nsg\"\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n\n"
                        "  security_rule {\n"
                        "    name                       = \"AllowHTTPS\"\n"
                        "    priority                   = 100\n"
                        "    direction                  = \"Inbound\"\n"
                        "    access                     = \"Allow\"\n"
                        "    protocol                   = \"Tcp\"\n"
                        "    source_port_range          = \"*\"\n"
                        "    destination_port_range     = \"443\"\n"
                        "    source_address_prefix      = \"Internet\"\n"
                        "    destination_address_prefix = \"*\"\n"
                        "  }\n\n"
                        "  security_rule {\n"
                        "    name                       = \"DenyAllInbound\"\n"
                        "    priority                   = 4096\n"
                        "    direction                  = \"Inbound\"\n"
                        "    access                     = \"Deny\"\n"
                        "    protocol                   = \"*\"\n"
                        "    source_port_range          = \"*\"\n"
                        "    destination_port_range     = \"*\"\n"
                        "    source_address_prefix      = \"*\"\n"
                        "    destination_address_prefix = \"*\"\n"
                        "  }\n"
                        "}\n\n"
                        "# Subnet\n"
                        "resource \"azurerm_subnet\" \"app_subnet\" {\n"
                        "  name                 = \"app-subnet\"\n"
                        "  resource_group_name  = azurerm_resource_group.example.name\n"
                        "  virtual_network_name = azurerm_virtual_network.example.name\n"
                        "  address_prefixes     = [\"10.0.1.0/24\"]\n\n"
                        "  service_endpoints = [\n"
                        "    \"Microsoft.Storage\",\n"
                        "    \"Microsoft.Sql\"\n"
                        "  ]\n"
                        "}\n\n"
                        "# NSG Association\n"
                        "resource \"azurerm_subnet_network_security_group_association\" \"app_nsg_assoc\" {\n"
                        "  subnet_id                 = azurerm_subnet.app_subnet.id\n"
                        "  network_security_group_id = azurerm_network_security_group.app_nsg.id\n"
                        "}\n\n"
                        "Ref: azurerm_subnet_network_security_group_association (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet_network_security_group_association)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: NSG rule allowing all traffic (HIGH)
        nsg_rule_match = self._find_line(lines, r'security_rule\s*{.*source_address_prefix\s*=\s*"?\*"?.*destination_port_range\s*=\s*"?\*"?.*access\s*=\s*"?Allow"?')
        
        if nsg_rule_match:
            line_num = nsg_rule_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="NSG Rule Allowing All Traffic",
                description=(
                    "Network Security Group rule allowing traffic from any source to any destination port. "
                    "KSI-CNA-03 requires using logical networking capabilities to enforce traffic flow controls (SC-7) - "
                    "NSG rules must follow least privilege and only allow necessary traffic."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=5),
                remediation=(
                    "Configure NSG rules with specific source/destination restrictions:\n"
                    "resource \"azurerm_network_security_group\" \"restrictive_nsg\" {\n"
                    "  name                = \"restrictive-nsg\"\n"
                    "  location            = azurerm_resource_group.example.location\n"
                    "  resource_group_name = azurerm_resource_group.example.name\n\n"
                    "  # Allow HTTPS from specific IP range\n"
                    "  security_rule {\n"
                    "    name                       = \"AllowHTTPSFromSpecificIP\"\n"
                    "    priority                   = 100\n"
                    "    direction                  = \"Inbound\"\n"
                    "    access                     = \"Allow\"\n"
                    "    protocol                   = \"Tcp\"\n"
                    "    source_port_range          = \"*\"\n"
                    "    destination_port_range     = \"443\"\n"
                    "    source_address_prefix      = \"203.0.113.0/24\"  # Specific IP range\n"
                    "    destination_address_prefix = \"*\"\n"
                    "  }\n\n"
                    "  # Allow management from VNet only\n"
                    "  security_rule {\n"
                    "    name                       = \"AllowManagementFromBastion\"\n"
                    "    priority                   = 200\n"
                    "    direction                  = \"Inbound\"\n"
                    "    access                     = \"Allow\"\n"
                    "    protocol                   = \"Tcp\"\n"
                    "    source_port_range          = \"*\"\n"
                    "    destination_port_ranges    = [\"22\", \"3389\"]  # Specific ports\n"
                    "    source_address_prefix      = \"VirtualNetwork\"  # From VNet only\n"
                    "    destination_address_prefix = \"*\"\n"
                    "  }\n\n"
                    "  # Explicit deny all other inbound\n"
                    "  security_rule {\n"
                    "    name                       = \"DenyAllInbound\"\n"
                    "    priority                   = 4096\n"
                    "    direction                  = \"Inbound\"\n"
                    "    access                     = \"Deny\"\n"
                    "    protocol                   = \"*\"\n"
                    "    source_port_range          = \"*\"\n"
                    "    destination_port_range     = \"*\"\n"
                    "    source_address_prefix      = \"*\"\n"
                    "    destination_address_prefix = \"*\"\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: azurerm_network_security_group (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_group)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-03 compliance.
        
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
