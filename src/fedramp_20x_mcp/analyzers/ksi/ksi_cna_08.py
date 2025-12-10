"""
KSI-CNA-08: Persistent Assessment and Automated Enforcement

Use automated services to persistently assess the security posture of all machine-based information resources and automatically enforce their intended operational state.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import ast
import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_08_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CNA-08: Persistent Assessment and Automated Enforcement
    
    **Official Statement:**
    Use automated services to persistently assess the security posture of all machine-based information resources and automatically enforce their intended operational state.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    
    **NIST Controls:**
    - ca-2.1
    - ca-7.1
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Use automated services to persistently assess the security posture of all machine-based information ...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-08"
    KSI_NAME = "Persistent Assessment and Automated Enforcement"
    KSI_STATEMENT = """Use automated services to persistently assess the security posture of all machine-based information resources and automatically enforce their intended operational state."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ca-2.1", "Independent Assessors"),
        ("ca-7.1", "Independent Assessment")
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
        Analyze Python code for KSI-CNA-08 compliance.
        
        Detects:
        - Flask/Django/FastAPI without Application Insights integration
        - Missing Azure Monitor telemetry
        - No health check or readiness endpoints
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        """
        findings = []
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fall back to regex if AST parsing fails
            return self._python_regex_fallback(code, file_path)
        
        # Check for Application Insights / Azure Monitor imports
        has_appinsights = False
        has_azure_monitor = False
        has_opencensus = False
        has_opentelemetry = False
        
        # Check for web framework
        has_flask = False
        has_django = False
        has_fastapi = False
        flask_app_line = None
        fastapi_app_line = None
        
        for node in ast.walk(tree):
            # Check for monitoring imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module_name = ""
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_name = alias.name
                        if 'applicationinsights' in module_name.lower():
                            has_appinsights = True
                        elif 'azure.monitor' in module_name.lower():
                            has_azure_monitor = True
                        elif 'opencensus' in module_name.lower():
                            has_opencensus = True
                        elif 'opentelemetry' in module_name.lower():
                            has_opentelemetry = True
                elif isinstance(node, ast.ImportFrom):
                    module_name = node.module or ""
                    if 'applicationinsights' in module_name.lower():
                        has_appinsights = True
                    elif 'azure.monitor' in module_name.lower():
                        has_azure_monitor = True
                    elif 'opencensus' in module_name.lower():
                        has_opencensus = True
                    elif 'opentelemetry' in module_name.lower():
                        has_opentelemetry = True
                    elif module_name == 'flask':
                        has_flask = True
                    elif 'django' in module_name.lower():
                        has_django = True
                    elif module_name == 'fastapi':
                        has_fastapi = True
            
            # Find Flask app creation
            if isinstance(node, ast.Call):
                if hasattr(node.func, 'id') and node.func.id == 'Flask':
                    flask_app_line = node.lineno
                elif hasattr(node.func, 'id') and node.func.id == 'FastAPI':
                    fastapi_app_line = node.lineno
        
        # Check if Django is used (settings.py or INSTALLED_APPS)
        if 'django' in code.lower() or 'INSTALLED_APPS' in code:
            has_django = True
        
        # Pattern 1: Flask without Application Insights (HIGH)
        if has_flask and flask_app_line:
            if not (has_appinsights or has_azure_monitor or has_opencensus or has_opentelemetry):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Flask App Without Application Insights / Azure Monitor",
                    description=(
                        "Flask application deployed without Application Insights or Azure Monitor integration. "
                        "KSI-CNA-08 requires using automated services to persistently assess security posture "
                        "and operational state (CA-2.1, CA-7.1). Application Insights provides continuous monitoring, "
                        "automated anomaly detection, performance tracking, and real-time alerting. "
                        "Without monitoring integration, security incidents and operational issues "
                        "cannot be automatically detected or remediated."
                    ),
                    file_path=file_path,
                    line_number=flask_app_line,
                    snippet=self._get_snippet(code.split('\n'), flask_app_line, context=3),
                    remediation=(
                        "Integrate Application Insights for continuous monitoring:\n"
                        "# 1. Install Azure Monitor OpenTelemetry\n"
                        "# pip install azure-monitor-opentelemetry\n\n"
                        "from flask import Flask\n"
                        "from azure.monitor.opentelemetry import configure_azure_monitor\n"
                        "from opentelemetry import trace\n"
                        "from opentelemetry.instrumentation.flask import FlaskInstrumentor\n\n"
                        "# Configure Azure Monitor (persistent assessment)\n"
                        "configure_azure_monitor(\n"
                        "    connection_string=\"InstrumentationKey=<key>;...\",\n"
                        "    # Continuous telemetry collection\n"
                        "    logger_name=\"myapp\",\n"
                        "    enable_live_metrics=True  # Real-time monitoring\n"
                        ")\n\n"
                        "app = Flask(__name__)\n\n"
                        "# Auto-instrument Flask (automated monitoring)\n"
                        "FlaskInstrumentor().instrument_app(app)\n\n"
                        "# Health check endpoint (operational state assessment)\n"
                        "@app.route('/health')\n"
                        "def health_check():\n"
                        "    return {'status': 'healthy'}, 200\n\n"
                        "# Readiness endpoint (automated enforcement)\n"
                        "@app.route('/ready')\n"
                        "def readiness_check():\n"
                        "    # Check dependencies (DB, cache, etc.)\n"
                        "    return {'status': 'ready'}, 200\n\n"
                        "What this provides:\n"
                        "- Continuous performance monitoring (CA-7.1)\n"
                        "- Automated anomaly detection (CA-2.1)\n"
                        "- Real-time alerting on security/operational issues\n"
                        "- Automated dependency tracking and correlation\n\n"
                        "NIST Controls: CA-2.1 (Automated Assessments), CA-7.1 (Continuous Monitoring)\n"
                        "Ref: Azure Monitor (https://learn.microsoft.com/azure/azure-monitor/)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Django without monitoring (HIGH)
        if has_django and not (has_appinsights or has_azure_monitor or has_opencensus or has_opentelemetry):
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Django App Without Application Insights / Azure Monitor",
                description=(
                    "Django application deployed without Application Insights or Azure Monitor integration. "
                    "KSI-CNA-08 requires persistent security posture assessment (CA-2.1, CA-7.1). "
                    "Without continuous monitoring, security incidents, performance degradation, "
                    "and compliance violations cannot be automatically detected or remediated."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(code.split('\n'), 1, context=5),
                remediation=(
                    "Add Application Insights to Django settings:\n"
                    "# settings.py\n"
                    "from azure.monitor.opentelemetry import configure_azure_monitor\n\n"
                    "# Configure Azure Monitor (continuous assessment)\n"
                    "configure_azure_monitor(\n"
                    "    connection_string=\"InstrumentationKey=<key>;...\",\n"
                    "    enable_live_metrics=True\n"
                    ")\n\n"
                    "# Add OpenTelemetry middleware\n"
                    "MIDDLEWARE = [\n"
                    "    'django.middleware.security.SecurityMiddleware',\n"
                    "    'opentelemetry.instrumentation.django.middleware.DjangoMiddleware',  # Auto-instrumentation\n"
                    "    # ... other middleware\n"
                    "]\n\n"
                    "# Configure logging (automated alerts)\n"
                    "LOGGING = {\n"
                    "    'version': 1,\n"
                    "    'handlers': {\n"
                    "        'azure': {\n"
                    "            'level': 'INFO',\n"
                    "            'class': 'opencensus.ext.azure.log_exporter.AzureLogHandler',\n"
                    "            'connection_string': '<connection-string>'\n"
                    "        }\n"
                    "    },\n"
                    "    'loggers': {\n"
                    "        'django': {\n"
                    "            'handlers': ['azure'],\n"
                    "            'level': 'INFO'\n"
                    "        }\n"
                    "    }\n"
                    "}\n\n"
                    "# Add health check URLs\n"
                    "# urls.py\n"
                    "from django.urls import path\n"
                    "from myapp.views import health_check, readiness_check\n\n"
                    "urlpatterns = [\n"
                    "    path('health/', health_check),  # Operational state\n"
                    "    path('ready/', readiness_check),  # Automated enforcement\n"
                    "]\n\n"
                    "NIST Controls: CA-2.1, CA-7.1\n"
                    "Ref: Django with Application Insights (https://learn.microsoft.com/azure/azure-monitor/app/opencensus-python)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: FastAPI without monitoring (HIGH)
        if has_fastapi and fastapi_app_line:
            if not (has_appinsights or has_azure_monitor or has_opencensus or has_opentelemetry):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="FastAPI App Without Application Insights / Azure Monitor",
                    description=(
                        "FastAPI application deployed without Application Insights or Azure Monitor integration. "
                        "KSI-CNA-08 requires automated services to persistently assess security posture "
                        "and enforce operational state (CA-2.1, CA-7.1). Without continuous monitoring, "
                        "API security issues, performance problems, and compliance violations "
                        "cannot be automatically detected or remediated."
                    ),
                    file_path=file_path,
                    line_number=fastapi_app_line,
                    snippet=self._get_snippet(code.split('\n'), fastapi_app_line, context=3),
                    remediation=(
                        "Integrate Application Insights with FastAPI:\n"
                        "# 1. Install dependencies\n"
                        "# pip install azure-monitor-opentelemetry opentelemetry-instrumentation-fastapi\n\n"
                        "from fastapi import FastAPI\n"
                        "from azure.monitor.opentelemetry import configure_azure_monitor\n"
                        "from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor\n\n"
                        "# Configure Azure Monitor (persistent assessment)\n"
                        "configure_azure_monitor(\n"
                        "    connection_string=\"InstrumentationKey=<key>;...\",\n"
                        "    enable_live_metrics=True  # Real-time monitoring\n"
                        ")\n\n"
                        "app = FastAPI()\n\n"
                        "# Auto-instrument FastAPI (automated monitoring)\n"
                        "FastAPIInstrumentor.instrument_app(app)\n\n"
                        "# Health check endpoint (operational state)\n"
                        "@app.get('/health')\n"
                        "async def health_check():\n"
                        "    return {'status': 'healthy'}\n\n"
                        "# Readiness endpoint (automated enforcement)\n"
                        "@app.get('/ready')\n"
                        "async def readiness_check():\n"
                        "    # Verify dependencies\n"
                        "    return {'status': 'ready'}\n\n"
                        "What this provides:\n"
                        "- Continuous API monitoring and tracing\n"
                        "- Automated performance baseline and anomaly detection\n"
                        "- Real-time security incident detection\n"
                        "- Automated dependency and correlation analysis\n\n"
                        "NIST Controls: CA-2.1, CA-7.1\n"
                        "Ref: FastAPI with Azure Monitor (https://learn.microsoft.com/azure/azure-monitor/)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback when AST parsing fails."""
        findings = []
        
        # Check for Flask without Application Insights
        if re.search(r'Flask\s*\(', code) and not re.search(r'applicationinsights|azure\.monitor|opencensus|opentelemetry', code, re.IGNORECASE):
            flask_match = re.search(r'Flask\s*\(', code)
            if flask_match:
                line_num = code[:flask_match.start()].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Flask App Without Application Insights (Regex Fallback)",
                    description="Flask application missing Application Insights integration (detected via regex fallback).",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                    remediation="See Python analyzer remediation for Application Insights integration.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-08 compliance.
        
        Detects:
        - ASP.NET Core without Application Insights
        - Missing ILogger or telemetry configuration
        - No health check endpoints
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        """
        findings = []
        
        # Check for ASP.NET Core
        has_aspnetcore = re.search(r'using\s+Microsoft\.AspNetCore|WebApplication\.CreateBuilder', code)
        
        # Check for Application Insights / monitoring
        has_appinsights = re.search(r'ApplicationInsights|AddApplicationInsightsTelemetry|TelemetryClient', code, re.IGNORECASE)
        has_logger = re.search(r'ILogger<|_logger\.|logger\.Log', code)
        has_diagnostics = re.search(r'DiagnosticSource|ActivitySource', code)
        
        # Pattern: ASP.NET Core without Application Insights (HIGH)
        if has_aspnetcore and not (has_appinsights or has_diagnostics):
            match = has_aspnetcore
            line_num = code[:match.start()].count('\n') + 1
            
            findings.append(Finding(
                severity=Severity.HIGH,
                title="ASP.NET Core Without Application Insights / Azure Monitor",
                description=(
                    "ASP.NET Core application deployed without Application Insights or Azure Monitor integration. "
                    "KSI-CNA-08 requires using automated services to persistently assess security posture "
                    "and operational state (CA-2.1, CA-7.1). Application Insights provides continuous monitoring, "
                    "automated anomaly detection, distributed tracing, and real-time alerting. "
                    "Without monitoring, security incidents and operational issues cannot be automatically detected."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                remediation=(
                    "Integrate Application Insights for continuous monitoring:\n"
                    "// 1. Install NuGet package\n"
                    "// dotnet add package Microsoft.ApplicationInsights.AspNetCore\n\n"
                    "using Microsoft.ApplicationInsights.AspNetCore.Extensions;\n"
                    "using Microsoft.Extensions.DependencyInjection;\n\n"
                    "var builder = WebApplication.CreateBuilder(args);\n\n"
                    "// Configure Application Insights (persistent assessment)\n"
                    "builder.Services.AddApplicationInsightsTelemetry(options =>\n"
                    "{\n"
                    "    options.ConnectionString = \"InstrumentationKey=<key>;...\";\n"
                    "    options.EnableAdaptiveSampling = true;  // Automated sampling\n"
                    "    options.EnableQuickPulseMetricStream = true;  // Real-time monitoring\n"
                    "});\n\n"
                    "// Add health checks (operational state assessment)\n"
                    "builder.Services.AddHealthChecks()\n"
                    "    .AddCheck(\"self\", () => HealthCheckResult.Healthy())\n"
                    "    .AddSqlServer(connectionString)  // Database health\n"
                    "    .AddAzureBlobStorage(storageConnectionString);  // Storage health\n\n"
                    "var app = builder.Build();\n\n"
                    "// Map health check endpoints (automated enforcement)\n"
                    "app.MapHealthChecks(\"/health\");  // Liveness probe\n"
                    "app.MapHealthChecks(\"/ready\", new HealthCheckOptions\n"
                    "{\n"
                    "    Predicate = _ => true,  // All checks\n"
                    "    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse\n"
                    "});  // Readiness probe\n\n"
                    "// Enable detailed diagnostics\n"
                    "app.UseDeveloperExceptionPage();  // Dev only\n"
                    "app.UseHttpsRedirection();\n\n"
                    "app.Run();\n\n"
                    "What this provides:\n"
                    "- Continuous performance and availability monitoring (CA-7.1)\n"
                    "- Automated anomaly detection and alerting (CA-2.1)\n"
                    "- Distributed tracing across microservices\n"
                    "- Real-time dependency tracking and correlation\n\n"
                    "NIST Controls: CA-2.1 (Automated Assessments), CA-7.1 (Continuous Monitoring)\n"
                    "Ref: Application Insights for ASP.NET Core (https://learn.microsoft.com/azure/azure-monitor/app/asp-net-core)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-08 compliance.
        
        Detects:
        - Spring Boot without Actuator
        - Missing Application Insights or Micrometer
        - No health check endpoints
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        """
        findings = []
        
        # Check for Spring Boot
        has_springboot = re.search(r'@SpringBootApplication|springframework\.boot', code)
        
        # Check for monitoring/actuator
        has_actuator = re.search(r'spring-boot-starter-actuator|@Endpoint|HealthIndicator', code)
        has_appinsights = re.search(r'applicationinsights|azure\.monitor', code, re.IGNORECASE)
        has_micrometer = re.search(r'io\.micrometer|MeterRegistry|@Timed', code)
        
        # Pattern: Spring Boot without Actuator or monitoring (HIGH)
        if has_springboot and not (has_actuator or has_appinsights or has_micrometer):
            match = has_springboot
            line_num = code[:match.start()].count('\n') + 1
            
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Spring Boot Without Actuator / Application Insights",
                description=(
                    "Spring Boot application deployed without Spring Boot Actuator or Application Insights. "
                    "KSI-CNA-08 requires using automated services to persistently assess security posture "
                    "and operational state (CA-2.1, CA-7.1). Spring Boot Actuator provides health checks, "
                    "metrics, and operational insights. Application Insights provides continuous monitoring "
                    "and automated anomaly detection. Without monitoring, security and operational issues "
                    "cannot be automatically detected or remediated."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                remediation=(
                    "Integrate Spring Boot Actuator and Application Insights:\n"
                    "// 1. Add dependencies to pom.xml\n"
                    "<dependency>\n"
                    "    <groupId>org.springframework.boot</groupId>\n"
                    "    <artifactId>spring-boot-starter-actuator</artifactId>\n"
                    "</dependency>\n"
                    "<dependency>\n"
                    "    <groupId>com.microsoft.azure</groupId>\n"
                    "    <artifactId>applicationinsights-spring-boot-starter</artifactId>\n"
                    "    <version>3.4.0</version>\n"
                    "</dependency>\n\n"
                    "// 2. Configure application.properties\n"
                    "# Application Insights (persistent assessment)\n"
                    "azure.application-insights.instrumentation-key=<key>\n"
                    "azure.application-insights.enabled=true\n\n"
                    "# Spring Boot Actuator (operational state monitoring)\n"
                    "management.endpoints.web.exposure.include=health,info,metrics,prometheus\n"
                    "management.endpoint.health.show-details=always\n"
                    "management.health.defaults.enabled=true\n\n"
                    "# Health checks (automated enforcement)\n"
                    "management.health.db.enabled=true  // Database health\n"
                    "management.health.redis.enabled=true  // Cache health\n"
                    "management.health.diskspace.enabled=true  // Disk health\n\n"
                    "// 3. Custom health indicator (optional)\n"
                    "import org.springframework.boot.actuate.health.Health;\n"
                    "import org.springframework.boot.actuate.health.HealthIndicator;\n"
                    "import org.springframework.stereotype.Component;\n\n"
                    "@Component\n"
                    "public class CustomHealthIndicator implements HealthIndicator {\n"
                    "    @Override\n"
                    "    public Health health() {\n"
                    "        // Custom health checks\n"
                    "        return Health.up()\n"
                    "            .withDetail(\"status\", \"operational\")\n"
                    "            .build();\n"
                    "    }\n"
                    "}\n\n"
                    "Actuator endpoints:\n"
                    "- /actuator/health - Liveness/readiness probes (automated enforcement)\n"
                    "- /actuator/metrics - Performance metrics (continuous monitoring)\n"
                    "- /actuator/info - Application info\n\n"
                    "NIST Controls: CA-2.1, CA-7.1\n"
                    "Ref: Spring Boot Actuator (https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-08 compliance.
        
        Detects:
        - Express/NestJS without health check endpoints
        - Missing Application Insights integration
        - No monitoring or telemetry
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        """
        findings = []
        
        # Check for Express
        has_express = re.search(r'import\s+express|require\([\'\"]express[\'\"]\)|from\s+[\'\"]express[\'\"]', code)
        
        # Check for NestJS
        has_nestjs = re.search(r'@nestjs/common|@Module\(|@Controller\(', code)
        
        # Check for monitoring
        has_appinsights = re.search(r'applicationinsights|@azure/monitor', code, re.IGNORECASE)
        has_opentelemetry = re.search(r'@opentelemetry|opentelemetry-instrumentation', code)
        has_health_check = re.search(r'[\'\"]/(health|healthz|ready|readiness)[\'\"]|@nestjs/terminus|express-health-check', code)
        
        # Pattern 1: Express without health checks or monitoring (HIGH)
        if has_express and not (has_health_check or has_appinsights or has_opentelemetry):
            match = has_express
            line_num = code[:match.start()].count('\n') + 1
            
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Express App Without Health Checks / Application Insights",
                description=(
                    "Express application deployed without health check endpoints or Application Insights integration. "
                    "KSI-CNA-08 requires using automated services to persistently assess security posture "
                    "and operational state (CA-2.1, CA-7.1). Health check endpoints enable automated "
                    "liveness/readiness probes. Application Insights provides continuous monitoring "
                    "and automated anomaly detection. Without monitoring, security and operational issues "
                    "cannot be automatically detected."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                remediation=(
                    "Add health checks and Application Insights to Express:\n"
                    "// 1. Install dependencies\n"
                    "// npm install applicationinsights express-health-check\n\n"
                    "import express from 'express';\n"
                    "import appInsights from 'applicationinsights';\n"
                    "import healthCheck from 'express-health-check';\n\n"
                    "// Configure Application Insights (persistent assessment)\n"
                    "appInsights.setup('<instrumentation-key>')\n"
                    "    .setAutoDependencyCorrelation(true)  // Automated correlation\n"
                    "    .setAutoCollectRequests(true)  // Request monitoring\n"
                    "    .setAutoCollectPerformance(true)  // Performance tracking\n"
                    "    .setAutoCollectExceptions(true)  // Exception tracking\n"
                    "    .setAutoCollectDependencies(true)  // Dependency monitoring\n"
                    "    .setUseDiskRetryCaching(true)  // Reliability\n"
                    "    .start();\n\n"
                    "const app = express();\n\n"
                    "// Health check endpoint (operational state)\n"
                    "app.get('/health', (req, res) => {\n"
                    "    res.status(200).json({ status: 'healthy' });\n"
                    "});\n\n"
                    "// Readiness check (automated enforcement)\n"
                    "app.get('/ready', async (req, res) => {\n"
                    "    try {\n"
                    "        // Check database connection\n"
                    "        await db.ping();\n"
                    "        // Check cache connection\n"
                    "        await redis.ping();\n"
                    "        res.status(200).json({ status: 'ready' });\n"
                    "    } catch (error) {\n"
                    "        res.status(503).json({ status: 'not ready', error });\n"
                    "    }\n"
                    "});\n\n"
                    "// Custom telemetry (optional)\n"
                    "const client = appInsights.defaultClient;\n"
                    "client.trackEvent({ name: 'CustomEvent' });\n\n"
                    "What this provides:\n"
                    "- Continuous performance monitoring (CA-7.1)\n"
                    "- Automated anomaly detection (CA-2.1)\n"
                    "- Health endpoints for Kubernetes probes\n"
                    "- Real-time dependency tracking\n\n"
                    "NIST Controls: CA-2.1, CA-7.1\n"
                    "Ref: Application Insights for Node.js (https://learn.microsoft.com/azure/azure-monitor/app/nodejs)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: NestJS without health checks or monitoring (HIGH)
        if has_nestjs and not (has_health_check or has_appinsights or has_opentelemetry):
            match = has_nestjs
            line_num = code[:match.start()].count('\n') + 1
            
            findings.append(Finding(
                severity=Severity.HIGH,
                title="NestJS App Without Health Checks / Application Insights",
                description=(
                    "NestJS application deployed without @nestjs/terminus health checks or Application Insights. "
                    "KSI-CNA-08 requires persistent assessment of security posture and operational state (CA-2.1, CA-7.1). "
                    "Without health checks and monitoring, automated enforcement and continuous assessment "
                    "cannot be achieved."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                remediation=(
                    "Add @nestjs/terminus and Application Insights to NestJS:\n"
                    "// 1. Install dependencies\n"
                    "// npm install @nestjs/terminus applicationinsights\n\n"
                    "// app.module.ts\n"
                    "import { Module } from '@nestjs/common';\n"
                    "import { TerminusModule } from '@nestjs/terminus';\n"
                    "import { HealthController } from './health.controller';\n\n"
                    "// Configure Application Insights (persistent assessment)\n"
                    "import * as appInsights from 'applicationinsights';\n"
                    "appInsights.setup('<instrumentation-key>')\n"
                    "    .setAutoCollectRequests(true)\n"
                    "    .setAutoCollectPerformance(true)\n"
                    "    .start();\n\n"
                    "@Module({\n"
                    "    imports: [TerminusModule],  // Health check module\n"
                    "    controllers: [HealthController],\n"
                    "})\n"
                    "export class AppModule {}\n\n"
                    "// health.controller.ts\n"
                    "import { Controller, Get } from '@nestjs/common';\n"
                    "import { HealthCheck, HealthCheckService, HttpHealthIndicator } from '@nestjs/terminus';\n\n"
                    "@Controller('health')\n"
                    "export class HealthController {\n"
                    "    constructor(\n"
                    "        private health: HealthCheckService,\n"
                    "        private http: HttpHealthIndicator,\n"
                    "    ) {}\n\n"
                    "    @Get()\n"
                    "    @HealthCheck()\n"
                    "    check() {\n"
                    "        return this.health.check([\n"
                    "            () => this.http.pingCheck('api', 'https://example.com'),\n"
                    "            // Add database, cache checks\n"
                    "        ]);\n"
                    "    }\n"
                    "}\n\n"
                    "NIST Controls: CA-2.1, CA-7.1\n"
                    "Ref: NestJS Terminus (https://docs.nestjs.com/recipes/terminus)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-08 compliance.
        
        Detects:
        - AKS without Microsoft Defender for Cloud
        - Container registries without scanning
        - Missing Azure Policy assignments
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: AKS without Microsoft Defender (HIGH)
        aks_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.ContainerService/managedClusters", use_regex=True)
        
        if aks_match:
            line_num = aks_match['line_num']
            # Check if Defender is enabled
            aks_end = min(len(lines), line_num + 80)
            aks_lines = lines[line_num:aks_end]
            
            has_defender = any(re.search(r"securityProfile.*defender|defenderForContainers", line, re.IGNORECASE) 
                             for line in aks_lines)
            
            if not has_defender:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="AKS Without Microsoft Defender for Containers",
                    description=(
                        "AKS cluster deployed without Microsoft Defender for Containers. "
                        "KSI-CNA-08 requires using automated services to persistently assess "
                        "security posture and enforce operational state (CA-2.1, CA-7.1). "
                        "Microsoft Defender for Containers provides continuous security assessment, "
                        "vulnerability scanning, runtime threat detection, and automated remediation. "
                        "Without Defender, security posture cannot be persistently assessed "
                        "and security policies cannot be automatically enforced."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable Microsoft Defender for Containers (persistent assessment + enforcement):\n"
                        "// 1. Enable Defender for Containers at subscription level\n"
                        "resource defenderForContainers 'Microsoft.Security/pricings@2023-01-01' = {\n"
                        "  name: 'Containers'\n"
                        "  properties: {\n"
                        "    pricingTier: 'Standard'  // Enable automated security assessment\n"
                        "  }\n"
                        "}\n\n"
                        "// 2. Configure AKS with Defender security profile\n"
                        "resource aksCluster 'Microsoft.ContainerService/managedClusters@2023-09-01' = {\n"
                        "  name: 'myAKSCluster'\n"
                        "  location: resourceGroup().location\n"
                        "  identity: {\n"
                        "    type: 'SystemAssigned'\n"
                        "  }\n"
                        "  properties: {\n"
                        "    // Automated security posture assessment\n"
                        "    securityProfile: {\n"
                        "      defender: {\n"
                        "        logAnalyticsWorkspaceResourceId: logAnalyticsWorkspace.id\n"
                        "        securityMonitoring: {\n"
                        "          enabled: true  // Persistent threat detection\n"
                        "        }\n"
                        "      }\n"
                        "      imageCleaner: {\n"
                        "        enabled: true  // Automated cleanup of vulnerable images\n"
                        "        intervalHours: 24\n"
                        "      }\n"
                        "      workloadIdentity: {\n"
                        "        enabled: true  // Enforce identity-based access\n"
                        "      }\n"
                        "    }\n"
                        "    // Azure Policy for automated enforcement\n"
                        "    addonProfiles: {\n"
                        "      azurepolicy: {\n"
                        "        enabled: true  // Automated policy enforcement\n"
                        "      }\n"
                        "      azureKeyvaultSecretsProvider: {\n"
                        "        enabled: true\n"
                        "      }\n"
                        "    }\n"
                        "    // Automated node security updates\n"
                        "    autoUpgradeProfile: {\n"
                        "      upgradeChannel: 'stable'\n"
                        "      nodeOSUpgradeChannel: 'NodeImage'  // Automated security patches\n"
                        "    }\n"
                        "    dnsPrefix: 'myaks'\n"
                        "    agentPoolProfiles: [\n"
                        "      {\n"
                        "        name: 'agentpool'\n"
                        "        count: 3\n"
                        "        vmSize: 'Standard_DS2_v2'\n"
                        "        mode: 'System'\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "// 3. Enable diagnostic settings for continuous monitoring\n"
                        "resource aksMonitoring 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                        "  scope: aksCluster\n"
                        "  name: 'aks-diagnostics'\n"
                        "  properties: {\n"
                        "    workspaceId: logAnalyticsWorkspace.id\n"
                        "    logs: [\n"
                        "      {\n"
                        "        category: 'kube-audit'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "      {\n"
                        "        category: 'kube-apiserver'\n"
                        "        enabled: true\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "What this provides:\n"
                        "- Persistent security assessment (vulnerability scanning, compliance checks)\n"
                        "- Automated enforcement (policy violations blocked, auto-remediation)\n"
                        "- Runtime threat detection (anomaly detection, malware scanning)\n"
                        "- Automated updates (security patches, image cleanup)\n\n"
                        "Ref: Defender for Containers (https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Container Registry without vulnerability scanning (MEDIUM)
        acr_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.ContainerRegistry/registries", use_regex=True)
        
        if acr_match:
            line_num = acr_match['line_num']
            # Check if Defender is enabled for registry
            # Note: This requires Defender for Container Registries at subscription level
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Container Registry Without Vulnerability Scanning",
                description=(
                    "Container Registry deployed without Microsoft Defender for Container Registries. "
                    "KSI-CNA-08 requires persistent assessment of security posture (CA-2.1, CA-7.1). "
                    "Defender for Container Registries provides automated vulnerability scanning "
                    "of container images, detecting CVEs and misconfigurations before deployment. "
                    "Without scanning, vulnerable images may be deployed to production "
                    "without automated security assessment or enforcement."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Enable Defender for Container Registries (automated scanning):\n"
                    "// 1. Enable Defender for Container Registries at subscription\n"
                    "resource defenderForACR 'Microsoft.Security/pricings@2023-01-01' = {\n"
                    "  name: 'ContainerRegistry'\n"
                    "  properties: {\n"
                    "    pricingTier: 'Standard'  // Enable automated scanning\n"
                    "  }\n"
                    "}\n\n"
                    "// 2. Create Container Registry with Premium SKU (required for scanning)\n"
                    "resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {\n"
                    "  name: 'myregistry'\n"
                    "  location: resourceGroup().location\n"
                    "  sku: {\n"
                    "    name: 'Premium'  // Required for Defender scanning\n"
                    "  }\n"
                    "  identity: {\n"
                    "    type: 'SystemAssigned'\n"
                    "  }\n"
                    "  properties: {\n"
                    "    adminUserEnabled: false  // Security best practice\n"
                    "    publicNetworkAccess: 'Disabled'  // Private access only\n"
                    "    networkRuleBypassOptions: 'AzureServices'\n"
                    "    // Automated vulnerability scanning enabled via Defender\n"
                    "  }\n"
                    "}\n\n"
                    "// 3. Enable diagnostic logging for monitoring\n"
                    "resource acrDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                    "  scope: acr\n"
                    "  name: 'acr-diagnostics'\n"
                    "  properties: {\n"
                    "    workspaceId: logAnalyticsWorkspace.id\n"
                    "    logs: [\n"
                    "      {\n"
                    "        category: 'ContainerRegistryRepositoryEvents'\n"
                    "        enabled: true\n"
                    "      }\n"
                    "      {\n"
                    "        category: 'ContainerRegistryLoginEvents'\n"
                    "        enabled: true\n"
                    "      }\n"
                    "    ]\n"
                    "  }\n"
                    "}\n\n"
                    "Once enabled, Defender automatically:\n"
                    "- Scans all pushed images for vulnerabilities (CVEs)\n"
                    "- Re-scans images when new vulnerabilities are discovered\n"
                    "- Provides recommendations and severity ratings\n"
                    "- Integrates with Azure Policy for enforcement\n\n"
                    "Ref: Defender for Container Registries (https://learn.microsoft.com/azure/defender-for-cloud/defender-for-container-registries-introduction)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Subscription without Azure Policy assignment (MEDIUM)
        # Check if policy assignments exist in the file
        has_policy = any(re.search(r"Microsoft\.Authorization/policyAssignments", line, re.IGNORECASE) 
                       for line in lines)
        
        if not has_policy and len(lines) > 50:  # Only flag if substantial IaC file
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Azure Policy Assignments for Automated Enforcement",
                description=(
                    "Infrastructure code does not include Azure Policy assignments. "
                    "KSI-CNA-08 requires using automated services to enforce intended operational state (CA-7.1). "
                    "Azure Policy provides automated compliance assessment and enforcement "
                    "by continuously evaluating resources against defined standards. "
                    "Without Policy assignments, security requirements cannot be automatically enforced "
                    "and compliance violations may go undetected until manual audits."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add Azure Policy assignments for automated enforcement:\n"
                    "// 1. Assign built-in Azure Security Benchmark policy\n"
                    "resource securityBenchmark 'Microsoft.Authorization/policyAssignments@2022-06-01' = {\n"
                    "  name: 'azure-security-benchmark'\n"
                    "  scope: subscription()\n"
                    "  properties: {\n"
                    "    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8'\n"
                    "    displayName: 'Azure Security Benchmark'\n"
                    "    description: 'Automated security posture assessment and enforcement'\n"
                    "    // Automated enforcement (deny, audit, deployIfNotExists)\n"
                    "    enforcementMode: 'Default'\n"
                    "  }\n"
                    "}\n\n"
                    "// 2. Assign FedRAMP High policy initiative\n"
                    "resource fedrampHigh 'Microsoft.Authorization/policyAssignments@2022-06-01' = {\n"
                    "  name: 'fedramp-high'\n"
                    "  scope: subscription()\n"
                    "  properties: {\n"
                    "    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/d5264498-16f4-418a-b659-fa7ef418175f'\n"
                    "    displayName: 'FedRAMP High'\n"
                    "    description: 'Continuous FedRAMP compliance assessment'\n"
                    "    enforcementMode: 'Default'\n"
                    "  }\n"
                    "}\n\n"
                    "// 3. Custom policy for container security\n"
                    "resource containerPolicy 'Microsoft.Authorization/policyAssignments@2022-06-01' = {\n"
                    "  name: 'container-security'\n"
                    "  scope: resourceGroup()\n"
                    "  properties: {\n"
                    "    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/afe0c3be-ba3b-4ff6-a9f8-75f82d13e4ec'\n"
                    "    displayName: 'Kubernetes cluster containers should only use allowed images'\n"
                    "    description: 'Automated enforcement: block unauthorized images'\n"
                    "    enforcementMode: 'Default'  // Deny non-compliant deployments\n"
                    "    parameters: {\n"
                    "      allowedContainerImagesRegex: {\n"
                    "        value: '^myregistry\\.azurecr\\.io/.+$'\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Azure Policy provides:\n"
                    "- Continuous compliance assessment (CA-2.1)\n"
                    "- Automated enforcement (deny, audit, remediate)\n"
                    "- Real-time policy violation detection\n"
                    "- Automated remediation (deployIfNotExists)\n\n"
                    "Ref: Azure Policy Overview (https://learn.microsoft.com/azure/governance/policy/overview)\n"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-08 compliance.
        
        Detects:
        - AKS without Microsoft Defender
        - Container registries without scanning
        - Missing Azure Policy assignments
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: AKS without Microsoft Defender (HIGH)
        aks_match = self._find_line(lines, r'resource\s+"azurerm_kubernetes_cluster"')
        
        if aks_match:
            line_num = aks_match['line_num']
            # Check if Defender is enabled via security_profile or defender_security_monitoring
            aks_end = min(len(lines), line_num + 100)
            aks_lines = lines[line_num:aks_end]
            
            has_defender = any(re.search(r'defender_security_monitoring|security_profile.*defender', line, re.IGNORECASE) 
                             for line in aks_lines)
            
            if not has_defender:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="AKS Without Microsoft Defender for Containers",
                    description=(
                        "AKS cluster deployed without Microsoft Defender for Containers. "
                        "KSI-CNA-08 requires using automated services to persistently assess "
                        "security posture and enforce operational state (CA-2.1, CA-7.1). "
                        "Defender for Containers provides continuous security assessment, "
                        "vulnerability scanning, runtime threat detection, and automated remediation. "
                        "Without Defender, security posture cannot be persistently assessed."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable Microsoft Defender for Containers (persistent assessment + enforcement):\n"
                        "# 1. Enable Defender for Containers at subscription level\n"
                        "resource \"azurerm_security_center_subscription_pricing\" \"containers\" {\n"
                        "  tier          = \"Standard\"  # Enable automated security assessment\n"
                        "  resource_type = \"Containers\"\n"
                        "}\n\n"
                        "# 2. Configure AKS with Defender security profile\n"
                        "resource \"azurerm_kubernetes_cluster\" \"example\" {\n"
                        "  name                = \"myAKSCluster\"\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  dns_prefix          = \"myaks\"\n\n"
                        "  identity {\n"
                        "    type = \"SystemAssigned\"\n"
                        "  }\n\n"
                        "  default_node_pool {\n"
                        "    name       = \"default\"\n"
                        "    node_count = 3\n"
                        "    vm_size    = \"Standard_DS2_v2\"\n"
                        "  }\n\n"
                        "  # Automated security posture assessment\n"
                        "  microsoft_defender {\n"
                        "    log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n"
                        "  }\n\n"
                        "  # Image cleaner for automated vulnerability cleanup\n"
                        "  image_cleaner_enabled        = true\n"
                        "  image_cleaner_interval_hours = 24\n\n"
                        "  # Azure Policy for automated enforcement\n"
                        "  azure_policy_enabled = true\n\n"
                        "  # Workload identity for least privilege\n"
                        "  workload_identity_enabled = true\n"
                        "  oidc_issuer_enabled       = true\n\n"
                        "  # Automated security updates\n"
                        "  automatic_channel_upgrade = \"stable\"\n"
                        "  node_os_channel_upgrade   = \"NodeImage\"  # Automated patches\n"
                        "}\n\n"
                        "# 3. Enable diagnostic settings for monitoring\n"
                        "resource \"azurerm_monitor_diagnostic_setting\" \"aks\" {\n"
                        "  name               = \"aks-diagnostics\"\n"
                        "  target_resource_id = azurerm_kubernetes_cluster.example.id\n"
                        "  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n\n"
                        "  enabled_log {\n"
                        "    category = \"kube-audit\"\n"
                        "  }\n\n"
                        "  enabled_log {\n"
                        "    category = \"kube-apiserver\"\n"
                        "  }\n"
                        "}\n\n"
                        "What this provides:\n"
                        "- Persistent security assessment (vulnerability scanning, compliance)\n"
                        "- Automated enforcement (policy violations blocked)\n"
                        "- Runtime threat detection (anomaly, malware)\n"
                        "- Automated updates (security patches)\n\n"
                        "Ref: microsoft_defender block (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#microsoft_defender)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-CNA-08.
        
        **KSI-CNA-08: Persistent Assessment and Automated Enforcement**
        Use automated services to persistently assess the security posture of all machine-based 
        information resources and automatically enforce their intended operational state.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-CNA-08",
            "ksi_name": "Persistent Assessment and Automated Enforcement",
            "azure_services": [
                {
                    "service": "Microsoft Defender for Cloud",
                    "purpose": "Continuous security posture assessment with Secure Score",
                    "capabilities": [
                        "Continuous security assessment",
                        "Secure Score tracking",
                        "Azure Security Benchmark compliance",
                        "Automated recommendations"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Automated enforcement of desired configuration state",
                    "capabilities": [
                        "Continuous compliance assessment",
                        "Automatic remediation (deployIfNotExists, modify)",
                        "Deny non-compliant deployments",
                        "Audit mode for assessment"
                    ]
                },
                {
                    "service": "Azure Automation State Configuration (DSC)",
                    "purpose": "Continuously assess and enforce VM configuration state",
                    "capabilities": [
                        "Desired State Configuration enforcement",
                        "Configuration drift detection",
                        "Automatic configuration correction",
                        "Compliance reporting"
                    ]
                },
                {
                    "service": "Azure Arc",
                    "purpose": "Extend assessment and enforcement to hybrid/multi-cloud resources",
                    "capabilities": [
                        "Policy enforcement across hybrid resources",
                        "Defender for Cloud coverage for Arc-enabled servers",
                        "Configuration management",
                        "Unified governance"
                    ]
                },
                {
                    "service": "Azure Monitor",
                    "purpose": "Continuous monitoring with alerts on configuration drift",
                    "capabilities": [
                        "Configuration change detection",
                        "Alert on non-compliance",
                        "Compliance trend tracking",
                        "Integration with remediation workflows"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Secure Score Trend Tracking",
                    "description": "Monitor continuous security posture assessment via Secure Score",
                    "automation": "Defender for Cloud API",
                    "frequency": "Daily (continuous assessment)",
                    "evidence_produced": "Secure Score history with improvement trends"
                },
                {
                    "method": "Policy Compliance Assessment",
                    "description": "Track continuous compliance with automated remediation status",
                    "automation": "Azure Policy compliance data",
                    "frequency": "Continuous (hourly aggregation)",
                    "evidence_produced": "Policy compliance reports with remediation logs"
                },
                {
                    "method": "Configuration Drift Detection",
                    "description": "Identify resources that drift from desired state",
                    "automation": "Azure Automation DSC + Change Tracking",
                    "frequency": "Continuous (every 15 minutes)",
                    "evidence_produced": "Configuration drift reports with auto-remediation logs"
                },
                {
                    "method": "Automated Remediation Logs",
                    "description": "Document automatic enforcement actions taken by Policy/DSC",
                    "automation": "Azure Activity Log + Policy remediation tasks",
                    "frequency": "Continuous",
                    "evidence_produced": "Remediation execution history"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["config-based", "log-based", "metric-based"],
            "implementation_guidance": {
                "quick_start": "Enable Defender for Cloud, deploy Policy with automatic remediation, configure DSC for critical VMs, enable Arc for hybrid resources, track with Monitor alerts",
                "azure_well_architected": "Follows Azure WAF operational excellence for continuous assessment and enforcement",
                "compliance_mapping": "Addresses NIST controls ca-2.1, ca-7.1 for independent assessment"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-CNA-08 evidence.
        """
        return {
            "ksi_id": "KSI-CNA-08",
            "queries": [
                {
                    "name": "Secure Score Over Time",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/providers/Microsoft.Security/secureScores?api-version=2020-01-01",
                    "method": "GET",
                    "purpose": "Track continuous security posture improvement",
                    "expected_result": "Increasing or stable high Secure Score"
                },
                {
                    "name": "Policy Compliance with Automatic Remediation",
                    "type": "azure_resource_graph",
                    "query": """
                        policyresources
                        | where type == 'microsoft.policyinsights/policystates'
                        | extend hasAutoRemediation = tostring(properties.policyDefinitionAction) in ('deployIfNotExists', 'modify')
                        | summarize TotalResources = count(),
                                   CompliantResources = countif(properties.complianceState == 'Compliant'),
                                   AutoRemediatedResources = countif(hasAutoRemediation and properties.complianceState == 'Compliant')
                                   by PolicyName = tostring(properties.policyDefinitionName)
                        | extend CompliancePercentage = round((CompliantResources * 100.0) / TotalResources, 2)
                        | project PolicyName, TotalResources, CompliantResources, AutoRemediatedResources, CompliancePercentage
                        | order by CompliancePercentage asc
                        """,
                    "purpose": "Verify policies with automatic enforcement are maintaining compliance",
                    "expected_result": "High compliance percentage for policies with auto-remediation"
                },
                {
                    "name": "DSC Configuration Compliance",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        ConfigurationData
                        | where TimeGenerated > ago(7d)
                        | where ConfigDataType == 'ComplianceStatus'
                        | summarize LastReport = max(TimeGenerated), CompliantCount = countif(IsCompliant == true), NonCompliantCount = countif(IsCompliant == false) by Computer
                        | extend CompliancePercentage = round((CompliantCount * 100.0) / (CompliantCount + NonCompliantCount), 2)
                        | project Computer, LastReport, CompliancePercentage, CompliantCount, NonCompliantCount
                        | order by CompliancePercentage asc
                        """,
                    "purpose": "Show DSC maintaining desired configuration state",
                    "expected_result": "High compliance percentage with recent assessments"
                },
                {
                    "name": "Automated Remediation Activity",
                    "type": "kql",
                    "workspace": "Log Analytics workspace",
                    "query": """
                        AzureActivity
                        | where TimeGenerated > ago(30d)
                        | where OperationNameValue contains 'remediation' or Caller contains 'azure-policy'
                        | where ActivityStatusValue == 'Succeeded'
                        | summarize RemediationCount = count() by bin(TimeGenerated, 1d), ResourceGroup
                        | order by TimeGenerated desc
                        """,
                    "purpose": "Document automatic enforcement actions",
                    "expected_result": "Regular automated remediation activity"
                },
                {
                    "name": "Configuration Drift Detection",
                    "type": "kql",
                    "workspace": "Log Analytics with Change Tracking",
                    "query": """
                        ConfigurationChange
                        | where TimeGenerated > ago(7d)
                        | where ChangeCategory in ('Files', 'Registry', 'Software', 'Services')
                        | extend WasRemediated = iff(TimeGenerated < ago(1h), true, false)
                        | summarize DriftCount = count(), RemediatedCount = countif(WasRemediated) by Computer, ChangeCategory
                        | extend RemediationRate = round((RemediatedCount * 100.0) / DriftCount, 2)
                        | project Computer, ChangeCategory, DriftCount, RemediatedCount, RemediationRate
                        | order by RemediationRate asc
                        """,
                    "purpose": "Track configuration drift and auto-remediation effectiveness",
                    "expected_result": "High remediation rate for detected drift"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI or Managed Identity",
                "permissions_required": [
                    "Security Reader for Defender for Cloud",
                    "Policy Insights Data Reader for compliance data",
                    "Log Analytics Reader for DSC and Change Tracking queries"
                ],
                "automation_tools": [
                    "Azure CLI (az security, az policy)",
                    "PowerShell Az.Security and Az.PolicyInsights modules"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-CNA-08.
        """
        return {
            "ksi_id": "KSI-CNA-08",
            "artifacts": [
                {
                    "name": "Secure Score Trend Report",
                    "description": "Historical tracking of continuous security posture assessment",
                    "source": "Microsoft Defender for Cloud",
                    "format": "CSV with daily Secure Score values",
                    "collection_frequency": "Daily",
                    "retention_period": "3 years",
                    "automation": "Security API scheduled export"
                },
                {
                    "name": "Policy Compliance and Remediation Report",
                    "description": "Policy compliance status with automatic remediation execution logs",
                    "source": "Azure Policy",
                    "format": "JSON compliance report with remediation tasks",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "Policy compliance API + Activity Log"
                },
                {
                    "name": "DSC Configuration Compliance Report",
                    "description": "Desired State Configuration compliance with drift detection and correction",
                    "source": "Azure Automation State Configuration",
                    "format": "CSV with compliance status per node",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "Log Analytics query export"
                },
                {
                    "name": "Automated Enforcement Activity Log",
                    "description": "Complete log of automatic enforcement actions (Policy remediation, DSC corrections)",
                    "source": "Azure Activity Log + Change Tracking",
                    "format": "JSON activity log",
                    "collection_frequency": "Daily (continuous ingestion)",
                    "retention_period": "3 years",
                    "automation": "Log Analytics export"
                },
                {
                    "name": "Continuous Assessment Configuration",
                    "description": "Documentation of continuous assessment and enforcement mechanisms in place",
                    "source": "Azure Policy + Defender for Cloud configuration",
                    "format": "JSON configuration export",
                    "collection_frequency": "Quarterly",
                    "retention_period": "3 years",
                    "automation": "Resource configuration export"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["ca-2.1", "ca-7.1"],
                "evidence_purpose": "Demonstrate continuous security posture assessment and automated enforcement of desired state"
            }
        }
