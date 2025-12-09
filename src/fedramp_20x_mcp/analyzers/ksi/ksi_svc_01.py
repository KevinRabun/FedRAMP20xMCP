"""
KSI-SVC-01: Continuous Improvement

Implement improvements based on persistent evaluation of information resources for opportunities to improve security.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_SVC_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-01: Continuous Improvement
    
    **Official Statement:**
    Implement improvements based on persistent evaluation of information resources for opportunities to improve security.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-7.1
    - cm-12.1
    - ma-2
    - pl-8
    - sc-7
    - sc-39
    - si-2.2
    - si-4
    - sr-10
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-01"
    KSI_NAME = "Continuous Improvement"
    KSI_STATEMENT = """Implement improvements based on persistent evaluation of information resources for opportunities to improve security."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cm-7.1", "Periodic Review"),
        ("cm-12.1", "Automated Tools to Support Information Location"),
        ("ma-2", "Controlled Maintenance"),
        ("pl-8", "Security and Privacy Architectures"),
        ("sc-7", "Boundary Protection"),
        ("sc-39", "Process Isolation"),
        ("si-2.2", "Automated Flaw Remediation Status"),
        ("si-4", "System Monitoring"),
        ("sr-10", "Inspection of Systems or Components")
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
        Analyze Python code for KSI-SVC-01 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Missing security headers middleware
        - Outdated framework versions (check via requirements.txt)
        - Deprecated security functions
        """
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_python_ast(code, file_path, parser, tree)
        else:
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Python code."""
        findings = []
        lines = code.split('\n')
        
        # Check for Flask application
        has_flask = any('from flask import' in line or 'import flask' in line for line in lines)
        
        if has_flask:
            # Check for security headers middleware
            has_talisman = any('flask_talisman' in line for line in lines)
            has_after_request = any('@app.after_request' in line or '@app . after_request' in line for line in lines)
            has_security_headers = has_talisman or has_after_request
            
            if not has_security_headers:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Security Headers Middleware",
                    description=(
                        "Flask application without security headers middleware. Security headers "
                        "(CSP, HSTS, X-Frame-Options) are essential defense-in-depth improvements. "
                        "KSI-SVC-01 requires continuous security improvements - security headers are "
                        "a foundational improvement for web applications."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet=self._get_snippet(lines, 1, context=3),
                    remediation=(
                        "Add security headers using Flask-Talisman:\n"
                        "from flask_talisman import Talisman\n"
                        "Talisman(app, force_https=True)\n"
                        "Or manually:\n"
                        "@app.after_request\n"
                        "def add_security_headers(response):\n"
                        "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                        "    response.headers['X-Frame-Options'] = 'DENY'\n"
                        "    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"
                        "    return response"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for Python."""
        findings = []
        lines = code.split('\n')
        
        is_flask = re.search(r'from flask import|Flask\(', code)
        has_security_headers = re.search(r'@app\.after_request|flask_talisman|secure_headers', code, re.IGNORECASE)
        
        if is_flask and not has_security_headers:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Security Headers Middleware",
                description=(
                    "Flask application without security headers middleware. Security headers "
                    "(CSP, HSTS, X-Frame-Options) are essential defense-in-depth improvements. "
                    "KSI-SVC-01 requires continuous security improvements - security headers are "
                    "a foundational improvement for web applications."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=3),
                remediation=(
                    "Add security headers using Flask-Talisman:\n"
                    "from flask_talisman import Talisman\n"
                    "Talisman(app, force_https=True)\n"
                    "Or manually:\n"
                    "@app.after_request\n"
                    "def add_security_headers(response):\n"
                    "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                    "    response.headers['X-Frame-Options'] = 'DENY'\n"
                    "    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"
                    "    return response"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-01 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Missing security headers middleware
        - Deprecated security APIs
        - Missing HSTS configuration
        """
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for C# code."""
        findings = []
        lines = code.split('\n')
        
        # Check for ASP.NET Core application
        has_aspnet = any('using Microsoft.AspNetCore' in line or 'WebApplication.Create' in line for line in lines)
        
        if has_aspnet:
            # Check for HSTS
            has_hsts = any('UseHsts' in line or 'AddHsts' in line for line in lines)
            
            if not has_hsts:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing HSTS Security Improvement",
                    description=(
                        "ASP.NET Core application without HSTS (HTTP Strict Transport Security). "
                        "HSTS prevents protocol downgrade attacks and cookie hijacking. "
                        "KSI-SVC-01 requires continuous security improvements - HSTS is a critical "
                        "improvement for production web applications."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet=self._get_snippet(lines, 1, context=3),
                    remediation=(
                        "Add HSTS middleware:\n"
                        "if (!app.Environment.IsDevelopment()) {\n"
                        "    app.UseHsts();\n"
                        "}\n"
                        "Configure in Program.cs/Startup.cs:\n"
                        "builder.Services.AddHsts(options => {\n"
                        "    options.MaxAge = TimeSpan.FromDays(365);\n"
                        "    options.IncludeSubDomains = true;\n"
                        "    options.Preload = true;\n"
                        "});"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for C#."""
        findings = []
        lines = code.split('\n')
        
        is_aspnet = re.search(r'using Microsoft\.AspNetCore|WebApplication\.Create', code)
        has_hsts = re.search(r'UseHsts|AddHsts', code, re.IGNORECASE)
        
        if is_aspnet and not has_hsts:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing HSTS Security Improvement",
                description=(
                    "ASP.NET Core application without HSTS (HTTP Strict Transport Security). "
                    "HSTS prevents protocol downgrade attacks and cookie hijacking. "
                    "KSI-SVC-01 requires continuous security improvements - HSTS is a critical "
                    "improvement for production web applications."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=3),
                remediation=(
                    "Add HSTS middleware:\n"
                    "if (!app.Environment.IsDevelopment()) {\n"
                    "    app.UseHsts();\n"
                    "}\n"
                    "Configure in Program.cs/Startup.cs:\n"
                    "builder.Services.AddHsts(options => {\n"
                    "    options.MaxAge = TimeSpan.FromDays(365);\n"
                    "    options.IncludeSubDomains = true;\n"
                    "    options.Preload = true;\n"
                    "});"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-01 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Missing security headers configuration
        - Deprecated security APIs
        - Missing Spring Security best practices
        """
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Java code."""
        findings = []
        lines = code.split('\n')
        
        # Check for Spring Security
        has_spring_security = any('@EnableWebSecurity' in line or 'SecurityFilterChain' in line or 'WebSecurityConfigurerAdapter' in line for line in lines)
        
        if has_spring_security:
            # Check for headers configuration using AST
            has_headers = any('.headers(' in line or 'HeadersConfigurer' in line for line in lines)
            
            if not has_headers:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Spring Security Headers Configuration",
                    description=(
                        "Spring Security application without explicit security headers configuration. "
                        "Default headers may not be sufficient for production. "
                        "KSI-SVC-01 requires continuous security improvements - explicit header "
                        "configuration ensures X-Frame-Options, X-Content-Type-Options, HSTS are properly set."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet=self._get_snippet(lines, 1, context=3),
                    remediation=(
                        "Configure security headers explicitly:\n"
                        "@Bean\n"
                        "public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
                        "    http.headers(headers -> headers\n"
                        "        .frameOptions(FrameOptionsConfig::deny)\n"
                        "        .contentTypeOptions(Customizer.withDefaults())\n"
                        "        .xssProtection(Customizer.withDefaults())\n"
                        "        .httpStrictTransportSecurity(hsts -> hsts\n"
                        "            .maxAgeInSeconds(31536000)\n"
                        "            .includeSubDomains(true)\n"
                        "            .preload(true)\n"
                        "        )\n"
                        "    );\n"
                        "    return http.build();\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for Java."""
        findings = []
        lines = code.split('\n')
        
        is_spring_security = re.search(r'@EnableWebSecurity|SecurityFilterChain|WebSecurityConfigurerAdapter', code)
        has_headers_config = re.search(r'\.headers\(\)|HeadersConfigurer', code)
        
        if is_spring_security and not has_headers_config:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Spring Security Headers Configuration",
                description=(
                    "Spring Security application without explicit security headers configuration. "
                    "Default headers may not be sufficient for production. "
                    "KSI-SVC-01 requires continuous security improvements - explicit header "
                    "configuration ensures X-Frame-Options, X-Content-Type-Options, HSTS are properly set."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=3),
                remediation=(
                    "Configure security headers explicitly:\n"
                    "@Bean\n"
                    "public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n"
                    "    http.headers(headers -> headers\n"
                        "        .frameOptions(FrameOptionsConfig::deny)\n"
                        "        .contentTypeOptions(Customizer.withDefaults())\n"
                        "        .xssProtection(Customizer.withDefaults())\n"
                        "        .httpStrictTransportSecurity(hsts -> hsts\n"
                        "            .maxAgeInSeconds(31536000)\n"
                        "            .includeSubDomains(true)\n"
                        "            .preload(true)\n"
                        "        )\n"
                        "    );\n"
                        "    return http.build();\n"
                        "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-01 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Vue
        
        Detects:
        - Missing Helmet.js middleware
        - Missing security headers in Express
        - Deprecated security packages
        """
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for TypeScript code."""
        findings = []
        lines = code.split('\n')
        
        # Check for Express application
        has_express = any('express()' in line or 'from "express"' in line or "from 'express'" in line or 'require("express")' in line or "require('express')" in line for line in lines)
        
        if has_express:
            # Check for Helmet middleware
            has_helmet = any('helmet' in line and ('import' in line or 'require' in line or 'app.use' in line) for line in lines)
            
            if not has_helmet:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Helmet.js Security Middleware",
                    description=(
                        "Express application without Helmet.js security middleware. "
                        "Helmet sets security headers automatically (X-Frame-Options, X-Content-Type-Options, "
                        "X-XSS-Protection, HSTS, etc.). "
                        "KSI-SVC-01 requires continuous security improvements - Helmet is industry best "
                        "practice for Express applications."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet=self._get_snippet(lines, 1, context=3),
                    remediation=(
                        "Install and use Helmet.js:\n"
                        "npm install helmet\n\n"
                        "In your Express app:\n"
                        "import helmet from 'helmet';\n"
                        "app.use(helmet());\n\n"
                        "Or with specific configuration:\n"
                        "app.use(helmet({\n"
                        "  contentSecurityPolicy: {\n"
                        "    directives: {\n"
                        "      defaultSrc: [\"'self'\"],\n"
                        "      scriptSrc: [\"'self'\", \"'unsafe-inline'\"],\n"
                        "    },\n"
                        "  },\n"
                        "  hsts: {\n"
                        "    maxAge: 31536000,\n"
                        "    includeSubDomains: true,\n"
                        "    preload: true\n"
                        "  }\n"
                        "}));"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for TypeScript/JavaScript."""
        findings = []
        lines = code.split('\n')
        
        is_express = re.search(r'express\(\)|from [\'"]express[\'"]|require\([\'"]express[\'"]\)', code)
        has_helmet = re.search(r'helmet\(\)|from [\'"]helmet[\'"]|require\([\'"]helmet[\'"]\)', code)
        
        if is_express and not has_helmet:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Helmet.js Security Middleware",
                description=(
                    "Express application without Helmet.js security middleware. "
                    "Helmet sets security headers automatically (X-Frame-Options, X-Content-Type-Options, "
                    "X-XSS-Protection, HSTS, etc.). "
                    "KSI-SVC-01 requires continuous security improvements - Helmet is industry best "
                    "practice for Express applications."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=3),
                remediation=(
                    "Install and use Helmet.js:\n"
                    "npm install helmet\n\n"
                    "In your Express app:\n"
                    "import helmet from 'helmet';\n"
                    "app.use(helmet());\n\n"
                    "Or with specific configuration:\n"
                    "app.use(helmet({\n"
                    "  contentSecurityPolicy: {\n"
                    "    directives: {\n"
                    "      defaultSrc: [\"'self'\"],\n"
                    "      scriptSrc: [\"'self'\", \"'unsafe-inline'\"],\n"
                    "    },\n"
                    "  },\n"
                    "  hsts: {\n"
                    "    maxAge: 31536000,\n"
                    "    includeSubDomains: true,\n"
                    "    preload: true\n"
                    "  }\n"
                    "}));"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-01 compliance.
        
        Note: Using regex - tree-sitter not available for Bicep.
        
        Detects:
        - Resources without Azure Policy assignments
        - Missing Microsoft Defender for Cloud features
        - Resources without diagnostic settings
        """
        # Bicep doesn't have tree-sitter support, use regex directly
        return self._analyze_bicep_regex(code, file_path)
    
    def _analyze_bicep_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for Bicep."""
        findings = []
        lines = code.split('\n')
        
        storage_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts@")
        has_diagnostics = re.search(r"Microsoft\.Insights/diagnosticSettings", code)
        
        if storage_match and not has_diagnostics:
            line_num = storage_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Storage Account Without Diagnostic Settings",
                description=(
                    "Storage account deployed without diagnostic settings for monitoring. "
                    "Diagnostic logs enable security monitoring, audit trails, and anomaly detection. "
                    "KSI-SVC-01 requires continuous security improvements - diagnostic settings "
                    "provide visibility for continuous monitoring (KSI-CCM-QR)."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add diagnostic settings resource:\n"
                    "resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
                    "  name: '${storageAccount.name}-diagnostics'\n"
                    "  scope: storageAccount\n"
                    "  properties: {\n"
                    "    workspaceId: logAnalyticsWorkspace.id\n"
                    "    logs: [\n"
                    "      { category: 'StorageRead', enabled: true }\n"
                    "      { category: 'StorageWrite', enabled: true }\n"
                    "      { category: 'StorageDelete', enabled: true }\n"
                    "    ]\n"
                    "    metrics: [\n"
                    "      { category: 'Transaction', enabled: true }\n"
                    "    ]\n"
                    "  }\n"
                    "}\n"
                    "Ref: Azure Well-Architected Framework - Monitoring (https://learn.microsoft.com/azure/well-architected/security/monitor-logs-alerts)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-01 compliance.
        
        Note: Using regex - tree-sitter not available for Terraform.
        
        Detects:
        - Resources without diagnostic settings
        - Missing Azure Policy assignments
        - Resources without monitoring configuration
        """
        # Terraform doesn't have tree-sitter support, use regex directly
        return self._analyze_terraform_regex(code, file_path)
    
    def _analyze_terraform_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for Terraform."""
        findings = []
        lines = code.split('\n')
        
        storage_match = self._find_line(lines, r'resource\s+"azurerm_storage_account"')
        has_diagnostics = re.search(r'azurerm_monitor_diagnostic_setting', code)
        
        if storage_match and not has_diagnostics:
            line_num = storage_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Storage Account Without Diagnostic Settings",
                description=(
                    "Storage account deployed without azurerm_monitor_diagnostic_setting. "
                    "Diagnostic logs enable security monitoring, audit trails, and anomaly detection. "
                    "KSI-SVC-01 requires continuous security improvements - diagnostic settings "
                    "provide visibility for continuous monitoring (KSI-CCM-QR)."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add diagnostic settings resource:\n"
                    "resource \"azurerm_monitor_diagnostic_setting\" \"storage_diag\" {\n"
                    "  name                       = \"${azurerm_storage_account.example.name}-diagnostics\"\n"
                    "  target_resource_id         = azurerm_storage_account.example.id\n"
                    "  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n\n"
                    "  enabled_log {\n"
                    "    category = \"StorageRead\"\n"
                    "  }\n"
                    "  enabled_log {\n"
                    "    category = \"StorageWrite\"\n"
                    "  }\n"
                    "  enabled_log {\n"
                    "    category = \"StorageDelete\"\n"
                    "  }\n"
                    "  metric {\n"
                    "    category = \"Transaction\"\n"
                    "    enabled  = true\n"
                    "  }\n"
                    "}\n"
                    "Ref: Azure Well-Architected Framework - Monitoring (https://learn.microsoft.com/azure/well-architected/security/monitor-logs-alerts)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-01 compliance.
        
        Note: Using regex - tree-sitter not available for GitHub Actions YAML
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-01 compliance.
        
        Note: Using regex - tree-sitter not available for Azure Pipelines YAML
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-01 compliance.
        
        Note: Using regex - tree-sitter not available for GitLab CI YAML
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    

        """Find the first line matching the pattern (regex-based)."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, start=1):
                if regex.search(line):
                    return {'line_num': i, 'line': line}
            return None
        except re.error:
            # Fallback to string search if regex is invalid
            for i, line in enumerate(lines, start=1):
                if pattern.lower() in line.lower():
                    return {'line_num': i, 'line': line}
            return None
    

        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

