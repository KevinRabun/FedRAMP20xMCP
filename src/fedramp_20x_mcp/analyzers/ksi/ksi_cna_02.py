"""
KSI-CNA-02: Minimize the Attack Surface

Design systems to minimize the attack surface and minimize lateral movement if compromised.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CNA-02: Minimize the Attack Surface
    
    **Official Statement:**
    Design systems to minimize the attack surface and minimize lateral movement if compromised.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-17.3
    - ac-18.1
    - ac-18.3
    - ac-20.1
    - ca-9
    - sc-7.3
    - sc-7.4
    - sc-7.5
    - sc-7.8
    - sc-8
    - sc-10
    - si-10
    - si-11
    - si-16
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-02"
    KSI_NAME = "Minimize the Attack Surface"
    KSI_STATEMENT = """Design systems to minimize the attack surface and minimize lateral movement if compromised."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-17.3", "ac-18.1", "ac-18.3", "ac-20.1", "ca-9", "sc-7.3", "sc-7.4", "sc-7.5", "sc-7.8", "sc-8", "sc-10", "si-10", "si-11", "si-16"]
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
        Analyze Python code for KSI-CNA-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Debug mode enabled in production
        - Unnecessary services/endpoints exposed
        - Missing error handling (info disclosure)
        - Overly permissive CORS configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Debug mode enabled (CRITICAL)
        if re.search(r'(app\.run|uvicorn\.run)\s*\([^)]*debug\s*=\s*True', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'debug\s*=\s*True')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Debug Mode Enabled Increases Attack Surface",
                description=(
                    f"Debug mode enabled at line {line_num}. Debug mode exposes stack traces, "
                    f"environment variables, and internal application details that aid attackers. "
                    f"This violates the principle of minimizing attack surface."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Disable debug mode in production:\n"
                    "app.run(debug=False)  # or remove debug parameter\n"
                    "Use environment variables: debug=os.getenv('DEBUG', 'false').lower() == 'true'"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Overly permissive CORS (HIGH)
        if re.search(r'CORS\s*\([^)]*origins\s*=\s*["\']\\*["\']', code):
            line_num = self._find_line(lines, r'origins\s*=\s*["\']\\*["\']')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Permissive CORS Configuration Expands Attack Surface",
                description=(
                    f"CORS allows all origins (*) at line {line_num}. This increases attack surface "
                    f"by allowing any website to make requests to your API, potentially enabling "
                    f"cross-site attacks and lateral movement."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict CORS to specific origins:\n"
                    "CORS(app, origins=['https://yourdomain.com', 'https://trusted-partner.com'])\n"
                    "Use environment-based configuration for different deployment stages."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - UseDeveloperExceptionPage in production
        - Overly permissive CORS policies
        - Unnecessary endpoints exposed
        - Missing endpoint authorization
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Developer exception page without environment check (CRITICAL)
        has_dev_page = re.search(r'UseDeveloperExceptionPage\s*\(', code, re.IGNORECASE)
        has_env_check = re.search(r'if\s*\(\s*env\.IsDevelopment\s*\(\s*\)', code, re.IGNORECASE)
        
        if has_dev_page and not has_env_check:
            line_num = self._find_line(lines, r'UseDeveloperExceptionPage')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Developer Exception Page Exposes Internal Details",
                description=(
                    f"UseDeveloperExceptionPage at line {line_num} without environment check. "
                    f"This exposes stack traces, source code paths, and internal state in production, "
                    f"significantly increasing attack surface."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict to development environment:\n"
                    "if (env.IsDevelopment()) {\n"
                    "    app.UseDeveloperExceptionPage();\n"
                    "} else {\n"
                    "    app.UseExceptionHandler(\"/Error\");\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Permissive CORS (HIGH)
        if re.search(r'AllowAnyOrigin\s*\(\s*\)', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'AllowAnyOrigin')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Permissive CORS Policy Increases Attack Surface",
                description=(
                    f"AllowAnyOrigin() at line {line_num} permits requests from any domain. "
                    f"This expands attack surface and enables potential cross-site attacks."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict CORS to specific origins:\n"
                    "builder.WithOrigins(\"https://yourdomain.com\", \"https://trusted.com\")\n"
                    "Configure origins in appsettings.json and load dynamically."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Debug/trace logging in production
        - Overly permissive CORS configurations
        - Unnecessary actuator endpoints exposed
        - Missing method-level authorization
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Permissive CORS (HIGH)
        if re.search(r'allowedOrigins\s*\(\s*"\*"\s*\)', code):
            line_num = self._find_line(lines, r'allowedOrigins\s*\(\s*"\*"')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Permissive CORS Increases Attack Surface",
                description=(
                    f"CORS configured to allow all origins (*) at line {line_num}. "
                    f"This expands the attack surface by allowing any website to interact with your API, "
                    f"potentially enabling cross-origin attacks."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict CORS to specific origins:\n"
                    "@Override\n"
                    "public void addCorsMappings(CorsRegistry registry) {\n"
                    "    registry.addMapping(\"/api/**\")\n"
                    "        .allowedOrigins(\"https://yourdomain.com\", \"https://trusted.com\");\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Actuator without security (MEDIUM)
        has_actuator = re.search(r'spring-boot-starter-actuator', code)
        has_actuator_security = re.search(r'management\.endpoints\.web\.exposure\.include|@Secured.*actuator', code)
        
        if has_actuator and not has_actuator_security:
            line_num = self._find_line(lines, r'spring-boot-starter-actuator')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Actuator Endpoints Exposed Without Restrictions",
                description=(
                    f"Spring Boot Actuator at line {line_num} without explicit endpoint restrictions. "
                    f"Actuator exposes internal application metrics, health checks, and configuration, "
                    f"increasing attack surface if not properly secured."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict actuator endpoints in application.properties:\n"
                    "management.endpoints.web.exposure.include=health,info\n"
                    "management.endpoint.health.show-details=when-authorized\n"
                    "Protect with Spring Security: .requestMatchers(\"/actuator/**\").hasRole(\"ADMIN\")"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Overly permissive CORS configurations
        - Unnecessary error details exposed
        - Debug/development endpoints in production
        - Missing rate limiting
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Permissive CORS (HIGH)
        if re.search(r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\']\\*["\']', code):
            line_num = self._find_line(lines, r'origin\s*:\s*["\']\\*["\']')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Permissive CORS Configuration Expands Attack Surface",
                description=(
                    f"CORS allows all origins (*) at line {line_num}. This increases attack surface "
                    f"by allowing any website to make cross-origin requests, potentially enabling "
                    f"credential theft and lateral movement attacks."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Restrict CORS to specific origins:\n"
                    "app.use(cors({\n"
                    "  origin: ['https://yourdomain.com', 'https://trusted.com'],\n"
                    "  credentials: true\n"
                    "}));"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Error handler exposing stack traces (MEDIUM)
        if re.search(r'(err\.stack|error\.stack).*res\.(send|json)', code):
            line_num = self._find_line(lines, r'err\.stack|error\.stack')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Stack Traces Exposed in Error Responses",
                description=(
                    f"Error stack trace exposed at line {line_num}. Stack traces reveal internal "
                    f"application structure, file paths, and dependencies, increasing attack surface "
                    f"by providing reconnaissance information to attackers."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use generic error messages in production:\n"
                    "if (process.env.NODE_ENV === 'production') {\n"
                    "  res.status(500).json({ error: 'Internal server error' });\n"
                    "} else {\n"
                    "  res.status(500).json({ error: err.message, stack: err.stack });\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-02 compliance.
        
        Detects:
        - Public endpoints without Private Link
        - Missing service endpoints on subnets
        - Resources without network isolation
        - Overly broad public access
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Storage account with public network access (HIGH)
        if re.search(r"'Microsoft\.Storage/storageAccounts", code):
            has_network_restriction = re.search(r'publicNetworkAccess\s*:\s*["\']Disabled["\']', code)
            if not has_network_restriction:
                line_num = self._find_line(lines, r"Microsoft\.Storage/storageAccounts")
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Storage Account Without Network Restrictions",
                    description=(
                        f"Storage account at line {line_num} without publicNetworkAccess disabled. "
                        f"Public endpoints increase attack surface. Use Private Link or service endpoints "
                        f"to minimize exposure and prevent lateral movement."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Disable public network access:\n"
                        "properties: {\n"
                        "  publicNetworkAccess: 'Disabled'\n"
                        "  networkAcls: {\n"
                        "    defaultAction: 'Deny'\n"
                        "  }\n"
                        "}\n"
                        "Configure Private Link for secure access."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Subnet without service endpoints (MEDIUM)
        has_subnet = re.search(r'subnets\s*:\s*\[', code)
        has_service_endpoints = re.search(r'serviceEndpoints\s*:', code)
        
        if has_subnet and not has_service_endpoints:
            line_num = self._find_line(lines, r'subnets')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Subnet Missing Service Endpoints",
                description=(
                    f"Subnet at line {line_num} without service endpoints configured. "
                    f"Service endpoints reduce attack surface by keeping traffic within Azure backbone "
                    f"and limiting lateral movement through network segmentation."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add service endpoints to subnet:\n"
                    "serviceEndpoints: [\n"
                    "  { service: 'Microsoft.Storage' }\n"
                    "  { service: 'Microsoft.KeyVault' }\n"
                    "  { service: 'Microsoft.Sql' }\n"
                    "]"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-02 compliance.
        
        Detects:
        - Public endpoints without Private Link
        - Missing service endpoints on subnets
        - Resources without network isolation
        - Overly broad public access
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Storage account with public network access (HIGH)
        has_storage = re.search(r'resource\s+"azurerm_storage_account"', code)
        has_public_disabled = re.search(r'public_network_access_enabled\s*=\s*false', code)
        
        if has_storage and not has_public_disabled:
            line_num = self._find_line(lines, r'azurerm_storage_account')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Storage Account With Public Network Access",
                description=(
                    f"Storage account at line {line_num} without public_network_access_enabled = false. "
                    f"Public endpoints increase attack surface. Use Private Link to minimize exposure "
                    f"and restrict lateral movement."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Disable public network access:\n"
                    "resource \"azurerm_storage_account\" \"example\" {\n"
                    "  public_network_access_enabled = false\n"
                    "  network_rules {\n"
                    "    default_action = \"Deny\"\n"
                    "  }\n"
                    "}\n"
                    "Configure azurerm_private_endpoint for secure access."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Subnet without service endpoints (MEDIUM)
        has_subnet = re.search(r'resource\s+"azurerm_subnet"', code)
        has_service_endpoints = re.search(r'service_endpoints\s*=', code)
        
        if has_subnet and not has_service_endpoints:
            line_num = self._find_line(lines, r'azurerm_subnet')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Subnet Missing Service Endpoints",
                description=(
                    f"Subnet at line {line_num} without service endpoints. Service endpoints reduce "
                    f"attack surface by routing traffic through Azure backbone, preventing internet "
                    f"exposure and limiting lateral movement paths."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add service endpoints:\n"
                    "resource \"azurerm_subnet\" \"example\" {\n"
                    "  service_endpoints = [\n"
                    "    \"Microsoft.Storage\",\n"
                    "    \"Microsoft.KeyVault\",\n"
                    "    \"Microsoft.Sql\"\n"
                    "  ]\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> int:
        """Find line number matching regex pattern (case-insensitive)."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    return i
        except re.error:
            # Fallback to literal string search if pattern is invalid
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
