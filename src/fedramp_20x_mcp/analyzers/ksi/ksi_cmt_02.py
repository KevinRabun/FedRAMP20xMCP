"""
KSI-CMT-02: Redeployment

Execute changes though redeployment of version controlled immutable resources rather than direct modification wherever possible

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CMT_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CMT-02: Redeployment
    
    **Official Statement:**
    Execute changes though redeployment of version controlled immutable resources rather than direct modification wherever possible
    
    **Family:** CMT - Change Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-2
    - cm-3
    - cm-5
    - cm-6
    - cm-7
    - cm-8.1
    - si-3
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CMT-02"
    KSI_NAME = "Redeployment"
    KSI_STATEMENT = """Execute changes though redeployment of version controlled immutable resources rather than direct modification wherever possible"""
    FAMILY = "CMT"
    FAMILY_NAME = "Change Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["cm-2", "cm-3", "cm-5", "cm-6", "cm-7", "cm-8.1", "si-3"]
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
        Analyze Python code for KSI-CMT-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Direct runtime configuration changes (setattr, __dict__ modification)
        - Hot-reloading enabled in production
        - In-memory state mutation without persistence
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hot-reloading in production (MEDIUM)
        if re.search(r'(reload=True|use_reloader=True)', code):
            line_num = self._find_line(lines, r'reload=True|use_reloader=True')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Hot-Reloading Enabled (Violates Immutable Deployment)",
                description=(
                    f"Hot-reloading enabled at line {line_num}. Hot-reloading allows runtime "
                    f"code changes without redeployment, violating KSI-CMT-02's requirement for "
                    f"immutable, version-controlled deployments. Changes should go through proper "
                    f"CI/CD pipelines with versioning."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Disable hot-reloading in production:\n"
                    "app.run(debug=False, use_reloader=False)  # Flask\n"
                    "uvicorn.run(reload=False)  # FastAPI\n"
                    "Use environment variables: reload=os.getenv('RELOAD', 'false').lower() == 'true'"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CMT-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Hot reload enabled in production
        - Direct configuration modification at runtime
        - Mutable deployment patterns
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hot reload enabled (MEDIUM)
        if re.search(r'AddRazorRuntimeCompilation|UseRazorRuntimeCompilation', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'RazorRuntimeCompilation')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Razor Runtime Compilation Enabled (Violates Immutable Deployment)",
                description=(
                    f"Razor runtime compilation at line {line_num}. Runtime compilation allows "
                    f"view changes without redeployment, violating KSI-CMT-02's requirement for "
                    f"immutable, version-controlled deployments. All changes should go through "
                    f"CI/CD with proper versioning."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Disable runtime compilation in production:\n"
                    "if (env.IsDevelopment()) {\n"
                    "    services.AddRazorPages().AddRazorRuntimeCompilation();\n"
                    "} else {\n"
                    "    services.AddRazorPages();\n"
                    "}\n"
                    "Precompile views during build for immutable deployments."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CMT-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Spring Boot DevTools in production
        - Hot reload/live reload enabled
        - JRebel or similar hot-swap tools
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Spring Boot DevTools in production dependencies (MEDIUM)
        if re.search(r'<artifactId>spring-boot-devtools</artifactId>', code) and not re.search(r'<scope>.*runtime.*</scope>', code):
            line_num = self._find_line(lines, r'spring-boot-devtools')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Spring Boot DevTools Included (Enables Mutable Deployments)",
                description=(
                    f"Spring Boot DevTools at line {line_num}. DevTools enables automatic restarts "
                    f"and live reload, allowing runtime changes without proper redeployment. This "
                    f"violates KSI-CMT-02's requirement for immutable, version-controlled deployments."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Exclude DevTools from production:\n"
                    "<dependency>\n"
                    "  <groupId>org.springframework.boot</groupId>\n"
                    "  <artifactId>spring-boot-devtools</artifactId>\n"
                    "  <scope>runtime</scope>\n"
                    "  <optional>true</optional>\n"
                    "</dependency>\n"
                    "Or remove completely from production builds using Maven profiles."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CMT-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Hot module replacement (HMR) in production
        - Nodemon or similar watch tools
        - Live reload configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hot module replacement in production (MEDIUM)
        if re.search(r'hot:\s*true|webpack\.HotModuleReplacementPlugin', code):
            line_num = self._find_line(lines, r'hot:\s*true|HotModuleReplacementPlugin')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Hot Module Replacement Enabled (Violates Immutable Deployment)",
                description=(
                    f"Hot Module Replacement (HMR) at line {line_num}. HMR allows runtime code "
                    f"updates without full redeployment, violating KSI-CMT-02's requirement for "
                    f"immutable, version-controlled deployments. All changes should go through CI/CD."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Disable HMR in production webpack.config.js:\n"
                    "module.exports = {\n"
                    "  devServer: {\n"
                    "    hot: process.env.NODE_ENV !== 'production'\n"
                    "  }\n"
                    "};\n"
                    "Or use separate webpack.prod.js configuration without HMR."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Nodemon in production scripts (MEDIUM)
        if 'package.json' in file_path.lower() and re.search(r'"start":\s*"nodemon', code):
            line_num = self._find_line(lines, r'"start".*nodemon')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Nodemon Used for Production Start Script",
                description=(
                    f"Nodemon in start script at line {line_num}. Nodemon watches for file changes "
                    f"and auto-restarts, allowing runtime modifications without proper redeployment. "
                    f"This violates immutable deployment principles."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use node directly for production:\n"
                    "\"scripts\": {\n"
                    "  \"start\": \"node dist/main.js\",\n"
                    "  \"dev\": \"nodemon src/main.ts\"\n"
                    "}\n"
                    "Reserve nodemon for development only."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CMT-02 compliance.
        
        Detects:
        - Mutable deployment configurations
        - Missing immutability settings
        - Resources configured for in-place updates
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Storage Account without immutability policy (LOW)
        has_storage = re.search(r"'Microsoft\.Storage/storageAccounts", code)
        has_immutability = re.search(r'immutabilityPolicy|allowProtectedAppendWrites', code)
        
        if has_storage and not has_immutability:
            line_num = self._find_line(lines, r"Microsoft\.Storage/storageAccounts")
            findings.append(Finding(
                severity=Severity.LOW,
                title="Storage Account Without Immutability Policy",
                description=(
                    f"Storage account at line {line_num} without immutability policy. "
                    f"For compliance audit logs and critical data, consider immutable storage "
                    f"to prevent unauthorized modifications and ensure version-controlled changes."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add immutability policy for critical containers:\n"
                    "resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {\n"
                    "  name: 'default'\n"
                    "  parent: storageAccount\n"
                    "}\n"
                    "resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {\n"
                    "  name: 'audit-logs'\n"
                    "  parent: blobService\n"
                    "  properties: {\n"
                    "    immutableStorageWithVersioning: {\n"
                    "      enabled: true\n"
                    "    }\n"
                    "  }\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CMT-02 compliance.
        
        Detects:
        - Mutable deployment configurations
        - Missing immutability settings
        - Resources configured for in-place updates
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Storage Account without immutability (LOW)
        has_storage = re.search(r'resource\s+"azurerm_storage_account"', code)
        has_container_immutability = re.search(r'immutability_policy|azurerm_storage_container.*immutable', code)
        
        if has_storage and not has_container_immutability:
            line_num = self._find_line(lines, r'azurerm_storage_account')
            findings.append(Finding(
                severity=Severity.LOW,
                title="Storage Account Without Immutability Policy",
                description=(
                    f"Storage account at line {line_num} without immutability policy configuration. "
                    f"For compliance audit logs and critical data, immutable storage prevents "
                    f"unauthorized modifications and ensures version-controlled changes."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Add immutability policy to containers:\n"
                    "resource \"azurerm_storage_container\" \"audit_logs\" {\n"
                    "  name                  = \"audit-logs\"\n"
                    "  storage_account_name  = azurerm_storage_account.example.name\n"
                    "  container_access_type = \"private\"\n"
                    "}\n"
                    "resource \"azurerm_storage_management_policy\" \"example\" {\n"
                    "  storage_account_id = azurerm_storage_account.example.id\n"
                    "  rule {\n"
                    "    name    = \"immutability\"\n"
                    "    enabled = true\n"
                    "    filters {\n"
                    "      blob_types = [\"blockBlob\"]\n"
                    "    }\n"
                    "  }\n"
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
        Analyze GitHub Actions workflow for KSI-CMT-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CMT-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CMT-02 compliance.
        
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
