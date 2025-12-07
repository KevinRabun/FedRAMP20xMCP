"""
KSI-SVC-04: Configuration Automation

Manage configuration of machine-based information resources using automation.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_SVC_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-04: Configuration Automation
    
    **Official Statement:**
    Manage configuration of machine-based information resources using automation.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2.4
    - cm-2
    - cm-2.2
    - cm-2.3
    - cm-6
    - cm-7.1
    - pl-9
    - pl-10
    - sa-5
    - si-5
    - sr-10
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Manage configuration of machine-based information resources using automation....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-04"
    KSI_NAME = "Configuration Automation"
    KSI_STATEMENT = """Manage configuration of machine-based information resources using automation."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-2.4", "cm-2", "cm-2.2", "cm-2.3", "cm-6", "cm-7.1", "pl-9", "pl-10", "sa-5", "si-5", "sr-10"]
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
        Analyze Python code for KSI-SVC-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Hardcoded configuration values
        - Missing configuration management frameworks
        - Manual configuration scripts without automation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hardcoded configuration in code (MEDIUM)
        hardcoded_patterns = [
            (r'(host|server|endpoint)\s*=\s*["\'](?!.*{.*})[a-zA-Z0-9.-]+["\']', "Hardcoded hostname/endpoint"),
            (r'(port)\s*=\s*\d{2,5}(?!\s*#.*config)', "Hardcoded port number"),
            (r'(timeout|retry)\s*=\s*\d+(?!\s*#.*config)', "Hardcoded timeout/retry value")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in Application Code",
                    description=(
                        f"Configuration value hardcoded in application code instead of using configuration management. "
                        f"KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        f"environment-specific configuration and automation (CM-2, CM-6). "
                        f"This violates FedRAMP 20x configuration automation requirements."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Use environment variables or configuration files:\n"
                        f"# Option 1: Environment variables\n"
                        f"import os\n"
                        f"{desc.split()[1].lower()} = os.getenv('{desc.split()[1].upper()}', 'default_value')\n\n"
                        f"# Option 2: Configuration management (Python-dotenv, Azure App Configuration)\n"
                        f"from azure.appconfiguration import AzureAppConfigurationClient\n"
                        f"from azure.identity import DefaultAzureCredential\n\n"
                        f"client = AzureAppConfigurationClient(\n"
                        f"    base_url=os.getenv('APPCONFIGURATION_ENDPOINT'),\n"
                        f"    credential=DefaultAzureCredential()\n"
                        f")\n"
                        f"config_value = client.get_configuration_setting(key='my-config-key').value\n\n"
                        f"Ref: Azure Well-Architected Framework - Operational Excellence "
                        f"(https://learn.microsoft.com/azure/well-architected/operational-excellence/app-configuration)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Hardcoded configuration values
        - Missing IConfiguration usage
        - Manual configuration without automation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hardcoded configuration (MEDIUM)
        hardcoded_patterns = [
            (r'(string\s+\w*(Url|Endpoint|Host|Server)\w*\s*=\s*"[^{])', "Hardcoded URL/endpoint"),
            (r'(int\s+\w*(Port|Timeout|Retry)\w*\s*=\s*\d)', "Hardcoded port/timeout value"),
            (r'(new\s+Uri\s*\(\s*"http)', "Hardcoded URI in constructor")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in C# Application",
                    description=(
                        f"Configuration value hardcoded in C# code instead of using IConfiguration. "
                        f"KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        f"environment-specific configuration and automation (CM-2, CM-6). "
                        f"ASP.NET Core provides IConfiguration for centralized configuration management."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Use IConfiguration for configuration management:\n"
                        f"// In Program.cs or Startup.cs\n"
                        f"var configuration = builder.Configuration;\n\n"
                        f"// Option 1: appsettings.json\n"
                        f"string endpoint = configuration[\"ServiceEndpoint\"];\n"
                        f"int port = configuration.GetValue<int>(\"ServicePort\");\n\n"
                        f"// Option 2: Azure App Configuration\n"
                        f"builder.Configuration.AddAzureAppConfiguration(options => {{\n"
                        f"    options.Connect(Environment.GetEnvironmentVariable(\"APPCONFIGURATION_CONNECTION_STRING\"))\n"
                        f"           .ConfigureKeyVault(kv => kv.SetCredential(new DefaultAzureCredential()));\n"
                        f"}});\n\n"
                        f"Ref: ASP.NET Core Configuration (https://learn.microsoft.com/aspnet/core/fundamentals/configuration/)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Hardcoded configuration values
        - Missing @Value or @ConfigurationProperties usage
        - Manual configuration without Spring Boot automation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hardcoded configuration (MEDIUM)
        hardcoded_patterns = [
            (r'(String\s+\w*(url|endpoint|host|server)\w*\s*=\s*"http)', "Hardcoded URL/endpoint"),
            (r'(int\s+\w*(port|timeout|retry)\w*\s*=\s*\d)', "Hardcoded port/timeout value"),
            (r'(private\s+static\s+final\s+String\s+\w*(URL|ENDPOINT|HOST)\w*\s*=\s*")', "Hardcoded constant configuration")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in Java Application",
                    description=(
                        f"Configuration value hardcoded in Java code instead of using Spring Boot configuration. "
                        f"KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        f"environment-specific configuration and automation (CM-2, CM-6). "
                        f"Spring Boot provides @Value and @ConfigurationProperties for centralized configuration."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Use Spring Boot configuration management:\n"
                        f"// Option 1: @Value annotation\n"
                        f"@Value(\"${{service.endpoint}}\")\n"
                        f"private String serviceEndpoint;\n\n"
                        f"@Value(\"${{service.port}}\")\n"
                        f"private int servicePort;\n\n"
                        f"// Option 2: @ConfigurationProperties\n"
                        f"@Configuration\n"
                        f"@ConfigurationProperties(prefix = \"service\")\n"
                        f"public class ServiceConfig {{\n"
                        f"    private String endpoint;\n"
                        f"    private int port;\n"
                        f"    // getters and setters\n"
                        f"}}\n\n"
                        f"// Option 3: Azure App Configuration\n"
                        f"@Bean\n"
                        f"public ConfigurationCustomizer configurationCustomizer() {{\n"
                        f"    return builder -> builder.addAzureAppConfiguration(options ->\n"
                        f"        options.connect(System.getenv(\"APPCONFIGURATION_CONNECTION_STRING\"))\n"
                        f"    );\n"
                        f"}}\n\n"
                        f"Ref: Spring Boot Externalized Configuration (https://docs.spring.io/spring-boot/reference/features/external-config.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Hardcoded configuration values
        - Missing environment variable usage
        - Manual configuration without automation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hardcoded configuration (MEDIUM)
        hardcoded_patterns = [
            (r'(const|let|var)\s+\w*(url|endpoint|host|server)\w*\s*=\s*[\'"]http', "Hardcoded URL/endpoint"),
            (r'(const|let|var)\s+\w*(port|timeout|retry)\w*\s*=\s*\d{2,5}', "Hardcoded port/timeout value"),
            (r'(baseURL|endpoint|host):\s*[\'"]http', "Hardcoded configuration in object literal")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in TypeScript/JavaScript Application",
                    description=(
                        f"Configuration value hardcoded in application code instead of using environment variables. "
                        f"KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        f"environment-specific configuration and automation (CM-2, CM-6). "
                        f"Node.js provides process.env for centralized configuration management."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Use environment variables or configuration libraries:\n"
                        f"// Option 1: Environment variables with dotenv\n"
                        f"import 'dotenv/config';\n"
                        f"const serviceEndpoint = process.env.SERVICE_ENDPOINT || 'default-value';\n"
                        f"const servicePort = parseInt(process.env.SERVICE_PORT || '3000');\n\n"
                        f"// Option 2: Configuration library (config)\n"
                        f"import config from 'config';\n"
                        f"const serviceEndpoint = config.get<string>('service.endpoint');\n\n"
                        f"// Option 3: Azure App Configuration\n"
                        f"import {{ AppConfigurationClient }} from '@azure/app-configuration';\n"
                        f"import {{ DefaultAzureCredential }} from '@azure/identity';\n\n"
                        f"const client = new AppConfigurationClient(\n"
                        f"  process.env.APPCONFIGURATION_ENDPOINT!,\n"
                        f"  new DefaultAzureCredential()\n"
                        f");\n"
                        f"const setting = await client.getConfigurationSetting({{ key: 'my-config-key' }});\n\n"
                        f"Ref: Azure App Configuration for Node.js (https://learn.microsoft.com/azure/azure-app-configuration/quickstart-javascript)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-04 compliance.
        
        Detects:
        - Manual VM configuration without Azure Automation
        - Missing Azure App Configuration references
        - Resources without configuration management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without Azure Automation DSC (MEDIUM)
        vm_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines@")
        has_dsc = re.search(r"Microsoft\.Compute/virtualMachines/.*/extensions.*DSC", code, re.IGNORECASE)
        has_custom_script = re.search(r"Microsoft\.Compute/virtualMachines/.*/extensions.*CustomScript", code, re.IGNORECASE)
        
        if vm_match and not has_dsc and has_custom_script:
            line_num = vm_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="VM Configuration Without Azure Automation DSC",
                description=(
                    "Virtual Machine deployed with CustomScriptExtension instead of Azure Automation DSC. "
                    "KSI-SVC-04 requires automated configuration management (CM-2, CM-6) - CustomScript is "
                    "imperative and doesn't provide drift detection, compliance reporting, or idempotent configuration. "
                    "Azure Automation DSC provides declarative configuration management with version control."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Use Azure Automation DSC extension instead:\n"
                    "resource vmDscExtension 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
                    "  name: '${virtualMachine.name}/DSC'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    publisher: 'Microsoft.Powershell'\n"
                    "    type: 'DSC'\n"
                    "    typeHandlerVersion: '2.77'\n"
                    "    autoUpgradeMinorVersion: true\n"
                    "    settings: {\n"
                    "      wmfVersion: 'latest'\n"
                    "      configuration: {\n"
                    "        url: automationAccount.properties.endpoint\n"
                    "        script: 'MyConfiguration.ps1'\n"
                    "        function: 'MyConfiguration'\n"
                    "      }\n"
                    "      configurationArguments: {\n"
                    "        nodeName: virtualMachine.name\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Or use Azure Machine Configuration (Policy Guest Configuration):\n"
                    "resource guestConfigExtension 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
                    "  name: '${virtualMachine.name}/AzurePolicyforWindows'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    publisher: 'Microsoft.GuestConfiguration'\n"
                    "    type: 'ConfigurationforWindows'\n"
                    "    typeHandlerVersion: '1.0'\n"
                    "    autoUpgradeMinorVersion: true\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Automation DSC (https://learn.microsoft.com/azure/automation/automation-dsc-overview)\n"
                    "Ref: Azure Machine Configuration (https://learn.microsoft.com/azure/governance/machine-configuration/overview)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-04 compliance.
        
        Detects:
        - Manual VM configuration without Azure Automation
        - Missing Azure App Configuration integration
        - Resources without configuration management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without DSC extension (MEDIUM)
        vm_match = self._find_line(lines, r'resource\s+"azurerm_virtual_machine"')
        has_dsc = re.search(r'azurerm_virtual_machine_extension.*type\s*=\s*"DSC"', code, re.IGNORECASE)
        has_custom_script = re.search(r'azurerm_virtual_machine_extension.*type\s*=\s*"CustomScript', code, re.IGNORECASE)
        
        if vm_match and not has_dsc and has_custom_script:
            line_num = vm_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="VM Configuration Without Azure Automation DSC",
                description=(
                    "Virtual Machine deployed with CustomScriptExtension instead of Azure Automation DSC. "
                    "KSI-SVC-04 requires automated configuration management (CM-2, CM-6) - CustomScript is "
                    "imperative and doesn't provide drift detection, compliance reporting, or idempotent configuration. "
                    "Azure Automation DSC provides declarative configuration management with version control."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Use azurerm_virtual_machine_extension with DSC:\n"
                    "resource \"azurerm_virtual_machine_extension\" \"dsc\" {\n"
                    "  name                       = \"DSC\"\n"
                    "  virtual_machine_id         = azurerm_virtual_machine.example.id\n"
                    "  publisher                  = \"Microsoft.Powershell\"\n"
                    "  type                       = \"DSC\"\n"
                    "  type_handler_version       = \"2.77\"\n"
                    "  auto_upgrade_minor_version = true\n\n"
                    "  settings = jsonencode({\n"
                    "    wmfVersion = \"latest\"\n"
                    "    configuration = {\n"
                    "      url      = azurerm_automation_account.example.endpoint\n"
                    "      script   = \"MyConfiguration.ps1\"\n"
                    "      function = \"MyConfiguration\"\n"
                    "    }\n"
                    "    configurationArguments = {\n"
                    "      nodeName = azurerm_virtual_machine.example.name\n"
                    "    }\n"
                    "  })\n"
                    "}\n\n"
                    "Or use Azure Machine Configuration (Policy Guest Configuration):\n"
                    "resource \"azurerm_virtual_machine_extension\" \"guest_config\" {\n"
                    "  name                       = \"AzurePolicyforWindows\"\n"
                    "  virtual_machine_id         = azurerm_virtual_machine.example.id\n"
                    "  publisher                  = \"Microsoft.GuestConfiguration\"\n"
                    "  type                       = \"ConfigurationforWindows\"\n"
                    "  type_handler_version       = \"1.0\"\n"
                    "  auto_upgrade_minor_version = true\n"
                    "}\n\n"
                    "Ref: Azure Automation DSC (https://learn.microsoft.com/azure/automation/automation-dsc-overview)\n"
                    "Ref: Azure Machine Configuration (https://learn.microsoft.com/azure/governance/machine-configuration/overview)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> Optional[Dict[str, Any]]:
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
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
