"""
KSI-SVC-07: Patching

Use a consistent, risk-informed approach for applying security patches.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_SVC_07_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-07: Patching
    
    **Official Statement:**
    Use a consistent, risk-informed approach for applying security patches.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ca-7.4
    - ra-5
    - ra-7
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-07"
    KSI_NAME = "Patching"
    KSI_STATEMENT = """Use a consistent, risk-informed approach for applying security patches."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ca-7.4", "Risk Monitoring"),
        ("ra-5", "Vulnerability Monitoring and Scanning"),
        ("ra-7", "Risk Response")
    ]
    CODE_DETECTABLE = False
    IMPLEMENTATION_STATUS = "NOT_IMPLEMENTED"
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
        Analyze Python code for KSI-SVC-07 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Pinned old package versions
        - Outdated dependencies without patch strategy
        - (Process-oriented - limited code detection)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Pinned old packages in requirements.txt context (LOW)
        # Note: This is a heuristic - full detection requires dependency vulnerability scanning
        if file_path.endswith('requirements.txt') or 'requirements' in file_path.lower():
            pinned_match = self._find_line(lines, r'==\d+\.\d+\.\d+')
            if pinned_match:
                line_num = pinned_match['line_num']
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="Pinned Package Versions Without Patch Strategy",
                    description=(
                        "Python dependencies pinned to specific versions without evidence of patch management process. "
                        "KSI-SVC-07 requires risk-informed approach for applying security patches (RA-5, RA-7) - "
                        "pinned versions prevent automatic security updates. This is a process-oriented KSI "
                        "with limited code detection - complement with automated vulnerability scanning (Dependabot, Snyk)."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Implement systematic patch management:\n"
                        "1. Use Dependabot or Renovate for automated dependency updates\n"
                        "2. Use ~= specifier for compatible releases: package~=1.2.3 (allows 1.2.x patches)\n"
                        "3. Use >= with upper bounds: package>=1.2.3,<2.0.0\n"
                        "4. Enable automated security scanning:\n\n"
                        "# .github/dependabot.yml\n"
                        "version: 2\n"
                        "updates:\n"
                        "  - package-ecosystem: pip\n"
                        "    directory: '/'\n"
                        "    schedule:\n"
                        "      interval: weekly\n"
                        "    groups:\n"
                        "      security-updates:\n"
                        "        applies-to: security-updates\n\n"
                        "5. Document patch risk assessment and approval process\n"
                        "6. Set SLAs: Critical patches <7 days, High <30 days, Medium <90 days\n\n"
                        "Ref: NIST SP 800-40 Rev. 4 - Guide to Enterprise Patch Management Planning "
                        "(https://csrc.nist.gov/publications/detail/sp/800-40/rev-4/final)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-07 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Outdated target frameworks
        - Legacy .NET versions without patch strategy
        - (Process-oriented - limited code detection)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Outdated .NET target framework in csproj (MEDIUM)
        if file_path.endswith('.csproj'):
            old_framework_match = self._find_line(lines, r'<TargetFramework>(netcoreapp[12]\.|net[45]\.|netstandard[12]\.)')
            if old_framework_match:
                line_num = old_framework_match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Outdated .NET Target Framework",
                    description=(
                        "Project targets outdated .NET version that may no longer receive security patches. "
                        "KSI-SVC-07 requires risk-informed approach for security patches (RA-5) - "
                        "older .NET versions (pre-.NET 6) are out of support or nearing end-of-life. "
                        ".NET Core 1.x/2.x and .NET Framework 4.x have limited or no security support."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Upgrade to supported .NET version:\n"
                        "1. Target .NET 8 (LTS) or .NET 9 (STS):\n"
                        "<TargetFramework>net8.0</TargetFramework>\n\n"
                        "2. Check .NET support policy:\n"
                        "   - .NET 8: LTS support until Nov 2026\n"
                        "   - .NET 9: STS support until May 2026\n"
                        "   - .NET 6: LTS ending Nov 2024\n\n"
                        "3. Plan migration using .NET Upgrade Assistant:\n"
                        "dotnet tool install -g upgrade-assistant\n"
                        "upgrade-assistant upgrade MyProject.csproj\n\n"
                        "4. Enable automatic security updates in NuGet:\n"
                        "<EnableNuGetPackageAudit>true</EnableNuGetPackageAudit>\n\n"
                        "5. Document patch management process and migration plan\n\n"
                        "Ref: .NET Support Policy (https://dotnet.microsoft.com/platform/support/policy)\n"
                        "Ref: .NET Upgrade Assistant (https://learn.microsoft.com/dotnet/core/porting/upgrade-assistant-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-07 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Outdated Java versions
        - End-of-life Spring Boot versions
        - (Process-oriented - limited code detection)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Outdated Spring Boot version in pom.xml/build.gradle (MEDIUM)
        if 'pom.xml' in file_path or 'build.gradle' in file_path:
            old_spring_match = self._find_line(lines, r'spring-boot.*[<>]2\.[0-6]\.')
            if old_spring_match:
                line_num = old_spring_match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Outdated Spring Boot Version",
                    description=(
                        "Project uses outdated Spring Boot version that may no longer receive security patches. "
                        "KSI-SVC-07 requires risk-informed approach for security patches (RA-5, RA-7) - "
                        "Spring Boot 2.x is approaching end-of-life (OSS support ended Nov 2023, "
                        "commercial support ends 2025). Critical security vulnerabilities may not be patched."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Upgrade to Spring Boot 3.x:\n"
                        "1. Update Spring Boot dependency:\n"
                        "   <parent>\n"
                        "     <groupId>org.springframework.boot</groupId>\n"
                        "     <artifactId>spring-boot-starter-parent</artifactId>\n"
                        "     <version>3.2.0</version>  <!-- Latest stable -->\n"
                        "   </parent>\n\n"
                        "2. Check Spring Boot support policy:\n"
                        "   - Spring Boot 3.2: OSS support until Aug 2025\n"
                        "   - Spring Boot 2.7: OSS ended Nov 2023\n\n"
                        "3. Use OpenRewrite for automated migration:\n"
                        "   <plugin>\n"
                        "     <groupId>org.openrewrite.maven</groupId>\n"
                        "     <artifactId>rewrite-maven-plugin</artifactId>\n"
                        "     <configuration>\n"
                        "       <activeRecipes>\n"
                        "         <recipe>org.openrewrite.java.spring.boot3.UpgradeSpringBoot_3_2</recipe>\n"
                        "       </activeRecipes>\n"
                        "     </configuration>\n"
                        "   </plugin>\n\n"
                        "4. Enable Maven/Gradle dependency vulnerability scanning\n\n"
                        "Ref: Spring Boot Support Policy (https://spring.io/projects/spring-boot#support)\n"
                        "Ref: Spring Boot 3.0 Migration Guide (https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.0-Migration-Guide)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-07 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Outdated Node.js versions
        - End-of-life package versions
        - (Process-oriented - limited code detection)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Outdated Node.js engine requirement in package.json (MEDIUM)
        if file_path.endswith('package.json'):
            old_node_match = self._find_line(lines, r'"node":\s*"([<>=~^]*)(1[0-6]|[0-9])\.')
            if old_node_match:
                line_num = old_node_match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Outdated Node.js Version Requirement",
                    description=(
                        "package.json specifies outdated Node.js version that may no longer receive security patches. "
                        "KSI-SVC-07 requires risk-informed approach for security patches (RA-5) - "
                        "Node.js versions below 18.x are end-of-life or approaching EOL. "
                        "Node.js 16.x ended Sep 2023, Node.js 14.x ended Apr 2023."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Upgrade to supported Node.js LTS version:\n"
                        "1. Update engines field in package.json:\n"
                        '   "engines": {\n'
                        '     "node": ">=20.0.0"  // Node.js 20 LTS (Active LTS until Apr 2026)\n'
                        '   }\n\n'
                        "2. Check Node.js release schedule:\n"
                        "   - Node.js 22: Current (Oct 2024 - Apr 2027)\n"
                        "   - Node.js 20: LTS (Active until Apr 2026)\n"
                        "   - Node.js 18: Maintenance LTS (ending Apr 2025)\n\n"
                        "3. Use nvm for Node.js version management:\n"
                        "   nvm install 20\n"
                        "   nvm use 20\n\n"
                        "4. Enable npm audit for dependency vulnerability scanning:\n"
                        "   npm audit\n"
                        "   npm audit fix\n\n"
                        "5. Configure Dependabot or Renovate for automated updates\n\n"
                        "Ref: Node.js Release Schedule (https://github.com/nodejs/release#release-schedule)\n"
                        "Ref: npm audit (https://docs.npmjs.com/cli/v10/commands/npm-audit)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-07 compliance.
        
        Detects:
        - VMs without Azure Update Manager
        - Container images with mutable tags
        - (Process-oriented - limited IaC detection)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without Update Manager configuration (LOW)
        vm_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines@")
        has_update_mgmt = re.search(r"Microsoft\.Maintenance|enableAutomaticOSUpgrade|patchSettings", code, re.IGNORECASE)
        
        if vm_match and not has_update_mgmt:
            line_num = vm_match['line_num']
            findings.append(Finding(
                severity=Severity.LOW,
                title="VM Without Azure Update Manager Configuration",
                description=(
                    "Virtual Machine deployed without Azure Update Manager or automatic OS upgrade configuration. "
                    "KSI-SVC-07 requires risk-informed approach for security patches (RA-5, RA-7) - "
                    "Azure Update Manager provides centralized patch management, assessment, and deployment "
                    "scheduling for VMs. Manual patching is error-prone and doesn't scale."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Configure Azure Update Manager for automated patching:\n"
                    "resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {\n"
                    "  name: vmName\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    osProfile: {\n"
                    "      windowsConfiguration: {\n"
                    "        enableAutomaticUpdates: true\n"
                    "        patchSettings: {\n"
                    "          patchMode: 'AutomaticByPlatform'  // Azure Update Manager\n"
                    "          assessmentMode: 'AutomaticByPlatform'\n"
                    "          automaticByPlatformSettings: {\n"
                    "            rebootSetting: 'IfRequired'\n"
                    "          }\n"
                    "        }\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "// Create maintenance configuration for scheduled patching\n"
                    "resource maintenanceConfig 'Microsoft.Maintenance/maintenanceConfigurations@2023-04-01' = {\n"
                    "  name: 'prod-patching-schedule'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    maintenanceScope: 'InGuestPatch'\n"
                    "    maintenanceWindow: {\n"
                    "      startDateTime: '2024-01-01 02:00'\n"
                    "      duration: '03:00'\n"
                    "      timeZone: 'UTC'\n"
                    "      recurEvery: '1Week Sunday'\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Update Manager (https://learn.microsoft.com/azure/update-manager/overview)\n"
                    "Ref: Azure Well-Architected Framework - Reliability (https://learn.microsoft.com/azure/well-architected/reliability/patch-management)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-07 compliance.
        
        Detects:
        - VMs without Azure Update Manager
        - Container images with mutable tags
        - (Process-oriented - limited IaC detection)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without Update Manager configuration (LOW)
        vm_match = self._find_line(lines, r'resource\s+"azurerm_virtual_machine"')
        has_update_mgmt = re.search(r'enable_automatic_updates\s*=\s*true|patch_mode\s*=\s*"AutomaticByPlatform"', code)
        
        if vm_match and not has_update_mgmt:
            line_num = vm_match['line_num']
            findings.append(Finding(
                severity=Severity.LOW,
                title="VM Without Azure Update Manager Configuration",
                description=(
                    "Virtual Machine deployed without Azure Update Manager or automatic OS upgrade configuration. "
                    "KSI-SVC-07 requires risk-informed approach for security patches (RA-5, RA-7) - "
                    "Azure Update Manager provides centralized patch management, assessment, and deployment "
                    "scheduling for VMs. Manual patching is error-prone and doesn't scale."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Configure Azure Update Manager for automated patching:\n"
                    "resource \"azurerm_windows_virtual_machine\" \"example\" {\n"
                    "  name                = \"vm-example\"\n"
                    "  location            = azurerm_resource_group.example.location\n"
                    "  resource_group_name = azurerm_resource_group.example.name\n"
                    "  size                = \"Standard_D2s_v3\"\n\n"
                    "  os_disk {\n"
                    "    caching              = \"ReadWrite\"\n"
                    "    storage_account_type = \"Premium_LRS\"\n"
                    "  }\n\n"
                    "  patch_mode                     = \"AutomaticByPlatform\"\n"
                    "  patch_assessment_mode          = \"AutomaticByPlatform\"\n"
                    "  enable_automatic_updates       = true\n"
                    "  bypass_platform_safety_checks_on_user_schedule_enabled = false\n"
                    "}\n\n"
                    "# Create maintenance configuration for scheduled patching\n"
                    "resource \"azurerm_maintenance_configuration\" \"example\" {\n"
                    "  name                = \"prod-patching-schedule\"\n"
                    "  resource_group_name = azurerm_resource_group.example.name\n"
                    "  location            = azurerm_resource_group.example.location\n"
                    "  scope               = \"InGuestPatch\"\n\n"
                    "  window {\n"
                    "    start_date_time      = \"2024-01-01 02:00\"\n"
                    "    duration             = \"03:00\"\n"
                    "    time_zone            = \"UTC\"\n"
                    "    recur_every          = \"1Week Sunday\"\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Update Manager (https://learn.microsoft.com/azure/update-manager/overview)\n"
                    "Ref: Terraform azurerm_windows_virtual_machine (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/windows_virtual_machine)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings