"""
KSI-RPL-03: System Backups

Perform system backups aligned with recovery objectives.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_RPL_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-RPL-03: System Backups
    
    **Official Statement:**
    Perform system backups aligned with recovery objectives.
    
    **Family:** RPL - Recovery Planning
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-2.3
    - cp-6
    - cp-9
    - cp-10
    - cp-10.2
    - si-12
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-RPL-03"
    KSI_NAME = "System Backups"
    KSI_STATEMENT = """Perform system backups aligned with recovery objectives."""
    FAMILY = "RPL"
    FAMILY_NAME = "Recovery Planning"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["cm-2.3", "cp-6", "cp-9", "cp-10", "cp-10.2", "si-12"]
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
        Analyze Python code for KSI-RPL-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform system backups aligned with recovery objectives....
        """
        findings = []
        
        # TODO: Implement Python-specific detection logic
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-RPL-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform system backups aligned with recovery objectives....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-RPL-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform system backups aligned with recovery objectives....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-RPL-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform system backups aligned with recovery objectives....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-RPL-03 compliance.
        
        Detects:
        - Missing Azure Backup configurations
        - Missing Recovery Services Vault
        - Insufficient backup retention periods
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: No Recovery Services Vault (HIGH)
        has_vault = bool(re.search(r"Microsoft\.RecoveryServices/vaults", code, re.IGNORECASE))
        has_vm_backup = bool(re.search(r"Microsoft\.RecoveryServices/vaults/.*backupPolicies", code, re.IGNORECASE))
        
        if not has_vault and re.search(r"Microsoft\.(Compute/virtualMachines|Sql|Storage/storageAccounts)", code):
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Azure Backup Configuration",
                description=(
                    "Infrastructure defines critical resources (VMs, databases, storage) without "
                    "Azure Backup configuration. KSI-RPL-03 requires system backups aligned "
                    "with recovery objectives per NIST CP-9."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add Azure Recovery Services Vault and backup policies:\n"
                    "resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {\n"
                    "  name: 'backup-vault'\n"
                    "  location: location\n"
                    "  sku: {\n"
                    "    name: 'RS0'  // Standard\n"
                    "    tier: 'Standard'\n"
                    "  }\n"
                    "  properties: {\n"
                    "    publicNetworkAccess: 'Disabled'  // FedRAMP best practice\n"
                    "  }\n"
                    "}\n\n"
                    "resource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {\n"
                    "  parent: vault\n"
                    "  name: 'daily-backup-policy'\n"
                    "  properties: {\n"
                    "    backupManagementType: 'AzureIaasVM'\n"
                    "    schedulePolicy: {\n"
                    "      schedulePolicyType: 'SimpleSchedulePolicy'\n"
                    "      scheduleRunFrequency: 'Daily'\n"
                    "      scheduleRunTimes: ['2023-01-01T02:00:00Z']\n"
                    "    }\n"
                    "    retentionPolicy: {\n"
                    "      retentionPolicyType: 'LongTermRetentionPolicy'\n"
                    "      dailySchedule: {\n"
                    "        retentionTimes: ['2023-01-01T02:00:00Z']\n"
                    "        retentionDuration: {\n"
                    "          count: 30  // 30 days minimum for FedRAMP\n"
                    "          durationType: 'Days'\n"
                    "        }\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Backup (https://learn.microsoft.com/azure/backup/)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Short retention period (MEDIUM)
        if re.search(r"retentionDuration.*count:\s*([1-9]|[12]\d)\s*//?\s*(Days|days)", code):
            line_num = self._find_line(lines, 'retentionDuration')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Insufficient Backup Retention Period",
                description=(
                    "Backup policy has retention period less than 30 days. KSI-RPL-03 "
                    "requires backups aligned with recovery objectives, typically 30+ days "
                    "for FedRAMP compliance per CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Increase retention period to at least 30 days:\n"
                    "retentionPolicy: {\n"
                    "  dailySchedule: {\n"
                    "    retentionDuration: {\n"
                    "      count: 30  // Minimum 30 days\n"
                    "      durationType: 'Days'\n"
                    "    }\n"
                    "  }\n"
                    "  weeklySchedule: {  // Consider weekly backups\n"
                    "    retentionDuration: {\n"
                    "      count: 12  // 12 weeks\n"
                    "      durationType: 'Weeks'\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: NIST CP-9 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-RPL-03 compliance.
        
        Detects:
        - Missing backup configurations (Azure/AWS)
        - Insufficient retention periods
        - Missing geo-redundancy
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure - No Recovery Vault (HIGH)
        has_azure_vault = bool(re.search(r'azurerm_recovery_services_vault', code))
        has_azure_policy = bool(re.search(r'azurerm_backup_policy_vm', code))
        has_azure_resources = bool(re.search(r'azurerm_(virtual_machine|linux_virtual_machine|windows_virtual_machine|mssql_database|postgresql_server)', code))
        
        if has_azure_resources and not (has_azure_vault or has_azure_policy):
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Azure Backup Configuration",
                description=(
                    "Infrastructure defines Azure resources without backup configuration. "
                    "KSI-RPL-03 requires system backups aligned with recovery objectives per NIST CP-9."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add Azure Backup configuration:\n"
                    "resource \"azurerm_recovery_services_vault\" \"vault\" {\n"
                    "  name                = \"backup-vault\"\n"
                    "  location            = azurerm_resource_group.rg.location\n"
                    "  resource_group_name = azurerm_resource_group.rg.name\n"
                    "  sku                 = \"Standard\"\n"
                    "  soft_delete_enabled = true\n"
                    "}\n\n"
                    "resource \"azurerm_backup_policy_vm\" \"policy\" {\n"
                    "  name                = \"daily-backup-policy\"\n"
                    "  resource_group_name = azurerm_resource_group.rg.name\n"
                    "  recovery_vault_name = azurerm_recovery_services_vault.vault.name\n"
                    "  \n"
                    "  backup {\n"
                    "    frequency = \"Daily\"\n"
                    "    time      = \"02:00\"\n"
                    "  }\n"
                    "  \n"
                    "  retention_daily {\n"
                    "    count = 30  # Minimum 30 days for FedRAMP\n"
                    "  }\n"
                    "  \n"
                    "  retention_weekly {\n"
                    "    count    = 12\n"
                    "    weekdays = [\"Sunday\"]\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Backup (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/backup_policy_vm)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: AWS - No backup plan (HIGH)
        has_aws_plan = bool(re.search(r'aws_backup_plan', code))
        has_aws_vault = bool(re.search(r'aws_backup_vault', code))
        has_aws_resources = bool(re.search(r'aws_(instance|db_instance|rds_cluster|efs_file_system)', code))
        
        if has_aws_resources and not (has_aws_plan or has_aws_vault):
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing AWS Backup Configuration",
                description=(
                    "Infrastructure defines AWS resources without backup configuration. "
                    "KSI-RPL-03 requires system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add AWS Backup configuration:\n"
                    "resource \"aws_backup_vault\" \"vault\" {\n"
                    "  name = \"backup-vault\"\n"
                    "}\n\n"
                    "resource \"aws_backup_plan\" \"plan\" {\n"
                    "  name = \"daily-backup-plan\"\n"
                    "  \n"
                    "  rule {\n"
                    "    rule_name         = \"daily_backup_rule\"\n"
                    "    target_vault_name = aws_backup_vault.vault.name\n"
                    "    schedule          = \"cron(0 2 * * ? *)\"  # 2 AM daily\n"
                    "    \n"
                    "    lifecycle {\n"
                    "      delete_after = 30  # Minimum 30 days for FedRAMP\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: AWS Backup (https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/backup_plan)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Short retention (MEDIUM)
        if re.search(r'(retention_daily.*count\s*=\s*([1-9]|[12]\d)\b|delete_after\s*=\s*([1-9]|[12]\d)\b)', code):
            line_num = self._find_line(lines, 'retention')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Insufficient Backup Retention Period",
                description=(
                    "Backup retention period is less than 30 days. KSI-RPL-03 requires "
                    "adequate retention per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Increase retention to at least 30 days:\n"
                    "retention_daily {\n"
                    "  count = 30\n"
                    "}\n"
                    "retention_weekly {\n"
                    "  count = 12\n"
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
        Analyze GitHub Actions workflow for KSI-RPL-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-RPL-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-RPL-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
