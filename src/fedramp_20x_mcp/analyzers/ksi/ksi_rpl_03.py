"""
KSI-RPL-03: System Backups - Enhanced Analyzer

NIST Control: CP-9 (Information System Backup)
FedRAMP Requirement: Perform system backups aligned with recovery objectives

KEY ENHANCEMENTS OVER ORIGINAL:
1. **Comprehensive Backup Detection**: Azure Backup, AWS Backup, GCP backup services
2. **Retention Validation**: Checks retention periods meet FedRAMP minimums (30+ days)
3. **Geo-Redundancy Detection**: Validates backup replication across regions
4. **Encryption Validation**: Ensures backup encryption at rest/transit
5. **Application Automation**: Detects backup automation in application code
6. **CI/CD Verification**: Detects backup verification tests in pipelines
7. **Multi-Cloud Support**: Azure, AWS, GCP backup patterns

Detection Patterns:
- Bicep: Recovery Services Vault, backup policies, retention settings, geo-redundancy
- Terraform: azurerm_backup_*, aws_backup_*, google_compute_*_backup resources
- Python: Azure Backup SDK, boto3 backup operations, GCP backup client
- C#: Azure.ResourceManager.RecoveryServices, AWS SDK, GCP SDK
- TypeScript: @azure/arm-recoveryservices, AWS SDK, GCP SDK
- CI/CD: Backup verification tests, restore testing automation

CODE_DETECTABLE: True - Backup configuration in IaC and backup automation in code are detectable
IMPLEMENTATION_STATUS: IMPLEMENTED

References:
- NIST CP-9: https://csrc.nist.gov/Projects/risk-management/sp800-53-controls
- Azure Backup: https://learn.microsoft.com/azure/backup/
- AWS Backup: https://aws.amazon.com/backup/
- Azure WAF Reliability: https://learn.microsoft.com/azure/well-architected/reliability/backup-and-disaster-recovery
"""

from typing import List, Dict
import re
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_RPL_03_Analyzer(BaseKSIAnalyzer):
    """Enhanced analyzer for KSI-RPL-03: System Backups compliance."""
    
    KSI_ID = "KSI-RPL-03"
    KSI_NAME = "System Backups"
    KSI_STATEMENT = "Perform system backups aligned with recovery objectives"
    FAMILY = "RPL"
    FAMILY_NAME = "Recovery Planning"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cm-2.3", "Retention of Previous Configurations"),
        ("cp-6", "Alternate Storage Site"),
        ("cp-9", "System Backup"),
        ("cp-10", "System Recovery and Reconstitution"),
        ("cp-10.2", "Transaction Recovery"),
        ("si-12", "Information Management and Retention")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    # FedRAMP minimum retention periods (days)
    MINIMUM_RETENTION_DAYS = 30
    RECOMMENDED_WEEKLY_RETENTION_WEEKS = 12
    RECOMMENDED_MONTHLY_RETENTION_MONTHS = 12
    
    # Required backup properties
    REQUIRED_BACKUP_FEATURES = {
        'retention_policy',
        'encryption',
        'geo_redundancy'
    }
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-RPL-03 compliance.
        
        Frameworks: Azure SDK, boto3 (AWS), google-cloud-storage (GCP)
        
        Detects:
        - Azure Backup SDK usage for backup automation
        - AWS boto3 backup operations
        - GCP backup client usage
        - Backup retention validation
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        if tree:
            return self._analyze_python_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Python backup SDK detection"""
        findings = []
        code_bytes = code.encode('utf8')
        lines = code.split('\n')
        
        # Find import statements
        import_nodes = parser.find_nodes_by_type(tree.root_node, "import_from_statement")
        
        has_azure_backup = False
        has_aws_backup = False
        has_gcp_backup = False
        azure_line = 1
        aws_line = 1
        gcp_line = 1
        
        for import_node in import_nodes:
            import_text = parser.get_node_text(import_node, code_bytes)
            
            # Azure Backup SDK
            if 'azure.mgmt.recoveryservices' in import_text and not has_azure_backup:
                has_azure_backup = True
                azure_line = code[:import_node.start_byte].count('\n') + 1
            
            # AWS boto3 - check via regular import too
            if 'boto3' in import_text and not has_aws_backup:
                has_aws_backup = True
                aws_line = code[:import_node.start_byte].count('\n') + 1
            
            # GCP backup
            if 'google.cloud' in import_text and ('storage' in import_text or 'compute' in import_text) and not has_gcp_backup:
                has_gcp_backup = True
                gcp_line = code[:import_node.start_byte].count('\n') + 1
        
        # Also check regular imports for boto3
        regular_imports = parser.find_nodes_by_type(tree.root_node, "import_statement")
        for imp in regular_imports:
            import_text = parser.get_node_text(imp, code_bytes)
            if 'boto3' in import_text and not has_aws_backup:
                has_aws_backup = True
                aws_line = code[:imp.start_byte].count('\n') + 1
        
        if has_azure_backup:
            findings.append(self._create_azure_backup_finding(file_path, azure_line, lines))
        
        if has_aws_backup:
            findings.append(self._create_aws_backup_finding(file_path, aws_line, lines))
        
        if has_gcp_backup:
            findings.append(self._create_gcp_backup_finding(file_path, gcp_line, lines))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback for Python analysis"""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure Backup SDK usage (INFO - positive indicator)
        azure_backup_patterns = [
            r'from\s+azure\.mgmt\.recoveryservices',
            r'from\s+azure\.mgmt\.recoveryservicesbackup',
            r'RecoveryServicesBackupClient',
            r'BackupManagementClient'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in azure_backup_patterns):
            line_num = self._find_pattern_line(lines, azure_backup_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Backup SDK Usage Detected",
                description=(
                    "Code uses Azure Backup SDK for backup automation. This supports "
                    "KSI-RPL-03 requirements for system backups per NIST CP-9. "
                    "Ensure backup policies include proper retention and geo-redundancy."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Verify backup configuration includes:\n"
                    "1. Retention policy: Minimum 30 days daily retention\n"
                    "2. Geo-redundancy: Enable cross-region replication\n"
                    "3. Encryption: Enable backup encryption at rest\n"
                    "4. Recovery testing: Regular restore verification\n\n"
                    "Example:\n"
                    "backup_policy = {\n"
                    "    'schedulePolicy': {'scheduleRunFrequency': 'Daily'},\n"
                    "    'retentionPolicy': {\n"
                    "        'dailySchedule': {'retentionDuration': {'count': 30, 'durationType': 'Days'}},\n"
                    "        'weeklySchedule': {'retentionDuration': {'count': 12, 'durationType': 'Weeks'}}\n"
                    "    }\n"
                    "}\n\n"
                    "Ref: Azure Backup Python SDK (https://learn.microsoft.com/python/api/azure-mgmt-recoveryservicesbackup/)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: AWS boto3 backup operations (INFO - positive indicator)
        aws_backup_patterns = [
            r'import\s+boto3',
            r'boto3\.client\([\'"]backup[\'"]',
            r'create_backup_plan',
            r'start_backup_job'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in aws_backup_patterns):
            line_num = self._find_pattern_line(lines, aws_backup_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="AWS Backup Operations Detected",
                description=(
                    "Code uses AWS boto3 for backup operations. This supports KSI-RPL-03 "
                    "requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Ensure AWS Backup configuration includes:\n"
                    "- Minimum 30-day retention\n"
                    "- Cross-region copy rules\n"
                    "- Backup vault encryption\n\n"
                    "Ref: AWS Backup boto3 (https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: GCP backup operations (INFO - positive indicator)
        gcp_backup_patterns = [
            r'from\s+google\.cloud\s+import\s+storage',
            r'from\s+google\.cloud\s+import\s+compute',
            r'create_snapshot',
            r'BackupClient'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in gcp_backup_patterns):
            line_num = self._find_pattern_line(lines, gcp_backup_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="GCP Backup Operations Detected",
                description=(
                    "Code uses GCP SDK for backup operations. This supports KSI-RPL-03 "
                    "requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Ensure GCP backup configuration includes:\n"
                    "- Snapshot retention policy\n"
                    "- Multi-region replication\n"
                    "- Encryption at rest\n\n"
                    "Ref: GCP Backup (https://cloud.google.com/compute/docs/disks/snapshots)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def _create_azure_backup_finding(self, file_path: str, line_num: int, lines: List[str]) -> Finding:
        """Create finding for Azure backup SDK usage."""
        return Finding(
            severity=Severity.INFO,
            title="Azure Backup SDK Usage Detected",
            description=(
                "Code uses Azure Recovery Services SDK for backup operations. "
                "This supports KSI-RPL-03 requirements for system backups per NIST CP-9."
            ),
            file_path=file_path,
            line_number=line_num,
            snippet=self._get_snippet(lines, line_num, context=3),
            remediation=(
                "Verify backup configuration:\n"
                "client = RecoveryServicesClient(credential, subscription_id)\n"
                "vault = client.vaults.create_or_update(\n"
                "    resource_group_name,\n"
                "    vault_name,\n"
                "    {\n"
                "        'location': 'eastus',\n"
                "        'sku': {'name': 'RS0', 'tier': 'Standard'},\n"
                "        'properties': {\n"
                "            'publicNetworkAccess': 'Disabled'\n"
                "        }\n"
                "    }\n"
                ")\n\n"
                "Ref: Azure Backup Python SDK (https://learn.microsoft.com/python/api/azure-mgmt-recoveryservices)"
            ),
            ksi_id=self.KSI_ID
        )
    
    def _create_aws_backup_finding(self, file_path: str, line_num: int, lines: List[str]) -> Finding:
        """Create finding for AWS backup operations."""
        return Finding(
            severity=Severity.INFO,
            title="AWS Backup Operations Detected",
            description=(
                "Code uses AWS boto3 for backup operations. This supports KSI-RPL-03 "
                "requirements for system backups per NIST CP-9."
            ),
            file_path=file_path,
            line_number=line_num,
            snippet=self._get_snippet(lines, line_num, context=3),
            remediation=(
                "Ensure AWS Backup configuration includes:\n"
                "- Minimum 30-day retention\n"
                "- Cross-region copy rules\n"
                "- Backup vault encryption\n\n"
                "Ref: AWS Backup boto3 (https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/backup.html)"
            ),
            ksi_id=self.KSI_ID
        )
    
    def _create_gcp_backup_finding(self, file_path: str, line_num: int, lines: List[str]) -> Finding:
        """Create finding for GCP backup operations."""
        return Finding(
            severity=Severity.INFO,
            title="GCP Backup Operations Detected",
            description=(
                "Code uses GCP SDK for backup operations. This supports KSI-RPL-03 "
                "requirements for system backups per NIST CP-9."
            ),
            file_path=file_path,
            line_number=line_num,
            snippet=self._get_snippet(lines, line_num, context=3),
            remediation=(
                "Ensure GCP backup configuration includes:\n"
                "- Snapshot retention policy\n"
                "- Multi-region replication\n"
                "- Encryption at rest\n\n"
                "Ref: GCP Backup (https://cloud.google.com/compute/docs/disks/snapshots)"
            ),
            ksi_id=self.KSI_ID
        )
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-RPL-03 compliance.
        
        Frameworks: Azure.ResourceManager.RecoveryServices, AWS SDK, GCP SDK
        
        Detects:
        - Azure Recovery Services client usage
        - AWS backup service calls
        - Backup policy configuration
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        if tree:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based C# backup SDK detection"""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Find using directives
        using_nodes = parser.find_nodes_by_type(tree.root_node, "using_directive")
        
        has_azure_backup = False
        has_aws_backup = False
        
        for using_node in using_nodes:
            using_text = parser.get_node_text(using_node, code_bytes)
            
            # Azure Backup SDK
            if 'Azure.ResourceManager.RecoveryServices' in using_text:
                if not has_azure_backup:
                    line_num = code[:using_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="Azure Backup SDK Usage Detected",
                        description=(
                            "Code uses Azure Recovery Services SDK for backup operations. "
                            "This supports KSI-RPL-03 requirements for system backups per NIST CP-9."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                        remediation=(
                            "Verify backup configuration:\n"
                            "var backupPolicy = new BackupProtectionPolicy\n"
                            "{\n"
                            "    SchedulePolicy = new SimpleSchedulePolicy\n"
                            "    {\n"
                            "        ScheduleRunFrequency = ScheduleRunType.Daily,\n"
                            "        ScheduleRunTimes = { DateTimeOffset.Parse(\"02:00:00\") }\n"
                            "    },\n"
                            "    RetentionPolicy = new LongTermRetentionPolicy\n"
                            "    {\n"
                            "        DailySchedule = new DailyRetentionSchedule\n"
                            "        {\n"
                            "            RetentionDuration = new RetentionDuration { Count = 30, DurationType = RetentionDurationType.Days }\n"
                            "        },\n"
                            "        WeeklySchedule = new WeeklyRetentionSchedule\n"
                            "        {\n"
                            "            RetentionDuration = new RetentionDuration { Count = 12, DurationType = RetentionDurationType.Weeks }\n"
                            "        }\n"
                            "    }\n"
                            "};\n\n"
                            "Ref: Azure Backup .NET SDK (https://learn.microsoft.com/dotnet/api/azure.resourcemanager.recoveryservicesbackup)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    has_azure_backup = True
            
            # AWS Backup SDK
            elif 'Amazon.Backup' in using_text:
                if not has_aws_backup:
                    line_num = code[:using_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="AWS Backup SDK Usage Detected",
                        description=(
                            "Code uses AWS SDK for backup operations. This supports KSI-RPL-03 "
                            "requirements for system backups per NIST CP-9."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                        remediation=(
                            "Ensure AWS Backup includes:\n"
                            "- Minimum 30-day retention\n"
                            "- Cross-region backup copies\n"
                            "- Vault encryption\n\n"
                            "Ref: AWS Backup .NET SDK (https://docs.aws.amazon.com/sdkfornet/v3/apidocs/items/Backup/NBackup.html)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    has_aws_backup = True
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based analysis for C#."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure Recovery Services usage (INFO - positive indicator)
        azure_backup_patterns = [
            r'using\s+Azure\.ResourceManager\.RecoveryServices',
            r'using\s+Azure\.ResourceManager\.RecoveryServicesBackup',
            r'RecoveryServicesBackupClient',
            r'BackupProtectedItemResource'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in azure_backup_patterns):
            line_num = self._find_pattern_line(lines, azure_backup_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Backup SDK Usage Detected",
                description=(
                    "Code uses Azure Recovery Services SDK for backup operations. "
                    "This supports KSI-RPL-03 requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Verify backup configuration:\n"
                    "var backupPolicy = new BackupProtectionPolicy\n"
                    "{\n"
                    "    SchedulePolicy = new SimpleSchedulePolicy\n"
                    "    {\n"
                    "        ScheduleRunFrequency = ScheduleRunType.Daily,\n"
                    "        ScheduleRunTimes = { DateTimeOffset.Parse(\"02:00:00\") }\n"
                    "    },\n"
                    "    RetentionPolicy = new LongTermRetentionPolicy\n"
                    "    {\n"
                    "        DailySchedule = new DailyRetentionSchedule\n"
                    "        {\n"
                    "            RetentionDuration = new RetentionDuration { Count = 30, DurationType = RetentionDurationType.Days }\n"
                    "        },\n"
                    "        WeeklySchedule = new WeeklyRetentionSchedule\n"
                    "        {\n"
                    "            RetentionDuration = new RetentionDuration { Count = 12, DurationType = RetentionDurationType.Weeks }\n"
                    "        }\n"
                    "    }\n"
                    "};\n\n"
                    "Ref: Azure Backup .NET SDK (https://learn.microsoft.com/dotnet/api/azure.resourcemanager.recoveryservicesbackup)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: AWS SDK backup usage (INFO - positive indicator)
        aws_backup_patterns = [
            r'using\s+Amazon\.Backup',
            r'AmazonBackupClient',
            r'CreateBackupPlanRequest',
            r'StartBackupJobRequest'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in aws_backup_patterns):
            line_num = self._find_pattern_line(lines, aws_backup_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="AWS Backup SDK Usage Detected",
                description=(
                    "Code uses AWS SDK for backup operations. This supports KSI-RPL-03 "
                    "requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Ensure AWS Backup includes:\n"
                    "- Minimum 30-day retention\n"
                    "- Cross-region backup copies\n"
                    "- Vault encryption\n\n"
                    "Ref: AWS Backup .NET SDK (https://docs.aws.amazon.com/sdkfornet/v3/apidocs/items/Backup/NBackup.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-RPL-03 compliance.
        
        Frameworks: Azure SDK, AWS SDK
        
        Detects:
        - Azure backup client usage
        - AWS backup service operations
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Java backup SDK detection"""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Find import declarations
        import_nodes = parser.find_nodes_by_type(tree.root_node, "import_declaration")
        
        has_azure_backup = False
        has_aws_backup = False
        
        for import_node in import_nodes:
            import_text = parser.get_node_text(import_node, code_bytes)
            
            # Azure Backup SDK
            if 'com.azure.resourcemanager.recoveryservices' in import_text:
                if not has_azure_backup:
                    line_num = code[:import_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="Azure Backup SDK Usage Detected",
                        description="Code uses Azure SDK for backup operations (KSI-RPL-03 compliance indicator).",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(code.split('\n'), line_num, context=2),
                        remediation=(
                            "Verify backup configuration meets FedRAMP requirements:\n"
                            "- Daily backups with 30+ day retention\n"
                            "- Geo-redundant storage\n"
                            "- Backup encryption enabled\n\n"
                            "Ref: Azure Backup Java SDK (https://learn.microsoft.com/java/api/overview/azure/resourcemanager-recoveryservicesbackup-readme)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    has_azure_backup = True
            
            # AWS Backup SDK
            elif 'software.amazon.awssdk.services.backup' in import_text:
                if not has_aws_backup:
                    line_num = code[:import_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="AWS Backup SDK Usage Detected",
                        description="Code uses AWS SDK for backup operations (KSI-RPL-03 compliance indicator).",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(code.split('\n'), line_num, context=2),
                        remediation="Ensure AWS Backup includes 30+ day retention and cross-region copies.",
                        ksi_id=self.KSI_ID
                    ))
                    has_aws_backup = True
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based analysis for Java."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure SDK backup usage (INFO)
        azure_patterns = [
            r'import\s+com\.azure\.resourcemanager\.recoveryservices',
            r'import\s+com\.azure\.resourcemanager\.recoveryservicesbackup',
            r'RecoveryServicesBackupManager'
        ]
        
        if any(re.search(pattern, code) for pattern in azure_patterns):
            line_num = self._find_pattern_line(lines, azure_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Backup SDK Usage Detected",
                description="Code uses Azure SDK for backup operations (KSI-RPL-03 compliance indicator).",
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Verify backup configuration meets FedRAMP requirements:\n"
                    "- Daily backups with 30+ day retention\n"
                    "- Geo-redundant storage\n"
                    "- Backup encryption enabled\n\n"
                    "Ref: Azure Backup Java SDK (https://learn.microsoft.com/java/api/overview/azure/resourcemanager-recoveryservicesbackup-readme)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: AWS SDK backup usage (INFO)
        aws_patterns = [
            r'import\s+software\.amazon\.awssdk\.services\.backup',
            r'BackupClient\.builder',
            r'CreateBackupPlanRequest'
        ]
        
        if any(re.search(pattern, code) for pattern in aws_patterns):
            line_num = self._find_pattern_line(lines, aws_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="AWS Backup SDK Usage Detected",
                description="Code uses AWS SDK for backup operations (KSI-RPL-03 compliance indicator).",
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation="Ensure AWS Backup includes 30+ day retention and cross-region copies.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-RPL-03 compliance.
        
        Frameworks: @azure/arm-recoveryservices, AWS SDK, GCP SDK
        
        Detects:
        - Azure backup client usage
        - AWS backup operations
        - Backup automation scripts
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based TypeScript backup SDK detection"""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Find import statements
        import_nodes = parser.find_nodes_by_type(tree.root_node, "import_statement")
        
        has_azure_backup = False
        has_aws_backup = False
        
        for import_node in import_nodes:
            import_text = parser.get_node_text(import_node, code_bytes)
            
            # Azure Backup SDK
            if '@azure/arm-recoveryservices' in import_text:
                if not has_azure_backup:
                    line_num = code[:import_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="Azure Backup SDK Usage Detected",
                        description=(
                            "Code uses Azure Backup SDK for backup automation. This supports "
                            "KSI-RPL-03 requirements for system backups per NIST CP-9."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(code.split('\n'), line_num, context=3),
                        remediation=(
                            "Verify backup policy configuration:\n"
                            "const backupPolicy = {\n"
                            "  schedulePolicy: {\n"
                            "    scheduleRunFrequency: 'Daily',\n"
                            "    scheduleRunTimes: ['02:00:00']\n"
                            "  },\n"
                            "  retentionPolicy: {\n"
                            "    dailySchedule: {\n"
                            "      retentionDuration: { count: 30, durationType: 'Days' }\n"
                            "    },\n"
                            "    weeklySchedule: {\n"
                            "      retentionDuration: { count: 12, durationType: 'Weeks' }\n"
                            "    }\n"
                            "  }\n"
                            "};\n\n"
                            "Ref: Azure Backup JS SDK (https://www.npmjs.com/package/@azure/arm-recoveryservicesbackup)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    has_azure_backup = True
            
            # AWS Backup SDK
            elif '@aws-sdk/client-backup' in import_text:
                if not has_aws_backup:
                    line_num = code[:import_node.start_byte].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.INFO,
                        title="AWS Backup SDK Usage Detected",
                        description="Code uses AWS SDK for backup operations (KSI-RPL-03 compliance indicator).",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(code.split('\n'), line_num, context=2),
                        remediation="Ensure AWS Backup configuration includes 30+ day retention and cross-region copies.",
                        ksi_id=self.KSI_ID
                    ))
                    has_aws_backup = True
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based analysis for TypeScript."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure SDK backup usage (INFO)
        azure_patterns = [
            r'from\s+[\'"]@azure/arm-recoveryservices',
            r'from\s+[\'"]@azure/arm-recoveryservicesbackup',
            r'RecoveryServicesBackupClient',
            r'BackupManagementClient'
        ]
        
        if any(re.search(pattern, code) for pattern in azure_patterns):
            line_num = self._find_pattern_line(lines, azure_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Backup SDK Usage Detected",
                description=(
                    "Code uses Azure Backup SDK for backup automation. This supports "
                    "KSI-RPL-03 requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Verify backup policy configuration:\n"
                    "const backupPolicy = {\n"
                    "  schedulePolicy: {\n"
                    "    scheduleRunFrequency: 'Daily',\n"
                    "    scheduleRunTimes: ['02:00:00']\n"
                    "  },\n"
                    "  retentionPolicy: {\n"
                    "    dailySchedule: {\n"
                    "      retentionDuration: { count: 30, durationType: 'Days' }\n"
                    "    },\n"
                    "    weeklySchedule: {\n"
                    "      retentionDuration: { count: 12, durationType: 'Weeks' }\n"
                    "    }\n"
                    "  }\n"
                    "};\n\n"
                    "Ref: Azure Backup JS SDK (https://www.npmjs.com/package/@azure/arm-recoveryservicesbackup)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: AWS SDK backup usage (INFO)
        aws_patterns = [
            r'from\s+[\'"]@aws-sdk/client-backup',
            r'BackupClient',
            r'CreateBackupPlanCommand',
            r'StartBackupJobCommand'
        ]
        
        if any(re.search(pattern, code) for pattern in aws_patterns):
            line_num = self._find_pattern_line(lines, aws_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="AWS Backup SDK Usage Detected",
                description="Code uses AWS SDK for backup operations (KSI-RPL-03 compliance indicator).",
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation="Ensure AWS Backup configuration includes 30+ day retention and cross-region copies.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-RPL-03 compliance.
        
        Note: Using regex - tree-sitter not available for Bicep
        
        Detects:
        - Missing Azure Backup configurations
        - Missing Recovery Services Vault
        - Insufficient backup retention periods
        - Missing geo-redundancy (GRS/GZRS)
        - Missing backup encryption
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: No Recovery Services Vault (HIGH)
        has_vault = bool(re.search(r"Microsoft\.RecoveryServices/vaults", code, re.IGNORECASE))
        has_backup_policy = bool(re.search(r"Microsoft\.RecoveryServices/vaults/.*backupPolicies", code, re.IGNORECASE))
        has_protected_items = bool(re.search(r"Microsoft\.RecoveryServices/vaults/.*backupFabrics", code, re.IGNORECASE))
        has_critical_resources = bool(re.search(
            r"Microsoft\.(Compute/virtualMachines|Sql|Storage/storageAccounts|DBforPostgreSQL|DBforMySQL)",
            code,
            re.IGNORECASE
        ))
        
        if has_critical_resources and not has_vault:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Azure Backup Configuration",
                description=(
                    "Infrastructure defines critical resources (VMs, databases, storage) without "
                    "Azure Backup configuration. KSI-RPL-03 requires system backups aligned "
                    "with recovery objectives per NIST CP-9. Missing Recovery Services Vault and backup policies."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add Azure Recovery Services Vault with backup policies:\n\n"
                    "resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {\n"
                    "  name: 'backup-vault'\n"
                    "  location: location\n"
                    "  sku: {\n"
                    "    name: 'RS0'  // Standard tier\n"
                    "    tier: 'Standard'\n"
                    "  }\n"
                    "  properties: {\n"
                    "    publicNetworkAccess: 'Disabled'  // FedRAMP best practice\n"
                    "    encryption: {\n"
                    "      infrastructureEncryption: 'Enabled'  // Double encryption\n"
                    "      kekIdentity: {\n"
                    "        userAssignedIdentity: managedIdentityId\n"
                    "      }\n"
                    "      keyVaultProperties: {\n"
                    "        keyUri: keyVaultKeyUri\n"
                    "      }\n"
                    "    }\n"
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
                    "          count: 30  // Minimum 30 days for FedRAMP\n"
                    "          durationType: 'Days'\n"
                    "        }\n"
                    "      }\n"
                    "      weeklySchedule: {\n"
                    "        daysOfTheWeek: ['Sunday']\n"
                    "        retentionTimes: ['2023-01-01T02:00:00Z']\n"
                    "        retentionDuration: {\n"
                    "          count: 12  // 12 weeks recommended\n"
                    "          durationType: 'Weeks'\n"
                    "        }\n"
                    "      }\n"
                    "      monthlySchedule: {\n"
                    "        retentionScheduleFormatType: 'Weekly'\n"
                    "        retentionScheduleWeekly: {\n"
                    "          daysOfTheWeek: ['Sunday']\n"
                    "          weeksOfTheMonth: ['First']\n"
                    "        }\n"
                    "        retentionTimes: ['2023-01-01T02:00:00Z']\n"
                    "        retentionDuration: {\n"
                    "          count: 12  // 12 months recommended\n"
                    "          durationType: 'Months'\n"
                    "        }\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Backup (https://learn.microsoft.com/azure/backup/)\n"
                    "Ref: Azure WAF Reliability (https://learn.microsoft.com/azure/well-architected/reliability/backup-and-disaster-recovery)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Short retention period (MEDIUM)
        retention_match = re.search(
            r"retentionDuration.*?count:\s*(\d+)",
            code,
            re.DOTALL
        )
        if retention_match:
            retention_days = int(retention_match.group(1))
            if retention_days < self.MINIMUM_RETENTION_DAYS:
                result = self._find_line(lines, 'retentionDuration')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Insufficient Backup Retention Period",
                    description=(
                        f"Backup policy has retention period of {retention_days} days, which is "
                        f"less than FedRAMP minimum of {self.MINIMUM_RETENTION_DAYS} days. "
                        f"KSI-RPL-03 requires backups aligned with recovery objectives per NIST CP-9."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Increase retention period to at least {self.MINIMUM_RETENTION_DAYS} days:\n\n"
                        "retentionPolicy: {\n"
                        "  retentionPolicyType: 'LongTermRetentionPolicy'\n"
                        "  dailySchedule: {\n"
                        "    retentionDuration: {\n"
                        "      count: 30  // FedRAMP minimum\n"
                        "      durationType: 'Days'\n"
                        "    }\n"
                        "  }\n"
                        "  weeklySchedule: {\n"
                        "    retentionDuration: {\n"
                        "      count: 12  // Recommended\n"
                        "      durationType: 'Weeks'\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: NIST CP-9 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Missing geo-redundancy (MEDIUM)
        if has_vault:
            # Check if storage redundancy is configured
            storage_config_match = re.search(
                r"storageModelType:\s*['\"]?(LocallyRedundant|ZoneRedundant)['\"]?",
                code,
                re.IGNORECASE
            )
            
            if storage_config_match:
                storage_type = storage_config_match.group(1)
                if storage_type.lower() in ['locallyredundant', 'zoneredundant']:
                    result = self._find_line(lines, 'storageModelType')

                    line_num = result['line_num'] if result else 0
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Backup Storage Missing Geo-Redundancy",
                        description=(
                            f"Backup vault uses {storage_type} storage instead of geo-redundant storage. "
                            f"FedRAMP recommends geo-redundant backup storage (GRS or GZRS) for "
                            f"disaster recovery per Azure WAF Reliability pillar."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            "Configure geo-redundant storage for disaster recovery:\n\n"
                            "resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {\n"
                            "  name: 'backup-vault'\n"
                            "  location: location\n"
                            "  sku: {\n"
                            "    name: 'RS0'\n"
                            "    tier: 'Standard'\n"
                            "  }\n"
                            "  properties: {\n"
                            "    redundancySettings: {\n"
                            "      standardTierStorageRedundancy: 'GeoRedundant'  // GRS for cross-region\n"
                            "      crossRegionRestore: 'Enabled'  // Enable cross-region restore\n"
                            "    }\n"
                            "  }\n"
                            "}\n\n"
                            "Ref: Azure Backup redundancy (https://learn.microsoft.com/azure/backup/backup-azure-backup-faq#what-is-the-difference-between-grs-and-lrs)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 4: Missing backup encryption (HIGH)
        if has_vault and not re.search(r"encryption:\s*\{", code, re.IGNORECASE):
            vault_line = self._find_line(lines, "Microsoft.RecoveryServices/vaults")
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Backup Encryption Configuration",
                description=(
                    "Recovery Services Vault does not have encryption configured. "
                    "FedRAMP requires encryption at rest for backup data per KSI-SVC-06 "
                    "and NIST SC-28."
                ),
                file_path=file_path,
                line_number=vault_line,
                snippet=self._get_snippet(lines, vault_line, context=3),
                remediation=(
                    "Add encryption configuration to Recovery Services Vault:\n\n"
                    "resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {\n"
                    "  name: 'backup-vault'\n"
                    "  location: location\n"
                    "  identity: {\n"
                    "    type: 'UserAssigned'\n"
                    "    userAssignedIdentities: {\n"
                    "      '${managedIdentityId}': {}\n"
                    "    }\n"
                    "  }\n"
                    "  properties: {\n"
                    "    encryption: {\n"
                    "      infrastructureEncryption: 'Enabled'  // Double encryption\n"
                    "      kekIdentity: {\n"
                    "        userAssignedIdentity: managedIdentityId\n"
                    "      }\n"
                    "      keyVaultProperties: {\n"
                    "        keyUri: keyVaultKeyUri  // Customer-managed key\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Backup encryption (https://learn.microsoft.com/azure/backup/backup-encryption)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-RPL-03 compliance.
        
        Note: Using regex - tree-sitter not available for Terraform HCL
        
        Detects:
        - Missing backup configurations (Azure/AWS/GCP)
        - Insufficient retention periods
        - Missing geo-redundancy
        - Missing encryption
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Azure - No Recovery Vault (HIGH)
        has_azure_vault = bool(re.search(r'resource\s+"azurerm_recovery_services_vault"', code))
        has_azure_policy = bool(re.search(r'resource\s+"azurerm_backup_policy_vm"', code))
        has_azure_resources = bool(re.search(
            r'resource\s+"azurerm_(virtual_machine|linux_virtual_machine|windows_virtual_machine|mssql_database|postgresql_server|mysql_server)"',
            code
        ))
        
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
                    "Add Azure Backup configuration:\n\n"
                    "resource \"azurerm_recovery_services_vault\" \"vault\" {\n"
                    "  name                = \"backup-vault\"\n"
                    "  location            = azurerm_resource_group.rg.location\n"
                    "  resource_group_name = azurerm_resource_group.rg.name\n"
                    "  sku                 = \"Standard\"\n"
                    "  soft_delete_enabled = true\n"
                    "  \n"
                    "  encryption {\n"
                    "    key_id                            = azurerm_key_vault_key.backup_key.id\n"
                    "    infrastructure_encryption_enabled = true  // Double encryption\n"
                    "  }\n"
                    "}\n\n"
                    "resource \"azurerm_backup_policy_vm\" \"policy\" {\n"
                    "  name                = \"daily-backup-policy\"\n"
                    "  resource_group_name = azurerm_resource_group.rg.name\n"
                    "  recovery_vault_name = azurerm_recovery_services_vault.vault.name\n"
                    "  \n"
                    "  timezone = \"UTC\"\n"
                    "  \n"
                    "  backup {\n"
                    "    frequency = \"Daily\"\n"
                    "    time      = \"02:00\"\n"
                    "  }\n"
                    "  \n"
                    "  retention_daily {\n"
                    "    count = 30  # FedRAMP minimum\n"
                    "  }\n"
                    "  \n"
                    "  retention_weekly {\n"
                    "    count    = 12\n"
                    "    weekdays = [\"Sunday\"]\n"
                    "  }\n"
                    "  \n"
                    "  retention_monthly {\n"
                    "    count    = 12\n"
                    "    weekdays = [\"Sunday\"]\n"
                    "    weeks    = [\"First\"]\n"
                    "  }\n"
                    "}\n\n"
                    "resource \"azurerm_backup_protected_vm\" \"vm\" {\n"
                    "  resource_group_name = azurerm_resource_group.rg.name\n"
                    "  recovery_vault_name = azurerm_recovery_services_vault.vault.name\n"
                    "  source_vm_id        = azurerm_virtual_machine.vm.id\n"
                    "  backup_policy_id    = azurerm_backup_policy_vm.policy.id\n"
                    "}\n\n"
                    "Ref: Azure Backup Terraform (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/backup_policy_vm)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: AWS - No backup plan (HIGH)
        has_aws_plan = bool(re.search(r'resource\s+"aws_backup_plan"', code))
        has_aws_vault = bool(re.search(r'resource\s+"aws_backup_vault"', code))
        has_aws_resources = bool(re.search(
            r'resource\s+"aws_(instance|db_instance|rds_cluster|efs_file_system|ebs_volume)"',
            code
        ))
        
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
                    "Add AWS Backup configuration:\n\n"
                    "resource \"aws_backup_vault\" \"vault\" {\n"
                    "  name        = \"backup-vault\"\n"
                    "  kms_key_arn = aws_kms_key.backup.arn  # Encryption required\n"
                    "}\n\n"
                    "resource \"aws_backup_plan\" \"plan\" {\n"
                    "  name = \"daily-backup-plan\"\n"
                    "  \n"
                    "  rule {\n"
                    "    rule_name         = \"daily_backup_rule\"\n"
                    "    target_vault_name = aws_backup_vault.vault.name\n"
                    "    schedule          = \"cron(0 2 * * ? *)\"  # 2 AM UTC daily\n"
                    "    \n"
                    "    lifecycle {\n"
                    "      delete_after = 30  # FedRAMP minimum (days)\n"
                    "    }\n"
                    "    \n"
                    "    copy_action {\n"
                    "      destination_vault_arn = aws_backup_vault.vault_secondary.arn  # Cross-region\n"
                    "      lifecycle {\n"
                    "        delete_after = 30\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "  \n"
                    "  rule {\n"
                    "    rule_name         = \"weekly_backup_rule\"\n"
                    "    target_vault_name = aws_backup_vault.vault.name\n"
                    "    schedule          = \"cron(0 2 ? * SUN *)\"  # Weekly on Sunday\n"
                    "    \n"
                    "    lifecycle {\n"
                    "      delete_after = 84  # 12 weeks\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "resource \"aws_backup_selection\" \"selection\" {\n"
                    "  name         = \"backup-selection\"\n"
                    "  iam_role_arn = aws_iam_role.backup.arn\n"
                    "  plan_id      = aws_backup_plan.plan.id\n"
                    "  \n"
                    "  resources = [\n"
                    "    aws_instance.example.arn,\n"
                    "    aws_db_instance.example.arn\n"
                    "  ]\n"
                    "}\n\n"
                    "Ref: AWS Backup Terraform (https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/backup_plan)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Short retention period (MEDIUM)
        retention_match = re.search(
            r'(retention_daily\s*\{\s*count\s*=\s*(\d+)|delete_after\s*=\s*(\d+))',
            code
        )
        if retention_match:
            retention_days = int(retention_match.group(2) or retention_match.group(3))
            if retention_days < self.MINIMUM_RETENTION_DAYS:
                result = self._find_line(lines, 'retention')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Insufficient Backup Retention Period",
                    description=(
                        f"Backup retention period is {retention_days} days, which is less than "
                        f"FedRAMP minimum of {self.MINIMUM_RETENTION_DAYS} days. KSI-RPL-03 "
                        f"requires adequate retention per NIST CP-9."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Increase retention to at least {self.MINIMUM_RETENTION_DAYS} days:\n\n"
                        "retention_daily {\n"
                        "  count = 30  # FedRAMP minimum\n"
                        "}\n"
                        "retention_weekly {\n"
                        "  count    = 12\n"
                        "  weekdays = [\"Sunday\"]\n"
                        "}\n"
                        "retention_monthly {\n"
                        "  count    = 12\n"
                        "  weekdays = [\"Sunday\"]\n"
                        "  weeks    = [\"First\"]\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 4: Missing encryption for backup vault (HIGH)
        if has_azure_vault or has_aws_vault:
            # Check Azure vault encryption
            if has_azure_vault and not re.search(r'encryption\s*\{', code):
                vault_line = self._find_line(lines, 'azurerm_recovery_services_vault')
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Missing Azure Backup Vault Encryption",
                    description=(
                        "Azure Recovery Services Vault does not have encryption configured. "
                        "FedRAMP requires encryption at rest per KSI-SVC-06."
                    ),
                    file_path=file_path,
                    line_number=vault_line,
                    snippet=self._get_snippet(lines, vault_line, context=3),
                    remediation=(
                        "Add encryption to Recovery Services Vault:\n\n"
                        "resource \"azurerm_recovery_services_vault\" \"vault\" {\n"
                        "  encryption {\n"
                        "    key_id                            = azurerm_key_vault_key.backup_key.id\n"
                        "    infrastructure_encryption_enabled = true\n"
                        "  }\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
            
            # Check AWS vault encryption
            if has_aws_vault and not re.search(r'kms_key_arn', code):
                vault_line = self._find_line(lines, 'aws_backup_vault')
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Missing AWS Backup Vault Encryption",
                    description=(
                        "AWS Backup Vault does not have KMS encryption configured. "
                        "FedRAMP requires encryption at rest per KSI-SVC-06."
                    ),
                    file_path=file_path,
                    line_number=vault_line,
                    snippet=self._get_snippet(lines, vault_line, context=3),
                    remediation=(
                        "Add KMS encryption to AWS Backup Vault:\n\n"
                        "resource \"aws_backup_vault\" \"vault\" {\n"
                        "  name        = \"backup-vault\"\n"
                        "  kms_key_arn = aws_kms_key.backup.arn\n"
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
        
        Detects:
        - Backup verification tests
        - Restore testing automation
        - Backup configuration validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Backup verification tests (INFO - positive indicator)
        backup_test_patterns = [
            r'backup.*verify',
            r'test.*backup',
            r'backup.*validation',
            r'restore.*test'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in backup_test_patterns):
            line_num = self._find_pattern_line(lines, backup_test_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="Backup Verification Tests Detected",
                description=(
                    "CI/CD pipeline includes backup verification tests. This supports "
                    "KSI-RPL-03 requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Ensure backup tests include:\n"
                    "- Backup creation verification\n"
                    "- Restore functionality testing\n"
                    "- Retention policy validation\n"
                    "- Encryption verification\n\n"
                    "Example:\n"
                    "- name: Verify Backup Configuration\n"
                    "  run: |\n"
                    "    az backup policy show --name daily-backup-policy\n"
                    "    az backup protection check-vm --vm-id $VM_ID\n"
                    "    # Test restore to verify backup integrity\n"
                    "    az backup restore restore-disks --restore-to-staging-storage-account"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-RPL-03 compliance.
        
        Detects backup verification and restore testing.
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Backup verification (INFO)
        backup_patterns = [
            r'backup.*verification',
            r'test.*restore',
            r'az\s+backup\s+policy',
            r'RecoveryServicesBackupClient'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in backup_patterns):
            line_num = self._find_pattern_line(lines, backup_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="Backup Verification in Azure Pipelines",
                description=(
                    "Pipeline includes backup verification steps. This supports KSI-RPL-03 "
                    "requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Ensure backup verification includes:\n"
                    "- task: AzureCLI@2\n"
                    "  displayName: 'Verify Backup Configuration'\n"
                    "  inputs:\n"
                    "    azureSubscription: '$(azureSubscription)'\n"
                    "    scriptType: 'bash'\n"
                    "    scriptLocation: 'inlineScript'\n"
                    "    inlineScript: |\n"
                    "      az backup policy show --name daily-backup-policy\n"
                    "      az backup protection check-vm --vm-id $(vmId)\n"
                    "      # Verify retention meets FedRAMP requirements (30+ days)\n"
                    "      retention=$(az backup policy show --name daily-backup-policy --query 'properties.retentionPolicy.dailySchedule.retentionDuration.count' -o tsv)\n"
                    "      if [ $retention -lt 30 ]; then\n"
                    "        echo \"ERROR: Retention period less than FedRAMP minimum (30 days)\"\n"
                    "        exit 1\n"
                    "      fi"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-RPL-03 compliance.
        
        Detects backup verification and restore testing.
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Backup verification (INFO)
        backup_patterns = [
            r'backup.*test',
            r'restore.*verification',
            r'az\s+backup',
            r'aws\s+backup'
        ]
        
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in backup_patterns):
            line_num = self._find_pattern_line(lines, backup_patterns)
            findings.append(Finding(
                severity=Severity.INFO,
                title="Backup Verification in GitLab CI",
                description=(
                    "Pipeline includes backup verification. This supports KSI-RPL-03 "
                    "requirements for system backups per NIST CP-9."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Ensure backup verification includes:\n"
                    "backup:verify:\n"
                    "  stage: test\n"
                    "  script:\n"
                    "    - az backup policy show --name daily-backup-policy\n"
                    "    - az backup protection check-vm --vm-id $VM_ID\n"
                    "    # Verify backup encryption\n"
                    "    - az backup vault show --query 'properties.encryption' -o json\n"
                    "  rules:\n"
                    "    - if: '$CI_PIPELINE_SOURCE == \"schedule\"'"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    

        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 1
    
    def _find_pattern_line(self, lines: List[str], patterns: List[str]) -> int:
        """Find line number matching any pattern."""
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return i
        return 1
    

        """Get code snippet around line number."""
        if line_number == 0:
            line_number = 1
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

