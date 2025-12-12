"""
FRR-ADS-09: Historical Authorization Data

Providers MUST make historical versions of _authorization data_ available for three years to all necessary parties UNLESS otherwise specified by applicable FedRAMP requirements; deltas between versions MAY be consolidated quarterly.

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_09_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-09: Historical Authorization Data
    
    **Official Statement:**
    Providers MUST make historical versions of _authorization data_ available for three years to all necessary parties UNLESS otherwise specified by applicable FedRAMP requirements; deltas between versions MAY be consolidated quarterly.
    
    **Family:** ADS - Authorization Data Sharing
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-ADS-09"
    FRR_NAME = "Historical Authorization Data"
    FRR_STATEMENT = """Providers MUST make historical versions of _authorization data_ available for three years to all necessary parties UNLESS otherwise specified by applicable FedRAMP requirements; deltas between versions MAY be consolidated quarterly."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SI-12", "Information Management and Retention"),
        ("AU-11", "Audit Record Retention"),
        ("CP-9", "System Backup"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-MLA-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-09 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for FRR-ADS-09 compliance using AST.
        
        Detects historical data retention mechanisms:
        - Versioning systems (git libraries, version control)
        - Retention policies (3 years = 1095 days)
        - Archive mechanisms (backup, archive storage)
        - Version history management
        
        Uses AST for accurate detection with regex fallback.
        """
        findings = []
        
        # AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Find retention/versioning/archive functions
                retention_functions = [
                    'set_retention', 'configure_retention', 'retention_policy',
                    'archive_data', 'create_archive', 'backup_data', 'create_backup',
                    'version_data', 'create_version', 'version_history',
                    'store_historical', 'retain_historical'
                ]
                
                for func_name in retention_functions:
                    calls = parser.find_function_calls(tree.root_node, func_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Historical data retention function detected",
                            description=f"Found retention/versioning function: {func_name}()",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this mechanism retains authorization data for 3 years (1095 days)."
                        ))
                
                # Check for retention period literals (3 years, 1095 days, 36 months)
                number_nodes = parser.find_nodes_by_type(tree.root_node, 'integer')
                retention_values = [1095, 365 * 3, 36]  # days, days, months
                for num_node in number_nodes:
                    num_text = parser.get_node_text(num_node, code_bytes)
                    try:
                        num_val = int(num_text)
                        if num_val in retention_values:
                            line_num = num_node.start_point[0] + 1
                            findings.append(Finding(
                                frr_id=self.FRR_ID,
                                title="3-year retention period detected",
                                description=f"Found retention value: {num_val}",
                                severity=Severity.INFO,
                                line_number=line_num,
                                code_snippet=num_text,
                                recommendation="Verify this retention period applies to authorization data."
                            ))
                    except ValueError:
                        pass
                
                # Check string literals for retention/versioning keywords
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                retention_keywords = ['3 year', '1095 day', 'retention', 'version history', 'archive', 'historical data']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in retention_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Retention/versioning reference detected",
                            description="Found retention policy or versioning reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify 3-year retention for authorization data."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        retention_patterns = [
            r'retention.*3.*year',
            r'retain.*1095.*day',
            r'36.*month.*retention',
            r'historical.*version',
            r'archive.*authorization',
            r'version.*history',
            r'backup.*retention',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in retention_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Retention policy pattern detected",
                        description=f"Found retention pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify 3-year retention requirement for authorization data."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-09 compliance using AST.
        
        Detects historical data retention mechanisms:
        - Retention policy methods
        - Versioning/archive methods
        - Backup configuration
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Find retention/versioning methods
                retention_methods = [
                    'SetRetention', 'ConfigureRetention', 'RetentionPolicy',
                    'ArchiveData', 'CreateArchive', 'BackupData', 'CreateBackup',
                    'VersionData', 'CreateVersion', 'VersionHistory',
                    'StoreHistorical', 'RetainHistorical'
                ]
                
                for method_name in retention_methods:
                    calls = parser.find_function_calls(tree.root_node, method_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Historical data retention method detected",
                            description=f"Found retention method: {method_name}",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this mechanism retains authorization data for 3 years."
                        ))
                
                # Check string literals for retention keywords
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                retention_keywords = ['3 year', '1095 day', 'retention', 'version history', 'archive']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in retention_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Retention policy reference detected",
                            description="Found retention/versioning reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify 3-year retention for authorization data."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(SetRetention|RetentionPolicy|ArchiveData|VersionHistory)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Retention method pattern detected",
                    description="Found potential retention method",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure 3-year retention for authorization data."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-09 compliance using AST.
        
        Detects historical data retention mechanisms:
        - Retention policy methods
        - Versioning/archive methods
        - Backup configuration
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Find retention/versioning methods
                retention_methods = [
                    'setRetention', 'configureRetention', 'retentionPolicy',
                    'archiveData', 'createArchive', 'backupData', 'createBackup',
                    'versionData', 'createVersion', 'versionHistory',
                    'storeHistorical', 'retainHistorical'
                ]
                
                for method_name in retention_methods:
                    calls = parser.find_function_calls(tree.root_node, method_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Historical data retention method detected",
                            description=f"Found retention method: {method_name}()",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this mechanism retains authorization data for 3 years."
                        ))
                
                # Check string literals for retention keywords
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                retention_keywords = ['3 year', '1095 day', 'retention', 'version history', 'archive']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in retention_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Retention policy reference detected",
                            description="Found retention/versioning reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify 3-year retention for authorization data."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(setRetention|retentionPolicy|archiveData|versionHistory)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Retention method pattern detected",
                    description="Found potential retention method",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure 3-year retention for authorization data."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-09 compliance using AST.
        
        Detects historical data retention mechanisms:
        - Retention policy functions
        - Versioning/archive functions
        - Backup configuration
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Find retention/versioning functions
                retention_functions = [
                    'setRetention', 'configureRetention', 'retentionPolicy',
                    'archiveData', 'createArchive', 'backupData', 'createBackup',
                    'versionData', 'createVersion', 'versionHistory',
                    'storeHistorical', 'retainHistorical'
                ]
                
                for func_name in retention_functions:
                    calls = parser.find_function_calls(tree.root_node, func_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Historical data retention function detected",
                            description=f"Found retention function: {func_name}()",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this mechanism retains authorization data for 3 years."
                        ))
                
                # Check string literals for retention keywords
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                retention_keywords = ['3 year', '1095 day', 'retention', 'version history', 'archive']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in retention_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Retention policy reference detected",
                            description="Found retention/versioning reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify 3-year retention for authorization data."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(setRetention|retentionPolicy|archiveData|versionHistory)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Retention function pattern detected",
                    description="Found potential retention function",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure 3-year retention for authorization data."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-09 compliance.
        
        Detects Azure resources with retention/versioning capabilities:
        - Azure Backup retention policies
        - Storage account blob retention/versioning
        - Storage account soft delete configuration
        - Recovery Services vault configurations
        
        Note: Uses regex patterns as tree-sitter does not support Bicep.
        """
        findings = []
        lines = code.split('\n')
        
        # Azure resources with retention/versioning
        retention_resources = [
            r'Microsoft\.RecoveryServices/vaults',  # Azure Backup
            r'Microsoft\.Storage/storageAccounts.*blobServices.*containers',  # Blob retention
            r'Microsoft\.Backup/BackupVaults',
        ]
        
        # Retention policy properties
        retention_properties = [
            r'retentionPolicy',
            r'retentionDuration',
            r'retentionInDays.*1095',  # 3 years
            r'daysOfTheMonth.*36',  # 36 months
            r'enableVersioning.*true',
            r'deleteRetentionPolicy',
            r'days.*1095',
        ]
        
        for i, line in enumerate(lines, 1):
            # Check for retention resources
            for pattern in retention_resources:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Retention-capable Azure resource detected",
                        description=f"Found retention resource: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure retention policy configured for 3 years (1095 days) for authorization data."
                    ))
                    break
            
            # Check for retention properties
            for pattern in retention_properties:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Retention policy configuration detected",
                        description=f"Found retention setting: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify 3-year retention period for historical authorization data."
                    ))
                    break
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-09 compliance.
        
        Detects resources with retention/versioning capabilities:
        - Azure Backup retention policies
        - Storage account blob retention/versioning
        - Recovery Services vault configurations
        
        Note: Uses regex patterns as tree-sitter does not support Terraform.
        """
        findings = []
        lines = code.split('\n')
        
        # Terraform resources with retention
        retention_resources = [
            r'azurerm_recovery_services_vault',
            r'azurerm_backup_policy',
            r'azurerm_storage_account.*versioning',
            r'azurerm_storage_management_policy',
        ]
        
        # Retention policy properties
        retention_properties = [
            r'retention_daily.*count.*=.*1095',
            r'retention_yearly.*count.*=.*3',
            r'retention_monthly.*count.*=.*36',
            r'enable_versioning.*=.*true',
            r'delete_retention_policy',
            r'days.*=.*1095',
        ]
        
        for i, line in enumerate(lines, 1):
            # Check for retention resources
            for pattern in retention_resources:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Retention-capable resource detected",
                        description=f"Found retention resource: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure retention policy configured for 3 years for authorization data."
                    ))
                    break
            
            # Check for retention properties
            for pattern in retention_properties:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Retention policy configuration detected",
                        description=f"Found retention setting: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify 3-year retention period for historical authorization data."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-09 compliance.
        
        Detects backup/archive automation:
        - Backup workflows
        - Archive creation jobs
        - Versioning automation
        - Retention policy management
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Backup/archive automation patterns
        retention_patterns = [
            r'backup.*authorization',
            r'archive.*data',
            r'create.*backup',
            r'retention.*policy',
            r'version.*history',
            r'historical.*data',
            r'backup.*schedule',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in retention_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Backup/archive workflow detected",
                        description=f"Found retention automation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure workflow maintains 3-year retention for authorization data."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-09 compliance.
        
        Detects backup/archive automation:
        - Backup tasks
        - Archive creation steps
        - Versioning automation
        - Retention policy management
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Backup/archive automation patterns
        retention_patterns = [
            r'backup.*authorization',
            r'archive.*data',
            r'create.*backup',
            r'retention.*policy',
            r'version.*history',
            r'historical.*data',
            r'backup.*task',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in retention_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Backup/archive pipeline detected",
                        description=f"Found retention automation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure pipeline maintains 3-year retention for authorization data."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-09 compliance.
        
        Detects backup/archive automation:
        - Backup jobs
        - Archive creation stages
        - Versioning automation
        - Retention policy management
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Backup/archive automation patterns
        retention_patterns = [
            r'backup.*authorization',
            r'archive.*data',
            r'create.*backup',
            r'retention.*policy',
            r'version.*history',
            r'historical.*data',
            r'backup.*job',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in retention_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Backup/archive job detected",
                        description=f"Found retention automation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure job maintains 3-year retention for authorization data."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-09.
        
        FRR-ADS-09 requires retaining historical versions of authorization data
        for 3 years. Evidence focuses on retention policies, backup configurations,
        version history, and storage settings.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Yes',
            'automation_feasibility': 'High - retention policies and versioning configurations are code-detectable in storage, backup, and version control systems',
            'azure_services': [
                'Azure Backup - Automated backup with retention policies',
                'Azure Storage - Blob versioning and soft delete for 3-year retention',
                'Azure Recovery Services - Vault-based retention management',
                'Azure Policy - Enforce retention policy compliance',
                'Azure Resource Graph - Query retention configurations across resources'
            ],
            'collection_methods': [
                'Query storage account retention policies (3 years/1095 days)',
                'Retrieve backup retention schedules from Recovery Services vaults',
                'Export blob versioning configurations from storage accounts',
                'Collect version history logs from authorization data repositories',
                'Review backup job history and retention compliance',
                'Audit soft delete and point-in-time restore configurations'
            ],
            'implementation_steps': [
                '1. Configure Azure Storage blob versioning with 3-year retention',
                '2. Set up Azure Backup with 1095-day (3-year) retention policy',
                '3. Enable soft delete on storage accounts (365-day minimum)',
                '4. Configure Recovery Services vault retention policies',
                '5. Implement automated backup schedules with retention enforcement',
                '6. Set up Azure Policy to validate 3-year retention compliance',
                '7. Configure version history tracking for authorization data'
            ]
        }
    
    def get_evidence_collection_queries(self) -> list:
        """
        Get specific queries for collecting FRR-ADS-09 evidence.
        
        Returns queries for retention policies, backup configurations,
        versioning settings, and historical data management.
        """
        return [
            {
                'name': 'Storage Account Retention Policies',
                'type': 'Azure Resource Graph',
                'query': '''resources
| where type == "microsoft.storage/storageaccounts"
| extend blobRetention = properties.blobServices.retentionPolicy
| extend retentionDays = toint(blobRetention.days)
| extend versioningEnabled = tobool(properties.blobServices.containerDeleteRetentionPolicy.enabled)
| where retentionDays >= 1095 or versioningEnabled == true
| project name, resourceGroup, subscriptionId, retentionDays, versioningEnabled, softDeleteEnabled=blobRetention.enabled, location''',
                'description': 'Query storage accounts with 3-year (1095-day) retention policies or versioning enabled for historical authorization data'
            },
            {
                'name': 'Azure Backup Retention Policies',
                'type': 'Azure Resource Graph',
                'query': '''resources
| where type == "microsoft.recoveryservices/vaults"
| extend backupPolicies = properties.backupPolicies
| mv-expand policy = backupPolicies
| extend retentionDaily = toint(policy.retentionPolicy.dailySchedule.retentionDuration.count)
| extend retentionYearly = toint(policy.retentionPolicy.yearlySchedule.retentionDuration.count)
| where retentionDaily >= 1095 or retentionYearly >= 3
| project name, resourceGroup, policyName=policy.name, retentionDaily, retentionYearly, location''',
                'description': 'Retrieve backup vaults with 3-year retention policies configured for authorization data backups'
            },
            {
                'name': 'Blob Versioning Configuration',
                'type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceType == "STORAGEACCOUNTS"
| where OperationName == "GetBlobServiceProperties" or OperationName == "SetBlobServiceProperties"
| extend versioningEnabled = tostring(properties_s.versioning)
| extend changeTracking = tostring(properties_s.changeFeed)
| where versioningEnabled == "true" or changeTracking == "true"
| project TimeGenerated, ResourceId, versioningEnabled, changeTracking, retentionDays=properties_s.deleteRetentionPolicy
| order by TimeGenerated desc''',
                'description': 'Monitor blob versioning configurations and change tracking for historical authorization data'
            },
            {
                'name': 'Backup Job History and Retention',
                'type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceProvider == "MICROSOFT.RECOVERYSERVICES"
| where Category == "AzureBackupReport"
| where OperationName == "Backup" or OperationName == "Restore"
| extend retentionDuration = toint(properties_s.retentionDuration)
| where retentionDuration >= 1095
| summarize BackupCount=count(), LastBackup=max(TimeGenerated) by ResourceId, retentionDuration
| project ResourceId, BackupCount, LastBackup, RetentionYears=retentionDuration/365, ComplianceStatus=iff(retentionDuration >= 1095, "Compliant", "Non-Compliant")''',
                'description': 'Track backup job execution and verify 3-year retention compliance for authorization data'
            },
            {
                'name': 'Version History Access Logs',
                'type': 'KQL',
                'query': '''StorageBlobLogs
| where OperationName == "GetBlobVersion" or OperationName == "ListBlobVersions"
| where Uri contains "authorization-data" or Uri contains "fedramp"
| extend versionId = tostring(properties_s.versionId)
| extend versionAge = datetime_diff("day", now(), TimeGenerated)
| where versionAge <= 1095
| summarize AccessCount=count(), LastAccessed=max(TimeGenerated) by AccountName, ContainerName, BlobName, versionId
| project AccountName, ContainerName, BlobName, VersionId=versionId, AccessCount, LastAccessed, VersionAgeDays=versionAge''',
                'description': 'Monitor access to historical versions of authorization data within 3-year retention window'
            },
            {
                'name': 'Soft Delete and Point-in-Time Restore',
                'type': 'Azure Resource Graph',
                'query': '''resources
| where type == "microsoft.storage/storageaccounts"
| extend softDeleteRetention = toint(properties.deleteRetentionPolicy.days)
| extend pointInTimeRestore = tobool(properties.restorePolicy.enabled)
| extend restoreDays = toint(properties.restorePolicy.days)
| where softDeleteRetention >= 365 or (pointInTimeRestore == true and restoreDays >= 365)
| project name, resourceGroup, subscriptionId, softDeleteDays=softDeleteRetention, pointInTimeRestoreEnabled=pointInTimeRestore, restoreDays, location''',
                'description': 'Verify soft delete and point-in-time restore configurations support 3-year retention requirement'
            }
        ]
    
    def get_evidence_artifacts(self) -> list:
        """
        Get list of evidence artifacts to collect for FRR-ADS-09.
        
        Returns artifacts demonstrating 3-year historical data retention.
        """
        return [
            {
                'name': 'Storage Retention Policy Configuration',
                'description': 'Export of storage account retention policies showing 3-year (1095-day) retention for authorization data blobs',
                'location': 'Azure Storage account blob service properties',
                'format': 'JSON export with retention duration, versioning settings, and soft delete configuration'
            },
            {
                'name': 'Azure Backup Retention Schedules',
                'description': 'Backup policy configurations from Recovery Services vaults showing 3-year retention schedules',
                'location': 'Azure Recovery Services vaults / Backup policies',
                'format': 'JSON export with daily/monthly/yearly retention counts and policy details'
            },
            {
                'name': 'Version History Logs',
                'description': 'Version history records for authorization data showing versions retained for 3 years',
                'location': 'Azure Storage blob version metadata / version control system',
                'format': 'CSV or JSON with version IDs, creation timestamps, retention status, access logs'
            },
            {
                'name': 'Backup Job Execution History',
                'description': 'Historical backup job logs demonstrating regular backup execution and successful retention',
                'location': 'Azure Monitor logs / Recovery Services vault reports',
                'format': 'Log export showing backup timestamps, job status, retention applied, data protected'
            },
            {
                'name': 'Azure Policy Compliance Report',
                'description': 'Policy compliance status report for retention policy enforcement across authorization data storage',
                'location': 'Azure Policy compliance dashboard',
                'format': 'PDF or JSON report showing compliant/non-compliant resources and policy definitions'
            },
            {
                'name': 'Historical Data Access Audit',
                'description': 'Audit logs showing access to historical versions of authorization data within 3-year retention window',
                'location': 'Azure Storage analytics logs / Azure Monitor',
                'format': 'CSV export with access timestamps, user identities, version accessed, operation type'
            }
        ]
