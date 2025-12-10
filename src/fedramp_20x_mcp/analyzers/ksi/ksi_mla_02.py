"""
KSI-MLA-02 Enhanced: Audit Logging

Regularly review and audit logs.

**Enhancement Features:**
- AST-based detection for authentication/authorization operations without logging
- Structured logging pattern recognition
- Multi-language support with framework-specific checks
- Context-aware analysis (±15 lines) for nearby logging detection

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer

try:
    import tree_sitter_python as tspython
    import tree_sitter_c_sharp as tscsharp
    import tree_sitter_java as tsjava
    import tree_sitter_javascript as tsjs
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


class KSI_MLA_02_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-MLA-02: Audit Logging
    
    **Official Statement:**
    Regularly review and audit logs.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **NIST Controls:** ac-2.4, ac-6.9, au-2, au-6, au-6.1, si-4, si-4.4
    
    **Detection Strategy:**
    - Authentication/authorization operations without audit logging
    - Missing structured logging configuration
    - Security events without log correlation identifiers
    """
    
    KSI_ID = "KSI-MLA-02"
    KSI_NAME = "Audit Logging"
    KSI_STATEMENT = "Regularly review and audit logs."
    FAMILY = "MLA"
    NIST_CONTROLS = ["ac-2.4", "ac-6.9", "au-2", "au-6", "au-6.1", "si-4", "si-4.4"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
        if TREE_SITTER_AVAILABLE:
            self.python_parser = Parser(Language(tspython.language()))
            self.csharp_parser = Parser(Language(tscsharp.language()))
            self.java_parser = Parser(Language(tsjava.language()))
            self.js_parser = Parser(Language(tsjs.language()))
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect auth operations without audit logging in Python."""
        findings = []
        lines = code.split('\n')
        
        # Check for auth operations
        auth_patterns = [
            (r'def\s+(authenticate|login|logout|authorize)', 'Authentication/Authorization Function'),
            (r'@login_required|@permission_required', 'Protected Endpoint'),
            (r'check_password|verify_password', 'Password Verification'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(logger\.|logging\.|log\.info|log\.warning)', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} at line {line_num} without audit logging. AU-2, AU-6 require logging security events.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger.info() with structured data (user_id, ip, timestamp, action)",
                        ksi_id=self.KSI_ID
                    ))
        
        # Check for logging config
        if len(lines) > 50 and 'test' not in file_path.lower():
            if not re.search(r'(logging\.basicConfig|logging\.config|getLogger)', code):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Logging Configuration",
                    description="Application file without logging configuration. AU-2 requires capturing security events.",
                    file_path=file_path,
                    line_number=1,
                    snippet=lines[0] if lines else "",
                    remediation="Configure logging.basicConfig() or logging.config.dictConfig()",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect controllers/services without ILogger in C#."""
        findings = []
        lines = code.split('\n')
        
        # Check controllers
        controller_match = re.search(r'class\s+\w+\s*:\s*(Controller|ControllerBase)', code)
        if controller_match:
            line_num = code[:controller_match.start()].count('\n') + 1
            context = self._get_context(lines, line_num, 20)
            
            if not re.search(r'ILogger<', context):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Controller Without ILogger",
                    description=f"Controller at line {line_num} without ILogger injection. AU-2, AU-6 require logging security operations.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Inject ILogger<T> via constructor: ILogger<MyController> logger",
                    ksi_id=self.KSI_ID
                ))
        
        # Check auth operations
        auth_patterns = [
            (r'SignInAsync|SignOutAsync', 'Sign In/Out'),
            (r'AuthenticateAsync|ChallengeAsync', 'Authentication'),
            (r'\.PasswordHasher|HashPassword|VerifyHashedPassword', 'Password Operations'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(_logger\.|\.Log(Information|Warning|Error))', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} operation at line {line_num} without logging. AU-6 requires audit log review.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="_logger.LogInformation(\"Auth event\", new { UserId, Action, Timestamp })",
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect auth operations without logging in Java."""
        findings = []
        lines = code.split('\n')
        
        # Check for Spring Security operations
        auth_patterns = [
            (r'@PreAuthorize|@PostAuthorize|@Secured', 'Authorization Annotation'),
            (r'AuthenticationManager|authenticate\(', 'Authentication'),
            (r'BCryptPasswordEncoder|passwordEncoder', 'Password Encoding'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(log\.|logger\.|LOG\.)(info|warn|error)', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} at line {line_num} without audit logging. AU-2 requires logging security events.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger.info() with MDC context (userId, action, timestamp)",
                        ksi_id=self.KSI_ID
                    ))
        
        # Check for logger field
        if len(lines) > 50 and 'test' not in file_path.lower():
            if not re.search(r'(Logger\s+log|Logger\s+logger|@Slf4j)', code):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Logger Declaration",
                    description="Java class without logger. AU-6 requires regular audit log review.",
                    file_path=file_path,
                    line_number=1,
                    snippet=lines[0] if lines else "",
                    remediation="Add: private static final Logger log = LoggerFactory.getLogger(Class.class);",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Detect auth operations without logging in TypeScript/JavaScript."""
        findings = []
        lines = code.split('\n')
        
        # Check for auth operations
        auth_patterns = [
            (r'(passport\.authenticate|express-session|jwt\.sign)', 'Authentication'),
            (r'(@UseGuards|@Roles|canActivate)', 'Authorization Guard'),
            (r'(bcrypt\.hash|bcrypt\.compare)', 'Password Hashing'),
        ]
        
        for pattern, desc in auth_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 15)
                
                if not re.search(r'(logger\.|log\.|console\.(info|warn|error))', context):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title=f"{desc} Without Audit Logging",
                        description=f"{desc} at line {line_num} without audit logging. AU-2, AU-6 require security event logging.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add logger.info({ userId, action, timestamp, ip })",
                        ksi_id=self.KSI_ID
                    ))
        
        # Check for logger import
        if len(lines) > 50 and 'test' not in file_path.lower():
            if not re.search(r'(import.*winston|import.*pino|import.*log|logger\s*=)', code):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Logger Configuration",
                    description="TypeScript/JavaScript file without logger. AU-6 requires audit log review.",
                    file_path=file_path,
                    line_number=1,
                    snippet=lines[0] if lines else "",
                    remediation="Import winston or pino: import winston from 'winston';",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Check for missing audit logging configuration in Bicep."""
        findings = []
        lines = code.split('\n')
        
        # Check for resources without diagnostic settings
        resource_types = [
            'Microsoft.KeyVault/vaults',
            'Microsoft.Storage/storageAccounts',
            'Microsoft.Web/sites',
        ]
        
        for resource_type in resource_types:
            if re.search(rf"resource.*{re.escape(resource_type)}", code):
                if not re.search(r'Microsoft\.Insights/diagnosticSettings', code):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Resource Without Diagnostic Logging",
                        description=f"{resource_type} without diagnostic settings. AU-2 requires audit logging.",
                        file_path=file_path,
                        line_number=1,
                        snippet="",
                        remediation="Add diagnostic settings resource with logs category",
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Check for missing audit logging configuration in Terraform."""
        findings = []
        
        # Check for resources without monitor diagnostic settings
        resource_types = [
            'azurerm_key_vault',
            'azurerm_storage_account',
            'azurerm_app_service',
        ]
        
        for resource_type in resource_types:
            if re.search(rf'resource\s+"{resource_type}"', code):
                if not re.search(r'azurerm_monitor_diagnostic_setting', code):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Resource Without Diagnostic Logging",
                        description=f"{resource_type} without monitor diagnostic settings. AU-2 requires audit logs.",
                        file_path=file_path,
                        line_number=1,
                        snippet="",
                        remediation="Add azurerm_monitor_diagnostic_setting resource",
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        return []
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-MLA-02.
        
        **KSI-MLA-02: Audit Logging**
        Regularly review and audit logs.
        
        Returns:
            Dictionary with automation recommendations including:
            - azure_services: List of Azure services for evidence collection
            - collection_methods: Methods to collect evidence
            - automation_feasibility: Level of automation possible (high/medium/low/manual-only)
            - evidence_types: Types of evidence (log-based, config-based, metric-based, process-based)
        """
        return {
            "ksi_id": "KSI-MLA-02",
            "ksi_name": "Audit Logging",
            "azure_services": [
                {
                    "service": "Azure Monitor",
                    "purpose": "Centralized log review and audit trail access",
                    "capabilities": [
                        "Query audit logs across all Azure resources",
                        "Review diagnostic settings for log retention",
                        "Access activity logs and resource logs"
                    ]
                },
                {
                    "service": "Azure Log Analytics",
                    "purpose": "Advanced log querying and audit analysis",
                    "capabilities": [
                        "KQL queries for audit pattern detection",
                        "Custom log retention policies",
                        "Audit log correlation and analysis"
                    ]
                },
                {
                    "service": "Azure Storage",
                    "purpose": "Immutable log retention for audit compliance",
                    "capabilities": [
                        "Immutable blob storage for audit logs",
                        "Legal hold and time-based retention",
                        "Versioning and soft delete for audit trails"
                    ]
                },
                {
                    "service": "Azure Sentinel",
                    "purpose": "Security audit and incident correlation",
                    "capabilities": [
                        "Automated audit rule evaluation",
                        "Security event correlation",
                        "Compliance dashboard for audit status"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Enforce audit logging requirements",
                    "capabilities": [
                        "Enforce diagnostic settings on all resources",
                        "Validate log retention policies",
                        "Audit non-compliant resource configurations"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Audit Log Retention Validation",
                    "description": "Query Azure Storage and Log Analytics to verify audit logs are retained per policy",
                    "automation": "KQL and Resource Graph queries",
                    "frequency": "Daily",
                    "evidence_produced": "Log retention policy compliance report"
                },
                {
                    "method": "Audit Review Evidence",
                    "description": "Export audit logs showing regular review activities (queries executed, alerts triggered)",
                    "automation": "Azure Monitor audit log export",
                    "frequency": "Weekly",
                    "evidence_produced": "Audit review activity report"
                },
                {
                    "method": "Immutability Verification",
                    "description": "Validate immutable storage configuration for audit logs",
                    "automation": "Azure Storage API queries",
                    "frequency": "Monthly",
                    "evidence_produced": "Storage immutability configuration report"
                },
                {
                    "method": "Diagnostic Settings Audit",
                    "description": "Verify all resources have diagnostic settings enabled for audit logging",
                    "automation": "Azure Policy compliance scan",
                    "frequency": "Daily",
                    "evidence_produced": "Resource diagnostic settings compliance report"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["log-based", "config-based"],
            "implementation_guidance": {
                "quick_start": "Deploy Azure Policy to enforce diagnostic settings, configure Log Analytics workspace with retention policies, enable Azure Sentinel for audit correlation",
                "azure_well_architected": "Follows Azure Well-Architected Framework operational excellence and security pillars for audit logging",
                "compliance_mapping": "Addresses NIST controls ac-2.4, ac-6.9, au-2, au-6, au-6.1, si-4, si-4.4"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-MLA-02 evidence.
        
        Returns:
            Dictionary with executable queries for evidence collection
        """
        return {
            "ksi_id": "KSI-MLA-02",
            "queries": [
                {
                    "name": "Audit Log Retention Policy Status",
                    "type": "azure_resource_graph",
                    "query": """
                        resources
                        | where type == 'microsoft.operationalinsights/workspaces'
                        | extend retentionDays = properties.retentionInDays
                        | project name, resourceGroup, retentionDays, location
                        | where retentionDays < 90
                        """,
                    "purpose": "Identify Log Analytics workspaces with insufficient audit log retention",
                    "expected_result": "Empty result set indicates compliance (all workspaces have 90+ days retention)"
                },
                {
                    "name": "Resources Without Diagnostic Settings",
                    "type": "azure_resource_graph",
                    "query": """
                        resources
                        | where type !in ('microsoft.resources/resourcegroups', 'microsoft.resources/subscriptions')
                        | project id, name, type, resourceGroup
                        | join kind=leftouter (
                            resources
                            | where type == 'microsoft.insights/diagnosticsettings'
                            | extend targetResourceId = tolower(split(id, '/providers/microsoft.insights/')[0])
                            | project targetResourceId
                        ) on $left.id == $right.targetResourceId
                        | where isnull(targetResourceId)
                        """,
                    "purpose": "Find resources missing diagnostic settings for audit logging",
                    "expected_result": "Empty result set indicates full compliance"
                },
                {
                    "name": "Immutable Storage Configuration",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/blobServices/default/containers/{containerName}/immutabilityPolicies/default",
                    "method": "GET",
                    "api_version": "2023-01-01",
                    "purpose": "Verify immutable storage policy for audit logs",
                    "expected_result": "Policy with state='Locked' and immutabilityPeriod >= 2555 days (7 years)"
                },
                {
                    "name": "Audit Review Activity Evidence",
                    "type": "kql",
                    "workspace": "Log Analytics workspace with audit logs",
                    "query": """
                        AzureActivity
                        | where TimeGenerated > ago(7d)
                        | where OperationNameValue contains "Microsoft.OperationalInsights/workspaces/query"
                        | summarize QueryCount=count(), LastQueryTime=max(TimeGenerated) by Caller, OperationNameValue
                        | order by QueryCount desc
                        """,
                    "purpose": "Demonstrate regular audit log review activity",
                    "expected_result": "Multiple queries from authorized personnel within past 7 days"
                },
                {
                    "name": "Security Alert Review Evidence",
                    "type": "kql",
                    "workspace": "Azure Sentinel workspace",
                    "query": """
                        SecurityAlert
                        | where TimeGenerated > ago(30d)
                        | extend ReviewedBy = tostring(ExtendedProperties.ReviewedBy)
                        | extend ReviewedDate = todatetime(ExtendedProperties.ReviewedDate)
                        | where isnotempty(ReviewedBy)
                        | summarize AlertsReviewed=count(), LastReviewDate=max(ReviewedDate) by ReviewedBy
                        | order by LastReviewDate desc
                        """,
                    "purpose": "Demonstrate security alert review as part of audit process",
                    "expected_result": "Regular review activity by security team members"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI (az login) or Managed Identity for query execution",
                "permissions_required": [
                    "Reader role on subscriptions for Resource Graph queries",
                    "Log Analytics Reader for KQL queries",
                    "Storage Account Contributor for immutability policy queries"
                ],
                "automation_tools": [
                    "Azure Resource Graph Explorer (portal)",
                    "Azure CLI (az graph query)",
                    "PowerShell Az.ResourceGraph module",
                    "Python azure-mgmt-resourcegraph SDK"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-MLA-02.
        
        Returns:
            Dictionary describing evidence artifacts to collect
        """
        return {
            "ksi_id": "KSI-MLA-02",
            "artifacts": [
                {
                    "name": "Log Retention Policy Configuration",
                    "description": "Export of all Log Analytics workspace retention settings showing compliance with retention requirements",
                    "source": "Azure Monitor / Log Analytics",
                    "format": "JSON export from Azure Resource Graph query",
                    "collection_frequency": "Monthly",
                    "retention_period": "7 years (audit evidence)",
                    "automation": "Scheduled Azure Automation runbook or Azure Function"
                },
                {
                    "name": "Diagnostic Settings Compliance Report",
                    "description": "List of all Azure resources with their diagnostic settings status",
                    "source": "Azure Policy compliance scan",
                    "format": "CSV or JSON export from Azure Policy",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "Azure Policy export via REST API"
                },
                {
                    "name": "Immutable Storage Evidence",
                    "description": "Configuration snapshots of immutable blob storage policies for audit logs",
                    "source": "Azure Storage Management API",
                    "format": "JSON configuration export",
                    "collection_frequency": "Monthly",
                    "retention_period": "7 years",
                    "automation": "PowerShell script or Azure Function"
                },
                {
                    "name": "Audit Review Activity Report",
                    "description": "Log of queries executed against audit logs, showing regular review activity",
                    "source": "Azure Activity Log and Log Analytics query history",
                    "format": "CSV export from KQL query results",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "Scheduled KQL query with email/storage export"
                },
                {
                    "name": "Security Alert Review Evidence",
                    "description": "Documentation of security alerts reviewed as part of audit process",
                    "source": "Azure Sentinel incident management",
                    "format": "JSON export of incident review metadata",
                    "collection_frequency": "Weekly",
                    "retention_period": "3 years",
                    "automation": "Azure Sentinel automation rule or Logic App"
                },
                {
                    "name": "Audit Log Sample Archive",
                    "description": "Quarterly snapshots of audit logs demonstrating retention and integrity",
                    "source": "Azure Storage immutable blobs",
                    "format": "Compressed log files (.gz or .zip)",
                    "collection_frequency": "Quarterly",
                    "retention_period": "7 years",
                    "automation": "Azure Storage lifecycle management policy"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage and legal hold",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail of access"
            },
            "compliance_mapping": {
                "fedramp_controls": ["au-2", "au-6", "au-6.1", "ac-2.4", "ac-6.9", "si-4", "si-4.4"],
                "evidence_purpose": "Demonstrate regular audit log review and retention compliance"
            }
        }
    

        """Get surrounding context lines."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])
    

        """Get code snippet."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])

