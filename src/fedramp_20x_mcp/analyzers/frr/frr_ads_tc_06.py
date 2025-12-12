"""
FRR-ADS-TC-06: Access Logging

_Trust centers_ MUST log access to _authorization data_ and store summaries of access for at least six months; such information, as it pertains to specific parties, SHOULD be made available upon request by those parties.

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_TC_06_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-TC-06: Access Logging
    
    **Official Statement:**
    _Trust centers_ MUST log access to _authorization data_ and store summaries of access for at least six months; such information, as it pertains to specific parties, SHOULD be made available upon request by those parties.
    
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
    
    FRR_ID = "FRR-ADS-TC-06"
    FRR_NAME = "Access Logging"
    FRR_STATEMENT = """_Trust centers_ MUST log access to _authorization data_ and store summaries of access for at least six months; such information, as it pertains to specific parties, SHOULD be made available upon request by those parties."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AU-2", "Event Logging"),
        ("AU-3", "Content of Audit Records"),
        ("AU-11", "Audit Record Retention"),
        ("SI-4", "System Monitoring"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-MLA-01",
    ]
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-TC-06 analyzer."""
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
        Analyze Python code for FRR-ADS-TC-06 compliance using AST.
        
        Detects access logging mechanisms:
        - Access logging functions
        - 6-month retention policies (180 days)
        - Log storage and retrieval
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for logging-related functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['log_access', 'access_log', 'audit_log', 'track_access', 'record_access']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access logging function detected",
                            description="Found function for logging access to authorization data",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure logs stored for at least 6 months and available upon request."
                        ))
                
                # Check for retention period constants/variables (180 days = 6 months)
                assignments = parser.find_nodes_by_type(tree.root_node, 'assignment')
                for assignment in assignments:
                    assign_text = parser.get_node_text(assignment, code_bytes)
                    if any(keyword in assign_text.lower() for keyword in ['retention', '180', 'six_month', '6_month']) and 'log' in assign_text.lower():
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Log retention period detected",
                            description="Found log retention configuration",
                            severity=Severity.INFO,
                            line_number=assignment.start_point[0] + 1,
                            code_snippet=assign_text.split('\n')[0],
                            recommendation="Verify retention period is at least 6 months (180 days)."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        logging_patterns = [
            r'log.*access',
            r'access.*log',
            r'6.*month.*retention',
            r'180.*day',
            r'audit.*log',
            r'retention.*period',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in logging_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Access logging pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify 6-month retention for access logs."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-TC-06 compliance using AST.
        
        Detects access logging mechanisms in C#.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['logaccess', 'accesslog', 'auditlog', 'trackaccess', 'recordaccess']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access logging method detected",
                            description="Found method for logging access to authorization data",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure logs stored for at least 6 months."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:LogAccess|AccessLog|AuditLog|TrackAccess|RetentionDays.*180)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Access logging reference detected",
                    description="Found access logging code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify 6-month log retention."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-TC-06 compliance using AST.
        
        Detects access logging mechanisms in Java.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['logaccess', 'accesslog', 'auditlog', 'trackaccess', 'recordaccess']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access logging method detected",
                            description="Found method for logging access to authorization data",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure logs stored for at least 6 months."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:logAccess|accessLog|auditLog|trackAccess|retentionDays.*180)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Access logging reference detected",
                    description="Found access logging code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify 6-month log retention."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-TC-06 compliance using AST.
        
        Detects access logging mechanisms in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check function declarations
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['logaccess', 'accesslog', 'auditlog', 'trackaccess', 'recordaccess']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access logging function detected",
                            description="Found function for logging access to authorization data",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure logs stored for at least 6 months."
                        ))
                
                # Check arrow functions
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['log', 'audit', 'track', '180']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Logging handler detected",
                            description="Found handler for access logging",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify log retention period."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:logAccess|accessLog|auditLog|trackAccess|retentionDays.*180)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Access logging reference detected",
                    description="Found access logging code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify 6-month log retention."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-TC-06 compliance.
        
        Detects Log Analytics workspace retention configuration for 6-month requirement.
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Log Analytics workspace with retention period
        log_analytics_pattern = r"resource\s+\w+\s+'Microsoft\.OperationalInsights/workspaces@"
        retention_pattern = r"retentionInDays\s*:\s*(\d+)"
        
        for i, line in enumerate(lines, 1):
            if re.search(log_analytics_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Log Analytics workspace detected",
                    description="Found Log Analytics workspace for access logging",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify retentionInDays is at least 180 days (6 months)."
                ))
            
            retention_match = re.search(retention_pattern, line)
            if retention_match:
                retention_days = int(retention_match.group(1))
                if retention_days < 180:
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Insufficient log retention period",
                        description=f"Log retention set to {retention_days} days (minimum 180 required)",
                        severity=Severity.WARNING,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Set retentionInDays to at least 180 days (6 months)."
                    ))
                else:
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Compliant log retention detected",
                        description=f"Log retention set to {retention_days} days (meets 180-day requirement)",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Log retention meets FRR-ADS-TC-06 requirement."
                    ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-TC-06 compliance.
        
        Detects log retention configuration for 6-month requirement.
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Log Analytics workspace
        log_analytics_pattern = r'resource\s+"azurerm_log_analytics_workspace"'
        retention_pattern = r'retention_in_days\s*=\s*(\d+)'
        
        for i, line in enumerate(lines, 1):
            if re.search(log_analytics_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Log Analytics workspace detected",
                    description="Found Log Analytics workspace for access logging",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify retention_in_days is at least 180 days (6 months)."
                ))
            
            retention_match = re.search(retention_pattern, line)
            if retention_match:
                retention_days = int(retention_match.group(1))
                if retention_days < 180:
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Insufficient log retention period",
                        description=f"Log retention set to {retention_days} days (minimum 180 required)",
                        severity=Severity.WARNING,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Set retention_in_days to at least 180 days (6 months)."
                    ))
                else:
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Compliant log retention detected",
                        description=f"Log retention set to {retention_days} days (meets 180-day requirement)",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Log retention meets FRR-ADS-TC-06 requirement."
                    ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-TC-06 compliance.
        
        NOT APPLICABLE: Access logging with 6-month retention is an application and
        infrastructure logging concern, not CI/CD pipeline concern. The requirement
        mandates logging access to authorization data and retaining logs, which is
        implemented through application code and logging infrastructure (Log Analytics,
        CloudWatch, etc.), not build/deployment automation.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-TC-06 compliance.
        
        NOT APPLICABLE: Access logging with 6-month retention is an application and
        infrastructure logging concern, not CI/CD pipeline concern. The requirement
        mandates logging access to authorization data and retaining logs, which is
        implemented through application code and logging infrastructure, not build
        or deployment automation.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-TC-06 compliance.
        
        NOT APPLICABLE: Access logging with 6-month retention is an application and
        infrastructure logging concern, not CI/CD pipeline concern. The requirement
        mandates logging access to authorization data and retaining logs, which is
        implemented through application code and logging infrastructure, not build
        or deployment automation.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Provide specific queries for collecting evidence of FRR-ADS-TC-06 compliance.
        
        Returns:
            List of queries for various tools and platforms to collect evidence
            of access logging with 6-month retention.
        """
        return [
            # Azure Monitor - Access logs for authorization data
            "AzureDiagnostics | where Category == 'AuditEvent' or Category == 'AccessLog' | where TimeGenerated >= ago(180d) | summarize count() by Resource, Category, bin(TimeGenerated, 1d) | order by TimeGenerated desc",
            
            # Application Insights - Authorization data access events
            "customEvents | where name contains 'AuthorizationData' or name contains 'AccessLog' | where timestamp >= ago(180d) | extend UserId = tostring(customDimensions.UserId), Resource = tostring(customDimensions.Resource) | project timestamp, name, UserId, Resource",
            
            # Log Analytics workspace retention configuration
            "Usage | summarize arg_max(TimeGenerated, *) by DataType | extend RetentionDays = toint(parse_json(tostring(parse_json(Properties).RetentionInDays))) | where RetentionDays < 180 | project DataType, RetentionDays, Workspace = _ResourceId",
            
            # Azure Activity Log - Log retention policy changes
            "AzureActivity | where OperationNameValue contains 'DIAGNOSTICSETTINGS' or OperationNameValue contains 'RETENTION' | where TimeGenerated >= ago(90d) | extend Caller = tostring(Caller), Resource = tostring(Resource) | project TimeGenerated, OperationNameValue, Caller, Resource, ActivityStatusValue",
            
            # Access summary query (6-month window)
            "AppRequests | where TimeGenerated >= ago(180d) | where Url contains 'authorization' or Url contains 'auth-data' | summarize AccessCount = count(), UniqueUsers = dcount(UserId), FirstAccess = min(TimeGenerated), LastAccess = max(TimeGenerated) by Url | order by AccessCount desc",
            
            # Retention compliance check
            "AzureDiagnostics | summarize OldestLog = min(TimeGenerated), NewestLog = max(TimeGenerated), LogCount = count() by Resource | extend RetentionDays = datetime_diff('day', now(), OldestLog) | where RetentionDays >= 180 | project Resource, RetentionDays, OldestLog, NewestLog, LogCount"
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        List artifacts that serve as evidence for FRR-ADS-TC-06 compliance.
        
        Returns:
            List of evidence artifacts including logs, configurations, and reports
            that demonstrate 6-month log retention and availability.
        """
        return [
            "Access log exports for last 6 months (authorization data access)",
            "Log Analytics workspace retention configuration (showing 180+ days)",
            "Access log summaries by party/user for 6-month period",
            "Log retention policy documentation",
            "Audit trail showing log retention enforcement",
            "Access request fulfillment records (logs provided to requesting parties)",
            "Monitoring alerts configuration for log retention violations",
            "Storage account configuration for archived logs (6+ months)",
            "Log backup and disaster recovery procedures",
            "Evidence of log availability upon party request (email/ticket records)"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provide recommendations for automating evidence collection for FRR-ADS-TC-06.
        
        Returns guidance on automated evidence collection for:
        - Access logging to authorization data
        - 6-month log retention
        - Log availability upon request
        """
        return {
            "frr_id": self.FRR_ID,
            "frr_name": self.FRR_NAME,
            "powershell_scripts": [
                {
                    "name": "verify_log_retention",
                    "description": "Verify Log Analytics workspace retention meets 6-month requirement",
                    "script": """
# Verify log retention configuration
$workspaceId = "<workspace-id>"
$resourceGroup = "<resource-group>"

# Get workspace retention settings
Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup | 
    Where-Object {$_.CustomerId -eq $workspaceId} | 
    Select-Object Name, RetentionInDays, @{N='Compliant';E={$_.RetentionInDays -ge 180}}

# Check oldest logs
$query = "AzureDiagnostics | summarize OldestLog = min(TimeGenerated) by Resource"
Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query
                    """
                },
                {
                    "name": "export_access_logs",
                    "description": "Export access logs for 6-month period",
                    "script": """
# Export access logs for last 6 months
$workspaceId = "<workspace-id>"
$startDate = (Get-Date).AddDays(-180).ToString("yyyy-MM-ddTHH:mm:ss")
$endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")

$query = @"
AzureDiagnostics 
| where TimeGenerated between (datetime($startDate) .. datetime($endDate))
| where Category == 'AuditEvent' or Category == 'AccessLog'
| project TimeGenerated, Resource, Category, OperationName, ResultType, CallerIpAddress
"@

$results = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query
$results.Results | Export-Csv -Path "access_logs_6months_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
                    """
                }
            ],
            "cli_commands": [
                {
                    "tool": "az",
                    "command": "az monitor log-analytics workspace show --workspace-name <workspace> --resource-group <rg> --query '{name:name, retentionInDays:retentionInDays, compliant:retentionInDays>=`180`}'",
                    "description": "Check Log Analytics workspace retention configuration"
                },
                {
                    "tool": "az",
                    "command": "az monitor log-analytics query --workspace <workspace-id> --analytics-query 'AzureDiagnostics | summarize OldestLog=min(TimeGenerated), RetentionDays=datetime_diff(\"day\", now(), min(TimeGenerated)) by Resource'",
                    "description": "Verify actual log retention in workspace"
                },
                {
                    "tool": "az",
                    "command": "az storage account show --name <storage> --resource-group <rg> --query '{name:name, blobRetentionDays:properties.deleteRetentionPolicy.days}'",
                    "description": "Check storage account retention for archived logs"
                }
            ],
            "api_queries": [
                {
                    "service": "Azure Monitor API",
                    "endpoint": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspace}",
                    "description": "Get Log Analytics workspace retention configuration"
                },
                {
                    "service": "Azure Monitor Logs API",
                    "endpoint": "POST https://api.loganalytics.io/v1/workspaces/{workspaceId}/query",
                    "description": "Query access logs for 6-month period",
                    "body": "{\"query\": \"AzureDiagnostics | where TimeGenerated >= ago(180d) | where Category == 'AccessLog'\"}"
                }
            ],
            "monitoring_queries": [
                {
                    "service": "Azure Monitor",
                    "query": "AzureDiagnostics | where Category == 'AuditEvent' or Category == 'AccessLog' | summarize LogCount = count(), OldestLog = min(TimeGenerated), NewestLog = max(TimeGenerated) by Resource | extend RetentionDays = datetime_diff('day', now(), OldestLog)",
                    "description": "Monitor log retention compliance across resources"
                },
                {
                    "service": "Azure Application Insights",
                    "query": "customEvents | where name == 'AccessLogRequest' or name == 'LogRetrieval' | summarize count() by name, bin(timestamp, 1d)",
                    "description": "Track log access requests from parties"
                }
            ],
            "collection_notes": [
                "Configure Log Analytics workspace with minimum 180-day retention",
                "Export access log summaries monthly for 6-month compliance window",
                "Maintain process for providing logs upon party request",
                "Document log retention policy in System Security Plan (SSP)",
                "Archive logs to long-term storage (Azure Blob, S3) after 6 months",
                "Implement automated alerts for log retention violations"
            ],
            "best_practices": [
                "Use Azure Log Analytics with 180+ day retention for access logs",
                "Configure diagnostic settings to capture all authorization data access",
                "Enable log archival to Azure Storage for long-term retention",
                "Implement automated log export for party-specific access summaries",
                "Set up Azure Monitor alerts for retention policy violations",
                "Use Azure Policy to enforce minimum retention across all workspaces",
                "Document log request fulfillment procedures for parties",
                "Maintain audit trail of all log access and exports",
                "Test log retrieval procedures quarterly",
                "Consider Azure Blob immutable storage for tamper-proof log archives"
            ]
        }
