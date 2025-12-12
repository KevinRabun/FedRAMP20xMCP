"""
FRR-ADS-TC-05: Access Inventory

_Trust centers_ MUST maintain an inventory and history of federal agency users or systems with access to _authorization data_ and MUST make this information available to FedRAMP without interruption. 

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


class FRR_ADS_TC_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-TC-05: Access Inventory
    
    **Official Statement:**
    _Trust centers_ MUST maintain an inventory and history of federal agency users or systems with access to _authorization data_ and MUST make this information available to FedRAMP without interruption. 
    
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
    
    FRR_ID = "FRR-ADS-TC-05"
    FRR_NAME = "Access Inventory"
    FRR_STATEMENT = """_Trust centers_ MUST maintain an inventory and history of federal agency users or systems with access to _authorization data_ and MUST make this information available to FedRAMP without interruption. """
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-2", "Account Management"),
        ("AU-2", "Event Logging"),
        ("AU-11", "Audit Record Retention"),
        ("SI-4", "System Monitoring"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-MLA-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-TC-05 analyzer."""
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
        Analyze Python code for FRR-ADS-TC-05 compliance using AST.
        
        Detects access inventory mechanisms:
        - User/system inventory tracking
        - Access history logging
        - Inventory reporting functions
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for inventory-related functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['inventory', 'track_access', 'access_history', 'user_list', 'system_list', 'access_log']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access inventory function detected",
                            description="Found function for tracking access inventory or history",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure inventory and history maintained and available to FedRAMP without interruption."
                        ))
                
                # Check for database/logging calls related to inventory
                call_expressions = parser.find_nodes_by_type(tree.root_node, 'call')
                for call in call_expressions:
                    call_text = parser.get_node_text(call, code_bytes).lower()
                    if any(keyword in call_text for keyword in ['log_access', 'record_access', 'save_inventory', 'track_user']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access tracking call detected",
                            description="Found call to track or log access",
                            severity=Severity.INFO,
                            line_number=call.start_point[0] + 1,
                            code_snippet=call_text.split('\n')[0],
                            recommendation="Verify inventory data is retained and accessible without interruption."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        inventory_patterns = [
            r'access.*inventory',
            r'user.*history',
            r'track.*access',
            r'inventory.*users',
            r'access.*log',
            r'maintain.*inventory',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in inventory_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Access inventory pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure inventory and history maintained without interruption."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-TC-05 compliance using AST.
        
        Detects access inventory mechanisms in C#.
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
                    
                    if any(keyword in method_lower for keyword in ['inventory', 'trackaccess', 'accesshistory', 'userlist', 'accesslog']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access inventory method detected",
                            description="Found method for tracking access inventory",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure inventory maintained and available to FedRAMP."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:Inventory|TrackAccess|AccessHistory|UserList|AccessLog)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Access inventory reference detected",
                    description="Found access inventory tracking",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify inventory maintained without interruption."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-TC-05 compliance using AST.
        
        Detects access inventory mechanisms in Java.
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
                    
                    if any(keyword in method_lower for keyword in ['inventory', 'trackaccess', 'accesshistory', 'userlist', 'accesslog']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access inventory method detected",
                            description="Found method for tracking access inventory",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure inventory maintained and available to FedRAMP."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:inventory|trackAccess|accessHistory|userList|accessLog)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Access inventory reference detected",
                    description="Found access inventory tracking",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify inventory maintained without interruption."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-TC-05 compliance using AST.
        
        Detects access inventory mechanisms in TypeScript/JavaScript.
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
                    
                    if any(keyword in func_lower for keyword in ['inventory', 'trackaccess', 'accesshistory', 'userlist', 'accesslog']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access inventory function detected",
                            description="Found function for tracking access inventory",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure inventory maintained and available to FedRAMP."
                        ))
                
                # Check arrow functions
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['inventory', 'track', 'history', 'access']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Access tracking handler detected",
                            description="Found handler for access inventory",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify inventory data retained."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:inventory|trackAccess|accessHistory|userList|accessLog)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Access inventory reference detected",
                    description="Found access inventory tracking",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify inventory maintained without interruption."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-TC-05 compliance.
        
        NOT APPLICABLE: Maintaining inventory and history of federal agency users/systems
        with access to authorization data is an application-level data management concern,
        not infrastructure configuration. The requirement mandates:
        
        1. Inventory tracking (application database/storage)
        2. Access history retention (application logging)
        3. Continuous availability to FedRAMP (application feature)
        
        These are implemented through application code, databases, and logging systems,
        not through infrastructure-as-code templates.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-TC-05 compliance.
        
        NOT APPLICABLE: Maintaining inventory and history of federal agency users/systems
        with access to authorization data is an application-level data management concern,
        not infrastructure configuration. The requirement mandates:
        
        1. Inventory tracking (application database/storage)
        2. Access history retention (application logging)
        3. Continuous availability to FedRAMP (application feature)
        
        These are implemented through application code, databases, and logging systems,
        not through infrastructure-as-code templates.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-TC-05 compliance.
        
        NOT APPLICABLE: Inventory and history of federal agency access is an application
        data management concern, not CI/CD pipeline concern. The requirement mandates
        maintaining and providing access to inventory data, which is an application
        feature, not a build or deployment automation concern.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-TC-05 compliance.
        
        NOT APPLICABLE: Inventory and history of federal agency access is an application
        data management concern, not CI/CD pipeline concern. The requirement mandates
        maintaining and providing access to inventory data, which is an application
        feature, not a build or deployment automation concern.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-TC-05 compliance.
        
        NOT APPLICABLE: Inventory and history of federal agency access is an application
        data management concern, not CI/CD pipeline concern. The requirement mandates
        maintaining and providing access to inventory data, which is an application
        feature, not a build or deployment automation concern.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Provide specific queries for collecting evidence of FRR-ADS-TC-05 compliance.
        
        Returns:
            List of queries for various tools and platforms to collect evidence
            of access inventory and history maintenance.
        """
        return [
            # Azure Resource Graph - Query resources with access tracking
            "Resources | where type =~ 'Microsoft.Web/sites' or type =~ 'Microsoft.Sql/servers/databases' | extend accessTracking = properties.accessTracking | project name, resourceGroup, type, accessTracking",
            
            # Azure Monitor - Access inventory logs
            "AppRequests | extend UserId = tostring(customDimensions.UserId), SystemId = tostring(customDimensions.SystemId) | where isnotempty(UserId) or isnotempty(SystemId) | summarize AccessCount = count(), FirstAccess = min(TimeGenerated), LastAccess = max(TimeGenerated) by UserId, SystemId | order by LastAccess desc",
            
            # Application Insights - Inventory maintenance events
            "customEvents | where name in ('InventoryUpdated', 'AccessRecorded', 'UserAdded', 'SystemAdded') | extend EntityId = tostring(customDimensions.EntityId), EntityType = tostring(customDimensions.EntityType) | project timestamp, name, EntityId, EntityType",
            
            # Azure AD audit logs - Federal agency user access
            "AuditLogs | where Category == 'UserManagement' or Category == 'ApplicationManagement' | extend Initiator = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].displayName), Action = OperationName | where Target contains 'FedRAMP' or Target contains 'Federal' | project TimeGenerated, Action, Initiator, Target",
            
            # Activity logs - System access changes
            "AzureActivity | where CategoryValue == 'Administrative' and OperationNameValue contains 'ROLEASSIGNMENTS' | extend Caller = tostring(Caller), Resource = tostring(Resource), Status = tostring(ActivityStatusValue) | project TimeGenerated, OperationNameValue, Caller, Resource, Status",
            
            # Custom application logs - Inventory queries
            "traces | where message contains 'inventory' or message contains 'access history' or message contains 'federal agency' | extend severity = tostring(severityLevel) | summarize count() by severity, bin(timestamp, 1d)"
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        List artifacts that serve as evidence for FRR-ADS-TC-05 compliance.
        
        Returns:
            List of evidence artifacts including documents, logs, and reports
            that demonstrate inventory and history maintenance.
        """
        return [
            "Access inventory database export (current federal agency users and systems)",
            "Access history reports (last 3 years minimum)",
            "User provisioning and deprovisioning logs",
            "System access grant and revocation audit trail",
            "Inventory maintenance schedule and procedures documentation",
            "FedRAMP access reports showing continuous availability",
            "Database retention policy configuration for inventory data",
            "Backup and disaster recovery plan for inventory system",
            "Monitoring dashboards showing inventory system uptime and availability",
            "Access control matrix for federal agency users and systems"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provide recommendations for automating evidence collection for FRR-ADS-TC-05.
        
        Returns guidance on automated evidence collection for:
        - Access inventory tracking
        - History maintenance and retention
        - Continuous availability to FedRAMP
        """
        return {
            "frr_id": self.FRR_ID,
            "frr_name": self.FRR_NAME,
            "powershell_scripts": [
                {
                    "name": "export_access_inventory",
                    "description": "Export current inventory of federal agency access",
                    "script": """
# Export access inventory for federal agencies
$databaseServer = "<database-server>"
$databaseName = "<database-name>"

# Connect to inventory database
$query = @"
SELECT 
    UserId, 
    UserName, 
    SystemId, 
    SystemName, 
    AccessLevel, 
    GrantedDate, 
    LastAccessDate,
    FederalAgency
FROM AccessInventory
WHERE FederalAgency IS NOT NULL
ORDER BY LastAccessDate DESC
"@

Invoke-Sqlcmd -ServerInstance $databaseServer -Database $databaseName -Query $query | Export-Csv -Path "access_inventory_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
                    """
                },
                {
                    "name": "check_inventory_availability",
                    "description": "Check inventory system availability and uptime",
                    "script": """
# Check inventory system availability
$inventoryEndpoint = "<inventory-api-endpoint>"
$resourceGroup = "<resource-group>"

# Check web app status
Get-AzWebApp -ResourceGroupName $resourceGroup | Where-Object {$_.Name -like '*inventory*'} | Select-Object Name, State, AvailabilityState, @{N='Uptime';E={(Get-AzMetric -ResourceId $_.Id -MetricName 'Http2xx' -TimeGrain 01:00:00).Data}}

# Test endpoint availability
Test-NetConnection -ComputerName $inventoryEndpoint -Port 443
                    """
                }
            ],
            "cli_commands": [
                {
                    "tool": "az",
                    "command": "az sql db show --server <server> --name <db> --resource-group <rg> --query '{name:name, status:status, earliestRestoreDate:earliestRestoreDate, retentionDays:longTermRetentionBackupResourceId}'",
                    "description": "Check inventory database status and retention"
                },
                {
                    "tool": "az",
                    "command": "az monitor metrics list --resource <inventory-resource-id> --metric 'Availability' --interval PT1H --query 'value[].timeseries[].data[].{Time:timeStamp, Availability:average}'",
                    "description": "Check inventory system availability metrics"
                },
                {
                    "tool": "az",
                    "command": "az sql db audit-policy show --server <server> --name <db> --resource-group <rg>",
                    "description": "Verify audit policy for inventory database"
                }
            ],
            "api_queries": [
                {
                    "service": "Azure SQL Database API",
                    "endpoint": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Sql/servers/{server}/databases/{database}",
                    "description": "Get inventory database configuration and retention settings"
                },
                {
                    "service": "Azure Monitor API",
                    "endpoint": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/providers/Microsoft.Insights/metrics",
                    "description": "Get inventory system availability metrics"
                }
            ],
            "monitoring_queries": [
                {
                    "service": "Azure Monitor",
                    "query": "AzureDiagnostics | where ResourceType == 'SERVERS/DATABASES' and Category == 'SQLSecurityAuditEvents' | where Statement contains 'AccessInventory' | summarize count() by OperationName, bin(TimeGenerated, 1h)",
                    "description": "Track inventory database access and modifications"
                },
                {
                    "service": "Azure Application Insights",
                    "query": "availabilityResults | where name contains 'inventory' | summarize AvailabilityRate = avg(success) * 100, AvgDuration = avg(duration) by bin(timestamp, 1h)",
                    "description": "Monitor inventory system uptime and availability"
                }
            ],
            "collection_notes": [
                "Export access inventory daily to demonstrate continuous maintenance",
                "Retain access history for minimum 3 years per FedRAMP requirements",
                "Document inventory update frequency and procedures",
                "Maintain backup copies of inventory data for disaster recovery",
                "Monitor inventory system availability to ensure no interruption",
                "Implement automated alerts for inventory system downtime"
            ],
            "best_practices": [
                "Use Azure SQL Database with geo-replication for high availability",
                "Configure automated backups with long-term retention (3+ years)",
                "Implement real-time replication to secondary region",
                "Set up Azure Monitor alerts for inventory system health",
                "Use Application Insights to track inventory access patterns",
                "Maintain audit trail of all inventory modifications",
                "Document data retention policies in System Security Plan (SSP)",
                "Test disaster recovery procedures quarterly",
                "Provide FedRAMP read-only access to live inventory system",
                "Implement automated reporting for FedRAMP access requests"
            ]
        }
