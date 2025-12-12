"""
FRR-ADS-08: Trust Center Migration Notification

Providers MUST notify all necessary parties when migrating to a _trust center_ and MUST provide information in their existing USDA Connect Community Portal secure folders explaining how to use the _trust center_ to obtain _authorization data_.

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


class FRR_ADS_08_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-08: Trust Center Migration Notification
    
    **Official Statement:**
    Providers MUST notify all necessary parties when migrating to a _trust center_ and MUST provide information in their existing USDA Connect Community Portal secure folders explaining how to use the _trust center_ to obtain _authorization data_.
    
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
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-ADS-08"
    FRR_NAME = "Trust Center Migration Notification"
    FRR_STATEMENT = """Providers MUST notify all necessary parties when migrating to a _trust center_ and MUST provide information in their existing USDA Connect Community Portal secure folders explaining how to use the _trust center_ to obtain _authorization data_."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SA-9", "External System Services"),
        ("SI-12", "Information Management and Retention"),
        ("CP-2", "Contingency Plan"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-08 analyzer."""
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
        Analyze Python code for FRR-ADS-08 compliance.
        
        Detects trust center migration notification mechanisms:
        - Migration notification systems (send_email, notify_users, etc.)
        - Communication/announcement patterns
        - Documentation update mechanisms
        
        Uses AST for accurate detection with regex fallback.
        """
        findings = []
        
        # AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Find function calls related to migration notifications
                notification_functions = [
                    'send_email', 'send_notification', 'notify_users', 'notify_stakeholders',
                    'send_announcement', 'notify_parties', 'send_migration_notice',
                    'broadcast_migration', 'email_notification', 'alert_users'
                ]
                
                for func_name in notification_functions:
                    calls = parser.find_function_calls(tree.root_node, func_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration notification function detected",
                            description=f"Found notification function: {func_name}()",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this notification is sent to all necessary parties when migrating to trust center."
                        ))
                
                # Check string literals for migration-related content
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                migration_keywords = ['migration', 'trust center', 'usda connect', 'portal update', 'authorization data']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in migration_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration-related string content detected",
                            description="Found migration/trust center reference in string",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify this content includes migration notification information."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback if AST fails
        lines = code.split('\n')
        notification_patterns = [
            r'send.*email.*migration',
            r'notify.*migration',
            r'trust.*center.*migration',
            r'send.*notification',
            r'migration.*announcement',
            r'migration.*communication',
            r'usda.*connect.*portal',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in notification_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Migration notification pattern detected",
                        description=f"Found notification pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure notification sent to all necessary parties when migrating to trust center."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-08 compliance using AST.
        
        Detects migration notification methods:
        - Email/notification service calls
        - Migration announcement methods
        - Portal documentation update mechanisms
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Find notification method calls
                notification_methods = [
                    'SendEmail', 'SendNotification', 'NotifyUsers', 'NotifyStakeholders',
                    'SendAnnouncement', 'EmailService', 'NotificationService',
                    'BroadcastMigration', 'AlertUsers', 'SendMigrationNotice'
                ]
                
                for method_name in notification_methods:
                    calls = parser.find_function_calls(tree.root_node, method_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration notification method detected",
                            description=f"Found notification method: {method_name}",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this notification reaches all necessary parties during trust center migration."
                        ))
                
                # Check string literals for migration keywords
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                migration_keywords = ['migration', 'trust center', 'usda connect', 'portal', 'authorization data']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in migration_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration-related string detected",
                            description="Found migration/trust center reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify this content includes migration notification information."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(SendEmail|SendNotification|NotifyUsers|NotifyStakeholders)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Notification method pattern detected",
                    description="Found potential notification method",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure notification sent to all necessary parties when migrating to trust center."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-08 compliance using AST.
        
        Detects migration notification mechanisms:
        - Email/notification service method calls
        - Migration announcement patterns
        - Portal documentation updates
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Find notification method calls
                notification_methods = [
                    'sendEmail', 'sendNotification', 'notifyUsers', 'notifyStakeholders',
                    'sendAnnouncement', 'emailService', 'notificationService',
                    'broadcastMigration', 'alertUsers', 'sendMigrationNotice'
                ]
                
                for method_name in notification_methods:
                    calls = parser.find_function_calls(tree.root_node, method_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration notification method detected",
                            description=f"Found notification method: {method_name}()",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this notification reaches all necessary parties during trust center migration."
                        ))
                
                # Check string literals for migration keywords
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                migration_keywords = ['migration', 'trust center', 'usda connect', 'portal', 'authorization data']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in migration_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration-related string detected",
                            description="Found migration/trust center reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify this content includes migration notification information."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(sendEmail|sendNotification|notifyUsers|notifyStakeholders)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Notification method pattern detected",
                    description="Found potential notification method",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure notification sent to all necessary parties when migrating to trust center."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-08 compliance using AST.
        
        Detects migration notification mechanisms:
        - Email/notification API calls
        - Migration announcement functions
        - Portal documentation update logic
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Find notification function calls
                notification_functions = [
                    'sendEmail', 'sendNotification', 'notifyUsers', 'notifyStakeholders',
                    'sendAnnouncement', 'emailService', 'notificationService',
                    'broadcastMigration', 'alertUsers', 'sendMigrationNotice'
                ]
                
                for func_name in notification_functions:
                    calls = parser.find_function_calls(tree.root_node, func_name, code_bytes)
                    for call_node in calls:
                        line_num = call_node.start_point[0] + 1
                        call_text = parser.get_node_text(call_node, code_bytes)
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration notification function detected",
                            description=f"Found notification function: {func_name}()",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=call_text,
                            recommendation="Ensure this notification reaches all necessary parties during trust center migration."
                        ))
                
                # Check string literals for migration keywords
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                migration_keywords = ['migration', 'trust center', 'usda connect', 'portal', 'authorization data']
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in migration_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Migration-related string detected",
                            description="Found migration/trust center reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Verify this content includes migration notification information."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(sendEmail|sendNotification|notifyUsers|notifyStakeholders)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Notification function pattern detected",
                    description="Found potential notification function",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure notification sent to all necessary parties when migrating to trust center."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-08 compliance.
        
        Note: FRR-ADS-08 requires notifying parties when migrating to trust center
        and providing USDA portal documentation. This is a process-level requirement
        focused on communication and documentation, not infrastructure provisioning.
        
        Bicep defines infrastructure resources, not notification processes or
        documentation content, so this analyzer is not applicable for this requirement.
        
        Return: Empty findings list (requirement is not infrastructure-related)
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-08 compliance.
        
        Note: FRR-ADS-08 requires notifying parties when migrating to trust center
        and providing USDA portal documentation. This is a process-level requirement
        focused on communication and documentation, not infrastructure provisioning.
        
        Terraform defines infrastructure resources, not notification processes or
        documentation content, so this analyzer is not applicable for this requirement.
        
        Return: Empty findings list (requirement is not infrastructure-related)
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-08 compliance.
        
        Detects migration notification automation:
        - Email notification steps
        - Stakeholder notification actions
        - Portal documentation update workflows
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Notification automation patterns
        notification_patterns = [
            r'send.*email',
            r'notify.*stakeholder',
            r'notification.*action',
            r'email.*notification',
            r'migration.*notice',
            r'portal.*update',
            r'usda.*connect',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in notification_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Migration notification workflow detected",
                        description=f"Found notification automation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure workflow notifies all necessary parties during trust center migration."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-08 compliance.
        
        Detects migration notification automation:
        - Email notification tasks
        - Stakeholder notification steps
        - Portal documentation update tasks
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Notification automation patterns
        notification_patterns = [
            r'send.*email',
            r'notify.*stakeholder',
            r'notification.*task',
            r'email.*notification',
            r'migration.*notice',
            r'portal.*update',
            r'usda.*connect',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in notification_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Migration notification pipeline detected",
                        description=f"Found notification automation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure pipeline notifies all necessary parties during trust center migration."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-08 compliance.
        
        Detects migration notification automation:
        - Email notification jobs
        - Stakeholder notification stages
        - Portal documentation update jobs
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Notification automation patterns
        notification_patterns = [
            r'send.*email',
            r'notify.*stakeholder',
            r'notification.*job',
            r'email.*notification',
            r'migration.*notice',
            r'portal.*update',
            r'usda.*connect',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in notification_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Migration notification job detected",
                        description=f"Found notification automation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure job notifies all necessary parties during trust center migration."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-08.
        
        FRR-ADS-08 requires notifying parties when migrating to trust center
        and providing USDA Connect portal documentation. Evidence focuses on
        notification logs, communication records, and portal content.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Medium - notification systems and portal updates may be automated, but actual migration communication is process-level',
            'azure_services': [
                'Azure Communication Services - Email/SMS notification tracking',
                'Azure Monitor - Notification delivery logs',
                'Azure Storage - Portal documentation storage',
                'Azure Static Web Apps - USDA Connect portal hosting',
                'Azure Logic Apps - Notification workflow automation'
            ],
            'collection_methods': [
                'Query email notification logs for migration announcements',
                'Retrieve communication service delivery reports',
                'Export portal documentation content and update history',
                'Collect stakeholder notification receipts and confirmations',
                'Review notification workflow execution logs',
                'Audit portal access logs during migration period'
            ],
            'implementation_steps': [
                '1. Implement notification tracking system with delivery confirmation',
                '2. Configure Azure Communication Services for stakeholder notifications',
                '3. Set up Azure Monitor to log all migration-related notifications',
                '4. Create portal documentation explaining trust center access',
                '5. Establish notification workflow with stakeholder registry',
                '6. Configure notification receipts and acknowledgment tracking',
                '7. Implement portal update automation with version control'
            ]
        }
    
    def get_evidence_collection_queries(self) -> list:
        """
        Get specific queries for collecting FRR-ADS-08 evidence.
        
        Returns queries for notification logs, email delivery, portal updates,
        and communication tracking.
        """
        return [
            {
                'name': 'Migration Notification Delivery Logs',
                'type': 'KQL',
                'query': '''AzureDiagnostics
| where Category == "EmailLog" or Category == "CommunicationLog"
| where OperationName contains "SendEmail" or OperationName contains "SendNotification"
| where Message contains "migration" or Message contains "trust center"
| project TimeGenerated, OperationName, RecipientEmail=tostring(properties_s.recipient), Status=ResultType, DeliveryStatus=properties_s.deliveryStatus
| order by TimeGenerated desc''',
                'description': 'Retrieve email notification logs for trust center migration announcements sent to stakeholders'
            },
            {
                'name': 'Communication Services Delivery Reports',
                'type': 'Azure Resource Graph',
                'query': '''resources
| where type == "microsoft.communication/communicationservices"
| extend properties.emailServiceLogs
| mv-expand logs = properties.emailServiceLogs
| where logs.subject contains "migration" or logs.body contains "trust center"
| project name, resourceGroup, subscriptionId, emailSubject=logs.subject, recipient=logs.to, deliveryStatus=logs.status, sentDate=logs.timestamp''',
                'description': 'Query Azure Communication Services for migration notification delivery status and recipient confirmation'
            },
            {
                'name': 'USDA Portal Documentation Updates',
                'type': 'Azure Resource Graph',
                'query': '''resources
| where type == "microsoft.storage/storageaccounts" or type == "microsoft.web/staticsites"
| where tags.purpose == "usda-connect-portal" or tags.application == "trust-center-docs"
| extend properties.fileChanges
| mv-expand changes = properties.fileChanges
| where changes.path contains "trust-center" or changes.path contains "migration-guide"
| project name, resourceGroup, filePath=changes.path, lastModified=changes.timestamp, author=changes.modifiedBy''',
                'description': 'Track portal documentation updates explaining trust center access and migration process'
            },
            {
                'name': 'Notification Workflow Execution History',
                'type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceProvider == "MICROSOFT.LOGIC" and Category == "WorkflowRuntime"
| where resource_workflowName_s contains "migration-notification" or resource_workflowName_s contains "stakeholder-notify"
| where status_s == "Succeeded" or status_s == "Failed"
| project TimeGenerated, WorkflowName=resource_workflowName_s, RunStatus=status_s, RecipientCount=properties_s.recipientCount, NotificationsSent=properties_s.notificationsSent
| order by TimeGenerated desc''',
                'description': 'Review Logic Apps workflow execution for automated migration notification delivery'
            },
            {
                'name': 'Portal Access Logs During Migration',
                'type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceType == "STATICWEBAPPS" or ResourceType == "WEBAPPS"
| where tags_s contains "usda-connect" or appName_s contains "portal"
| where path_s contains "trust-center" or path_s contains "migration-guide" or path_s contains "authorization-data"
| summarize AccessCount=count(), UniqueUsers=dcount(userId_s) by bin(TimeGenerated, 1d), path_s
| order by TimeGenerated desc''',
                'description': 'Monitor portal access to trust center documentation and migration guidance pages'
            },
            {
                'name': 'Stakeholder Notification Receipts',
                'type': 'KQL',
                'query': '''AzureDiagnostics
| where Category == "NotificationReceipt" or Category == "EmailReceipt"
| where subject_s contains "migration" or body_s contains "trust center"
| extend recipient = tostring(properties_s.recipient), acknowledged = tobool(properties_s.acknowledged)
| summarize NotificationsSent=count(), Acknowledged=countif(acknowledged==true), Pending=countif(acknowledged==false) by recipient
| project Recipient=recipient, TotalNotifications=NotificationsSent, Acknowledged, Pending, AcknowledgmentRate=round((todouble(Acknowledged)/todouble(NotificationsSent))*100, 2)''',
                'description': 'Track stakeholder acknowledgment of migration notifications and identify parties who have not confirmed receipt'
            }
        ]
    
    def get_evidence_artifacts(self) -> list:
        """
        Get list of evidence artifacts to collect for FRR-ADS-08.
        
        Returns artifacts demonstrating migration notification and portal documentation.
        """
        return [
            {
                'name': 'Migration Notification Email Records',
                'description': 'Export of all migration notification emails sent to stakeholders, including subject lines, recipients, send timestamps, and delivery confirmation',
                'location': 'Azure Communication Services / Email service logs',
                'format': 'JSON export with email metadata and delivery status'
            },
            {
                'name': 'Stakeholder Notification Registry',
                'description': 'List of all parties notified about trust center migration, including agency contacts, FedRAMP representatives, and CISA contacts',
                'location': 'Notification system database / stakeholder management tool',
                'format': 'CSV or JSON with contact information, notification date, and acknowledgment status'
            },
            {
                'name': 'USDA Connect Portal Documentation',
                'description': 'Screenshot or export of USDA Connect portal content explaining how to use trust center to obtain authorization data',
                'location': 'USDA Connect Community Portal secure folder',
                'format': 'PDF export or HTML snapshot with metadata showing last update timestamp'
            },
            {
                'name': 'Trust Center Migration Guide',
                'description': 'Documentation explaining trust center migration process, access procedures, and authorization data retrieval instructions',
                'location': 'Azure Storage / Static Web App hosting portal documentation',
                'format': 'Markdown or PDF document with version control history'
            },
            {
                'name': 'Notification Workflow Configuration',
                'description': 'Export of automated notification workflow configuration showing how migration announcements are triggered and delivered',
                'location': 'Azure Logic Apps / notification automation system',
                'format': 'JSON workflow definition with trigger conditions and recipient distribution logic'
            },
            {
                'name': 'Communication Delivery Reports',
                'description': 'Delivery status reports from communication services showing successful notification delivery to all required parties',
                'location': 'Azure Communication Services / Email delivery service',
                'format': 'CSV or JSON report with recipient, delivery status, timestamp, and bounce/failure reasons'
            }
        ]
