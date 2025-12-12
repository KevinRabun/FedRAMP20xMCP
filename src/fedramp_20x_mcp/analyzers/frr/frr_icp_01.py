"""
FRR-ICP-01: Incident Reporting to FedRAMP

Providers MUST responsibly report _incidents_ to FedRAMP within 1 hour of identification by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov.

Official FedRAMP 20x Requirement
Source: FRR-ICP (ICP) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import Dict, List, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ICP_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-01: Incident Reporting to FedRAMP
    
    **Official Statement:**
    Providers MUST responsibly report _incidents_ to FedRAMP within 1 hour of identification by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov.
    
    **Family:** ICP - ICP
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Yes (Code, IaC, CI/CD)
    
    **Detection Strategy:**
    This analyzer detects incident reporting mechanisms through:
        1. Application code: Incident detection, logging, and alert/notification integrations
        2. Infrastructure: Azure Monitor alerts, Log Analytics, incident response automation resources
        3. CI/CD: Incident response workflow integrations, alerting configurations
    
    Detection focuses on identifying whether incident detection and reporting infrastructure is configured,
    not whether specific incidents are reported (which is a runtime/operational concern).
    """
    
    FRR_ID = "FRR-ICP-01"
    FRR_NAME = "Incident Reporting to FedRAMP"
    FRR_STATEMENT = """Providers MUST responsibly report _incidents_ to FedRAMP within 1 hour of identification by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov."""
    FAMILY = "ICP"
    FAMILY_NAME = "ICP"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("IR-4", "Incident Handling"),
        ("IR-6", "Incident Reporting"),
        ("IR-5", "Incident Monitoring"),
        ("IR-8", "Incident Response Plan"),
    ]
    CODE_DETECTABLE = True  # Detects incident response infrastructure and alerting configurations
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-01 analyzer."""
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
        Analyze Python code for FRR-ICP-01 incident reporting mechanisms.
        
        Detects:
        - Incident detection/logging frameworks (logging, structlog, etc.)
        - Alert/notification integrations (email, webhook, Azure Monitor)
        - Incident response automation hooks
        """
        findings = []
        lines = code.split('\n')
        
        has_incident_logging = False
        has_alert_mechanism = False
        
        # Use AST to detect logging and alerting
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for logging imports
                import_nodes = parser.find_nodes_by_type(tree.root_node, 'import_statement') + \
                              parser.find_nodes_by_type(tree.root_node, 'import_from_statement')
                
                for node in import_nodes:
                    import_text = parser.get_node_text(node, code_bytes).decode('utf8').lower()
                    if any(lib in import_text for lib in ['logging', 'structlog', 'loguru', 'azure.monitor']):
                        has_incident_logging = True
                    if any(lib in import_text for lib in ['smtplib', 'sendgrid', 'azure.communication', 'requests', 'httpx']):
                        has_alert_mechanism = True
                
                # Check for incident-related function calls
                call_nodes = parser.find_nodes_by_type(tree.root_node, 'call')
                for node in call_nodes:
                    call_text = parser.get_node_text(node, code_bytes).decode('utf8').lower()
                    if any(term in call_text for term in ['log.critical', 'log.error', 'logger.critical', 'incident', 'alert', 'notify']):
                        has_incident_logging = True
                
        except Exception:
            # Fallback to regex
            pass
        
        # Regex fallback for logging/alerting
        if not has_incident_logging:
            has_incident_logging = bool(re.search(r'(import\s+logging|from\s+\w+\s+import\s+\w*log)', code, re.IGNORECASE))
        
        if not has_alert_mechanism:
            has_alert_mechanism = bool(re.search(r'(send_?mail|send_?email|requests\.post|webhook|notify|alert)', code, re.IGNORECASE))
        
        # Report findings
        if not has_incident_logging:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident logging framework detected",
                description=f"Python code in '{file_path}' lacks incident logging framework. FRR-ICP-01 requires incident detection and reporting infrastructure. Implement logging for critical/security events.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add incident logging: 1) Import logging framework (logging, structlog), 2) Log critical/security events, 3) Configure log aggregation (Azure Monitor, CloudWatch)"
            ))
        
        if not has_alert_mechanism and 'incident' in code.lower():
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Incident detection without alerting mechanism",
                description=f"Code in '{file_path}' handles incidents but lacks alerting/notification mechanism. FRR-ICP-01 requires incident reporting to FedRAMP within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Implement alerting: 1) Add email notification (smtplib, SendGrid), 2) Integrate with Azure Monitor alerts, 3) Configure webhook to incident management system"
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ICP-01 incident reporting mechanisms.
        
        Detects:
        - Logging frameworks (ILogger, Serilog, NLog)
        - Alert/notification integrations (email, Azure Monitor)
        - Incident response automation
        """
        findings = []
        lines = code.split('\n')
        
        has_incident_logging = False
        has_alert_mechanism = False
        
        # Use AST to detect logging and alerting
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for using statements
                using_nodes = parser.find_nodes_by_type(tree.root_node, 'using_directive')
                for node in using_nodes:
                    using_text = parser.get_node_text(node, code_bytes).decode('utf8').lower()
                    if any(lib in using_text for lib in ['microsoft.extensions.logging', 'serilog', 'nlog', 'azure.monitor']):
                        has_incident_logging = True
                    if any(lib in using_text for lib in ['system.net.mail', 'sendgrid', 'azure.communication']):
                        has_alert_mechanism = True
        
        except Exception:
            # Fallback to regex
            pass
        
        # Regex fallback
        if not has_incident_logging:
            has_incident_logging = bool(re.search(r'(ILogger|Serilog|NLog|LoggerFactory)', code))
        
        if not has_alert_mechanism:
            has_alert_mechanism = bool(re.search(r'(SmtpClient|SendGrid|EmailMessage|HttpClient\.Post)', code, re.IGNORECASE))
        
        if not has_incident_logging:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident logging framework detected",
                description=f"C# code in '{file_path}' lacks incident logging framework. FRR-ICP-01 requires incident detection and reporting infrastructure.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add incident logging: 1) Inject ILogger<T>, 2) Log critical/security events, 3) Configure Application Insights or Azure Monitor"
            ))
        
        if not has_alert_mechanism and 'incident' in code.lower():
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Incident detection without alerting mechanism",
                description=f"Code in '{file_path}' handles incidents but lacks alerting. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Implement alerting: 1) Add SendGrid/SmtpClient for email, 2) Integrate with Azure Monitor, 3) Configure webhook notifications"
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ICP-01 incident reporting mechanisms.
        
        Detects:
        - Logging frameworks (Log4j, SLF4J, Logback)
        - Alert/notification integrations
        - Incident response automation
        """
        findings = []
        lines = code.split('\n')
        
        has_incident_logging = False
        has_alert_mechanism = False
        
        # Use AST to detect logging and alerting
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for import statements
                import_nodes = parser.find_nodes_by_type(tree.root_node, 'import_declaration')
                for node in import_nodes:
                    import_text = parser.get_node_text(node, code_bytes).decode('utf8').lower()
                    if any(lib in import_text for lib in ['org.slf4j', 'log4j', 'logback', 'java.util.logging']):
                        has_incident_logging = True
                    if any(lib in import_text for lib in ['javax.mail', 'org.apache.http', 'okhttp']):
                        has_alert_mechanism = True
        
        except Exception:
            # Fallback to regex
            pass
        
        # Regex fallback
        if not has_incident_logging:
            has_incident_logging = bool(re.search(r'(import.*?(slf4j|log4j|Logger))', code))
        
        if not has_alert_mechanism:
            has_alert_mechanism = bool(re.search(r'(javax\.mail|HttpClient|sendEmail|notify)', code, re.IGNORECASE))
        
        if not has_incident_logging:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident logging framework detected",
                description=f"Java code in '{file_path}' lacks incident logging framework. FRR-ICP-01 requires incident detection and reporting infrastructure.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add incident logging: 1) Import SLF4J/Log4j2, 2) Create logger instance, 3) Log critical/security events"
            ))
        
        if not has_alert_mechanism and 'incident' in code.lower():
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Incident detection without alerting mechanism",
                description=f"Code in '{file_path}' handles incidents but lacks alerting. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Implement alerting: 1) Add JavaMail for email notifications, 2) Use HttpClient for webhooks, 3) Integrate with monitoring system"
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ICP-01 incident reporting mechanisms.
        
        Detects:
        - Logging frameworks (winston, bunyan, pino)
        - Alert/notification integrations (nodemailer, axios)
        - Incident response automation
        """
        findings = []
        lines = code.split('\n')
        
        has_incident_logging = False
        has_alert_mechanism = False
        
        # Use AST to detect logging and alerting
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for import statements
                import_nodes = parser.find_nodes_by_type(tree.root_node, 'import_statement')
                for node in import_nodes:
                    import_text = parser.get_node_text(node, code_bytes).decode('utf8').lower()
                    if any(lib in import_text for lib in ['winston', 'bunyan', 'pino', 'console.log']):
                        has_incident_logging = True
                    if any(lib in import_text for lib in ['nodemailer', 'axios', '@azure/monitor', 'node-fetch']):
                        has_alert_mechanism = True
        
        except Exception:
            # Fallback to regex
            pass
        
        # Regex fallback
        if not has_incident_logging:
            has_incident_logging = bool(re.search(r"(import.*?(winston|bunyan|pino)|console\.(error|warn))", code, re.IGNORECASE))
        
        if not has_alert_mechanism:
            has_alert_mechanism = bool(re.search(r'(nodemailer|axios\.post|fetch.*post|sendEmail)', code, re.IGNORECASE))
        
        if not has_incident_logging:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident logging framework detected",
                description=f"TypeScript code in '{file_path}' lacks incident logging framework. FRR-ICP-01 requires incident detection and reporting infrastructure.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add incident logging: 1) Install winston/pino, 2) Create logger instance, 3) Log critical/security events to Azure Monitor"
            ))
        
        if not has_alert_mechanism and 'incident' in code.lower():
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Incident detection without alerting mechanism",
                description=f"Code in '{file_path}' handles incidents but lacks alerting. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Implement alerting: 1) Add nodemailer for email, 2) Use axios for webhook notifications, 3) Integrate with Azure Monitor"
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure for incident response resources.
        
        Checks for:
        - Azure Monitor alert rules
        - Log Analytics workspaces
        - Action groups for incident notification
        - Logic Apps/Functions for incident response automation
        """
        findings = []
        lines = code.split('\n')
        
        has_alert_rules = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Insights/(metricalerts|scheduledQueryRules)", code, re.IGNORECASE))
        has_log_analytics = bool(re.search(r"resource\s+\w+\s+'Microsoft\.OperationalInsights/workspaces", code, re.IGNORECASE))
        has_action_group = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Insights/actionGroups", code, re.IGNORECASE))
        has_automation = bool(re.search(r"resource\s+\w+\s+'Microsoft\.(Logic/workflows|Web/sites).*kind:\s*'functionapp'", code, re.IGNORECASE | re.DOTALL))
        
        # Check for monitoring/alerting infrastructure
        if not has_log_analytics and not has_alert_rules:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident monitoring infrastructure detected",
                description=f"Bicep template '{file_path}' lacks Azure Monitor or Log Analytics resources. FRR-ICP-01 requires incident detection and reporting capabilities.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Deploy monitoring: 1) Add Log Analytics workspace, 2) Configure Azure Monitor alert rules, 3) Set up diagnostic settings for resource logging"
            ))
        
        if has_alert_rules and not has_action_group:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Alert rules without notification action groups",
                description=f"Bicep template '{file_path}' defines alert rules but no action groups for notifications. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add action groups: 1) Create Microsoft.Insights/actionGroups resource, 2) Configure email/webhook notifications, 3) Link to alert rules via 'actions' property"
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure for incident response resources.
        
        Checks for:
        - Azure Monitor alert rules
        - Log Analytics workspaces
        - SNS topics / CloudWatch alarms (AWS)
        - Notification mechanisms
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Azure resources
        has_azure_alerts = bool(re.search(r'resource\s+"azurerm_(monitor_metric_alert|monitor_scheduled_query_rules_alert)"', code))
        has_azure_log_analytics = bool(re.search(r'resource\s+"azurerm_log_analytics_workspace"', code))
        has_azure_action_group = bool(re.search(r'resource\s+"azurerm_monitor_action_group"', code))
        
        # Check for AWS resources
        has_aws_cloudwatch = bool(re.search(r'resource\s+"aws_cloudwatch_(metric_alarm|log_group)"', code))
        has_aws_sns = bool(re.search(r'resource\s+"aws_sns_topic"', code))
        
        has_monitoring = has_azure_alerts or has_azure_log_analytics or has_aws_cloudwatch
        has_notifications = has_azure_action_group or has_aws_sns
        
        if not has_monitoring:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident monitoring infrastructure detected",
                description=f"Terraform template '{file_path}' lacks monitoring resources. FRR-ICP-01 requires incident detection and reporting capabilities.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Deploy monitoring: Azure: azurerm_log_analytics_workspace, azurerm_monitor_metric_alert; AWS: aws_cloudwatch_log_group, aws_cloudwatch_metric_alarm"
            ))
        
        if has_monitoring and not has_notifications:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Monitoring without notification mechanisms",
                description=f"Terraform '{file_path}' has monitoring but no notification resources. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add notifications: Azure: azurerm_monitor_action_group; AWS: aws_sns_topic with email/HTTPS subscriptions"
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions for incident response workflow integrations.
        
        Checks for:
        - Security scanning that triggers on incidents
        - Notification steps for security events
        - Integration with incident management systems
        """
        findings = []
        lines = code.split('\n')
        
        has_security_scanning = bool(re.search(r'uses:.*?(security|trivy|snyk|dependabot|codeql)', code, re.IGNORECASE))
        has_notification = bool(re.search(r'(slack/action|email|webhook|notify|alert)', code, re.IGNORECASE))
        has_on_security_trigger = bool(re.search(r'on:\s*\n?\s*(security_and_analysis|schedule)', code, re.IGNORECASE))
        
        # Check for incident response integration
        if has_security_scanning and not has_notification:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Security scanning without incident notifications",
                description=f"GitHub Actions workflow '{file_path}' includes security scanning but lacks notification steps. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add notifications: 1) Use slack/send-action for Slack alerts, 2) Add email notification step, 3) Integrate with PagerDuty/ServiceNow for incident management"
            ))
        
        if not has_security_scanning and 'deploy' in code.lower():
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Deployment without security incident detection",
                description=f"Workflow '{file_path}' deploys code but lacks security scanning for incident detection. FRR-ICP-01 requires systematic incident identification.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add security scanning: 1) Integrate Trivy/Snyk for vulnerability scanning, 2) Add CodeQL for code analysis, 3) Configure Dependabot for dependency alerts"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines for incident response workflow integrations.
        
        Checks for:
        - Security scanning tasks
        - Notification mechanisms
        - Integration with incident management
        """
        findings = []
        lines = code.split('\n')
        
        has_security_scanning = bool(re.search(r'(task:\s*SecurityScan|WhiteSource|Checkmarx|SonarQube)', code, re.IGNORECASE))
        has_notification = bool(re.search(r'(task:\s*SendEmail|SlackNotification|InvokeRESTAPI)', code, re.IGNORECASE))
        has_deploy = 'deploy' in code.lower() or 'azurewebapp' in code.lower()
        
        if has_security_scanning and not has_notification:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Security scanning without incident notifications",
                description=f"Azure Pipeline '{file_path}' includes security scanning but lacks notification tasks. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add notifications: 1) Use SendEmail task, 2) Add Slack notification extension, 3) Invoke webhook for incident management system"
            ))
        
        if has_deploy and not has_security_scanning:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Deployment without security incident detection",
                description=f"Pipeline '{file_path}' deploys code but lacks security scanning for incident detection. FRR-ICP-01 requires systematic incident identification.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add security scanning: 1) SecurityScan@0 task, 2) SonarQube analysis, 3) Dependency scanning with WhiteSource"
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI for incident response workflow integrations.
        
        Checks for:
        - Security scanning jobs (SAST, dependency scanning)
        - Notification mechanisms
        - Integration with incident management
        """
        findings = []
        lines = code.split('\n')
        
        # Note: Using regex - tree-sitter not available for GitLab CI YAML
        has_security_scanning = bool(re.search(r'(include:.*SAST|dependency_scanning|container_scanning)', code, re.IGNORECASE))
        has_notification = bool(re.search(r'(curl.*webhook|notify|alert|slack)', code, re.IGNORECASE))
        has_deploy = bool(re.search(r'(stage:\s*deploy|deploy:|production)', code, re.IGNORECASE))
        
        if has_security_scanning and not has_notification:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Security scanning without incident notifications",
                description=f"GitLab CI '{file_path}' includes security scanning but lacks notification mechanisms. FRR-ICP-01 requires incident reporting within 1 hour.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add notifications: 1) Use curl to call webhook on security findings, 2) Add Slack notification script, 3) Integrate with incident management API"
            ))
        
        if has_deploy and not has_security_scanning:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Deployment without security incident detection",
                description=f"GitLab CI '{file_path}' deploys code but lacks security scanning for incident detection. FRR-ICP-01 requires systematic incident identification.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add security scanning: 1) Include GitLab SAST template, 2) Enable dependency_scanning, 3) Add container_scanning for Docker images"
            ))
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get Azure Resource Graph and other queries for evidence collection.
        
        Returns a dict with 'automated_queries' key containing KQL queries.
        """
        return {
            'automated_queries': [
                "// Azure Monitor - Get incident alert rules",
                "resources",
                "| where type =~ 'Microsoft.Insights/metricAlerts' or type =~ 'Microsoft.Insights/scheduledQueryRules'",
                "| extend alertEnabled = properties.enabled, severity = properties.severity",
                "| project name, type, resourceGroup, alertEnabled, severity, location",
                "",
                "// Log Analytics - Get incident detection queries",
                "resources",
                "| where type =~ 'Microsoft.OperationalInsights/workspaces'",
                "| project workspaceId=id, workspaceName=name, resourceGroup, location",
                "",
                "// Action Groups - Get incident notification configurations",
                "resources",
                "| where type =~ 'Microsoft.Insights/actionGroups'",
                "| extend emailReceivers = properties.emailReceivers, webhookReceivers = properties.webhookReceivers",
                "| project name, resourceGroup, emailReceivers, webhookReceivers",
                "",
                "// Check if FedRAMP incident email is configured",
                "resources",
                "| where type =~ 'Microsoft.Insights/actionGroups'",
                "| mv-expand receiver = properties.emailReceivers",
                "| extend email = tostring(receiver.emailAddress)",
                "| where email contains 'fedramp_security@fedramp.gov' or email contains 'fedramp_security@gsa.gov'",
                "| project actionGroupName=name, email, resourceGroup"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get list of evidence artifacts to collect for FRR-ICP-01 compliance.
        
        Returns a dict with 'evidence_artifacts' key containing artifact list.
        """
        return {
            'evidence_artifacts': [
                "1. Incident Response Plan: Documented incident response plan (IRP) that includes procedures for identifying security incidents, defining incident severity levels, specifying 1-hour reporting requirement to FedRAMP, documenting escalation paths, and listing FedRAMP contact emails (fedramp_security@fedramp.gov, fedramp_security@gsa.gov).",
                
                "2. Incident Detection Infrastructure: Configuration exports showing incident detection capabilities including Azure Monitor alert rules, Log Analytics workspaces with security queries, application logging configurations, security scanning tools (Defender for Cloud, Sentinel), and automated detection mechanisms.",
                
                "3. Incident Notification Configuration: Evidence of automated notification systems including Action Group configurations with FedRAMP email addresses, email templates for incident reporting, webhook configurations to incident management systems, and notification testing records demonstrating 1-hour capability.",
                
                "4. Historical Incident Reports: Records of past incidents reported to FedRAMP showing incident identification timestamp, FedRAMP notification timestamp (within 1 hour), incident description/classification, email confirmation receipts from FedRAMP, and post-incident review documentation.",
                
                "5. Monitoring and Alerting Rules: Exports of monitoring configurations including security alert rules, anomaly detection settings, threat detection policies, log aggregation configurations, and SIEM integration (Azure Sentinel) demonstrating systematic incident identification.",
                
                "6. Staff Training Records: Documentation showing incident response team training including IRP training completion, 1-hour reporting requirement awareness, FedRAMP contact information familiarity, incident classification training, and regular tabletop exercise participation.",
                
                "7. Incident Communication Templates: Pre-approved templates for FedRAMP incident notification including required incident information fields, severity classification guidance, contact information verification, and approval workflow for incident reporting.",
                
                "8. Compliance Testing Evidence: Records of incident response testing including tabletop exercises simulating 1-hour reporting, notification system testing to FedRAMP addresses, incident detection tool validation, escalation procedure testing, and continuous improvement documentation."
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection.
        
        Returns a dict with 'implementation_notes' key containing guidance.
        """
        return {
            'implementation_notes': (
                "FRR-ICP-01 requires Providers to MUST responsibly report incidents to FedRAMP within 1 hour of identification by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov. This is a mandatory operational requirement focused on incident detection infrastructure and notification capabilities.\\n\\n"
                
                "CODE DETECTION STRATEGY:\\n"
                "While the actual reporting is operational, code analysis can verify incident response infrastructure:\\n"
                "1. Application Code: Detect logging frameworks, incident detection logic, alert/notification integrations\\n"
                "2. Infrastructure (Bicep/Terraform): Verify Azure Monitor alerts, Log Analytics, Action Groups, automation resources\\n"
                "3. CI/CD Pipelines: Check for security scanning, vulnerability detection, notification configurations\\n"
                "4. Focus: Infrastructure for incident detection and notification, not runtime incident reporting\\n\\n"
                
                "COMPLIANCE APPROACH:\\n"
                "1. Incident Detection Infrastructure:\\n"
                "   - Azure Monitor: Configure metric alerts and log query alerts for security events\\n"
                "   - Log Analytics: Deploy workspace with security-focused KQL queries\\n"
                "   - Microsoft Defender for Cloud: Enable for threat detection and security alerts\\n"
                "   - Azure Sentinel: Deploy SIEM for advanced incident detection (recommended)\\n"
                "   - Application Insights: Instrument code for exception and error tracking\\n"
                "   - Security Center: Enable continuous security assessment and alerts\\n\\n"
                
                "2. Incident Notification Mechanisms:\\n"
                "   - Action Groups: Configure with fedramp_security@fedramp.gov and fedramp_security@gsa.gov emails\\n"
                "   - Logic Apps: Automate incident report generation and email delivery\\n"
                "   - Azure Functions: Create serverless notification functions for incident alerts\\n"
                "   - Email Templates: Pre-configure templates with required incident information\\n"
                "   - Webhook Integration: Connect to incident management systems (ServiceNow, PagerDuty)\\n"
                "   - SMS/Phone: Configure backup notification channels for critical incidents\\n\\n"
                
                "3. 1-Hour Reporting Capability:\\n"
                "   - Real-time Detection: Configure alerts to trigger immediately upon incident identification\\n"
                "   - Automated Notifications: Use Action Groups to send immediate email notifications\\n"
                "   - Escalation: Implement tiered escalation if initial notification fails\\n"
                "   - 24/7 Monitoring: Ensure continuous monitoring and alerting coverage\\n"
                "   - Response Team: Maintain on-call rotation for incident response\\n"
                "   - Testing: Regularly test notification systems to verify 1-hour capability\\n\\n"
                
                "4. Incident Classification:\\n"
                "   - Define Incidents: Document what constitutes a reportable security incident\\n"
                "   - Severity Levels: Establish incident severity classification (Critical, High, Medium, Low)\\n"
                "   - FedRAMP Scope: Clarify which incidents require FedRAMP reporting\\n"
                "   - Thresholds: Set alert thresholds to balance detection with false positive reduction\\n"
                "   - Review Process: Implement human review for incident validation before reporting\\n\\n"
                
                "EVIDENCE COLLECTION:\\n"
                "Evidence for FRR-ICP-01 includes both infrastructure configuration and operational records:\\n"
                "- Incident Response Plan documenting 1-hour reporting requirement and FedRAMP contacts\\n"
                "- Azure Monitor alert rules, Log Analytics workspaces, and security scanning tools\\n"
                "- Action Group configurations with FedRAMP email addresses\\n"
                "- Historical incident reports to FedRAMP with timestamps demonstrating 1-hour compliance\\n"
                "- Monitoring and alerting rule exports showing systematic incident detection\\n"
                "- Staff training records on incident response and reporting procedures\\n"
                "- Incident communication templates pre-configured for FedRAMP reporting\\n"
                "- Compliance testing evidence including tabletop exercises and notification testing\\n\\n"
                
                "AZURE RESOURCE GRAPH QUERIES:\\n"
                "Use provided KQL queries to collect evidence of incident detection infrastructure:\\n"
                "- Query Microsoft.Insights/metricAlerts and scheduledQueryRules for alert configurations\\n"
                "- Query Microsoft.OperationalInsights/workspaces for Log Analytics deployment\\n"
                "- Query Microsoft.Insights/actionGroups to verify notification configurations\\n"
                "- Validate that Action Groups include FedRAMP email addresses\\n"
                "- Export alert rules to demonstrate systematic incident detection coverage\\n\\n"
                
                "RECOMMENDED AZURE SERVICES:\\n"
                "1. Microsoft Defender for Cloud: Comprehensive threat detection and security alerts\\n"
                "2. Azure Sentinel: SIEM for advanced incident detection and response automation\\n"
                "3. Azure Monitor: Metric and log-based alerting for infrastructure and applications\\n"
                "4. Log Analytics: Centralized log collection and security query workspace\\n"
                "5. Application Insights: Application-level error and exception tracking\\n"
                "6. Azure Logic Apps: Automated incident report generation and email delivery\\n"
                "7. Azure Functions: Serverless notification functions for incident alerts\\n\\n"
                
                "INCIDENT REPORTING EMAIL FORMAT:\\n"
                "When incidents occur, emails to FedRAMP should include:\\n"
                "- Incident ID and classification (severity level)\\n"
                "- Date/time of incident identification\\n"
                "- Description of incident (what happened, systems affected)\\n"
                "- Potential impact and scope\\n"
                "- Actions taken to contain/mitigate\\n"
                "- Current status and next steps\\n"
                "- Contact information for follow-up\\n"
                "- Expected timeline for resolution and follow-up report\\n\\n"
                
                "INTEGRATION WITH INCIDENT MANAGEMENT:\\n"
                "Integrate FedRAMP reporting with internal incident management:\\n"
                "- ServiceNow/Jira: Create incident tickets with FedRAMP reporting workflow\\n"
                "- PagerDuty: Configure on-call escalation with FedRAMP notification automation\\n"
                "- Slack/Teams: Set up incident channels with automated FedRAMP reporting reminders\\n"
                "- OSCAL: Export incident reports in machine-readable format for compliance automation\\n\\n"
                
                "TESTING AND VALIDATION:\\n"
                "Regularly test incident detection and reporting capabilities:\\n"
                "- Tabletop Exercises: Simulate incidents and practice 1-hour reporting\\n"
                "- Notification Testing: Verify Action Groups deliver to FedRAMP addresses\\n"
                "- Alert Validation: Test that security events trigger appropriate alerts\\n"
                "- Escalation Testing: Validate escalation procedures if primary notification fails\\n"
                "- Post-Incident Reviews: Analyze past incidents to improve detection and reporting\\n\\n"
                
                "LIMITATION: Code analysis detects incident response INFRASTRUCTURE (monitoring, alerting, notification configurations), not actual runtime incident reporting. Compliance with 1-hour reporting requirement must be validated through operational records and historical incident reports to FedRAMP."
            )
        }
