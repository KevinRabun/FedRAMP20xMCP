"""
KSI-INR-01: Incident Response Procedure

Always follow a documented incident response procedure.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_INR_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-INR-01: Incident Response Procedure
    
    **Official Statement:**
    Always follow a documented incident response procedure.
    
    **Family:** INR - Incident Response
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ir-4
    - ir-4.1
    - ir-6
    - ir-6.1
    - ir-6.3
    - ir-7
    - ir-7.1
    - ir-8
    - ir-8.1
    - si-4.5
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-INR-01"
    KSI_NAME = "Incident Response Procedure"
    KSI_STATEMENT = """Always follow a documented incident response procedure."""
    FAMILY = "INR"
    FAMILY_NAME = "Incident Response"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ir-4", "Incident Handling"),
        ("ir-4.1", "Automated Incident Handling Processes"),
        ("ir-6", "Incident Reporting"),
        ("ir-6.1", "Automated Reporting"),
        ("ir-6.3", "Supply Chain Coordination"),
        ("ir-7", "Incident Response Assistance"),
        ("ir-7.1", "Automation Support for Availability of Information and Support"),
        ("ir-8", "Incident Response Plan"),
        ("ir-8.1", "Breaches"),
        ("si-4.5", "System-generated Alerts")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
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
        Analyze Python code for KSI-INR-01 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Logging configuration with severity levels (CRITICAL, ERROR)
        - Exception handling with alerting
        - Integration with monitoring services
        """
        findings = []
        lines = code.split('\n')
        
        # Check for critical/error logging
        has_critical_logging = any(
            re.search(r'log(?:ger)?\.(?:critical|error)', line.lower())
            for line in lines
        )
        
        # Check for alerting integrations
        alerting_keywords = ['sentry', 'datadog', 'newrelic', 'applicationinsights', 'azure.monitor']
        has_alerting = any(keyword in code.lower() for keyword in alerting_keywords)
        
        if not has_critical_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.MEDIUM,
                title="No critical or error logging detected",
                description="Python code should implement logging for critical events to support incident detection per ir-4.1 (Automated Incident Handling Processes).",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add logger.critical() or logger.error() calls for incident-worthy events to enable automated alerting.",
                nist_control="ir-4.1"
            ))
        
        if has_critical_logging and not has_alerting:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.LOW,
                title="Logging present but no alerting service integration detected",
                description="Critical logging should be integrated with alerting services (Sentry, Application Insights) for automated incident reporting per ir-6.1 (Automated Reporting).",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Integrate with alerting service: Azure Application Insights, Sentry, or Datadog for automated incident notifications.",
                nist_control="ir-6.1"
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-INR-01 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - ILogger usage with LogLevel.Critical/Error
        - Exception handling with monitoring
        - Application Insights integration
        """
        findings = []
        lines = code.split('\n')
        
        # Check for critical/error logging
        has_critical_logging = any(
            re.search(r'(?:ILogger|_logger)\.Log(?:Critical|Error)', line)
            for line in lines
        )
        
        # Check for Application Insights or monitoring
        has_monitoring = any(
            keyword in code 
            for keyword in ['TelemetryClient', 'ApplicationInsights', 'ILogger<']
        )
        
        if not has_critical_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.MEDIUM,
                title="No critical or error logging detected",
                description="C# code should implement ILogger with LogCritical/LogError for incident detection per ir-4.1.",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Use ILogger.LogCritical() or ILogger.LogError() for incident-worthy events.",
                nist_control="ir-4.1"
            ))
        
        if has_critical_logging and not has_monitoring:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.LOW,
                title="Logging without monitoring integration",
                description="Critical logging should integrate with Application Insights or similar monitoring for automated reporting per ir-6.1.",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add Application Insights TelemetryClient for automated incident tracking.",
                nist_control="ir-6.1"
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-INR-01 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Always follow a documented incident response procedure....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-INR-01 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Always follow a documented incident response procedure....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-INR-01 compliance.
        
        Detects:
        - Azure Monitor action groups for incident notifications
        - Metric alerts for automated incident detection
        - Log Analytics alert rules
        """
        findings = []
        lines = code.split('\n')
        
        # Check for action groups (notification mechanism)
        has_action_groups = 'Microsoft.Insights/actionGroups' in code
        
        # Check for alert rules (incident detection)
        has_alerts = (
            'Microsoft.Insights/metricAlerts' in code or 
            'Microsoft.Insights/scheduledQueryRules' in code
        )
        
        if not has_action_groups:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.HIGH,
                title="No action groups configured for incident notifications",
                description="Bicep should define Microsoft.Insights/actionGroups for automated incident notifications per ir-6.1 (Automated Reporting).",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add actionGroups resource with email, SMS, webhook, or Azure Function receivers for incident response team.",
                nist_control="ir-6.1"
            ))
        
        if not has_alerts:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.HIGH,
                title="No alert rules configured for incident detection",
                description="Bicep should define alert rules (metricAlerts or scheduledQueryRules) for automated incident handling per ir-4.1.",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add Microsoft.Insights/metricAlerts or scheduledQueryRules to detect incidents automatically.",
                nist_control="ir-4.1"
            ))
        
        if has_alerts and has_action_groups:
            # Check if alerts reference action groups
            if not re.search(r'actionGroupId.*actionGroup', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    severity=Severity.MEDIUM,
                    title="Alert rules and action groups not connected",
                    description="Alert rules should reference action groups to enable automated notifications per si-4.5 (System-generated Alerts).",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Connect alert rules to action groups using actionGroupId property.",
                    nist_control="si-4.5"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-INR-01 compliance.
        
        Detects:
        - CloudWatch alarms (AWS)
        - SNS topics for notifications (AWS)
        - Datadog monitors
        - PagerDuty integrations
        """
        findings = []
        lines = code.split('\n')
        
        # Check for monitoring resources
        monitoring_resources = {
            'aws_cloudwatch_metric_alarm': 'CloudWatch metric alarm',
            'aws_cloudwatch_log_metric_filter': 'CloudWatch log metric filter',
            'datadog_monitor': 'Datadog monitor',
            'pagerduty_service': 'PagerDuty service',
            'azurerm_monitor_metric_alert': 'Azure Monitor metric alert',
            'azurerm_monitor_scheduled_query_rules_alert': 'Azure Monitor log alert'
        }
        
        # Check for notification resources
        notification_resources = {
            'aws_sns_topic': 'SNS topic',
            'aws_sns_topic_subscription': 'SNS subscription',
            'pagerduty_escalation_policy': 'PagerDuty escalation',
            'azurerm_monitor_action_group': 'Azure action group'
        }
        
        has_monitoring = any(resource in code for resource in monitoring_resources.keys())
        has_notifications = any(resource in code for resource in notification_resources.keys())
        
        if not has_monitoring:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.HIGH,
                title="No monitoring/alerting resources detected",
                description="Terraform should define monitoring resources (CloudWatch alarms, Datadog monitors, etc.) for automated incident detection per ir-4.1.",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add monitoring resources: aws_cloudwatch_metric_alarm, datadog_monitor, or azurerm_monitor_metric_alert.",
                nist_control="ir-4.1"
            ))
        
        if has_monitoring and not has_notifications:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.HIGH,
                title="Monitoring configured but no notification mechanism",
                description="Monitoring alerts should connect to notification services (SNS, PagerDuty, action groups) for automated reporting per ir-6.1.",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add notification resources: aws_sns_topic, pagerduty_service, or azurerm_monitor_action_group.",
                nist_control="ir-6.1"
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-INR-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-INR-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-INR-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-INR-01.
        
        **KSI-INR-01: Incident Response Procedure**
        Always follow a documented incident response procedure.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-INR-01",
            "ksi_name": "Incident Response Procedure",
            "azure_services": [
                {
                    "service": "Azure Sentinel",
                    "purpose": "Security incident detection, investigation, and response orchestration",
                    "capabilities": [
                        "Automated incident creation from security alerts",
                        "Incident response playbooks (Logic Apps)",
                        "Investigation graph and timeline",
                        "Incident status tracking and documentation"
                    ]
                },
                {
                    "service": "Azure Logic Apps",
                    "purpose": "Automated incident response workflows following documented procedures",
                    "capabilities": [
                        "Playbook execution for incident response steps",
                        "Integration with ticketing systems",
                        "Automated notifications and escalations",
                        "Evidence collection and preservation"
                    ]
                },
                {
                    "service": "Azure Monitor",
                    "purpose": "Incident detection through alerts and log correlation",
                    "capabilities": [
                        "Alert rules for incident triggers",
                        "Action groups for automated response",
                        "Log Analytics for incident investigation",
                        "Diagnostic data for root cause analysis"
                    ]
                },
                {
                    "service": "Microsoft Defender for Cloud",
                    "purpose": "Security incident detection and initial response recommendations",
                    "capabilities": [
                        "Security alerts with MITRE ATT&CK mapping",
                        "Automated response recommendations",
                        "Integration with Sentinel for escalation",
                        "Threat intelligence correlation"
                    ]
                },
                {
                    "service": "Azure DevOps / Service Now",
                    "purpose": "Incident ticket tracking and procedure documentation",
                    "capabilities": [
                        "Work item tracking for incident response",
                        "Procedure documentation in wikis",
                        "Runbook storage and version control",
                        "Post-incident review tracking"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Incident Response Execution Evidence",
                    "description": "Export Sentinel incident records showing documented procedure followed (playbook execution, investigation steps, resolution)",
                    "automation": "Sentinel incident export via REST API or KQL",
                    "frequency": "Monthly",
                    "evidence_produced": "Incident log with procedure compliance documentation"
                },
                {
                    "method": "Playbook Execution Logs",
                    "description": "Query Logic Apps run history to demonstrate automated response procedures executed",
                    "automation": "Logic Apps REST API or Azure Monitor logs",
                    "frequency": "Monthly",
                    "evidence_produced": "Playbook execution report with timestamps and outcomes"
                },
                {
                    "method": "Incident Response Time Metrics",
                    "description": "Calculate and report incident response SLA compliance (detection, response, resolution times)",
                    "automation": "KQL queries on Sentinel incident data",
                    "frequency": "Monthly",
                    "evidence_produced": "Incident response metrics dashboard and compliance report"
                },
                {
                    "method": "Procedure Documentation Validation",
                    "description": "Verify incident response procedures are documented and accessible in runbooks/wikis",
                    "automation": "DevOps wiki API or documentation repository scan",
                    "frequency": "Quarterly",
                    "evidence_produced": "Runbook inventory with last update dates and review status"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["log-based", "process-based"],
            "implementation_guidance": {
                "quick_start": "Deploy Sentinel with incident response playbooks, configure Logic Apps for automated procedures, enable Defender for Cloud integration, document runbooks in DevOps wiki",
                "azure_well_architected": "Follows Azure WAF operational excellence for automated incident response and reliability principles",
                "compliance_mapping": "Addresses NIST controls ir-4, ir-4.1, ir-6, ir-6.1, ir-7, ir-8"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-INR-01 evidence.
        """
        return {
            "ksi_id": "KSI-INR-01",
            "queries": [
                {
                    "name": "Incident Response Execution Evidence",
                    "type": "kql",
                    "workspace": "Azure Sentinel workspace",
                    "query": """
                        SecurityIncident
                        | where TimeGenerated > ago(30d)
                        | extend PlaybooksRun = array_length(parse_json(AdditionalData).alertProductNames)
                        | project 
                            IncidentNumber,
                            Title,
                            Severity,
                            Status,
                            CreatedTime = TimeGenerated,
                            ClosedTime,
                            Owner,
                            PlaybooksRun,
                            TimeToResolve = datetime_diff('hour', ClosedTime, TimeGenerated)
                        | order by CreatedTime desc
                        """,
                    "purpose": "Demonstrate incidents were handled following documented procedures",
                    "expected_result": "Incidents with assigned owners, playbook executions, and timely resolution"
                },
                {
                    "name": "Playbook Execution History",
                    "type": "kql",
                    "workspace": "Log Analytics workspace with Logic Apps diagnostics",
                    "query": """
                        AzureDiagnostics
                        | where ResourceProvider == 'MICROSOFT.LOGIC'
                        | where Category == 'WorkflowRuntime'
                        | where TimeGenerated > ago(30d)
                        | where resource_workflowName_s contains 'IR-' or resource_workflowName_s contains 'IncidentResponse'
                        | summarize 
                            TotalRuns = count(),
                            SuccessfulRuns = countif(status_s == 'Succeeded'),
                            FailedRuns = countif(status_s == 'Failed')
                            by resource_workflowName_s
                        | extend SuccessRate = round((SuccessfulRuns * 100.0) / TotalRuns, 2)
                        """,
                    "purpose": "Show automated incident response procedures executed via playbooks",
                    "expected_result": "Regular playbook executions with high success rate"
                },
                {
                    "name": "Incident Response SLA Compliance",
                    "type": "kql",
                    "workspace": "Azure Sentinel workspace",
                    "query": """
                        SecurityIncident
                        | where TimeGenerated > ago(90d)
                        | extend TimeToFirstResponse = datetime_diff('minute', FirstModifiedTime, CreatedTime)
                        | extend TimeToResolution = datetime_diff('hour', ClosedTime, CreatedTime)
                        | summarize 
                            TotalIncidents = count(),
                            AvgTimeToFirstResponse = avg(TimeToFirstResponse),
                            AvgTimeToResolution = avg(TimeToResolution),
                            Within1HourResponse = countif(TimeToFirstResponse <= 60),
                            Within24HourResolution = countif(TimeToResolution <= 24)
                            by Severity
                        | extend ResponseSLACompliance = round((Within1HourResponse * 100.0) / TotalIncidents, 2)
                        """,
                    "purpose": "Demonstrate incident response procedures meet defined SLAs",
                    "expected_result": "High SLA compliance rates indicating effective procedures"
                },
                {
                    "name": "Incident Runbook Inventory",
                    "type": "azure_devops_api",
                    "endpoint": "https://dev.azure.com/{org}/{project}/_apis/wiki/wikis/{wikiId}/pages?api-version=7.1",
                    "method": "GET",
                    "purpose": "Verify documented incident response procedures exist and are maintained",
                    "expected_result": "Comprehensive runbook documentation with recent review dates"
                },
                {
                    "name": "Sentinel Playbook Configuration",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Logic/workflows?api-version=2019-05-01",
                    "method": "GET",
                    "purpose": "Inventory automated incident response playbooks",
                    "expected_result": "Multiple playbooks configured for different incident types"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI (az login) or Managed Identity",
                "permissions_required": [
                    "Sentinel Reader for incident queries",
                    "Log Analytics Reader for playbook execution logs",
                    "Logic App Operator for playbook inventory",
                    "DevOps Reader for runbook documentation"
                ],
                "automation_tools": [
                    "Azure CLI (az sentinel, az monitor)",
                    "PowerShell Az.Sentinel and Az.LogicApp modules",
                    "Python azure-mgmt-securityinsight SDK"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-INR-01.
        """
        return {
            "ksi_id": "KSI-INR-01",
            "artifacts": [
                {
                    "name": "Incident Response Log",
                    "description": "Monthly export of all security incidents with response actions and outcomes",
                    "source": "Azure Sentinel SecurityIncident table",
                    "format": "CSV from KQL query with incident details",
                    "collection_frequency": "Monthly",
                    "retention_period": "7 years (incident records)",
                    "automation": "Scheduled KQL query with email and storage delivery"
                },
                {
                    "name": "Playbook Execution Report",
                    "description": "Monthly report of automated incident response playbook executions",
                    "source": "Logic Apps diagnostic logs via Log Analytics",
                    "format": "CSV with playbook name, execution count, success rate",
                    "collection_frequency": "Monthly",
                    "retention_period": "3 years",
                    "automation": "Scheduled KQL query"
                },
                {
                    "name": "Incident Response SLA Dashboard",
                    "description": "Real-time dashboard showing incident response time metrics and SLA compliance",
                    "source": "Sentinel incidents via Azure Workbook",
                    "format": "Azure Workbook (interactive dashboard)",
                    "collection_frequency": "Continuous (real-time)",
                    "retention_period": "Persistent (configuration stored)",
                    "automation": "Azure Monitor Workbook with auto-refresh"
                },
                {
                    "name": "Incident Response Runbook Documentation",
                    "description": "Documented incident response procedures and playbooks",
                    "source": "Azure DevOps wiki or GitHub documentation",
                    "format": "Markdown or PDF export",
                    "collection_frequency": "Quarterly (or on update)",
                    "retention_period": "3 years with version history",
                    "automation": "DevOps wiki export or GitHub repository snapshot"
                },
                {
                    "name": "Playbook Configuration Inventory",
                    "description": "Complete inventory of automated incident response playbooks",
                    "source": "Logic Apps configuration via REST API",
                    "format": "JSON export of workflow definitions",
                    "collection_frequency": "Quarterly",
                    "retention_period": "3 years",
                    "automation": "Azure CLI or PowerShell script"
                },
                {
                    "name": "Post-Incident Review Reports",
                    "description": "Documentation of lessons learned and procedure improvements from major incidents",
                    "source": "DevOps work items or manual documentation",
                    "format": "PDF or Word documents",
                    "collection_frequency": "Per incident (major incidents only)",
                    "retention_period": "7 years",
                    "automation": "Semi-automated via work item template"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with security team access"
            },
            "compliance_mapping": {
                "fedramp_controls": ["ir-4", "ir-4.1", "ir-6", "ir-6.1", "ir-7", "ir-8"],
                "evidence_purpose": "Demonstrate documented incident response procedures are followed consistently"
            }
        }
