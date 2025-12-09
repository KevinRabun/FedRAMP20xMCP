"""
KSI-INR-01: Incident Response Procedure

Always follow a documented incident response procedure.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
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
    
