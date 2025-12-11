"""
Reusable detection patterns for FRR analyzers.

This module provides common detection logic that can be reused across multiple FRR analyzers,
reducing duplication and ensuring consistency in compliance checking.
"""

import re
from typing import List, Tuple, Dict
from .base import Finding, Severity
from .ast_utils import ASTParser, CodeLanguage


# ============================================================================
# PYTHON CODE DETECTION PATTERNS
# ============================================================================

def detect_python_logging(code: str) -> Tuple[bool, List[str]]:
    """
    Detect logging frameworks in Python code.
    
    Returns:
        Tuple of (has_logging, detected_frameworks)
    """
    parser = ASTParser(CodeLanguage.PYTHON)
    tree = parser.parse(code)
    detected = []
    
    if tree:
        # AST-based detection
        code_bytes = code.encode('utf-8')
        root = tree.root_node
        
        # Find import statements
        for node in root.children:
            if node.type == 'import_statement' or node.type == 'import_from_statement':
                node_text = code_bytes[node.start_byte:node.end_byte].decode('utf-8')
                if re.search(r'\b(logging|structlog|loguru|azure\.monitor)\b', node_text):
                    detected.append(node_text.strip())
    else:
        # Fallback to regex
        if re.search(r'import\s+(logging|structlog|loguru)', code):
            detected.append('logging framework')
        if re.search(r'from\s+azure\.monitor', code):
            detected.append('azure.monitor')
    
    return (len(detected) > 0, detected)


def detect_python_monitoring(code: str) -> Tuple[bool, List[str]]:
    """
    Detect monitoring/observability frameworks in Python code.
    
    Returns:
        Tuple of (has_monitoring, detected_frameworks)
    """
    detected = []
    patterns = [
        (r'azure\.monitor', 'Azure Monitor'),
        (r'prometheus_client', 'Prometheus'),
        (r'opencensus|opentelemetry', 'OpenTelemetry/OpenCensus'),
        (r'sentry_sdk', 'Sentry'),
        (r'statsd|datadog', 'StatsD/Datadog'),
    ]
    
    for pattern, name in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            detected.append(name)
    
    return (len(detected) > 0, detected)


def detect_python_alerting(code: str) -> Tuple[bool, List[str]]:
    """
    Detect alerting/notification mechanisms in Python code.
    
    Returns:
        Tuple of (has_alerting, detected_mechanisms)
    """
    detected = []
    patterns = [
        (r'smtplib|email\.message', 'Email (SMTP)'),
        (r'sendgrid|mailgun|ses', 'Email Service'),
        (r'slack_sdk|slack_webhook', 'Slack'),
        (r'azure\.communication', 'Azure Communication Services'),
        (r'requests\.post.*webhook', 'Webhook'),
        (r'def\s+\w*alert\w*|def\s+\w*notify\w*', 'Alert/Notify Functions'),
    ]
    
    for pattern, name in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            detected.append(name)
    
    return (len(detected) > 0, detected)


def detect_python_vulnerability_tracking(code: str) -> Tuple[bool, List[str]]:
    """
    Detect vulnerability tracking/scanning in Python code.
    
    Returns:
        Tuple of (has_vuln_tracking, detected_tools)
    """
    detected = []
    patterns = [
        (r'safety|safety\.check', 'Safety'),
        (r'bandit|bandit\.core', 'Bandit'),
        (r'snyk', 'Snyk'),
        (r'trivy', 'Trivy'),
        (r'cve|nvd|vulnerability', 'CVE/Vulnerability References'),
        (r'security\..*scan|scan.*security', 'Security Scanning'),
    ]
    
    for pattern, name in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            detected.append(name)
    
    return (len(detected) > 0, detected)


# ============================================================================
# BICEP INFRASTRUCTURE DETECTION PATTERNS
# ============================================================================

def detect_bicep_monitoring_resources(code: str) -> Dict[str, bool]:
    """
    Detect Azure monitoring resources in Bicep code.
    
    Returns:
        Dict with detected resource types
    """
    return {
        'log_analytics': bool(re.search(r'Microsoft\.OperationalInsights/workspaces', code)),
        'application_insights': bool(re.search(r'Microsoft\.Insights/components', code)),
        'alert_rules': bool(re.search(r'Microsoft\.Insights/(metricalerts|scheduledQueryRules)', code)),
        'action_groups': bool(re.search(r'Microsoft\.Insights/actionGroups', code)),
        'diagnostic_settings': bool(re.search(r'Microsoft\.Insights/diagnosticSettings', code)),
        'workbooks': bool(re.search(r'Microsoft\.Insights/workbooks', code)),
    }


def detect_bicep_security_resources(code: str) -> Dict[str, bool]:
    """
    Detect Azure security resources in Bicep code.
    
    Returns:
        Dict with detected resource types
    """
    return {
        'defender': bool(re.search(r'Microsoft\.Security/(pricings|autoProvisioningSettings|workspaceSettings)', code)),
        'key_vault': bool(re.search(r'Microsoft\.KeyVault/vaults', code)),
        'managed_identity': bool(re.search(r'Microsoft\.ManagedIdentity/userAssignedIdentities', code)),
        'rbac': bool(re.search(r'Microsoft\.Authorization/roleAssignments', code)),
        'policy': bool(re.search(r'Microsoft\.Authorization/policyAssignments', code)),
        'security_center': bool(re.search(r'Microsoft\.Security/', code)),
    }


def detect_bicep_network_security(code: str) -> Dict[str, bool]:
    """
    Detect network security resources in Bicep code.
    
    Returns:
        Dict with detected resource types
    """
    return {
        'nsg': bool(re.search(r'Microsoft\.Network/networkSecurityGroups', code)),
        'firewall': bool(re.search(r'Microsoft\.Network/azureFirewalls', code)),
        'waf': bool(re.search(r'Microsoft\.Network/ApplicationGatewayWebApplicationFirewallPolicies', code)),
        'private_endpoint': bool(re.search(r'Microsoft\.Network/privateEndpoints', code)),
        'bastion': bool(re.search(r'Microsoft\.Network/bastionHosts', code)),
    }


def detect_bicep_automation_resources(code: str) -> Dict[str, bool]:
    """
    Detect automation resources for incident/vulnerability response in Bicep code.
    
    Returns:
        Dict with detected resource types
    """
    return {
        'logic_apps': bool(re.search(r'Microsoft\.Logic/workflows', code)),
        'function_apps': bool(re.search(r"Microsoft\.Web/sites.*kind:\s*'functionapp'", code)),
        'automation_accounts': bool(re.search(r'Microsoft\.Automation/automationAccounts', code)),
        'runbooks': bool(re.search(r'Microsoft\.Automation/automationAccounts/runbooks', code)),
    }


# ============================================================================
# TERRAFORM INFRASTRUCTURE DETECTION PATTERNS
# ============================================================================

def detect_terraform_monitoring_resources(code: str) -> Dict[str, bool]:
    """
    Detect Azure monitoring resources in Terraform code.
    
    Returns:
        Dict with detected resource types
    """
    return {
        'log_analytics': bool(re.search(r'resource\s+"azurerm_log_analytics_workspace"', code)),
        'application_insights': bool(re.search(r'resource\s+"azurerm_application_insights"', code)),
        'alert_rules': bool(re.search(r'resource\s+"azurerm_monitor_(metric|scheduled_query_rules)_alert"', code)),
        'action_groups': bool(re.search(r'resource\s+"azurerm_monitor_action_group"', code)),
        'diagnostic_settings': bool(re.search(r'resource\s+"azurerm_monitor_diagnostic_setting"', code)),
    }


def detect_terraform_security_resources(code: str) -> Dict[str, bool]:
    """
    Detect Azure security resources in Terraform code.
    
    Returns:
        Dict with detected resource types
    """
    return {
        'defender': bool(re.search(r'resource\s+"azurerm_security_center', code)),
        'key_vault': bool(re.search(r'resource\s+"azurerm_key_vault"', code)),
        'managed_identity': bool(re.search(r'resource\s+"azurerm_user_assigned_identity"', code)),
        'rbac': bool(re.search(r'resource\s+"azurerm_role_assignment"', code)),
        'policy': bool(re.search(r'resource\s+"azurerm_policy_assignment"', code)),
    }


# ============================================================================
# CI/CD PIPELINE DETECTION PATTERNS
# ============================================================================

def detect_github_actions_security_scanning(code: str) -> Dict[str, bool]:
    """
    Detect security scanning tools in GitHub Actions workflows.
    
    Returns:
        Dict with detected tools
    """
    return {
        'trivy': bool(re.search(r'uses:.*trivy', code, re.IGNORECASE)),
        'snyk': bool(re.search(r'uses:.*snyk', code, re.IGNORECASE)),
        'codeql': bool(re.search(r'uses:.*github/codeql-action', code, re.IGNORECASE)),
        'dependabot': bool(re.search(r'dependabot', code, re.IGNORECASE)),
        'security_scanning': bool(re.search(r'uses:.*security.*scan|scan.*security', code, re.IGNORECASE)),
    }


def detect_github_actions_notifications(code: str) -> Dict[str, bool]:
    """
    Detect notification mechanisms in GitHub Actions workflows.
    
    Returns:
        Dict with detected notification types
    """
    return {
        'slack': bool(re.search(r'slack/action|slack.*webhook', code, re.IGNORECASE)),
        'email': bool(re.search(r'email|mail', code, re.IGNORECASE)),
        'webhook': bool(re.search(r'webhook|http.*post', code, re.IGNORECASE)),
        'teams': bool(re.search(r'microsoft.*teams|teams.*webhook', code, re.IGNORECASE)),
    }


def detect_cicd_deployment_gates(code: str) -> Dict[str, bool]:
    """
    Detect deployment gates and approval mechanisms in CI/CD.
    
    Returns:
        Dict with detected gate types
    """
    return {
        'manual_approval': bool(re.search(r'approval|manual.*gate|environment.*protection', code, re.IGNORECASE)),
        'environment': bool(re.search(r'environment:', code)),
        'security_gate': bool(re.search(r'security.*gate|gate.*security', code, re.IGNORECASE)),
    }


# ============================================================================
# FINDING GENERATORS
# ============================================================================

def create_missing_logging_finding(frr_id: str, file_path: str = "") -> Finding:
    """Generate a finding for missing logging infrastructure."""
    return Finding(
        frr_id=frr_id,
        severity=Severity.MEDIUM,
        message="No logging framework detected in application code",
        details=(
            "The application should implement structured logging to track incidents and security events. "
            "Consider using:\n"
            "- Python: logging, structlog, or loguru\n"
            "- C#: Serilog, NLog, or Microsoft.Extensions.Logging\n"
            "- Java: SLF4J with Logback or Log4j2\n"
            "- TypeScript: Winston or Pino"
        ),
        file_path=file_path,
        line_number=1,
        remediation="Implement a logging framework to capture application events and incidents."
    )


def create_missing_monitoring_finding(frr_id: str, file_path: str = "") -> Finding:
    """Generate a finding for missing monitoring infrastructure."""
    return Finding(
        frr_id=frr_id,
        severity=Severity.HIGH,
        message="No monitoring infrastructure detected",
        details=(
            "The infrastructure should include monitoring resources to track system health and security events. "
            "Required resources:\n"
            "- Azure: Log Analytics Workspace, Application Insights\n"
            "- Observability: Prometheus, Grafana, OpenTelemetry"
        ),
        file_path=file_path,
        line_number=1,
        remediation="Deploy monitoring infrastructure (Log Analytics, Application Insights, or equivalent)."
    )


def create_missing_alerting_finding(frr_id: str, file_path: str = "") -> Finding:
    """Generate a finding for missing alerting mechanisms."""
    return Finding(
        frr_id=frr_id,
        severity=Severity.HIGH,
        message="No alerting mechanism detected",
        details=(
            "The system should have alerting capabilities to notify stakeholders of incidents. "
            "Required components:\n"
            "- Azure: Action Groups for alert notifications\n"
            "- Code: Alert functions using email, Slack, or webhook integrations\n"
            "- CI/CD: Notification steps for security scan results"
        ),
        file_path=file_path,
        line_number=1,
        remediation="Implement alerting mechanisms (Action Groups, notification services, etc.)."
    )


def create_missing_security_scanning_finding(frr_id: str, file_path: str = "") -> Finding:
    """Generate a finding for missing security scanning in CI/CD."""
    return Finding(
        frr_id=frr_id,
        severity=Severity.MEDIUM,
        message="No security scanning detected in CI/CD pipeline",
        details=(
            "The CI/CD pipeline should include security scanning to detect vulnerabilities. "
            "Recommended tools:\n"
            "- Container scanning: Trivy, Snyk Container\n"
            "- Code scanning: GitHub CodeQL, Snyk Code\n"
            "- Dependency scanning: Dependabot, Snyk"
        ),
        file_path=file_path,
        line_number=1,
        remediation="Add security scanning steps to CI/CD pipeline (Trivy, Snyk, CodeQL)."
    )


def create_missing_vulnerability_tracking_finding(frr_id: str, file_path: str = "") -> Finding:
    """Generate a finding for missing vulnerability tracking."""
    return Finding(
        frr_id=frr_id,
        severity=Severity.HIGH,
        message="No vulnerability tracking mechanism detected",
        details=(
            "The system should track and manage vulnerabilities systematically. "
            "Required capabilities:\n"
            "- Vulnerability scanning tools (Trivy, Snyk, Defender for Cloud)\n"
            "- Tracking systems for remediation status\n"
            "- Integration with incident response"
        ),
        file_path=file_path,
        line_number=1,
        remediation="Implement vulnerability scanning and tracking (Microsoft Defender for Cloud recommended)."
    )
