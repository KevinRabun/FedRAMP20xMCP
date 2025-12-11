"""
Reusable detection patterns for FRR analyzers.

This module provides common detection logic that can be reused across multiple FRR analyzers
to ensure consistency and reduce duplication.
"""

import re
from typing import List, Tuple, Dict
from ..base import Finding, Severity
from ..ast_utils import ASTParser, CodeLanguage


# ============================================================================
# PYTHON DETECTION PATTERNS
# ============================================================================

def detect_python_logging(code: str) -> Tuple[bool, List[str]]:
    """Detect logging frameworks in Python code."""
    patterns = []
    
    try:
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        code_bytes = code.encode('utf8')
        
        if tree and tree.root_node:
            import_nodes = parser.find_nodes_by_type(tree.root_node, 'import_statement') + \
                          parser.find_nodes_by_type(tree.root_node, 'import_from_statement')
            
            for node in import_nodes:
                import_text = parser.get_node_text(node, code_bytes).decode('utf8').lower()
                if 'logging' in import_text:
                    patterns.append('logging')
                if 'structlog' in import_text:
                    patterns.append('structlog')
                if 'loguru' in import_text:
                    patterns.append('loguru')
    except Exception:
        pass
    
    # Fallback regex
    if not patterns:
        if re.search(r'import\s+logging', code, re.IGNORECASE):
            patterns.append('logging')
        if re.search(r'from\s+\w+\s+import\s+\w*log', code, re.IGNORECASE):
            patterns.append('logging')
    
    return len(patterns) > 0, patterns


def detect_python_monitoring(code: str) -> Tuple[bool, List[str]]:
    """Detect monitoring/observability integrations in Python code."""
    patterns = []
    
    monitoring_libs = [
        'azure.monitor', 'prometheus_client', 'opencensus', 'opentelemetry',
        'datadog', 'newrelic', 'sentry_sdk'
    ]
    
    for lib in monitoring_libs:
        if lib in code.lower():
            patterns.append(lib)
    
    return len(patterns) > 0, patterns


def detect_python_alerting(code: str) -> Tuple[bool, List[str]]:
    """Detect alerting/notification mechanisms in Python code."""
    patterns = []
    
    alert_libs = [
        'smtplib', 'sendgrid', 'azure.communication', 'twilio',
        'requests', 'httpx', 'pagerduty', 'slack_sdk'
    ]
    
    for lib in alert_libs:
        if lib in code.lower():
            patterns.append(lib)
    
    # Check for alert/notify function calls
    if re.search(r'(send_?mail|send_?email|notify|alert|webhook)', code, re.IGNORECASE):
        patterns.append('notification_function')
    
    return len(patterns) > 0, patterns


def detect_python_vulnerability_tracking(code: str) -> Tuple[bool, List[str]]:
    """Detect vulnerability tracking/management code in Python."""
    patterns = []
    
    # CVE/vulnerability related imports
    vuln_patterns = ['cve', 'vulnerability', 'nvd', 'security', 'trivy', 'snyk', 'dependabot']
    
    for pattern in vuln_patterns:
        if pattern in code.lower():
            patterns.append(pattern)
    
    return len(patterns) > 0, patterns


# ============================================================================
# BICEP/IaC DETECTION PATTERNS  
# ============================================================================

def detect_bicep_monitoring_resources(code: str) -> Dict[str, bool]:
    """Detect Azure monitoring resources in Bicep."""
    return {
        'log_analytics': bool(re.search(r"resource\s+\w+\s+'Microsoft\.OperationalInsights/workspaces", code, re.IGNORECASE)),
        'application_insights': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Insights/components", code, re.IGNORECASE)),
        'alert_rules': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Insights/(metricalerts|scheduledQueryRules)", code, re.IGNORECASE)),
        'action_groups': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Insights/actionGroups", code, re.IGNORECASE)),
        'diagnostic_settings': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Insights/diagnosticSettings", code, re.IGNORECASE)),
    }


def detect_bicep_security_resources(code: str) -> Dict[str, bool]:
    """Detect Azure security resources in Bicep."""
    return {
        'defender': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Security/(pricings|securityContacts|autoProvisioningSettings)", code, re.IGNORECASE)),
        'key_vault': bool(re.search(r"resource\s+\w+\s+'Microsoft\.KeyVault/vaults", code, re.IGNORECASE)),
        'managed_identity': bool(re.search(r"identity:\s*\{[^}]*type:\s*'(SystemAssigned|UserAssigned)", code, re.IGNORECASE | re.DOTALL)),
        'rbac': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Authorization/roleAssignments", code, re.IGNORECASE)),
        'policy': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Authorization/policyAssignments", code, re.IGNORECASE)),
    }


def detect_bicep_network_security(code: str) -> Dict[str, bool]:
    """Detect network security configurations in Bicep."""
    return {
        'nsg': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Network/networkSecurityGroups", code, re.IGNORECASE)),
        'firewall': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Network/(azureFirewalls|firewallPolicies)", code, re.IGNORECASE)),
        'waf': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Network/(applicationGateways|frontDoors).*sku.*WAF", code, re.IGNORECASE | re.DOTALL)),
        'private_endpoint': bool(re.search(r"resource\s+\w+\s+'Microsoft\.Network/privateEndpoints", code, re.IGNORECASE)),
    }


def detect_terraform_monitoring_resources(code: str) -> Dict[str, bool]:
    """Detect monitoring resources in Terraform."""
    return {
        'log_analytics': bool(re.search(r'resource\s+"azurerm_log_analytics_workspace"', code, re.IGNORECASE)),
        'application_insights': bool(re.search(r'resource\s+"azurerm_application_insights"', code, re.IGNORECASE)),
        'monitor_alert': bool(re.search(r'resource\s+"azurerm_monitor_(metric_alert|scheduled_query_rules_alert)"', code, re.IGNORECASE)),
        'action_group': bool(re.search(r'resource\s+"azurerm_monitor_action_group"', code, re.IGNORECASE)),
        'diagnostic_setting': bool(re.search(r'resource\s+"azurerm_monitor_diagnostic_setting"', code, re.IGNORECASE)),
    }


# ============================================================================
# CI/CD DETECTION PATTERNS
# ============================================================================

def detect_github_actions_security_scanning(code: str) -> Dict[str, bool]:
    """Detect security scanning in GitHub Actions."""
    return {
        'trivy': bool(re.search(r'uses:.*trivy', code, re.IGNORECASE)),
        'snyk': bool(re.search(r'uses:.*snyk', code, re.IGNORECASE)),
        'codeql': bool(re.search(r'uses:.*github/codeql-action', code, re.IGNORECASE)),
        'dependabot': 'dependabot' in code.lower(),
        'security_scanning': bool(re.search(r'uses:.*security', code, re.IGNORECASE)),
    }


def detect_github_actions_notifications(code: str) -> Dict[str, bool]:
    """Detect notification mechanisms in GitHub Actions."""
    return {
        'slack': bool(re.search(r'uses:.*slack', code, re.IGNORECASE)),
        'email': 'email' in code.lower() or 'mail' in code.lower(),
        'webhook': 'webhook' in code.lower(),
        'teams': bool(re.search(r'uses:.*teams', code, re.IGNORECASE)),
    }


def detect_cicd_deployment_gates(code: str) -> Dict[str, bool]:
    """Detect deployment gates/approval steps in CI/CD."""
    return {
        'manual_approval': bool(re.search(r'(approval|manual|gate)', code, re.IGNORECASE)),
        'environment': bool(re.search(r'environment:', code, re.IGNORECASE)),
        'security_gate': bool(re.search(r'(security.*check|vulnerability.*scan)', code, re.IGNORECASE)),
    }


# ============================================================================
# FINDING GENERATORS
# ============================================================================

def create_missing_logging_finding(frr_id: str, file_path: str, severity: Severity = Severity.MEDIUM) -> Finding:
    """Generate finding for missing logging infrastructure."""
    return Finding(
        ksi_id=frr_id,
        requirement_id=frr_id,
        title="No logging framework detected",
        description=f"Code in '{file_path}' lacks logging infrastructure. Implement logging for audit trail and incident detection.",
        severity=severity,
        file_path=file_path,
        line_number=1,
        code_snippet="",
        recommendation="Add logging: 1) Import logging framework (logging, structlog), 2) Log critical events, 3) Configure log aggregation"
    )


def create_missing_monitoring_finding(frr_id: str, file_path: str, severity: Severity = Severity.HIGH) -> Finding:
    """Generate finding for missing monitoring resources."""
    return Finding(
        ksi_id=frr_id,
        requirement_id=frr_id,
        title="No monitoring infrastructure detected",
        description=f"Infrastructure template '{file_path}' lacks monitoring resources. Deploy monitoring for visibility and alerting.",
        severity=severity,
        file_path=file_path,
        line_number=1,
        code_snippet="",
        recommendation="Deploy monitoring: 1) Add Log Analytics workspace, 2) Configure alert rules, 3) Set up diagnostic settings"
    )


def create_missing_alerting_finding(frr_id: str, file_path: str, severity: Severity = Severity.HIGH) -> Finding:
    """Generate finding for missing alerting mechanisms."""
    return Finding(
        ksi_id=frr_id,
        requirement_id=frr_id,
        title="No alerting mechanism detected",
        description=f"Code/infrastructure in '{file_path}' lacks alerting capability. Configure notifications for critical events.",
        severity=severity,
        file_path=file_path,
        line_number=1,
        code_snippet="",
        recommendation="Add alerting: 1) Configure action groups/notifications, 2) Integrate with incident management, 3) Set up escalation policies"
    )


def create_missing_security_scanning_finding(frr_id: str, file_path: str, severity: Severity = Severity.HIGH) -> Finding:
    """Generate finding for missing security scanning."""
    return Finding(
        ksi_id=frr_id,
        requirement_id=frr_id,
        title="No security scanning detected in CI/CD",
        description=f"Pipeline '{file_path}' lacks security scanning steps. Add vulnerability and code security scanning.",
        severity=severity,
        file_path=file_path,
        line_number=1,
        code_snippet="",
        recommendation="Add security scanning: 1) Integrate Trivy/Snyk, 2) Add CodeQL analysis, 3) Configure Dependabot alerts"
    )
