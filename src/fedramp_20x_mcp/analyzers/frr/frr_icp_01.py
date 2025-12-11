"""
FRR-ICP-01: Incident Reporting to FedRAMP

Providers MUST responsibly report _incidents_ to FedRAMP within 1 hour of identification by sending an email to fedramp_security@fedramp.gov or fedramp_security@gsa.gov.

Official FedRAMP 20x Requirement
Source: FRR-ICP (ICP) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
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
        Analyze C# code for FRR-ICP-01 compliance using AST.
        
        TODO: Implement C# analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for C#
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ICP-01 compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ICP-01 compliance using AST.
        
        TODO: Implement TypeScript analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
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
        Analyze Terraform infrastructure code for FRR-ICP-01 compliance.
        
        TODO: Implement Terraform analysis
        - Detect relevant resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Terraform regex patterns
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
        Analyze Azure Pipelines YAML for FRR-ICP-01 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ICP-01 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ICP-01.
        
        This requirement is not directly code-detectable. Provides manual validation guidance.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'No',
            'automation_approach': 'Manual validation required - use evidence collection queries and documentation review',
            'evidence_artifacts': [
                # TODO: List evidence artifacts to collect
                # Examples:
                # - "Configuration export from service X"
                # - "Access logs showing activity Y"
                # - "Documentation showing policy Z"
            ],
            'collection_queries': [
                # TODO: Add KQL or API queries for evidence
                # Examples for Azure:
                # - "AzureDiagnostics | where Category == 'X' | project TimeGenerated, Property"
                # - "GET https://management.azure.com/subscriptions/{subscriptionId}/..."
            ],
            'manual_validation_steps': [
                # TODO: Add manual validation procedures
                # 1. "Review documentation for X"
                # 2. "Verify configuration setting Y"
                # 3. "Interview stakeholder about Z"
            ],
            'recommended_services': [
                # TODO: List Azure/AWS services that help with this requirement
                # Examples:
                # - "Azure Policy - for configuration validation"
                # - "Azure Monitor - for activity logging"
                # - "Microsoft Defender for Cloud - for security posture"
            ],
            'integration_points': [
                # TODO: List integration with other tools
                # Examples:
                # - "Export to OSCAL format for automated reporting"
                # - "Integrate with ServiceNow for change management"
            ]
        }
