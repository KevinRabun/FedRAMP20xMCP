"""
FRR-SCN-01: Notifications

Providers MUST notify all necessary parties when Significant Change Notifications are required, including at least FedRAMP and all agency customers. Providers MAY share Significant Change Notifications publicly or with other parties.

Official FedRAMP 20x Requirement
Source: FRR-SCN (SCN) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_SCN_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-SCN-01: Notifications
    
    **Official Statement:**
    Providers MUST notify all necessary parties when Significant Change Notifications are required, including at least FedRAMP and all agency customers. Providers MAY share Significant Change Notifications publicly or with other parties.
    
    **Family:** SCN - SCN
    
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
    
    FRR_ID = "FRR-SCN-01"
    FRR_NAME = "Notifications"
    FRR_STATEMENT = """Providers MUST notify all necessary parties when Significant Change Notifications are required, including at least FedRAMP and all agency customers. Providers MAY share Significant Change Notifications publicly or with other parties."""
    FAMILY = "SCN"
    FAMILY_NAME = "SCN"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("IR-6", "Incident Reporting"),
        ("PM-15", "Security and Privacy Groups and Associations"),
        ("CP-2", "Contingency Plan")
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = ["KSI-ICP-08", "KSI-ICP-09"]
    
    def __init__(self):
        """Initialize FRR-SCN-01 analyzer."""
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
        Check for notification systems for significant changes.
        
        Detects:
        - Email notification systems (SMTP, SendGrid, SES)
        - Webhook implementations
        - Message queue notifications (SQS, Azure Service Bus)
        - Alerting systems integration
        """
        findings = []
        lines = code.split('\n')
        
        # Check for notification/alerting code
        notification_patterns = [
            r'send.*email', r'smtp', r'sendgrid', r'ses\.send',
            r'notify.*customer', r'notify.*agency', r'webhook',
            r'post.*notification', r'alert.*customer',
            r'EmailMessage', r'smtplib', r'send_mail'
        ]
        
        has_notification = False
        for i, line in enumerate(lines, start=1):
            for pattern in notification_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_notification = True
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Notification system detected - verify SCN coverage",
                        description=f"Line {i} implements notification functionality. FRR-SCN-01 requires notifying FedRAMP and all agency customers for Significant Change Notifications.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Ensure notification system covers: (1) FedRAMP notification, (2) All agency customers, (3) Significant change events (security updates, service changes, incident notifications), (4) Audit trail of notifications sent"
                    ))
                    return findings
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Check C# for notification systems (SmtpClient, SendGrid, etc)."""
        patterns = [r'SmtpClient', r'SendGridClient', r'MailMessage', r'IEmailSender']
        return self._check_notifications(code, file_path, patterns)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Check Java for notification systems (JavaMail, AWS SES, etc)."""
        patterns = [r'javax\.mail', r'MimeMessage', r'AmazonSimpleEmailService', r'sendEmail']
        return self._check_notifications(code, file_path, patterns)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Check TypeScript for notification systems (Nodemailer, SendGrid, etc)."""
        patterns = [r'nodemailer', r'@sendgrid', r'transporter\.sendMail', r'webhook']
        return self._check_notifications(code, file_path, patterns)
    
    def _check_notifications(self, code: str, file_path: str, patterns: List[str]) -> List[Finding]:
        """Shared notification detection logic."""
        findings = []
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Notification system found",
                    description="Notification functionality detected. Verify it handles Significant Change Notifications to FedRAMP and all customers per FRR-SCN-01.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Ensure SCN notifications reach FedRAMP and all agency customers"
                ))
                break
        return findings
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-SCN-01 compliance.
        
        TODO: Implement Bicep analysis
        - Detect relevant Azure resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Bicep regex patterns
        # Example:
        # resource_pattern = r"resource\s+\w+\s+'Microsoft\.\w+/\w+@[\d-]+'\s*="
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-SCN-01 compliance.
        
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
        Analyze GitHub Actions workflow for FRR-SCN-01 compliance.
        
        TODO: Implement GitHub Actions analysis
        - Check for required steps/actions
        - Verify compliance configuration
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitHub Actions analysis
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-SCN-01 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-SCN-01 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get KQL queries for collecting FRR-SCN-01 evidence.
        
        Returns queries to collect evidence of Significant Change Notification
        systems and notification delivery to FedRAMP and agency customers.
        """
        return {
            "automated_queries": [
                # Azure Monitor: Email notifications sent (last 90 days)
                """AzureDiagnostics
                | where TimeGenerated > ago(90d)
                | where Category == 'EmailDelivery' or OperationName contains 'SendEmail'
                | where RecipientAddress_s contains 'fedramp' or RecipientAddress_s contains 'agency' or RecipientAddress_s contains 'customer'
                | project TimeGenerated, RecipientAddress_s, Subject_s, DeliveryStatus_s
                | order by TimeGenerated desc""",
                
                # Azure Logic Apps/Functions: Notification workflows
                """Resources
                | where type =~ 'microsoft.logic/workflows' or type =~ 'microsoft.web/sites'
                | where name contains 'notification' or name contains 'scn' or name contains 'alert'
                | project name, type, resourceGroup, subscriptionId, properties""",
                
                # SendGrid/Communication Services: Notification logs
                """AzureDiagnostics
                | where ResourceProvider == 'MICROSOFT.COMMUNICATION'
                | where TimeGenerated > ago(90d)
                | summarize NotificationCount=count() by EmailTo_s, bin(TimeGenerated, 1d)
                | where EmailTo_s contains 'fedramp' or EmailTo_s contains 'gov'
                | order by TimeGenerated desc"""
            ],
            "manual_queries": [
                "Review email server logs for SCN deliveries to FedRAMP email addresses",
                "Check notification service (SendGrid/SES) for customer notification lists",
                "Verify notification templates include FedRAMP contact addresses"
            ]
        }
    
    def get_evidence_artifacts(self) -> dict:
        """
        Get list of evidence artifacts for FRR-SCN-01 compliance.
        
        Returns documentation and logs demonstrating Significant Change
        Notification delivery to required parties.
        """
        return {
            "evidence_artifacts": [
                "SCN-POLICY.md - Policy requiring notification to FedRAMP and all customers",
                "NOTIFICATION-TEMPLATES/ - Email templates for SCN notifications",
                "scn-logs/ - Delivery logs showing notifications sent to FedRAMP/customers",
                "RECIPIENT-LIST.md - Maintained list of FedRAMP and agency contacts",
                "notification-config.yaml - Configuration for notification service",
                "AUDIT-TRAIL.md - Tracking of all SCN notifications sent (dates, recipients)",
                "CUSTOMER-CONFIRMATION/ - Customer acknowledgments of SCN receipt"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating FRR-SCN-01 evidence collection.
        
        Returns guidance for implementing and documenting Significant Change
        Notification systems with required recipient coverage.
        """
        return {
            "implementation_notes": [
                "1. Implement notification system",
                "   - Use Azure Communication Services, SendGrid, or AWS SES",
                "   - Create notification service with recipient management",
                "   - Support multiple delivery channels (email, webhook, portal)",
                "   - Example: Azure Logic App triggered by SCN events",
                "",
                "2. Maintain recipient lists",
                "   - Store FedRAMP contact email addresses (info@fedramp.gov, etc.)",
                "   - Maintain list of all agency customer contacts",
                "   - Support recipient groups (FedRAMP, Agency-A, Agency-B)",
                "   - Quarterly validation of contact information accuracy",
                "",
                "3. Implement notification templates",
                "   - Create SCN email templates with required information",
                "   - Include: change description, impact, timeline, action required",
                "   - Support different SCN types (security, service, incident)",
                "   - Version control templates in Git",
                "",
                "4. Enable audit logging",
                "   - Log all SCN notifications: timestamp, recipients, content, delivery status",
                "   - Enable Application Insights on notification service",
                "   - Retain logs for 90 days minimum (365 days recommended)",
                "   - Alert on delivery failures to FedRAMP/customers",
                "",
                "5. Automate evidence collection",
                "   - Schedule monthly KQL queries to extract notification logs",
                "   - Generate SCN summary report (count, recipients, delivery rate)",
                "   - Store logs in Azure Blob Storage for compliance review",
                "   - Example: Power Automate flow exporting SCN logs to SharePoint"
            ]
        }
