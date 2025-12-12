"""
FRR-ICP-02: Incident Reporting to Agencies

Providers MUST responsibly report _incidents_ to all _agency_ customers within 1 hour of identification using the _incident_ communications points of contact provided by each _agency_ customer.

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


class FRR_ICP_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-02: Incident Reporting to Agencies
    
    **Official Statement:**
    Providers MUST responsibly report _incidents_ to all _agency_ customers within 1 hour of identification using the _incident_ communications points of contact provided by each _agency_ customer.
    
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
    This requirement is code-detectable by checking for:
        1. Application code: Incident notification mechanisms, contact management systems, alert functions
        2. Infrastructure: Alerting infrastructure (Action Groups, notification services), automation workflows
        3. CI/CD: Notification steps, incident communication pipelines
        4. Configuration: Agency contact management, notification routing
    """
    
    FRR_ID = "FRR-ICP-02"
    FRR_NAME = "Incident Reporting to Agencies"
    FRR_STATEMENT = """Providers MUST responsibly report _incidents_ to all _agency_ customers within 1 hour of identification using the _incident_ communications points of contact provided by each _agency_ customer."""
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
    CODE_DETECTABLE = True  # Detects agency notification mechanisms and contact management
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-02 analyzer."""
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
        Analyze Python code for FRR-ICP-02 compliance using AST.
        
        Detects:
        - Notification mechanisms for agency communication
        - Contact management systems
        - Alert/notification functions with agency/customer routing
        - Multi-recipient notification logic
        """
        findings = []
        
        from ..detection_patterns import detect_python_alerting, create_missing_alerting_finding
        
        # Check for alerting/notification mechanisms
        has_alerting, detected_mechanisms = detect_python_alerting(code)
        
        # Check for agency/customer contact management
        has_contact_mgmt = bool(re.search(
            r'(agency|customer|client).*contact|contact.*(agency|customer|client)|'
            r'def\s+\w*notify.*agency|def\s+\w*alert.*customer|'
            r'notification.*routing|contact.*management',
            code, re.IGNORECASE
        ))
        
        # Check for multi-recipient notification
        has_multi_recipient = bool(re.search(
            r'for\s+\w+\s+in\s+(agencies|customers|clients|contacts)|'
            r'recipients|to_addresses|notification_list',
            code, re.IGNORECASE
        ))
        
        if not has_alerting:
            findings.append(create_missing_alerting_finding(self.FRR_ID, file_path))
        
        if not has_contact_mgmt:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.HIGH,
                message="No agency contact management detected",
                details=(
                    "FRR-ICP-02 requires incident reporting to ALL agency customers. "
                    "The code should include agency contact management with:"
                    "\n- Contact information storage (database, config)"
                    "\n- Agency/customer identification"
                    "\n- Contact point routing logic"
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement agency contact management system for incident notifications."
            ))
        
        if has_alerting and not has_multi_recipient:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.MEDIUM,
                message="Alerting detected but no multi-recipient notification logic found",
                details=(
                    "FRR-ICP-02 requires notifying ALL agency customers. "
                    "Ensure notification logic handles multiple recipients."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Add multi-recipient notification logic to alert all agency customers."
            ))
        # Example from FRR-VDR-08:
        # try:
        #     parser = ASTParser(CodeLanguage.PYTHON)
        #     tree = parser.parse(code)
        #     code_bytes = code.encode('utf8')
        #     
        #     if tree and tree.root_node:
        #         # Find relevant nodes
        #         nodes = parser.find_nodes_by_type(tree.root_node, 'node_type')
        #         for node in nodes:
        #             node_text = parser.get_node_text(node, code_bytes)
        #             # Check for violations
        #         
        #         return findings
        # except Exception:
        #     pass
        
        # TODO: Implement regex fallback
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ICP-02 agency notification mechanisms.
        """
        findings = []
        
        has_alerting = bool(re.search(r'(ILogger|SendGrid|SmtpClient|HttpClient.*Post)', code))
        has_contact_mgmt = bool(re.search(r'(Agency|Customer|Client).*Contact|Contact.*(Agency|Customer)', code, re.IGNORECASE))
        has_multi_recipient = bool(re.search(r'foreach.*\((agencies|customers|clients)|IEnumerable|List<.*Contact>', code, re.IGNORECASE))
        
        if not has_alerting:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident notification mechanism detected",
                description=f"C# code in '{file_path}' lacks alerting. FRR-ICP-02 requires incident reporting to agency customers within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Implement agency notification: 1) Add SendGrid/SmtpClient, 2) Create agency contact management, 3) Add multi-recipient logic"
            ))
        
        if not has_contact_mgmt:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No agency contact management detected",
                description=f"Code must manage agency contacts for incident notifications.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add agency contact management with database/config storage"
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ICP-02 agency notification mechanisms.
        """
        findings = []
        
        has_alerting = bool(re.search(r'(javax\.mail|HttpClient|sendEmail|notify)', code, re.IGNORECASE))
        has_contact_mgmt = bool(re.search(r'(Agency|Customer|Client).*Contact|Contact.*(Agency|Customer)', code))
        has_multi_recipient = bool(re.search(r'for.*:\s*(agencies|customers|clients)|List<.*Contact>', code, re.IGNORECASE))
        
        if not has_alerting:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident notification mechanism detected",
                description=f"Java code in '{file_path}' lacks alerting. FRR-ICP-02 requires incident reporting to agency customers within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Implement agency notification: 1) Add JavaMail, 2) Create agency contact management, 3) Add multi-recipient logic"
            ))
        
        if not has_contact_mgmt:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No agency contact management detected",
                description=f"Code must manage agency contacts for incident notifications.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add agency contact management with database/config storage"
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ICP-02 agency notification mechanisms.
        """
        findings = []
        
        has_alerting = bool(re.search(r'(nodemailer|axios\.post|fetch.*post|sendEmail)', code, re.IGNORECASE))
        has_contact_mgmt = bool(re.search(r'(agency|customer|client).*contact|contact.*(agency|customer)', code, re.IGNORECASE))
        has_multi_recipient = bool(re.search(r'for.*of\s+(agencies|customers|clients)|\[\].*Contact', code, re.IGNORECASE))
        
        if not has_alerting:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No incident notification mechanism detected",
                description=f"TypeScript code in '{file_path}' lacks alerting. FRR-ICP-02 requires incident reporting to agency customers within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Implement agency notification: 1) Add nodemailer, 2) Create agency contact management, 3) Add multi-recipient logic"
            ))
        
        if not has_contact_mgmt:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No agency contact management detected",
                description=f"Code must manage agency contacts for incident notifications.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add agency contact management with database/config storage"
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure for agency notification resources.
        """
        findings = []
        
        has_action_group = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Insights/actionGroups", code))
        has_logic_app = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Logic/workflows", code))
        has_function = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Web/sites.*kind:\s*'functionapp'", code, re.DOTALL))
        
        has_notification_infra = has_action_group or has_logic_app or has_function
        
        if not has_notification_infra:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No agency notification infrastructure detected",
                description=f"Bicep template '{file_path}' lacks notification resources. FRR-ICP-02 requires incident reporting to all agency customers within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Deploy notification infrastructure: 1) Action Groups for multi-recipient alerts, 2) Logic Apps for agency notification workflows, 3) Functions for custom notification logic"
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure for agency notification resources.
        """
        findings = []
        
        has_azure_action_group = bool(re.search(r'resource\s+"azurerm_monitor_action_group"', code))
        has_azure_logic_app = bool(re.search(r'resource\s+"azurerm_logic_app_workflow"', code))
        has_aws_sns = bool(re.search(r'resource\s+"aws_sns_topic"', code))
        
        has_notification_infra = has_azure_action_group or has_azure_logic_app or has_aws_sns
        
        if not has_notification_infra:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="No agency notification infrastructure detected",
                description=f"Terraform '{file_path}' lacks notification resources. FRR-ICP-02 requires incident reporting to all agency customers within 1 hour.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Deploy notification: Azure: azurerm_monitor_action_group, azurerm_logic_app_workflow; AWS: aws_sns_topic with multi-subscriber support"
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions for agency notification workflows.
        """
        findings = []
        
        has_notification = bool(re.search(r'(slack/action|email|webhook|notify)', code, re.IGNORECASE))
        has_security_scan = bool(re.search(r'uses:.*?(security|trivy|snyk)', code, re.IGNORECASE))
        
        if has_security_scan and not has_notification:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Security scanning without agency notifications",
                description=f"GitHub Actions '{file_path}' has security scanning but lacks agency notification steps. FRR-ICP-02 requires incident reporting to all agency customers.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add agency notifications: 1) Multi-recipient email action, 2) Webhook to incident management, 3) Slack notifications with agency channels"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines for agency notification tasks.
        """
        findings = []
        
        has_notification = bool(re.search(r'(task:\s*SendEmail|SlackNotification|InvokeRESTAPI)', code, re.IGNORECASE))
        has_security_scan = bool(re.search(r'(task:\s*SecurityScan|SonarQube)', code, re.IGNORECASE))
        
        if has_security_scan and not has_notification:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Security scanning without agency notifications",
                description=f"Azure Pipeline '{file_path}' has security scanning but lacks agency notification tasks. FRR-ICP-02 requires incident reporting to all agency customers.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add agency notifications: SendEmail task with agency recipient list, InvokeRESTAPI for incident management integration"
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI for agency notification mechanisms.
        """
        findings = []
        
        # Note: Using regex - tree-sitter not available for GitLab CI YAML
        has_notification = bool(re.search(r'(curl.*webhook|notify|alert)', code, re.IGNORECASE))
        has_security_scan = bool(re.search(r'(include:.*SAST|dependency_scanning)', code, re.IGNORECASE))
        
        if has_security_scan and not has_notification:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Security scanning without agency notifications",
                description=f"GitLab CI '{file_path}' has security scanning but lacks agency notification mechanisms. FRR-ICP-02 requires incident reporting to all agency customers.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add agency notifications: curl commands to webhook endpoints, integration with incident management API"
            ))
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """Get Azure Resource Graph queries for agency notification evidence."""
        return {
            'automated_queries': [
                "// Action Groups - Get multi-recipient notification configurations",
                "resources",
                "| where type =~ 'Microsoft.Insights/actionGroups'",
                "| extend emailCount = array_length(properties.emailReceivers), webhookCount = array_length(properties.webhookReceivers)",
                "| project name, resourceGroup, emailCount, webhookCount, location",
                "",
                "// Logic Apps - Get agency notification workflows",
                "resources",
                "| where type =~ 'Microsoft.Logic/workflows'",
                "| extend state = properties.state",
                "| project name, resourceGroup, state, location",
                "",
                "// Function Apps - Get notification functions",
                "resources",
                "| where type =~ 'Microsoft.Web/sites' and kind contains 'functionapp'",
                "| project name, resourceGroup, location"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Get evidence artifacts for FRR-ICP-02."""
        return {
            'evidence_artifacts': [
                "1. Agency Contact Registry: Database or configuration system containing all agency customer contacts including agency identifiers, incident communication points of contact (names, emails, phone numbers), contact verification dates, escalation contacts, and agency-specific notification preferences.",
                
                "2. Incident Response Plan - Agency Notification: Documented procedures for agency incident reporting including 1-hour notification requirement, agency contact lookup process, multi-recipient notification mechanisms, notification templates, and confirmation tracking.",
                
                "3. Notification Infrastructure Configuration: Azure Action Groups configured with agency email addresses, Logic Apps for agency notification workflows, Function Apps for custom agency notification logic, multi-recipient email configurations, and webhook integrations to agency incident systems.",
                
                "4. Historical Agency Incident Notifications: Records of past incidents reported to agencies showing incident identification timestamp, agency notification timestamps (within 1 hour), list of notified agencies, confirmation receipts from agencies, and notification method (email, API, portal).",
                
                "5. Agency Onboarding Documentation: Records showing how agency contacts are collected during onboarding including contact information forms, contact verification process, incident communication channel setup, and contact update procedures.",
                
                "6. Multi-Tenant Notification Testing: Evidence of testing multi-agency notification including test scenarios with multiple agencies, notification delivery verification across all agencies, timing validation (1-hour capability), and agency feedback on notification effectiveness.",
                
                "7. Contact Management System Export: Export from contact management system showing all agency customers, contact information completeness, last verification dates, and active/inactive status.",
                
                "8. Notification Failure Handling: Procedures for handling notification failures including retry logic, alternative notification channels, escalation procedures when agency unreachable, and notification failure tracking/reporting."
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Get automation recommendations for FRR-ICP-02."""
        return {
            'implementation_notes': (
                "FRR-ICP-02 requires Providers to MUST responsibly report incidents to ALL agency customers within 1 hour of identification using the incident communications points of contact provided by each agency customer. This extends FRR-ICP-01 (FedRAMP reporting) to include all agency customers.\\n\\n"
                
                "CODE DETECTION STRATEGY:\\n"
                "1. Application Code: Detect agency contact management, multi-recipient notification logic, alert mechanisms\\n"
                "2. Infrastructure (Bicep/Terraform): Verify Action Groups, Logic Apps, Function Apps for agency notifications\\n"
                "3. CI/CD Pipelines: Check for notification steps with multi-recipient support\\n"
                "4. Focus: Multi-tenant notification capabilities, contact management, scalable alerting\\n\\n"
                
                "COMPLIANCE APPROACH:\\n"
                "1. Agency Contact Management:\\n"
                "   - Contact Registry: Maintain database of all agency customer contacts\\n"
                "   - Contact Collection: Collect incident POCs during agency onboarding\\n"
                "   - Contact Verification: Regularly verify and update agency contacts\\n"
                "   - Multi-Tenant Support: Design for many agencies (1-1000+ agencies)\\n"
                "   - Contact Updates: Process for agencies to update their contacts\\n"
                "   - Contact Storage: Secure storage with encryption and access controls\\n\\n"
                
                "2. Multi-Agency Notification Infrastructure:\\n"
                "   - Action Groups: Configure with multiple agency email recipients\\n"
                "   - Logic Apps: Build workflows to notify all agency customers\\n"
                "   - Function Apps: Create notification functions with agency iteration logic\\n"
                "   - Email Service: Use scalable email service (SendGrid, Azure Communication Services)\\n"
                "   - API Integration: Support agencies with API-based incident notification\\n"
                "   - Incident Portal: Provide portal where agencies can view incidents\\n\\n"
                
                "3. 1-Hour Notification to ALL Agencies:\\n"
                "   - Parallel Notifications: Send to all agencies simultaneously (not sequential)\\n"
                "   - Scalability: Design to handle notification to many agencies quickly\\n"
                "   - Delivery Confirmation: Track successful delivery to each agency\\n"
                "   - Retry Logic: Automatically retry failed notifications\\n"
                "   - Alternative Channels: Use multiple channels (email, SMS, API, portal)\\n"
                "   - Performance Testing: Validate can notify all agencies within 1 hour\\n\\n"
                
                "4. Notification Content and Templates:\\n"
                "   - Incident Details: Include incident ID, severity, description, impact\\n"
                "   - Agency-Specific: Customize message per agency (affected services, tenant-specific impact)\\n"
                "   - Action Items: Clear next steps for agency customers\\n"
                "   - Contact Information: CSP incident response contacts for follow-up\\n"
                "   - Status Updates: Mechanism for ongoing status communication\\n\\n"
                
                "EVIDENCE COLLECTION:\\n"
                "Evidence for FRR-ICP-02 includes both infrastructure and operational records:\\n"
                "- Agency contact registry with all customer incident contacts\\n"
                "- Incident Response Plan documenting agency notification procedures\\n"
                "- Notification infrastructure configurations (Action Groups, Logic Apps, Functions)\\n"
                "- Historical incident notification records to agencies with timestamps\\n"
                "- Agency onboarding documentation showing contact collection\\n"
                "- Multi-tenant notification testing evidence\\n"
                "- Contact management system exports\\n"
                "- Notification failure handling procedures\\n\\n"
                
                "RECOMMENDED AZURE SERVICES:\\n"
                "1. Azure Monitor Action Groups: Multi-recipient email/SMS/webhook notifications\\n"
                "2. Azure Logic Apps: Agency notification workflows with iteration and retry\\n"
                "3. Azure Functions: Custom notification logic for agency-specific requirements\\n"
                "4. Azure Communication Services: Scalable email service for mass notifications\\n"
                "5. Azure SQL/Cosmos DB: Agency contact registry storage\\n"
                "6. Azure App Service: Agency incident portal for self-service incident viewing\\n"
                "7. Azure API Management: API endpoints for agencies preferring API-based notifications\\n\\n"
                
                "MULTI-TENANT ARCHITECTURE:\\n"
                "Design notification system for multi-tenant scale:\\n"
                "- Database Design: Agency contacts table with tenant isolation\\n"
                "- Notification Logic: Iterate over ALL agency customers on incident\\n"
                "- Parallel Processing: Use async/parallel notification (Azure Functions Durable)\\n"
                "- Performance: Optimize for notifying 100-1000+ agencies within minutes\\n"
                "- Failure Isolation: One agency notification failure shouldn't block others\\n"
                "- Audit Trail: Track notification status per agency per incident\\n\\n"
                
                "AGENCY CONTACT LIFECYCLE:\\n"
                "1. Onboarding: Collect incident contacts during agency customer onboarding\\n"
                "2. Verification: Verify contacts work (test notifications)\\n"
                "3. Updates: Process for agencies to update their contacts (portal, API, email)\\n"
                "4. Annual Review: Require agencies to review/confirm contacts annually\\n"
                "5. Deprovisioning: Remove contacts when agency offboards\\n\\n"
                
                "NOTIFICATION CONFIRMATION:\\n"
                "Track and confirm agency notifications:\\n"
                "- Delivery Tracking: Log successful email/SMS/API delivery per agency\\n"
                "- Read Receipts: Optional email read receipts (some agencies may support)\\n"
                "- Acknowledgment: Provide mechanism for agencies to acknowledge receipt\\n"
                "- Failure Alerts: Alert CSP ops team if agency notifications fail\\n"
                "- Reporting: Generate reports showing which agencies were notified and when\\n\\n"
                
                "TESTING AND VALIDATION:\\n"
                "Test multi-agency notification capabilities:\\n"
                "- Load Testing: Simulate notifying all agencies simultaneously\\n"
                "- Timing Testing: Validate can complete within 1-hour requirement\\n"
                "- Failure Testing: Test retry logic and alternative channels\\n"
                "- Agency Feedback: Collect feedback from agencies on notification effectiveness\\n"
                "- Tabletop Exercises: Practice agency notification during incident simulations\\n\\n"
                
                "LIMITATION: Code analysis detects notification INFRASTRUCTURE and contact management capabilities, not actual runtime incident reporting to agencies. Compliance validated through operational records of historical agency notifications."
            )
        }
