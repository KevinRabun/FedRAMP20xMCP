"""
FRR-ADS-AC-02: Prospective Customer Access

Providers SHOULD share at least the _authorization package_ with prospective agency customers upon request and MUST notify FedRAMP within five business days if a prospective agency customer request is denied.  

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_AC_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-AC-02: Prospective Customer Access
    
    **Official Statement:**
    Providers SHOULD share at least the _authorization package_ with prospective agency customers upon request and MUST notify FedRAMP within five business days if a prospective agency customer request is denied.  
    
    **Family:** ADS - Authorization Data Sharing
    
    **Primary Keyword:** SHOULD
    
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
    
    FRR_ID = "FRR-ADS-AC-02"
    FRR_NAME = "Prospective Customer Access"
    FRR_STATEMENT = """Providers SHOULD share at least the _authorization package_ with prospective agency customers upon request and MUST notify FedRAMP within five business days if a prospective agency customer request is denied.  """
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-2", "Account Management"),
        ("AC-3", "Access Enforcement"),
        ("SA-9", "External System Services"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-AC-02 analyzer."""
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
        Analyze Python code for FRR-ADS-AC-02 compliance using AST.
        
        Detects prospective customer access mechanisms:
        - Access request handling functions
        - Denial notification systems (5 business days)
        - Authorization package sharing workflows
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function definitions for access requests
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in function_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    # Check for access request handling
                    if any(keyword in func_name_lower for keyword in ['access_request', 'customer_request', 'prospective_customer', 'authorization_package', 'share_package']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Customer access request function detected",
                            description="Found prospective customer access request handling function",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify function handles authorization package sharing requests."
                        ))
                    
                    # Check for denial notification (MUST notify within 5 business days)
                    if any(keyword in func_name_lower for keyword in ['notify_denial', 'deny_request', 'denial_notification', 'notify_fedramp']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Denial notification function detected",
                            description="Found denial notification function - MUST notify FedRAMP within 5 business days",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify notification sent to FedRAMP within 5 business days when prospective customer request denied."
                        ))
                
                # Check for string literals with time constraints
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in string_literals:
                    string_text = parser.get_node_text(string_node, code_bytes).lower()
                    if '5' in string_text and any(keyword in string_text for keyword in ['business day', 'working day', 'notification', 'notify']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="5 business day notification constraint detected",
                            description="Found reference to 5 business day notification requirement",
                            severity=Severity.INFO,
                            line_number=string_node.start_point[0] + 1,
                            code_snippet=string_text[:100],
                            recommendation="Verify implementation notifies FedRAMP within 5 business days of denial."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        access_patterns = [
            r'customer.*access.*request',
            r'prospective.*customer',
            r'authorization.*package',
            r'deny.*request.*notif',
            r'fedramp.*notif.*denial',
            r'5.*business.*day',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in access_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Customer access pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure prospective customers can request authorization package and FedRAMP notified within 5 business days if denied."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-AC-02 compliance using AST.
        
        Detects prospective customer access in ASP.NET:
        - Access request handler methods
        - Denial notification services (5 business days)
        - Authorization package sharing APIs
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['accessrequest', 'prospectivecustomer', 'authorizationpackage', 'sharepackage']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Customer access request method detected",
                            description="Found prospective customer access handling method",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify method handles authorization package sharing requests."
                        ))
                    
                    if any(keyword in method_name_lower for keyword in ['notifydenial', 'denyrequest', 'notifyfedramp', 'denialnotification']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Denial notification method detected",
                            description="Found denial notification - MUST notify FedRAMP within 5 business days",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify FedRAMP notification within 5 business days of denial."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:AccessRequest|ProspectiveCustomer|AuthorizationPackage|NotifyDenial)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Customer access mechanism detected",
                    description="Found access request or notification method",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify authorization package sharing and 5-day notification compliance."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-AC-02 compliance using AST.
        
        Detects prospective customer access in Spring Boot:
        - Access request handler methods
        - Denial notification services (5 business days)
        - Authorization package sharing REST APIs
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['accessrequest', 'prospectivecustomer', 'authorizationpackage', 'sharepackage']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Customer access request method detected",
                            description="Found prospective customer access handling method",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify method handles authorization package sharing requests."
                        ))
                    
                    if any(keyword in method_name_lower for keyword in ['notifydenial', 'denyrequest', 'notifyfedramp', 'denialnotification']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Denial notification method detected",
                            description="Found denial notification - MUST notify FedRAMP within 5 business days",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify FedRAMP notification within 5 business days of denial."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:accessRequest|prospectiveCustomer|authorizationPackage|notifyDenial)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Customer access mechanism detected",
                    description="Found access request or notification method",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify authorization package sharing and 5-day notification compliance."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-AC-02 compliance using AST.
        
        Detects prospective customer access in Express/NestJS:
        - Access request handler functions
        - Denial notification services (5 business days)
        - Authorization package sharing endpoints
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function declarations
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    if any(keyword in func_name_lower for keyword in ['accessrequest', 'prospectivecustomer', 'authorizationpackage', 'sharepackage']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Customer access request function detected",
                            description="Found prospective customer access handling function",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify function handles authorization package sharing requests."
                        ))
                    
                    if any(keyword in func_name_lower for keyword in ['notifydenial', 'denyrequest', 'notifyfedramp', 'denialnotification']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Denial notification function detected",
                            description="Found denial notification - MUST notify FedRAMP within 5 business days",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify FedRAMP notification within 5 business days of denial."
                        ))
                
                # Check arrow functions
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['accessrequest', 'notifydenial', 'authorizationpackage']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Customer access mechanism detected",
                            description="Found access request or notification handler",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify authorization package sharing and 5-day notification compliance."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:accessRequest|prospectiveCustomer|authorizationPackage|notifyDenial)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Customer access mechanism detected",
                    description="Found access request or notification function",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify authorization package sharing and 5-day notification compliance."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-AC-02 compliance.
        
        NOT APPLICABLE: Prospective customer access request handling and denial
        notifications are business process and application logic requirements,
        not infrastructure configuration requirements. The requirement involves:
        1. Sharing authorization packages with prospective customers (SHOULD)
        2. Notifying FedRAMP within 5 business days of denial (MUST)
        
        These are implemented in application code (request handlers, notification
        services, workflow systems), not in Azure infrastructure definitions.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-AC-02 compliance.
        
        NOT APPLICABLE: Prospective customer access request handling and denial
        notifications are business process and application logic requirements,
        not infrastructure configuration requirements. The requirement involves:
        1. Sharing authorization packages with prospective customers (SHOULD)
        2. Notifying FedRAMP within 5 business days of denial (MUST)
        
        These are implemented in application code (request handlers, notification
        services, workflow systems), not in cloud infrastructure definitions.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-AC-02 compliance.
        
        NOT APPLICABLE: Prospective customer access requests and denial notifications
        are business process requirements managed in application code and workflow
        systems, not in CI/CD pipeline configurations. The requirement involves
        manual or automated handling of customer requests and regulatory notifications,
        which are runtime operational concerns, not build/deployment concerns.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-AC-02 compliance.
        
        NOT APPLICABLE: Prospective customer access requests and denial notifications
        are business process requirements managed in application code and workflow
        systems, not in CI/CD pipeline configurations. The requirement involves
        manual or automated handling of customer requests and regulatory notifications,
        which are runtime operational concerns, not build/deployment concerns.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-AC-02 compliance.
        
        NOT APPLICABLE: Prospective customer access requests and denial notifications
        are business process requirements managed in application code and workflow
        systems, not in CI/CD pipeline configurations. The requirement involves
        manual or automated handling of customer requests and regulatory notifications,
        which are runtime operational concerns, not build/deployment concerns.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-AC-02.
        
        Partially code-detectable (can find request handlers, but process compliance requires logs).
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Medium - can detect request handlers, but requires access logs and notification records',
            'automation_approach': 'Hybrid - automated handler detection + log analysis for process compliance',
            'recommended_services': [
                'Azure Logic Apps - Workflow automation for access requests and notifications',
                'Azure Service Bus - Queue-based request processing with tracking',
                'Azure API Management - Track and log authorization package requests',
                'Azure Monitor Application Insights - Log access requests and denial notifications',
                'Azure Notification Hubs - Send FedRAMP denial notifications',
                'Microsoft Power Automate - Automate 5-day notification workflow',
            ],
            'collection_methods': [
                'Application request log analysis',
                'Notification service audit logs',
                'Access request tracking database queries',
                'FedRAMP notification records review',
                'Customer communication logs',
                'Time-to-notification metrics (5 business day compliance)',
            ],
            'implementation_steps': [
                '1. Implement access request handler for prospective agency customers',
                '2. Create authorization package sharing workflow (SHOULD requirement)',
                '3. Build denial notification system that triggers on request denial',
                '4. Configure automated notification to FedRAMP within 5 business days (MUST)',
                '5. Implement business day calculator (exclude weekends/holidays)',
                '6. Log all access requests with timestamps and outcomes',
                '7. Track notification delivery and confirmation',
                '8. Create alerts for approaching 5-day deadline',
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get automated queries for collecting evidence of FRR-ADS-AC-02 compliance.
        
        Returns KQL queries and API calls for Azure services.
        """
        return [
            {
                'query_name': 'Prospective Customer Access Requests',
                'query_type': 'KQL',
                'query': '''AppRequests
| where Url contains "access-request" or Url contains "authorization-package"
| extend RequestType = case(
    ResultCode >= 200 and ResultCode < 300, "Approved",
    ResultCode >= 400 and ResultCode < 500, "Denied",
    "Other"
)
| summarize Count = count() by RequestType, bin(TimeGenerated, 1d)
| order by TimeGenerated desc''',
                'data_source': 'Azure Application Insights',
                'evidence_type': 'Access request volume and approval/denial patterns',
            },
            {
                'query_name': 'Denial Notification Timeliness',
                'query_type': 'KQL',
                'query': '''AppTraces
| where Message contains "denial notification" or Message contains "notify FedRAMP"
| extend DenialTime = todatetime(Properties["denial_timestamp"])
| extend NotificationTime = TimeGenerated
| extend BusinessDaysToNotify = datetime_diff("day", NotificationTime, DenialTime)
| where BusinessDaysToNotify <= 5
| project DenialTime, NotificationTime, BusinessDaysToNotify, CustomerID = Properties["customer_id"]
| order by NotificationTime desc''',
                'data_source': 'Azure Application Insights',
                'evidence_type': 'FedRAMP notification timeliness (5 business day compliance)',
            },
            {
                'query_name': 'Service Bus Access Request Messages',
                'query_type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceType == "SERVICEBUS"
| where OperationName contains "Send" or OperationName contains "Receive"
| where Message contains "access-request" or Message contains "authorization-package"
| project TimeGenerated, OperationName, Status, MessageId = Properties["MessageId"]
| order by TimeGenerated desc
| take 100''',
                'data_source': 'Azure Service Bus',
                'evidence_type': 'Queued access request processing',
            },
            {
                'query_name': 'Logic Apps Notification Workflows',
                'query_type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceType == "WORKFLOWS"
| where resource_workflowName_s contains "denial" or resource_workflowName_s contains "notification"
| where status_s == "Succeeded"
| project TimeGenerated, WorkflowName = resource_workflowName_s, Status = status_s, RunId = resource_runId_s
| order by TimeGenerated desc
| take 50''',
                'data_source': 'Azure Logic Apps',
                'evidence_type': 'Automated denial notification workflow executions',
            },
            {
                'query_name': 'API Management Authorization Package Requests',
                'query_type': 'KQL',
                'query': '''AzureDiagnostics
| where ResourceType == "APIMANAGEMENT"
| where url_s contains "/authorization-package" or url_s contains "/auth-package"
| project TimeGenerated, Method = httpMethod_s, Url = url_s, StatusCode = responseCode_d, ClientIP = clientIP_s
| order by TimeGenerated desc
| take 100''',
                'data_source': 'Azure API Management',
                'evidence_type': 'Authorization package access requests via API',
            },
            {
                'query_name': 'Late Notification Violations (Over 5 Business Days)',
                'query_type': 'KQL',
                'query': '''AppTraces
| where Message contains "denial notification"
| extend DenialTime = todatetime(Properties["denial_timestamp"])
| extend NotificationTime = TimeGenerated
| extend BusinessDaysToNotify = datetime_diff("day", NotificationTime, DenialTime)
| where BusinessDaysToNotify > 5
| project DenialTime, NotificationTime, BusinessDaysToNotify, CustomerID = Properties["customer_id"], ViolationSeverity = "HIGH"
| order by BusinessDaysToNotify desc''',
                'data_source': 'Azure Application Insights',
                'evidence_type': 'Non-compliance instances (notifications exceeding 5 business days)',
            },
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts for FRR-ADS-AC-02 compliance.
        
        Returns specific documents and exports needed to demonstrate compliance.
        """
        return [
            'Access request policy document (how prospective customers request authorization packages)',
            'Authorization package sharing process documentation',
            'Access request log export (all prospective customer requests with timestamps)',
            'Denial notification records sent to FedRAMP (with timestamps)',
            'Business day calculator logic documentation (excludes weekends/holidays)',
            'Notification timeliness report (all denials with time-to-notification metrics)',
            'FedRAMP notification email/API call confirmations',
            'Access request approval/denial workflow diagram',
            'Non-compliance incidents report (any notifications exceeding 5 business days)',
            'Customer communication records (prospective agency customer correspondence)',
        ]
