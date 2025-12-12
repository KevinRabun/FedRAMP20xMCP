"""
FRR-CCM-01: Ongoing Authorization Reports

Providers MUST make an _Ongoing Authorization Report_ available to _all necessary parties_ every 3 months, in a consistent format that is human readable, covering the entire period since the previous summary; this report MUST include high-level summaries of at least the following information:

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-01: Ongoing Authorization Reports
    
    **Official Statement:**
    Providers MUST make an _Ongoing Authorization Report_ available to _all necessary parties_ every 3 months, in a consistent format that is human readable, covering the entire period since the previous summary; this report MUST include high-level summaries of at least the following information:
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
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
    
    FRR_ID = "FRR-CCM-01"
    FRR_NAME = "Ongoing Authorization Reports"
    FRR_STATEMENT = """Providers MUST make an _Ongoing Authorization Report_ available to _all necessary parties_ every 3 months, in a consistent format that is human readable, covering the entire period since the previous summary; this report MUST include high-level summaries of at least the following information:"""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("CA-2", "Control Assessments"),
        ("SI-4", "System Monitoring"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-01 analyzer."""
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
        Analyze Python code for FRR-CCM-01 compliance.
        
        Detects ongoing authorization report generation:
        - Quarterly report generation (3 months / 90 days)
        - Authorization report mechanisms
        - Report formatting and distribution
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for report generation functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['ongoing_authorization_report', 'quarterly_report', 'authorization_summary']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Ongoing Authorization Report generation detected",
                            description="Found function for generating ongoing authorization reports",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure report available every 3 months in human-readable format."
                        ))
                
                # Check for 3-month/90-day intervals in assignments
                assignments = parser.find_nodes_by_type(tree.root_node, 'assignment')
                for assignment in assignments:
                    assign_text = parser.get_node_text(assignment, code_bytes).lower()
                    if ('90' in assign_text or '3' in assign_text) and any(keyword in assign_text for keyword in ['month', 'day', 'quarter']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Quarterly reporting interval detected",
                            description="Found 3-month/90-day reporting configuration",
                            severity=Severity.INFO,
                            line_number=assignment.start_point[0] + 1,
                            code_snippet=assign_text.split('\n')[0],
                            recommendation="Verify quarterly report generation schedule."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        report_patterns = [
            r'ongoing.*authorization.*report',
            r'quarterly.*report',
            r'3.*month.*report',
            r'90.*day.*report',
            r'authorization.*summary',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in report_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Authorization report mechanism detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure report available every 3 months in human-readable format."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-01 compliance using AST.
        
        Detects ongoing authorization report generation in C#.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['ongoingauthorizationreport', 'quarterlyreport', 'authorizationsummary']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Ongoing Authorization Report generation detected",
                            description="Found method for generating ongoing authorization reports",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure report available every 3 months in human-readable format."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:OngoingAuthorizationReport|QuarterlyReport|AuthorizationSummary)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Authorization report mechanism detected",
                    description="Found authorization report code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify quarterly report generation."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-01 compliance using AST.
        
        Detects ongoing authorization report generation in Java.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['ongoingauthorizationreport', 'quarterlyreport', 'authorizationsummary']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Ongoing Authorization Report generation detected",
                            description="Found method for generating ongoing authorization reports",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure report available every 3 months in human-readable format."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:ongoingAuthorizationReport|quarterlyReport|authorizationSummary)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Authorization report mechanism detected",
                    description="Found authorization report code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify quarterly report generation."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-01 compliance using AST.
        
        Detects ongoing authorization report generation in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['ongoingauthorizationreport', 'quarterlyreport', 'authorizationsummary']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Ongoing Authorization Report generation detected",
                            description="Found function for generating ongoing authorization reports",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure report available every 3 months in human-readable format."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:ongoingAuthorizationReport|quarterlyReport|authorizationSummary)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Authorization report mechanism detected",
                    description="Found authorization report code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify quarterly report generation."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-01 compliance.
        
        NOT APPLICABLE: Ongoing Authorization Reports are business process and documentation
        requirements that must be prepared quarterly (every 3 months) covering system status,
        changes, incidents, and compliance. This is not an infrastructure configuration concern
        but a policy and procedural requirement involving manual compilation of system data into
        human-readable reports.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-01 compliance.
        
        NOT APPLICABLE: Ongoing Authorization Reports are business process and documentation
        requirements that must be prepared quarterly (every 3 months) covering system status,
        changes, incidents, and compliance. This is not an infrastructure configuration concern
        but a policy and procedural requirement.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-01 compliance.
        
        NOT APPLICABLE: Ongoing Authorization Reports are business process and documentation
        requirements that must be prepared quarterly. While CI/CD pipelines could potentially
        automate data collection for reports, the requirement mandates human-readable reports
        covering system status, changes, and compliance - this is a policy and procedural
        requirement, not a CI/CD automation concern.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-01 compliance.
        
        NOT APPLICABLE: Ongoing Authorization Reports are business process and documentation
        requirements that must be prepared quarterly. This is a policy and procedural
        requirement for human-readable reporting, not a CI/CD pipeline concern.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-01 compliance.
        
        NOT APPLICABLE: Ongoing Authorization Reports are business process and documentation
        requirements that must be prepared quarterly. This is a policy and procedural
        requirement for human-readable reporting, not a CI/CD pipeline concern.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-CCM-01.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_approach': 'Partial automation - detect report generation code, manual validation for report content and distribution',
            'evidence_artifacts': [
                "ongoing_authorization_report_q1.pdf",
                "ongoing_authorization_report_q2.pdf",
                "ongoing_authorization_report_q3.pdf",
                "ongoing_authorization_report_q4.pdf",
                "report_distribution_logs.json",
                "report_generation_schedule.json",
                "quarterly_summary_template.docx",
                "report_access_list.json",
            ],
            'collection_queries': [
                "AzureDiagnostics | where Category == 'ApplicationLogs' and Message contains 'authorization report' | project TimeGenerated, Message",
                "traces | where message contains 'quarterly report' or message contains 'ongoing authorization' | summarize count() by bin(timestamp, 90d)",
                "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/secureScores",
                "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments",
            ],
            'manual_validation_steps': [
                "1. Review quarterly Ongoing Authorization Reports for completeness (every 3 months)",
                "2. Verify reports are in human-readable format (PDF, Word, or HTML)",
                "3. Confirm reports cover entire period since previous summary",
                "4. Validate reports include required high-level summaries (incidents, changes, vulnerabilities, etc.)",
                "5. Verify reports are distributed to all necessary parties (FedRAMP, Agency AO, etc.)",
                "6. Check report generation schedule aligns with 3-month requirement",
            ],
            'recommended_services': [
                "Azure Monitor - Collect system activity and changes for reports",
                "Microsoft Defender for Cloud - Security posture and vulnerability data",
                "Azure Policy - Compliance status for reports",
                "Azure Log Analytics - Incident and event data aggregation",
                "Azure DevOps/GitHub - Change tracking for reports",
            ],
            'integration_points': [
                "Export compliance data to report generation tools",
                "Integrate with document management systems for report distribution",
                "Connect to GRC platforms for automated report compilation",
                "Use Azure Resource Graph for infrastructure change tracking",
            ]
        }
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get queries for collecting evidence of FRR-CCM-01 compliance.
        """
        return {
            "report_generation_logs": "SELECT timestamp, message FROM application_logs WHERE message LIKE '%ongoing authorization report%' OR message LIKE '%quarterly report%'",
            "quarterly_report_count": "SELECT COUNT(*) as report_count FROM reports WHERE type = 'ongoing_authorization' AND timestamp > ago(365d) GROUP BY bin(timestamp, 90d)",
            "report_distribution": "SELECT timestamp, recipient, report_name FROM distribution_logs WHERE report_type = 'ongoing_authorization'",
            "security_incidents_summary": "SecurityIncident | where TimeGenerated > ago(90d) | summarize count() by Severity",
            "configuration_changes": "AzureActivity | where OperationNameValue contains 'write' and TimeGenerated > ago(90d) | summarize count() by ResourceType",
            "vulnerability_summary": "az security assessment list --query \"[?status.code=='Unhealthy']\"",
        }
    
    def get_evidence_artifacts(self) -> list:
        """
        Get list of evidence artifacts for FRR-CCM-01 compliance.
        """
        return [
            "ongoing_authorization_report_q1.pdf",
            "ongoing_authorization_report_q2.pdf",
            "ongoing_authorization_report_q3.pdf",
            "ongoing_authorization_report_q4.pdf",
            "report_distribution_logs.json",
            "report_generation_schedule.json",
            "quarterly_summary_template.docx",
            "report_access_list.json",
            "report_approval_records.json",
            "quarterly_metrics_summary.xlsx",
        ]
