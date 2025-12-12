"""
FRR-CCM-02: Avoiding Simultaneous Reports

Providers SHOULD establish a regular 3 month cycle for _Ongoing Authorization Reports_ that is spread out from the beginning, middle, or end of each quarter.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-02: Avoiding Simultaneous Reports
    
    **Official Statement:**
    Providers SHOULD establish a regular 3 month cycle for _Ongoing Authorization Reports_ that is spread out from the beginning, middle, or end of each quarter.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
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
    
    FRR_ID = "FRR-CCM-02"
    FRR_NAME = "Avoiding Simultaneous Reports"
    FRR_STATEMENT = """Providers SHOULD establish a regular 3 month cycle for _Ongoing Authorization Reports_ that is spread out from the beginning, middle, or end of each quarter."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-02 analyzer."""
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
        Analyze Python code for FRR-CCM-02 compliance.
        
        Detects report scheduling mechanisms:
        - Quarterly report cycles
        - Report scheduling patterns
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for scheduling functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['report_schedule', 'quarterly_cycle', 'schedule_report']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Report scheduling function detected",
                            description="Found function for scheduling quarterly reports",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Establish 3-month cycle spread throughout quarters."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        schedule_patterns = [
            r'report.*schedule',
            r'quarterly.*cycle',
            r'3.*month.*cycle',
            r'report.*timing',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in schedule_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Report scheduling detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Establish regular 3-month cycle spread throughout quarter."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-02 compliance using AST.
        
        Detects report scheduling mechanisms in C#.
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
                    
                    if any(keyword in method_lower for keyword in ['reportschedule', 'quarterlycycle', 'schedulereport']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Report scheduling method detected",
                            description="Found method for scheduling quarterly reports",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Establish 3-month cycle spread throughout quarters."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:ReportSchedule|QuarterlyCycle|ScheduleReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Report scheduling detected",
                    description="Found report scheduling code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify 3-month cycle spread."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-02 compliance using AST.
        
        Detects report scheduling mechanisms in Java.
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
                    
                    if any(keyword in method_lower for keyword in ['reportschedule', 'quarterlycycle', 'schedulereport']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Report scheduling method detected",
                            description="Found method for scheduling quarterly reports",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Establish 3-month cycle spread throughout quarters."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:reportSchedule|quarterlyCycle|scheduleReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Report scheduling detected",
                    description="Found report scheduling code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify 3-month cycle spread."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-02 compliance using AST.
        
        Detects report scheduling mechanisms in TypeScript/JavaScript.
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
                    
                    if any(keyword in func_lower for keyword in ['reportschedule', 'quarterlycycle', 'schedulereport']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Report scheduling function detected",
                            description="Found function for scheduling quarterly reports",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Establish 3-month cycle spread throughout quarters."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:reportSchedule|quarterlyCycle|scheduleReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Report scheduling detected",
                    description="Found report scheduling code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify 3-month cycle spread."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-02 compliance.
        
        NOT APPLICABLE: Report scheduling and timing policies (spreading reports across
        beginning, middle, or end of quarters) are business process and policy concerns,
        not infrastructure configuration. This requirement addresses organizational
        coordination to avoid simultaneous report submissions, which is a procedural
        matter.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-02 compliance.
        
        NOT APPLICABLE: Report scheduling and timing policies are business process
        and policy concerns, not infrastructure configuration.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-02 compliance.
        
        NOT APPLICABLE: Report scheduling policies (spreading across quarters) are
        organizational and policy concerns, not CI/CD automation concerns. While
        pipelines could schedule jobs, the requirement addresses coordinating timing
        to avoid simultaneous submissions, which is a procedural matter.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-02 compliance.
        
        NOT APPLICABLE: Report scheduling policies are organizational and policy
        concerns, not CI/CD automation concerns.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-02 compliance.
        
        NOT APPLICABLE: Report scheduling policies are organizational and policy
        concerns, not CI/CD automation concerns.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-CCM-02.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_approach': 'Partial automation - detect scheduling code, manual validation for timing coordination',
            'evidence_artifacts': [
                "report_schedule_policy.pdf",
                "quarterly_report_calendar.xlsx",
                "report_submission_history.json",
                "report_timing_coordination.json",
                "quarterly_cycle_documentation.md",
            ],
            'collection_queries': [
                "SELECT report_date, report_type FROM reports WHERE type = 'ongoing_authorization' ORDER BY report_date",
                "traces | where message contains 'report schedule' | project timestamp, message",
            ],
            'manual_validation_steps': [
                "1. Review report submission schedule documentation",
                "2. Verify reports are spread across beginning, middle, or end of quarters",
                "3. Confirm 3-month cycle is established and maintained",
                "4. Validate coordination with FedRAMP to avoid simultaneous submissions",
                "5. Check historical report dates align with policy",
            ],
            'recommended_services': [
                "Azure DevOps - Schedule and track report generation",
                "Microsoft Project - Coordinate reporting schedules",
                "SharePoint - Document and share report calendars",
            ],
            'integration_points': [
                "Integrate with calendar systems for automated scheduling reminders",
                "Connect to project management tools for coordination",
            ]
        }
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get queries for collecting evidence of FRR-CCM-02 compliance.
        """
        return {
            "report_submission_dates": "SELECT report_date, report_type FROM reports WHERE type = 'ongoing_authorization' AND report_date > ago(365d) ORDER BY report_date",
            "quarterly_intervals": "SELECT DATEDIFF(day, LAG(report_date) OVER (ORDER BY report_date), report_date) as days_between FROM reports WHERE type = 'ongoing_authorization'",
            "schedule_logs": "traces | where message contains 'report schedule' or message contains 'quarterly cycle' | project timestamp, message",
        }
    
    def get_evidence_artifacts(self) -> list:
        """
        Get list of evidence artifacts for FRR-CCM-02 compliance.
        """
        return [
            "report_schedule_policy.pdf",
            "quarterly_report_calendar.xlsx",
            "report_submission_history.json",
            "report_timing_coordination.json",
            "quarterly_cycle_documentation.md",
            "historical_report_dates.json",
        ]
