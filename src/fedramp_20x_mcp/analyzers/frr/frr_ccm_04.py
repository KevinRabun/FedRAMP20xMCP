"""
FRR-CCM-04: Feedback Mechanism

Providers MUST establish and share an asynchronous mechanism for _all necessary parties_ to provide feedback or ask questions about each _Ongoing Authorization Report_.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-04: Feedback Mechanism
    
    **Official Statement:**
    Providers MUST establish and share an asynchronous mechanism for _all necessary parties_ to provide feedback or ask questions about each _Ongoing Authorization Report_.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - SA-11 (Developer Testing and Evaluation)
    
    **Related KSIs:**
    - KSI-CMT-01 (Timely communication of security information)
    
    **Detectability:** Partial
    
    **Detection Strategy:**
    Application code analyzers detect feedback mechanisms in web applications, APIs,
    and user interfaces (feedback forms, submission handlers, question APIs).
    Infrastructure and CI/CD analyzers are not applicable as feedback mechanisms
    are application-level features requiring user interfaces and communication systems.
    """
    
    FRR_ID = "FRR-CCM-04"
    FRR_NAME = "Feedback Mechanism"
    FRR_STATEMENT = """Providers MUST establish and share an asynchronous mechanism for _all necessary parties_ to provide feedback or ask questions about each _Ongoing Authorization Report_."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-04 analyzer."""
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
        Analyze Python code for FRR-CCM-04 compliance.
        
        Detects feedback mechanisms:
        - Asynchronous feedback systems
        - Question submission mechanisms
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for feedback-related functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['submit_feedback', 'ask_question', 'report_feedback', 'feedback_form']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Feedback mechanism detected",
                            description="Found function for feedback submission",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure asynchronous feedback mechanism available for all parties."
                        ))
                
                # Check for async decorators on feedback functions
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    if 'async def' in func_text and 'feedback' in func_text.lower():
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Asynchronous feedback function detected",
                            description="Found async feedback mechanism",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify feedback mechanism is accessible to all necessary parties."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        feedback_patterns = [
            r'feedback.*mechanism',
            r'async.*feedback',
            r'submit.*question',
            r'feedback.*form',
            r'report.*feedback',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in feedback_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Feedback mechanism detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure asynchronous feedback mechanism available."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-04 compliance using AST.
        
        Detects feedback mechanisms in C#.
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
                    
                    if any(keyword in method_lower for keyword in ['submitfeedback', 'askquestion', 'feedbackform']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Feedback mechanism detected",
                            description="Found method for feedback submission",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure asynchronous feedback mechanism available."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:SubmitFeedback|AskQuestion|FeedbackForm|Task<.*>.*Feedback)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Feedback mechanism detected",
                    description="Found feedback code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify async feedback mechanism."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-04 compliance using AST.
        
        Detects feedback mechanisms in Java.
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
                    
                    if any(keyword in method_lower for keyword in ['submitfeedback', 'askquestion', 'feedbackform']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Feedback mechanism detected",
                            description="Found method for feedback submission",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure asynchronous feedback mechanism available."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:submitFeedback|askQuestion|feedbackForm|CompletableFuture.*feedback)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Feedback mechanism detected",
                    description="Found feedback code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify async feedback mechanism."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-04 compliance using AST.
        
        Detects feedback mechanisms in TypeScript/JavaScript.
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
                    
                    if any(keyword in func_lower for keyword in ['submitfeedback', 'askquestion', 'feedbackform']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Feedback mechanism detected",
                            description="Found function for feedback submission",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure asynchronous feedback mechanism available."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:submitFeedback|askQuestion|feedbackForm|async.*feedback)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Feedback mechanism detected",
                    description="Found feedback code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify async feedback mechanism."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-04 compliance.
        
        NOT APPLICABLE: Establishing an asynchronous feedback mechanism for report questions
        and feedback is an application-level feature requiring user interfaces, forms, APIs,
        or integration with ticketing/communication systems. This is not an infrastructure
        configuration concern but an application functionality implemented in application code.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-04 compliance.
        
        NOT APPLICABLE: Feedback mechanisms are application-level features, not
        infrastructure configuration concerns.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-04 compliance.
        
        NOT APPLICABLE: Asynchronous feedback mechanisms for report questions are
        application-level features requiring user interfaces and communication systems.
        This is not a CI/CD pipeline concern but an application functionality.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-04 compliance.
        
        NOT APPLICABLE: Feedback mechanisms are application-level features, not
        CI/CD automation concerns.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-04 compliance.
        
        NOT APPLICABLE: Feedback mechanisms are application-level features, not
        CI/CD automation concerns.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Returns Azure Resource Graph and KQL queries for evidence collection.
        """
        return [
            # Query 1: Feedback system application logs
            """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'feedback' or Message contains 'question'
| summarize SubmissionCount = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
            
            # Query 2: Feedback endpoint availability
            """AppAvailabilityResults
| where TimeGenerated > ago(90d)
| where Name contains 'feedback'
| summarize AvailabilityPercentage = avg(Success) * 100""",
            
            # Query 3: Feedback mechanism access logs
            """AppRequests
| where TimeGenerated > ago(90d)
| where Url contains 'feedback' or Url contains 'question'
| summarize RequestCount = count(), UniqueUsers = dcount(UserId) by bin(TimeGenerated, 1d)
| order by TimeGenerated desc"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Feedback mechanism documentation (process description)",
            "Feedback submission interface screenshots",
            "Access instructions provided to necessary parties (FedRAMP, Agency AO, stakeholders)",
            "Feedback mechanism URL and access credentials (if applicable)",
            "Records of feedback submissions received (90-day sample)",
            "Feedback system availability reports (quarterly)",
            "Evidence of feedback mechanism announcement to all parties",
            "Feedback response process documentation",
            "Feedback system monitoring logs",
            "User access logs for feedback system"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "Feedback System Logs",
                    "description": "Query Azure Monitor logs for feedback mechanism activity",
                    "query": """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'feedback' or Message contains 'question' or Message contains 'report'
| where Message contains 'submit' or Message contains 'mechanism'
| project TimeGenerated, Message, Properties
| order by TimeGenerated desc""",
                    "schedule": "Quarterly (before each Ongoing Authorization Report)"
                },
                {
                    "name": "Feedback System Availability",
                    "description": "Check availability metrics for feedback endpoints",
                    "query": """AppAvailabilityResults
| where TimeGenerated > ago(90d)
| where Name contains 'feedback' or Name contains 'report'
| summarize AvailabilityPercentage = avg(Success) * 100 by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
                    "schedule": "Daily"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Feedback Mechanism Documentation",
                    "description": "Documentation of feedback submission process",
                    "location": "Azure Storage Account / documentation container"
                },
                {
                    "name": "Feedback System Access Instructions",
                    "description": "Instructions provided to necessary parties for accessing feedback mechanism",
                    "location": "Public documentation / Authorization Package"
                },
                {
                    "name": "Feedback Submission Records",
                    "description": "Records of feedback submissions received",
                    "location": "Azure SQL Database / feedback tables"
                }
            ],
            "implementation_notes": [
                "Configure Azure Monitor Application Insights for feedback system",
                "Track feedback submissions using custom events",
                "Store feedback mechanism access instructions in Authorization Package",
                "Maintain public documentation of feedback submission process",
                "Ensure feedback mechanism URL is accessible to all necessary parties"
            ]
        }
