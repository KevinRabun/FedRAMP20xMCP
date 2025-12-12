"""
FRR-CCM-05: Anonymized Feedback Summary

Providers MUST maintain an anonymized and desensitized summary of the feedback, questions, and answers about each _Ongoing Authorization Report_ as an addendum to the _Ongoing Authorization Report_.

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


class FRR_CCM_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-05: Anonymized Feedback Summary
    
    **Official Statement:**
    Providers MUST maintain an anonymized and desensitized summary of the feedback, questions, and answers about each _Ongoing Authorization Report_ as an addendum to the _Ongoing Authorization Report_.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - CA-7 (Continuous Monitoring)
    - AC-4 (Information Flow Enforcement)
    - SI-12 (Information Management and Retention)
    
    **Related KSIs:**
    - KSI-AFR-01 (Automated reporting)
    - KSI-MLA-01 (Machine learning for anomaly detection)
    
    **Detectability:** Partial
    
    **Detection Strategy:**
    Application code analyzers detect anonymization/desensitization functions and
    feedback summary generation code. Infrastructure and CI/CD analyzers are not
    applicable as anonymization is an application-level data processing concern.
    """
    
    FRR_ID = "FRR-CCM-05"
    FRR_NAME = "Anonymized Feedback Summary"
    FRR_STATEMENT = """Providers MUST maintain an anonymized and desensitized summary of the feedback, questions, and answers about each _Ongoing Authorization Report_ as an addendum to the _Ongoing Authorization Report_."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("AC-4", "Information Flow Enforcement"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-MLA-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-05 analyzer."""
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
        Analyze Python code for FRR-CCM-05 compliance.
        
        Detects anonymization mechanisms:
        - Anonymize/desensitize functions
        - Feedback summary generation
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for anonymization functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['anonymize', 'desensitize', 'redact', 'sanitize']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Anonymization function detected",
                            description="Found function for anonymizing/desensitizing data",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure feedback is anonymized and desensitized in report addendum."
                        ))
                    
                    if 'feedback' in func_lower and 'summary' in func_lower:
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Feedback summary function detected",
                            description="Found function for generating feedback summaries",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify feedback summary is anonymized and added to report addendum."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        anonymization_patterns = [
            r'anonymi[sz]e',
            r'desensiti[sz]e',
            r'feedback.*summary',
            r'redact.*feedback',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in anonymization_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Anonymization mechanism detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure feedback anonymized in report addendum."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-05 compliance using AST.
        
        Detects anonymization mechanisms in C#.
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
                    
                    if any(keyword in method_lower for keyword in ['anonymize', 'desensitize', 'redact', 'sanitize']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Anonymization method detected",
                            description="Found method for anonymizing data",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure feedback anonymized in report addendum."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:Anonymize|Desensitize|Redact|Sanitize).*Feedback', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Anonymization code detected",
                    description="Found anonymization code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify anonymization in report addendum."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-05 compliance using AST.
        
        Detects anonymization mechanisms in Java.
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
                    
                    if any(keyword in method_lower for keyword in ['anonymize', 'desensitize', 'redact', 'sanitize']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Anonymization method detected",
                            description="Found method for anonymizing data",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure feedback anonymized in report addendum."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:anonymize|desensitize|redact|sanitize).*[Ff]eedback', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Anonymization code detected",
                    description="Found anonymization code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify anonymization in report addendum."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-05 compliance using AST.
        
        Detects anonymization mechanisms in TypeScript/JavaScript.
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
                    
                    if any(keyword in func_lower for keyword in ['anonymize', 'desensitize', 'redact', 'sanitize']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Anonymization function detected",
                            description="Found function for anonymizing data",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure feedback anonymized in report addendum."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:anonymize|desensitize|redact|sanitize).*feedback', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Anonymization code detected",
                    description="Found anonymization code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify anonymization in report addendum."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-05 compliance.
        
        NOT APPLICABLE: Anonymizing and desensitizing feedback data for report addendums
        is an application-level data processing concern, not infrastructure configuration.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-05 compliance.
        
        NOT APPLICABLE: Anonymization is application-level data processing, not
        infrastructure configuration.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-05 compliance.
        
        NOT APPLICABLE: Anonymizing feedback for report addendums is application
        data processing, not CI/CD automation.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-05 compliance.
        
        NOT APPLICABLE: Anonymization is application data processing, not CI/CD.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-05 compliance.
        
        NOT APPLICABLE: Anonymization is application data processing, not CI/CD.
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
            # Query 1: Anonymization function usage logs
            """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'anonymize' or Message contains 'desensitize' or Message contains 'redact'
| where Message contains 'feedback'
| summarize AnonymizationCount = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
            
            # Query 2: Report addendum generation logs
            """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'feedback' and Message contains 'summary'
| where Message contains 'addendum' or Message contains 'report'
| project TimeGenerated, Message, Properties
| order by TimeGenerated desc""",
            
            # Query 3: Data sanitization events
            """AppEvents
| where TimeGenerated > ago(90d)
| where Name contains 'FeedbackAnonymized' or Name contains 'DataDesensitized'
| summarize EventCount = count() by Name, bin(TimeGenerated, 1d)
| order by TimeGenerated desc"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Anonymization policy documentation",
            "Feedback summary addendum samples (most recent 3 reports)",
            "Anonymization process documentation (procedures for removing PII)",
            "Desensitization guidelines and standards",
            "Report addendum templates showing feedback summary structure",
            "Anonymization function source code or configuration",
            "Evidence of PII removal from feedback summaries",
            "Audit logs of anonymization processing",
            "Quality assurance reports for anonymization effectiveness",
            "Training materials on feedback anonymization requirements"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "Anonymization Function Usage",
                    "description": "Track usage of anonymization functions in application code",
                    "query": """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'anonymize' or Message contains 'desensitize'
| where Message contains 'feedback'
| summarize UsageCount = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
                    "schedule": "Quarterly (before each Ongoing Authorization Report)"
                },
                {
                    "name": "Report Addendum Generation",
                    "description": "Monitor generation of feedback summary addendums",
                    "query": """AppEvents
| where TimeGenerated > ago(90d)
| where Name == 'ReportAddendumGenerated' or Name == 'FeedbackSummaryCreated'
| project TimeGenerated, Properties
| order by TimeGenerated desc""",
                    "schedule": "Quarterly"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Anonymization Policy",
                    "description": "Policy document describing feedback anonymization procedures",
                    "location": "Azure Storage Account / policy-documents container"
                },
                {
                    "name": "Feedback Summary Addendums",
                    "description": "Samples of anonymized feedback summaries attached to reports",
                    "location": "Azure Storage Account / report-addendums container"
                },
                {
                    "name": "Anonymization Audit Logs",
                    "description": "Logs showing anonymization processing of feedback data",
                    "location": "Azure Monitor Logs / Application Insights"
                }
            ],
            "implementation_notes": [
                "Configure Application Insights custom events for anonymization tracking",
                "Store feedback summary addendums with timestamps and report IDs",
                "Document anonymization procedures including PII removal techniques",
                "Maintain audit trail of all anonymization operations",
                "Implement automated testing of anonymization effectiveness",
                "Archive addendum samples for evidence collection"
            ]
        }
