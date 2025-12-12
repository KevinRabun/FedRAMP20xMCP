"""
FRR-CCM-06: Protect Sensitive Information

Providers MUST NOT irresponsibly disclose sensitive information in an _Ongoing Authorization Report_ that would _likely_ have an adverse effect on the _cloud service offering_.

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


class FRR_CCM_06_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-06: Protect Sensitive Information
    
    **Official Statement:**
    Providers MUST NOT irresponsibly disclose sensitive information in an _Ongoing Authorization Report_ that would _likely_ have an adverse effect on the _cloud service offering_.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - AC-4 (Information Flow Enforcement)
    - SC-4 (Information in Shared System Resources)
    - SI-12 (Information Management and Retention)
    
    **Related KSIs:**
    - KSI-AFR-01 (Automated reporting)
    - KSI-MLA-01 (Machine learning for anomaly detection)
    
    **Detectability:** Partial
    
    **Detection Strategy:**
    Application code analyzers detect sanitization, redaction, and information
    protection mechanisms. Infrastructure and CI/CD analyzers are not applicable
    as protecting sensitive information in reports is an application-level data
    processing and documentation concern.
    """
    
    FRR_ID = "FRR-CCM-06"
    FRR_NAME = "Protect Sensitive Information"
    FRR_STATEMENT = """Providers MUST NOT irresponsibly disclose sensitive information in an _Ongoing Authorization Report_ that would _likely_ have an adverse effect on the _cloud service offering_."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-4", "Information Flow Enforcement"),
        ("SC-4", "Information in Shared System Resources"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-MLA-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-06 analyzer."""
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
        Analyze Python code for FRR-CCM-06 compliance using AST.
        
        Detects sensitive information protection:
        - Sanitization functions
        - Information leakage detection
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for sanitization/redaction functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['sanitize', 'redact', 'mask', 'scrub', 'filter_sensitive']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Information protection mechanism detected",
                            description="Found sanitization/redaction function",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure sensitive information protected in reports."
                        ))
                    
                    if 'report' in func_lower and any(kw in func_lower for kw in ['protect', 'secure', 'hide']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Report protection function detected",
                            description="Found function protecting report information",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify no irresponsible disclosure in reports."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        protection_patterns = [
            r'sanitize',
            r'redact.*sensitive',
            r'protect.*information',
            r'mask.*data',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in protection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Information protection detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify no irresponsible disclosure."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-06 compliance using AST.
        
        Detects information protection mechanisms in C#.
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
                    
                    if any(keyword in method_lower for keyword in ['sanitize', 'redact', 'mask', 'scrub']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Information protection method detected",
                            description="Found sanitization method",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure sensitive information protected in reports."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:Sanitize|Redact|Mask|Scrub).*(?:Report|Information)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Information protection detected",
                    description="Found protection code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify no irresponsible disclosure."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-06 compliance using AST.
        
        Detects information protection mechanisms in Java.
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
                    
                    if any(keyword in method_lower for keyword in ['sanitize', 'redact', 'mask', 'scrub']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Information protection method detected",
                            description="Found sanitization method",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure sensitive information protected in reports."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:sanitize|redact|mask|scrub).*(?:Report|Information)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Information protection detected",
                    description="Found protection code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify no irresponsible disclosure."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-06 compliance using AST.
        
        Detects information protection mechanisms in TypeScript/JavaScript.
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
                    
                    if any(keyword in func_lower for keyword in ['sanitize', 'redact', 'mask', 'scrub']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Information protection function detected",
                            description="Found sanitization function",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure sensitive information protected in reports."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:sanitize|redact|mask|scrub).*(?:report|information)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Information protection detected",
                    description="Found protection code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify no irresponsible disclosure."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-06 compliance.
        
        NOT APPLICABLE: Protecting sensitive information in Ongoing Authorization
        Reports is an application-level data processing and documentation concern,
        not infrastructure configuration.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-06 compliance.
        
        NOT APPLICABLE: Protecting sensitive information in reports is application
        data processing, not infrastructure configuration.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-06 compliance.
        
        NOT APPLICABLE: Protecting sensitive information in reports is application
        data processing and documentation, not CI/CD automation.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-06 compliance.
        
        NOT APPLICABLE: Report information protection is application concern, not CI/CD.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-06 compliance.
        
        NOT APPLICABLE: Report information protection is application concern, not CI/CD.
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
            # Query 1: Information sanitization logs
            """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'sanitize' or Message contains 'redact' or Message contains 'mask'
| where Message contains 'report' or Message contains 'sensitive'
| summarize SanitizationCount = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
            
            # Query 2: Report generation with protection
            """AppEvents
| where TimeGenerated > ago(90d)
| where Name contains 'ReportGenerated' or Name contains 'ReportPublished'
| where Properties contains 'sanitized' or Properties contains 'redacted'
| project TimeGenerated, Name, Properties
| order by TimeGenerated desc""",
            
            # Query 3: Sensitive data access for reports
            """AppRequests
| where TimeGenerated > ago(90d)
| where Url contains 'report' or Url contains 'authorization'
| where Properties contains 'sensitive' or Properties contains 'protected'
| summarize RequestCount = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Information disclosure policy documentation",
            "Sensitive information handling procedures",
            "Report sanitization guidelines",
            "Sample Ongoing Authorization Reports (with sensitive information redacted)",
            "Information classification schema",
            "Report review process documentation",
            "Sanitization function source code or configuration",
            "Report generation logs showing protection mechanisms",
            "Security review records for published reports",
            "Incident reports related to information disclosure (if any)"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "Report Sanitization Tracking",
                    "description": "Monitor sanitization of sensitive information in reports",
                    "query": """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'sanitize' or Message contains 'redact'
| where Message contains 'report'
| summarize SanitizationEvents = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
                    "schedule": "Quarterly (before each report publication)"
                },
                {
                    "name": "Information Protection Compliance",
                    "description": "Verify information protection mechanisms in report generation",
                    "query": """AppEvents
| where TimeGenerated > ago(90d)
| where Name == 'ReportGenerated'
| extend IsSanitized = Properties contains 'sanitized'
| summarize Total = count(), Sanitized = countif(IsSanitized) by bin(TimeGenerated, 1d)
| extend ComplianceRate = (Sanitized * 100.0) / Total
| order by TimeGenerated desc""",
                    "schedule": "Monthly"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Information Disclosure Policy",
                    "description": "Policy governing disclosure of sensitive information in reports",
                    "location": "Azure Storage Account / policy-documents container"
                },
                {
                    "name": "Report Sanitization Logs",
                    "description": "Logs showing sanitization of sensitive information",
                    "location": "Azure Monitor Logs / Application Insights"
                },
                {
                    "name": "Published Report Samples",
                    "description": "Samples of published reports demonstrating information protection",
                    "location": "Azure Storage Account / published-reports container"
                }
            ],
            "implementation_notes": [
                "Configure Application Insights custom events for report sanitization",
                "Implement automated scanning of reports for sensitive information patterns",
                "Document information classification schema for report content",
                "Maintain audit trail of report review and approval process",
                "Establish escalation procedures for sensitive information concerns",
                "Use Azure Information Protection for automatic data classification"
            ]
        }
