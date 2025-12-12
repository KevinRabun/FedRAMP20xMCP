"""
FRR-CCM-07: Responsible Public Sharing

Providers MAY responsibly share some or all of the information an _Ongoing Authorization Report_ publicly or with other parties if the provider determines doing so will NOT _likely_ have an adverse effect on the _cloud service offering_.

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


class FRR_CCM_07_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-07: Responsible Public Sharing
    
    **Official Statement:**
    Providers MAY responsibly share some or all of the information an _Ongoing Authorization Report_ publicly or with other parties if the provider determines doing so will NOT _likely_ have an adverse effect on the _cloud service offering_.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
    **Primary Keyword:** MAY
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - AC-4 (Information Flow Enforcement)
    - SI-12 (Information Management and Retention)
    
    **Related KSIs:**
    - KSI-AFR-01 (Automated reporting)
    
    **Detectability:** Partial
    
    **Detection Strategy:**
    Application code analyzers detect public sharing mechanisms and transparency
    features. Infrastructure and CI/CD analyzers are not applicable as public
    sharing decisions are policy and documentation concerns, not technical implementation.
    """
    
    FRR_ID = "FRR-CCM-07"
    FRR_NAME = "Responsible Public Sharing"
    FRR_STATEMENT = """Providers MAY responsibly share some or all of the information an _Ongoing Authorization Report_ publicly or with other parties if the provider determines doing so will NOT _likely_ have an adverse effect on the _cloud service offering_."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "MAY"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-4", "Information Flow Enforcement"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-07 analyzer."""
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
        Analyze Python code for FRR-CCM-07 compliance.
        
        Detects public sharing mechanisms:
        - Public report sharing
        - Transparency mechanisms
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for public sharing functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if 'public' in func_lower and any(kw in func_lower for kw in ['share', 'publish', 'report']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public sharing mechanism detected",
                            description="Found function for public report sharing",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="May responsibly share if no adverse effect."
                        ))
                    
                    if 'transparency' in func_lower or 'disclosure' in func_lower:
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Transparency mechanism detected",
                            description="Found transparency/disclosure function",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify responsible sharing determination."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        sharing_patterns = [
            r'public.*share',
            r'public.*report',
            r'transparency',
            r'share.*publicly',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in sharing_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Public sharing detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="May share if no adverse effect."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-07 compliance using AST.
        
        Detects public sharing mechanisms in C#.
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
                    
                    if 'public' in method_lower and any(kw in method_lower for kw in ['share', 'publish', 'report']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public sharing method detected",
                            description="Found method for public sharing",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="May share if no adverse effect."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:PublicShare|SharePublicly|PublishReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Public sharing detected",
                    description="Found sharing code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify responsible sharing."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-07 compliance using AST.
        
        Detects public sharing mechanisms in Java.
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
                    
                    if 'public' in method_lower and any(kw in method_lower for kw in ['share', 'publish', 'report']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public sharing method detected",
                            description="Found method for public sharing",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="May share if no adverse effect."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:publicShare|sharePublicly|publishReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Public sharing detected",
                    description="Found sharing code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify responsible sharing."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-07 compliance using AST.
        
        Detects public sharing mechanisms in TypeScript/JavaScript.
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
                    
                    if 'public' in func_lower and any(kw in func_lower for kw in ['share', 'publish', 'report']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Public sharing function detected",
                            description="Found function for public sharing",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="May share if no adverse effect."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:publicShare|sharePublicly|publishReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Public sharing detected",
                    description="Found sharing code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify responsible sharing."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-07 compliance.
        
        NOT APPLICABLE: Decisions about public sharing of report information are
        policy and documentation concerns, not infrastructure configuration.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-07 compliance.
        
        NOT APPLICABLE: Public sharing decisions are policy concerns, not
        infrastructure configuration.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-07 compliance.
        
        NOT APPLICABLE: Public sharing decisions are policy and documentation
        concerns, not CI/CD automation.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-07 compliance.
        
        NOT APPLICABLE: Public sharing is policy concern, not CI/CD.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-07 compliance.
        
        NOT APPLICABLE: Public sharing is policy concern, not CI/CD.
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
            # Query 1: Public report sharing activity
            """AppEvents
| where TimeGenerated > ago(90d)
| where Name contains 'ReportPublished' or Name contains 'ReportShared'
| where Properties contains 'public' or Properties contains 'external'
| project TimeGenerated, Name, Properties
| order by TimeGenerated desc""",
            
            # Query 2: Transparency portal access logs
            """AppRequests
| where TimeGenerated > ago(90d)
| where Url contains 'transparency' or Url contains 'public-reports'
| summarize AccessCount = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
            
            # Query 3: Report disclosure decisions
            """AppTraces
| where TimeGenerated > ago(90d)
| where Message contains 'disclosure' or Message contains 'public sharing'
| where Message contains 'decision' or Message contains 'approved'
| project TimeGenerated, Message, Properties
| order by TimeGenerated desc"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Public sharing policy documentation",
            "Disclosure decision process documentation",
            "Risk assessment for public information sharing",
            "List of publicly shared reports or report excerpts",
            "Transparency portal documentation (if applicable)",
            "Approval records for public disclosures",
            "Public-facing report repository or website",
            "Evidence of adverse effect analysis before sharing",
            "Stakeholder communication about public disclosures",
            "Public sharing decision matrix or criteria"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "Public Report Sharing Tracking",
                    "description": "Monitor public sharing of report information",
                    "query": """AppEvents
| where TimeGenerated > ago(90d)
| where Name == 'ReportPublished' or Name == 'ReportShared'
| where Properties contains 'public'
| summarize ShareCount = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
                    "schedule": "Quarterly"
                },
                {
                    "name": "Transparency Portal Activity",
                    "description": "Track access to public transparency portal",
                    "query": """AppRequests
| where TimeGenerated > ago(90d)
| where Url contains 'transparency' or Url contains 'public'
| summarize Requests = count(), UniqueUsers = dcount(UserId) by bin(TimeGenerated, 1d)
| order by TimeGenerated desc""",
                    "schedule": "Monthly"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Public Sharing Policy",
                    "description": "Policy governing public disclosure of report information",
                    "location": "Azure Storage Account / policy-documents container"
                },
                {
                    "name": "Public Disclosure Records",
                    "description": "Records of publicly shared report information",
                    "location": "Azure Storage Account / public-disclosures container"
                },
                {
                    "name": "Disclosure Decision Logs",
                    "description": "Logs of decisions regarding public sharing",
                    "location": "Azure Monitor Logs / Application Insights"
                }
            ],
            "implementation_notes": [
                "Document criteria for determining 'no adverse effect' on cloud service",
                "Establish approval workflow for public information sharing",
                "Maintain audit trail of all public disclosure decisions",
                "Consider transparency portal for publishing approved information",
                "Track public access to shared information",
                "Regularly review public disclosures for continued appropriateness",
                "Integrate with risk management process for disclosure decisions"
            ]
        }
