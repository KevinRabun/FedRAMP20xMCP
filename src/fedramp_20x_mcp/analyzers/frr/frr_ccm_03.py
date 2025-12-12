"""
FRR-CCM-03: Public Next Report Date

Providers MUST publicly include the target date for their next _Ongoing Authorization Report_ with the _authorization data_ required by FRR-ADS-01.

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


class FRR_CCM_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-03: Public Next Report Date
    
    **Official Statement:**
    Providers MUST publicly include the target date for their next _Ongoing Authorization Report_ with the _authorization data_ required by FRR-ADS-01.
    
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
    
    FRR_ID = "FRR-CCM-03"
    FRR_NAME = "Public Next Report Date"
    FRR_STATEMENT = """Providers MUST publicly include the target date for their next _Ongoing Authorization Report_ with the _authorization data_ required by FRR-ADS-01."""
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
        """Initialize FRR-CCM-03 analyzer."""
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
        Analyze Python code for FRR-CCM-03 compliance.
        
        Detects next report date publication:
        - Report date fields
        - Target date publication
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for date-related variables and functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['next_report_date', 'target_date', 'upcoming_report']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Next report date publication detected",
                            description="Found function for publishing next report date",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure next report date publicly included with authorization data."
                        ))
                
                # Check for date field assignments
                assignments = parser.find_nodes_by_type(tree.root_node, 'assignment')
                for assignment in assignments:
                    assign_text = parser.get_node_text(assignment, code_bytes).lower()
                    if any(keyword in assign_text for keyword in ['next_report_date', 'target_date', 'upcoming_report_date']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Report date field detected",
                            description="Found next report date field",
                            severity=Severity.INFO,
                            line_number=assignment.start_point[0] + 1,
                            code_snippet=assign_text.split('\n')[0],
                            recommendation="Verify date is publicly accessible with authorization data."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        date_patterns = [
            r'next.*report.*date',
            r'target.*date',
            r'report.*schedule.*date',
            r'upcoming.*report',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in date_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Report date publication detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure next report date publicly included with authorization data."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-03 compliance using AST.
        
        Detects next report date publication in C#.
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
                    
                    if any(keyword in method_lower for keyword in ['nextreportdate', 'targetdate', 'upcomingreport']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Next report date publication detected",
                            description="Found method for publishing next report date",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure date publicly included with authorization data."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:NextReportDate|TargetDate|UpcomingReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Report date detected",
                    description="Found report date code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify date is publicly accessible."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-03 compliance using AST.
        
        Detects next report date publication in Java.
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
                    
                    if any(keyword in method_lower for keyword in ['nextreportdate', 'targetdate', 'upcomingreport']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Next report date publication detected",
                            description="Found method for publishing next report date",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure date publicly included with authorization data."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:nextReportDate|targetDate|upcomingReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Report date detected",
                    description="Found report date code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify date is publicly accessible."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-03 compliance using AST.
        
        Detects next report date publication in TypeScript/JavaScript.
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
                    
                    if any(keyword in func_lower for keyword in ['nextreportdate', 'targetdate', 'upcomingreport']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Next report date publication detected",
                            description="Found function for publishing next report date",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure date publicly included with authorization data."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:nextReportDate|targetDate|upcomingReport)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Report date detected",
                    description="Found report date code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify date is publicly accessible."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-03 compliance.
        
        NOT APPLICABLE: Publishing the target date for the next Ongoing Authorization Report
        is an application-level feature requiring a user interface, API endpoint, or public
        documentation page. This is not an infrastructure configuration concern but an
        application functionality implemented in application code, not IaC templates.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-03 compliance.
        
        NOT APPLICABLE: Publishing the target date for next report is an application-level
        feature, not an infrastructure configuration concern.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-03 compliance.
        
        NOT APPLICABLE: Publishing the target date for next report requires application-level
        features (UI, API, documentation). While CI/CD could automate updates, the requirement
        mandates public display of the date, which is an application functionality concern,
        not a build/deployment automation concern.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-03 compliance.
        
        NOT APPLICABLE: Publishing the target date for next report is an application-level
        feature, not a CI/CD automation concern.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-03 compliance.
        
        NOT APPLICABLE: Publishing the target date for next report is an application-level
        feature, not a CI/CD automation concern.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-CCM-03.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_approach': 'Partial automation - detect date publication code, manual validation for public visibility',
            'evidence_artifacts': [
                "authorization_data_webpage_screenshot.png",
                "next_report_date_api_response.json",
                "public_authorization_data.json",
                "report_date_documentation.pdf",
                "authorization_portal_config.json",
            ],
            'collection_queries': [
                "GET https://authorization-portal.example.com/api/authorization-data (verify next_report_date field exists)",
                "traces | where message contains 'next report date' or message contains 'target date' | project timestamp, message",
            ],
            'manual_validation_steps': [
                "1. Visit public authorization data page/portal and verify next report date is displayed",
                "2. Confirm next report date is included in authorization data per FRR-ADS-01",
                "3. Verify date format is clear and human-readable",
                "4. Check API endpoint includes next_report_date field",
                "5. Validate date is accessible to all necessary parties without authentication",
            ],
            'recommended_services': [
                "Azure App Service - Host public authorization portal",
                "Azure API Management - Expose authorization data API",
                "Azure Static Web Apps - Publish authorization data webpage",
            ],
            'integration_points': [
                "Integrate with authorization data publication system (FRR-ADS-01)",
                "Connect to report scheduling system to auto-update date",
            ]
        }
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get queries for collecting evidence of FRR-CCM-03 compliance.
        """
        return {
            "authorization_data_api": "GET /api/authorization-data (check for next_report_date field)",
            "date_publication_logs": "traces | where message contains 'next report date' or message contains 'publish' | project timestamp, message",
            "public_access_logs": "requests | where url contains 'authorization' and url contains 'date' | summarize count() by bin(timestamp, 1d)",
        }
    
    def get_evidence_artifacts(self) -> list:
        """
        Get list of evidence artifacts for FRR-CCM-03 compliance.
        """
        return [
            "authorization_data_webpage_screenshot.png",
            "next_report_date_api_response.json",
            "public_authorization_data.json",
            "report_date_documentation.pdf",
            "authorization_portal_config.json",
            "public_access_verification.json",
        ]
