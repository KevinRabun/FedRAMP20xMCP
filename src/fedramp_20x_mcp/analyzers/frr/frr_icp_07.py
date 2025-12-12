"""
FRR-ICP-07: Final Incident Report

Providers MUST provide a final report once the _incident_ is resolved and recovery is complete that describes at least:

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


class FRR_ICP_07_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-07: Final Incident Report
    
    **Official Statement:**
    Providers MUST provide a final report once the _incident_ is resolved and recovery is complete that describes at least:
    
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
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-ICP-07"
    FRR_NAME = "Final Incident Report"
    FRR_STATEMENT = """Providers MUST provide a final report once the _incident_ is resolved and recovery is complete that describes at least:"""
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
    CODE_DETECTABLE = True  # Detects final report generation and post-incident documentation
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-07 analyzer."""
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
        Analyze Python code for FRR-ICP-07 compliance using AST.
        
        Detects:
        - Final report generation
        - Incident summary creation
        - Root cause analysis documentation
        """
        findings = []
        
        # Check for report generation
        has_report_gen = bool(re.search(
            r'generate.*report|create.*report|final.*report|incident.*summary',
            code, re.IGNORECASE
        ))
        
        # Check for root cause analysis
        has_rca = bool(re.search(
            r'root.*cause|rca|post.*mortem|incident.*analysis|lessons.*learned',
            code, re.IGNORECASE
        ))
        
        # Check for comprehensive data collection
        has_data_collection = bool(re.search(
            r'timeline|impact.*assessment|remediation.*steps|recovery.*actions',
            code, re.IGNORECASE
        ))
        
        if not has_report_gen:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.HIGH,
                message="No final report generation detected",
                details=(
                    "FRR-ICP-07 requires comprehensive final reports after incident resolution. "
                    "Implement automated report generation."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement final incident report generation."
            ))
        
        if not has_rca:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.MEDIUM,
                message="No root cause analysis detected",
                details=(
                    "FRR-ICP-07 requires root cause analysis in final reports. "
                    "Implement RCA documentation."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement root cause analysis documentation."
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
        """Analyze C# for final report generation."""
        findings = []
        has_report = bool(re.search(r'(GenerateReport|CreateReport|FinalReport|IncidentSummary)', code, re.IGNORECASE))
        if not has_report:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No report generation", description=f"FRR-ICP-07 requires final incident reports.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement final incident report generation"
            ))
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java for final report generation."""
        findings = []
        has_report = bool(re.search(r'(generateReport|createReport|finalReport|incidentSummary)', code, re.IGNORECASE))
        if not has_report:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No report generation", description=f"FRR-ICP-07 requires final incident reports.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement final incident report generation"
            ))
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript for final report generation."""
        findings = []
        has_report = bool(re.search(r'(generateReport|createReport|finalReport|incidentSummary)', code, re.IGNORECASE))
        if not has_report:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No report generation", description=f"FRR-ICP-07 requires final incident reports.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement final incident report generation"
            ))
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep for report generation services."""
        return []  # Final report generation is runtime operational
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for report generation services."""
        return []  # Final report generation is runtime operational
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for report generation."""
        return []  # Final report generation is runtime operational
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for report generation."""
        return []  # Final report generation is runtime operational
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for report generation."""
        return []  # Final report generation is runtime operational
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """Get automated queries for FRR-ICP-07 evidence (final incident reports)."""
        return {
            'automated_queries': [
                "AzureActivity | where OperationNameValue contains 'report' or OperationNameValue contains 'document' | summarize by ResourceId, TimeGenerated",
                "Resources | where type contains 'storage' or type contains 'cosmosdb' | project name, type, resourceGroup",
                "AzureDiagnostics | where Category == 'AuditEvent' and Message contains 'incident' | project TimeGenerated, Message"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Get evidence artifacts for FRR-ICP-07 (final incident reports)."""
        return {
            'evidence_artifacts': [
                "Final incident report template and procedures (section of IRP)",
                "Historical final incident reports",
                "Root cause analysis documentation",
                "Incident timeline and impact assessment",
                "Remediation steps and recovery actions documentation",
                "Lessons learned and post-mortem reports",
                "Final report generation mechanism documentation",
                "Report distribution and acknowledgment records"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Get automation recommendations for FRR-ICP-07 (final incident reports)."""
        return {
            'implementation_notes': [
                "Implement automated final incident report generation",
                "Establish final report template with required sections (root cause, timeline, impact, remediation, lessons learned)",
                "Configure report generation triggers (incident closure/resolution)",
                "Implement comprehensive data collection for reports (timeline, logs, impact metrics)",
                "Automate report distribution to all parties (FedRAMP, CISA if applicable, agencies)",
                "Test final report generation with sample incidents",
                "Document final reporting procedures and timelines"
            ]
        }
