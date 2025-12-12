"""
FRR-ICP-04: Incident Updates

Providers MUST update _all necessary parties_, including at least FedRAMP, CISA (if applicable), and all _agency_ customers, at least once per calendar day until the _incident_ is resolved and recovery is complete.

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


class FRR_ICP_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-04: Incident Updates
    
    **Official Statement:**
    Providers MUST update _all necessary parties_, including at least FedRAMP, CISA (if applicable), and all _agency_ customers, at least once per calendar day until the _incident_ is resolved and recovery is complete.
    
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
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-ICP-04"
    FRR_NAME = "Incident Updates"
    FRR_STATEMENT = """Providers MUST update _all necessary parties_, including at least FedRAMP, CISA (if applicable), and all _agency_ customers, at least once per calendar day until the _incident_ is resolved and recovery is complete."""
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
    CODE_DETECTABLE = True  # Detects scheduled update mechanisms and daily notification logic
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-04 analyzer."""
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
        Analyze Python code for FRR-ICP-04 compliance using AST.
        
        Detects:
        - Scheduled update mechanisms (cron, APScheduler, celery beat)
        - Daily notification logic
        - Status tracking for ongoing incidents
        """
        findings = []
        
        from ..detection_patterns import detect_python_alerting
        
        # Check for alerting mechanisms
        has_alerting, _ = detect_python_alerting(code)
        
        # Check for scheduling mechanisms
        has_scheduler = bool(re.search(
            r'apscheduler|schedule|celery.*beat|cron|recurring|daily|periodic',
            code, re.IGNORECASE
        ))
        
        # Check for status tracking
        has_status_tracking = bool(re.search(
            r'status|state|incident.*tracking|update.*history|resolution.*status',
            code, re.IGNORECASE
        ))
        
        if not has_alerting:
            from ..detection_patterns import create_missing_alerting_finding
            findings.append(create_missing_alerting_finding(self.FRR_ID, file_path))
        
        if not has_scheduler:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.HIGH,
                message="No scheduled update mechanism detected",
                details=(
                    "FRR-ICP-04 requires daily updates to all parties until incident resolution. "
                    "Implement scheduled notification using APScheduler, Celery Beat, or similar."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement scheduled daily update mechanism (APScheduler, Celery Beat)."
            ))
        
        if not has_status_tracking:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.MEDIUM,
                message="No incident status tracking detected",
                details=(
                    "FRR-ICP-04 requires updates until resolution. "
                    "Implement status tracking to determine when updates are no longer needed."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement incident status tracking system."
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
        """Analyze C# for scheduled incident updates."""
        findings = []
        has_scheduler = bool(re.search(r'(Quartz|Hangfire|Timer|Schedule)', code))
        if not has_scheduler:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No scheduled update mechanism", description=f"FRR-ICP-04 requires daily updates until resolution.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement scheduled updates: Hangfire, Quartz, or System.Threading.Timer"
            ))
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java for scheduled incident updates."""
        findings = []
        has_scheduler = bool(re.search(r'(Quartz|ScheduledExecutorService|Timer|@Scheduled)', code))
        if not has_scheduler:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No scheduled update mechanism", description=f"FRR-ICP-04 requires daily updates until resolution.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement scheduled updates: Quartz, ScheduledExecutorService, or @Scheduled annotation"
            ))
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript for scheduled incident updates."""
        findings = []
        has_scheduler = bool(re.search(r'(node-cron|node-schedule|setInterval|cron)', code, re.IGNORECASE))
        if not has_scheduler:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No scheduled update mechanism", description=f"FRR-ICP-04 requires daily updates until resolution.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement scheduled updates: node-cron, node-schedule, or setInterval"
            ))
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep for scheduled update automation."""
        findings = []
        has_scheduler = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Logic/workflows", code))
        has_function = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Web/sites.*kind:\s*'functionapp'", code, re.DOTALL))
        if not (has_scheduler or has_function):
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No scheduled update automation", description=f"FRR-ICP-04 requires daily updates.",
                severity=Severity.MEDIUM, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Deploy scheduling: Logic Apps with recurrence trigger or Function Apps with timer trigger"
            ))
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for scheduled update automation."""
        findings = []
        has_scheduler = bool(re.search(r'resource\s+"(azurerm_logic_app_workflow|azurerm_function_app|aws_lambda_function)"', code))
        if not has_scheduler:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No scheduled update automation", description=f"FRR-ICP-04 requires daily updates.",
                severity=Severity.MEDIUM, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Deploy scheduling: azurerm_logic_app_workflow, azurerm_function_app, or aws_lambda_function"
            ))
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for scheduled workflows."""
        return []  # Daily updates are runtime operational, not CI/CD
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for scheduled tasks."""
        return []  # Daily updates are runtime operational
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for scheduled jobs."""
        return []  # Daily updates are runtime operational
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """Get automated queries for FRR-ICP-04 evidence (daily incident updates)."""
        return {
            'automated_queries': [
                "AzureActivity | where ResourceProviderValue == 'Microsoft.Logic' and OperationNameValue contains 'workflows' | summarize by ResourceId, Properties",
                "AzureActivity | where ResourceProviderValue == 'Microsoft.Automation' and OperationNameValue contains 'schedules' | summarize by ResourceId, Properties",
                "Resources | where type == 'microsoft.logic/workflows' | extend recurrence = properties.definition.triggers | project name, resourceGroup, recurrence"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Get evidence artifacts for FRR-ICP-04 (daily incident updates)."""
        return {
            'evidence_artifacts': [
                "Daily incident update procedures (section of IRP)",
                "Scheduling configuration exports (Logic Apps, Automation accounts, cron jobs)",
                "Status tracking system configuration",
                "Historical incident update records showing daily frequency",
                "Update automation infrastructure documentation",
                "Incident update templates for all parties (FedRAMP, CISA, agencies)",
                "Recipient management exports (FedRAMP, CISA, agency contacts)",
                "Update delivery testing evidence"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Get automation recommendations for FRR-ICP-04 (daily incident updates)."""
        return {
            'implementation_notes': [
                "Configure daily update scheduling (Azure Logic Apps with recurrence, Azure Automation, or equivalent)",
                "Implement status tracking system for incident lifecycle",
                "Automate recipient management (FedRAMP, CISA if applicable, all agency customers)",
                "Configure update templates for consistent communication",
                "Test daily update delivery to all parties",
                "Monitor update frequency compliance (at least once per calendar day)",
                "Continue updates until incident resolved and recovery complete"
            ]
        }
