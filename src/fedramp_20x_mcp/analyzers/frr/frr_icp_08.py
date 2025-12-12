"""
FRR-ICP-08: Automated Reporting

Providers SHOULD use automated mechanisms for reporting incidents and providing updates to all necessary parties (including CISA).

Official FedRAMP 20x Requirement
Source: FRR-ICP (ICP) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import Dict, List, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ICP_08_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-08: Automated Reporting
    
    **Official Statement:**
    Providers SHOULD use automated mechanisms for reporting incidents and providing updates to all necessary parties (including CISA).
    
    **Family:** ICP - ICP
    
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
    
    FRR_ID = "FRR-ICP-08"
    FRR_NAME = "Automated Reporting"
    FRR_STATEMENT = """Providers SHOULD use automated mechanisms for reporting incidents and providing updates to all necessary parties (including CISA)."""
    FAMILY = "ICP"
    FAMILY_NAME = "ICP"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("IR-4", "Incident Handling"),
        ("IR-6", "Incident Reporting"),
        ("IR-5", "Incident Monitoring"),
        ("IR-8", "Incident Response Plan"),
    ]
    CODE_DETECTABLE = True  # Detects automation mechanisms for incident reporting
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-08 analyzer."""
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
        Analyze Python code for FRR-ICP-08 compliance using AST.
        
        Detects:
        - Automation frameworks and orchestration
        - Workflow engines
        - Event-driven architecture
        """
        findings = []
        
        # Check for automation frameworks
        has_automation = bool(re.search(
            r'celery|airflow|prefect|temporal|workflow|orchestration|automation',
            code, re.IGNORECASE
        ))
        
        # Check for event-driven patterns
        has_event_driven = bool(re.search(
            r'event.*bus|message.*queue|pub.*sub|azure.*servicebus|event.*grid',
            code, re.IGNORECASE
        ))
        
        # Check for automated alerting
        from ..detection_patterns import detect_python_alerting
        has_alerting, _ = detect_python_alerting(code)
        
        if not has_automation:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="No automation framework detected",
                details=(
                    "FRR-ICP-08 recommends automated incident reporting. "
                    "Consider using Celery, Airflow, or workflow orchestration."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Consider implementing automation framework (Celery, Airflow)."
            ))
        
        if not has_event_driven and not has_alerting:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,  # SHOULD requirement
                message="No event-driven or automated alerting detected",
                details=(
                    "FRR-ICP-08 recommends automated mechanisms for incident reporting. "
                    "Consider implementing event-driven architecture."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Consider implementing event-driven incident reporting."
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
        """Analyze C# for automation frameworks."""
        findings = []
        has_automation = bool(re.search(r'(Workflow|Automation|Orchestration|EventDriven)', code, re.IGNORECASE))
        if not has_automation:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No automation framework", description=f"FRR-ICP-08 recommends automated incident reporting.",
                severity=Severity.LOW, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Consider implementing automated reporting: Hangfire, Azure Logic Apps, or workflow engines"
            ))
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java for automation frameworks."""
        findings = []
        has_automation = bool(re.search(r'(Workflow|Automation|Orchestration|EventDriven)', code, re.IGNORECASE))
        if not has_automation:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No automation framework", description=f"FRR-ICP-08 recommends automated incident reporting.",
                severity=Severity.LOW, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Consider implementing automated reporting: Spring Integration, Apache Camel, or workflow engines"
            ))
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript for automation frameworks."""
        findings = []
        has_automation = bool(re.search(r'(workflow|automation|orchestration|eventDriven)', code, re.IGNORECASE))
        if not has_automation:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No automation framework", description=f"FRR-ICP-08 recommends automated incident reporting.",
                severity=Severity.LOW, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Consider implementing automated reporting: n8n, workflow libraries, or event-driven patterns"
            ))
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep for automation services."""
        findings = []
        has_automation = bool(re.search(r"resource\s+\w+\s+'Microsoft\.(Logic|Automation)", code))
        if not has_automation:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No automation infrastructure", description=f"FRR-ICP-08 recommends automated reporting.",
                severity=Severity.LOW, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Consider deploying: Logic Apps or Automation accounts"
            ))
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for automation services."""
        findings = []
        has_automation = bool(re.search(r'resource\s+"(azurerm_logic_app|azurerm_automation|aws_lambda)"', code))
        if not has_automation:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No automation infrastructure", description=f"FRR-ICP-08 recommends automated reporting.",
                severity=Severity.LOW, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Consider deploying: azurerm_logic_app_workflow or aws_lambda_function"
            ))
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for automation workflows."""
        return []  # Automated reporting is runtime operational
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for automation workflows."""
        return []  # Automated reporting is runtime operational
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for automation workflows."""
        return []  # Automated reporting is runtime operational
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """Get automated queries for FRR-ICP-08 evidence (automated incident reporting)."""
        return {
            'automated_queries': [
                "Resources | where type == 'microsoft.logic/workflows' or type == 'microsoft.automation/automationaccounts' | project name, type, resourceGroup",
                "AzureActivity | where ResourceProviderValue contains 'Logic' or ResourceProviderValue contains 'Automation' | summarize by ResourceId",
                "Resources | where tags contains 'automation' or tags contains 'workflow' | project name, type, resourceGroup"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Get evidence artifacts for FRR-ICP-08 (automated incident reporting)."""
        return {
            'evidence_artifacts': [
                "Automation framework documentation and architecture",
                "Workflow engine configuration exports (Logic Apps, Automation accounts)",
                "Automated reporting mechanism implementation",
                "Historical automated incident reports",
                "Integration testing evidence for automated reporting",
                "Event-driven architecture documentation",
                "Automation monitoring and alerting configuration",
                "Manual vs automated reporting comparison metrics"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Get automation recommendations for FRR-ICP-08 (automated incident reporting)."""
        return {
            'implementation_notes': [
                "Implement automation frameworks (Azure Logic Apps, Azure Automation, workflow engines)",
                "Configure event-driven architecture for incident detection and reporting",
                "Automate report generation and distribution to all parties",
                "Test automated reporting mechanisms with sample incidents",
                "Monitor automation execution and failure rates",
                "Document automation workflows and decision logic",
                "Establish fallback procedures for automation failures"
            ]
        }
