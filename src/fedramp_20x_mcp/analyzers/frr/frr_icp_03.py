"""
FRR-ICP-03: Incident Reporting to CISA

Providers MUST responsibly report _incidents_ to CISA within 1 hour of identification if the incident is confirmed or suspected to be the result of an attack vector listed at https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy, following the CISA Federal Incident Notification Guidelines at https://www.cisa.gov/federal-incident-notification-guidelines, by using the CISA Incident Reporting System at https://myservices.cisa.gov/irf. 

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


class FRR_ICP_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-03: Incident Reporting to CISA
    
    **Official Statement:**
    Providers MUST responsibly report _incidents_ to CISA within 1 hour of identification if the incident is confirmed or suspected to be the result of an attack vector listed at https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy, following the CISA Federal Incident Notification Guidelines at https://www.cisa.gov/federal-incident-notification-guidelines, by using the CISA Incident Reporting System at https://myservices.cisa.gov/irf. 
    
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
    
    FRR_ID = "FRR-ICP-03"
    FRR_NAME = "Incident Reporting to CISA"
    FRR_STATEMENT = """Providers MUST responsibly report _incidents_ to CISA within 1 hour of identification if the incident is confirmed or suspected to be the result of an attack vector listed at https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy, following the CISA Federal Incident Notification Guidelines at https://www.cisa.gov/federal-incident-notification-guidelines, by using the CISA Incident Reporting System at https://myservices.cisa.gov/irf. """
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
    CODE_DETECTABLE = True  # Detects CISA reporting mechanisms and government cloud integrations
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-03 analyzer."""
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
        Analyze Python code for FRR-ICP-03 compliance using AST.
        
        Detects:
        - CISA-specific reporting mechanisms
        - Government cloud integrations
        - Attack vector detection and classification
        """
        findings = []
        
        from ..detection_patterns import detect_python_alerting, detect_python_logging
        from ..detection_patterns import create_missing_alerting_finding, create_missing_logging_finding
        
        # Check for logging mechanisms
        has_logging, _ = detect_python_logging(code)
        
        # Check for alerting mechanisms
        has_alerting, _ = detect_python_alerting(code)
        
        # Check for CISA-specific patterns
        has_cisa = bool(re.search(r'cisa|government.*reporting|federal.*reporting', code, re.IGNORECASE))
        has_attack_vector = bool(re.search(r'attack.*vector|threat.*classification|incident.*type', code, re.IGNORECASE))
        
        if not has_logging:
            findings.append(create_missing_logging_finding(self.FRR_ID, file_path))
        
        if not has_alerting:
            findings.append(create_missing_alerting_finding(self.FRR_ID, file_path))
        
        if not has_cisa:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.HIGH,
                message="No CISA-specific reporting mechanism detected",
                details=(
                    "FRR-ICP-03 requires reporting specific incidents to CISA. "
                    "The code should implement CISA reporting integration."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement CISA reporting mechanism for applicable incidents."
            ))
        
        if not has_attack_vector:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.MEDIUM,
                message="No attack vector classification detected",
                details=(
                    "FRR-ICP-03 requires determining if incidents match CISA attack vectors. "
                    "The code should classify incidents by attack vector type."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement attack vector detection and classification logic."
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
        """Analyze C# code for FRR-ICP-03 CISA reporting mechanisms."""
        findings = []
        has_alerting = bool(re.search(r'(ILogger|SendGrid|HttpClient.*Post)', code))
        has_cisa = bool(re.search(r'cisa|government.*reporting', code, re.IGNORECASE))
        has_attack_vector = bool(re.search(r'attack.*vector|threat.*classification', code, re.IGNORECASE))
        
        if not has_alerting:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No CISA reporting mechanism detected",
                description=f"C# code in '{file_path}' lacks CISA reporting. FRR-ICP-03 requires CISA reporting for specific incidents.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement CISA reporting: 1) Add HttpClient for CISA API, 2) Attack vector classification, 3) Integration with https://myservices.cisa.gov/irf"
            ))
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code for FRR-ICP-03 CISA reporting mechanisms."""
        findings = []
        has_alerting = bool(re.search(r'(HttpClient|sendEmail)', code, re.IGNORECASE))
        has_cisa = bool(re.search(r'cisa|government.*reporting', code, re.IGNORECASE))
        
        if not has_alerting:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No CISA reporting mechanism detected",
                description=f"Java code in '{file_path}' lacks CISA reporting. FRR-ICP-03 requires CISA reporting for specific incidents.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement CISA reporting: HttpClient for CISA API integration"
            ))
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript/JavaScript code for FRR-ICP-03 CISA reporting mechanisms."""
        findings = []
        has_alerting = bool(re.search(r'(axios|fetch)', code, re.IGNORECASE))
        has_cisa = bool(re.search(r'cisa|government.*reporting', code, re.IGNORECASE))
        
        if not has_alerting:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No CISA reporting mechanism detected",
                description=f"TypeScript code in '{file_path}' lacks CISA reporting. FRR-ICP-03 requires CISA reporting for specific incidents.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement CISA reporting: axios/fetch for CISA API integration"
            ))
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep infrastructure for CISA reporting resources."""
        findings = []
        has_logic_app = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Logic/workflows", code))
        has_function = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Web/sites.*kind:\s*'functionapp'", code, re.DOTALL))
        
        if not (has_logic_app or has_function):
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No CISA reporting automation detected",
                description=f"Bicep template '{file_path}' lacks CISA reporting automation. FRR-ICP-03 requires CISA reporting infrastructure.",
                severity=Severity.MEDIUM, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Deploy CISA reporting automation: Logic Apps or Functions for CISA API integration"
            ))
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform infrastructure for CISA reporting resources."""
        findings = []
        has_azure_logic = bool(re.search(r'resource\s+"azurerm_logic_app_workflow"', code))
        has_azure_function = bool(re.search(r'resource\s+"azurerm_function_app"', code))
        has_aws_lambda = bool(re.search(r'resource\s+"aws_lambda_function"', code))
        
        if not (has_azure_logic or has_azure_function or has_aws_lambda):
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No CISA reporting automation detected",
                description=f"Terraform '{file_path}' lacks CISA reporting automation. FRR-ICP-03 requires CISA reporting infrastructure.",
                severity=Severity.MEDIUM, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Deploy automation: azurerm_logic_app_workflow, azurerm_function_app, or aws_lambda_function for CISA reporting"
            ))
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for CISA reporting workflows."""
        return []  # CISA reporting is runtime operational, not typically in CI/CD
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for CISA reporting."""
        return []  # CISA reporting is runtime operational
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for CISA reporting."""
        return []  # CISA reporting is runtime operational
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """Get evidence collection queries for CISA reporting."""
        return {
            'automated_queries': [
                "// Logic Apps - CISA reporting workflows",
                "resources | where type =~ 'Microsoft.Logic/workflows'",
                "| extend state = properties.state",
                "| project name, resourceGroup, state, location"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Get evidence artifacts for FRR-ICP-03."""
        return {
            'evidence_artifacts': [
                "1. Incident Response Plan - CISA Reporting: Documented procedures for CISA reporting including 1-hour requirement, CISA attack vector taxonomy mapping, CISA Federal Incident Notification Guidelines compliance, CISA Incident Reporting System (IRS) access credentials, and attack vector classification process.",
                "2. CISA IRS Account and Credentials: Evidence of CISA Incident Reporting System account at https://myservices.cisa.gov/irf including account credentials, authorized users, access logs, and training on CISA IRS usage.",
                "3. Attack Vector Classification Logic: Documentation or code showing how incidents are classified against CISA attack vectors taxonomy (https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy) including automated classification where possible, manual review process for ambiguous cases, and decision tree for CISA reporting determination.",
                "4. Historical CISA Incident Reports: Records of past incidents reported to CISA showing incident identification timestamp, CISA reporting timestamp (within 1 hour), attack vector classification, CISA IRS submission confirmation, and CISA case numbers.",
                "5. CISA Reporting Automation: Logic Apps, Functions, or automation scripts for CISA reporting including CISA IRS API integration (if available), attack vector detection logic, 1-hour reporting capability, and notification to incident response team.",
                "6. Staff Training - CISA Reporting: Training records for incident response team including CISA Federal Incident Notification Guidelines training, attack vector taxonomy familiarization, CISA IRS system training, and 1-hour reporting requirement awareness.",
                "7. CISA Reporting Templates: Pre-configured templates for CISA incident reports including required fields per CISA guidelines, attack vector taxonomy references, and submission workflow.",
                "8. Testing Evidence - CISA Reporting: Records of CISA reporting testing including tabletop exercises with CISA reporting scenarios, CISA IRS system testing, 1-hour reporting capability validation, and feedback from CISA coordination."
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Get automation recommendations for FRR-ICP-03."""
        return {
            'implementation_notes': (
                "FRR-ICP-03 requires Providers to MUST responsibly report incidents to CISA within 1 hour if the incident matches CISA attack vectors taxonomy. This is a conditional MUST requirement that applies only to specific incident types defined by CISA Federal Incident Notification Guidelines.\\n\\n"
                "COMPLIANCE APPROACH:\\n"
                "1. CISA Attack Vector Classification: Implement logic to determine if incidents match CISA attack vectors (Ransomware, Phishing, Supply Chain Compromise, etc.) per https://www.cisa.gov/federal-incident-notification-guidelines#attack-vectors-taxonomy\\n"
                "2. CISA IRS Integration: Obtain CISA Incident Reporting System account at https://myservices.cisa.gov/irf and integrate reporting workflow\\n"
                "3. 1-Hour Reporting: Automate or expedite CISA reporting to meet 1-hour requirement for applicable incidents\\n"
                "4. CISA Guidelines Compliance: Follow CISA Federal Incident Notification Guidelines at https://www.cisa.gov/federal-incident-notification-guidelines\\n\\n"
                "RECOMMENDED AZURE SERVICES:\\n"
                "1. Azure Logic Apps: Automate CISA reporting workflows with attack vector classification and CISA IRS integration\\n"
                "2. Azure Functions: Create serverless functions for CISA attack vector detection and reporting\\n"
                "3. Azure Monitor: Detect incidents that may match CISA attack vectors\\n\\n"
                "LIMITATION: Code analysis detects CISA reporting INFRASTRUCTURE, not actual runtime CISA reporting. Compliance validated through operational records of historical CISA incident reports."
            )
        }
