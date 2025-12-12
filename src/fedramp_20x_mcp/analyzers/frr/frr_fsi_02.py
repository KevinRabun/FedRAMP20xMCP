"""
FRR-FSI-02: Criticality Designators

FedRAMP MUST convey the criticality of the message in the subject line using one of the following designators if the message requires an elevated response:

Official FedRAMP 20x Requirement
Source: FRR-FSI (FedRAMP Security Incident) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import Dict, List, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_FSI_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-FSI-02: Criticality Designators
    
    **Official Statement:**
    FedRAMP MUST convey the criticality of the message in the subject line using one of the following designators if the message requires an elevated response:
    
    **Family:** FSI - FedRAMP Security Incident
    
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
    
    FRR_ID = "FRR-FSI-02"
    FRR_NAME = "Criticality Designators"
    FRR_STATEMENT = """FedRAMP MUST convey the criticality of the message in the subject line using one of the following designators if the message requires an elevated response:"""
    FAMILY = "FSI"
    FAMILY_NAME = "FedRAMP Security Incident"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("IR-4", "Incident Handling"),
        ("IR-6", "Incident Reporting"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-FSI-02 analyzer."""
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
        Analyze Python code for FRR-FSI-02 compliance using AST.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP code requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-FSI-02 compliance using AST.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP code requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-FSI-02 compliance using AST.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP code requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-FSI-02 compliance using AST.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP code requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    def analyze_javascript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze JavaScript code for FRR-FSI-02 compliance using AST.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP code requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-FSI-02 compliance.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP infrastructure requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-FSI-02 compliance.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP infrastructure requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-FSI-02 compliance.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP CI/CD requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-FSI-02 compliance.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP CI/CD requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-FSI-02 compliance.
        
        NOT APPLICABLE: This requirement applies to FedRAMP (not CSPs) - FedRAMP
        MUST use criticality designators in subject lines when sending messages
        requiring elevated response. This is a FedRAMP operational requirement
        about message formatting, not a CSP CI/CD requirement.
        """
        return []  # NOT APPLICABLE - FedRAMP-side requirement
    
    # ============================================================================
    # EVIDENCE COLLECTION METHODS
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Return automated evidence collection queries for FRR-FSI-02.
        
        Returns:
            Dict containing automated query specifications.
        """
        return {
            "automated_queries": [
                "Note: FRR-FSI-02 is a FedRAMP-side requirement. CSPs verify FedRAMP "
                "messages received use proper criticality designators in subject lines"
            ]
        }
    
    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Return list of evidence artifacts needed for FRR-FSI-02 compliance.
        
        Returns:
            List of evidence artifact specifications.
        """
        return [
            {
                "artifact_id": "FSI-02-01",
                "name": "Sample FedRAMP Critical Messages",
                "description": "Sample high-priority FedRAMP messages showing criticality designators in subject lines",
                "collection_method": "Email Archive - Export sample critical FedRAMP communications"
            },
            {
                "artifact_id": "FSI-02-02",
                "name": "Criticality Designator Reference",
                "description": "Documentation of criticality designators used by FedRAMP (e.g., [URGENT], [ACTION REQUIRED])",
                "collection_method": "Document Review - FedRAMP communication standards documentation"
            },
            {
                "artifact_id": "FSI-02-03",
                "name": "Email Parsing Rules",
                "description": "CSP email system rules/filters for identifying FedRAMP critical messages by subject line",
                "collection_method": "Configuration Export - Email gateway/filtering rules"
            },
            {
                "artifact_id": "FSI-02-04",
                "name": "Alert Escalation Configuration",
                "description": "CSP alert system configuration for escalating FedRAMP messages with criticality designators",
                "collection_method": "Configuration Export - Incident management/ticketing system rules"
            },
            {
                "artifact_id": "FSI-02-05",
                "name": "Response Time Tracking",
                "description": "Logs showing CSP response times to FedRAMP messages by criticality level",
                "collection_method": "Log Query - Incident management system response metrics"
            },
            {
                "artifact_id": "FSI-02-06",
                "name": "Staff Training Documentation",
                "description": "Training materials for CSP staff on recognizing and responding to FedRAMP criticality designators",
                "collection_method": "Document Review - Training curriculum and attendance records"
            },
            {
                "artifact_id": "FSI-02-07",
                "name": "Message Handling Procedures",
                "description": "CSP procedures for triaging and responding to FedRAMP messages based on subject line criticality",
                "collection_method": "Document Review - Standard operating procedures"
            },
            {
                "artifact_id": "FSI-02-08",
                "name": "Notification Distribution Lists",
                "description": "CSP distribution lists/on-call schedules for critical FedRAMP communications",
                "collection_method": "Configuration Export - Notification system settings"
            }
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Return recommendations for automating evidence collection for FRR-FSI-02.
        
        Returns:
            Dict containing automation recommendations and implementation notes.
        """
        return {
            "implementation_notes": (
                "FRR-FSI-02 is a FedRAMP-side requirement: FedRAMP MUST convey criticality "
                "in message subject lines using specific designators when elevated response "
                "is required. This is NOT a CSP implementation requirement.\n\n"
                
                "CSP ROLE:\n"
                "- Recognize FedRAMP criticality designators in email subject lines\n"
                "- Configure email systems to properly route/escalate critical messages\n"
                "- Establish response procedures based on message criticality\n"
                "- Train staff on criticality levels and response expectations\n\n"
                
                "CRITICALITY DESIGNATORS (examples):\n"
                "- [URGENT] - Immediate action required\n"
                "- [ACTION REQUIRED] - Response needed by specific deadline\n"
                "- [TIME SENSITIVE] - Priority handling needed\n"
                "- [CRITICAL] - High-priority security or compliance matter\n"
                "Note: Actual designators defined by FedRAMP communication standards\n\n"
                
                "CSP MESSAGE HANDLING:\n"
                "- Email filtering: Identify messages with criticality designators\n"
                "- Automatic escalation: Route critical messages to appropriate teams\n"
                "- Alert generation: Notify on-call personnel of urgent messages\n"
                "- Response tracking: Monitor response times by criticality level\n\n"
                
                "RESPONSE TIME EXPECTATIONS:\n"
                "- [URGENT]: Immediate acknowledgment (within hours)\n"
                "- [ACTION REQUIRED]: Response by stated deadline\n"
                "- [TIME SENSITIVE]: Priority handling, faster than standard\n"
                "- Standard messages: Normal business response time\n\n"
                
                "AUTOMATION OPPORTUNITIES:\n"
                "1. Email parsing: Automated extraction of criticality designators\n"
                "2. Ticket creation: Auto-generate high-priority tickets from critical emails\n"
                "3. Alert routing: Automatically page on-call staff for urgent messages\n"
                "4. Response tracking: Dashboard showing response times by criticality\n\n"
                
                "EVIDENCE COLLECTION:\n"
                "- Sample emails with criticality designators\n"
                "- Email routing/filtering rules\n"
                "- Alert escalation configurations\n"
                "- Response time metrics by criticality level\n\n"
                
                "Note: This requirement ensures CSPs can appropriately prioritize and respond to "
                "FedRAMP communications requiring elevated attention. CSPs should configure email "
                "systems and procedures to recognize these designators but do not define the "
                "designators themselves - that is FedRAMP's responsibility."
            )
        }
