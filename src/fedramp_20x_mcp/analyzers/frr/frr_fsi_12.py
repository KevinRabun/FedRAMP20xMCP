"""
FRR-FSI-12: Notification of Changes

Providers MUST immediately notify FedRAMP of any changes in addressing for their _FedRAMP Security Inbox_ by emailing info@fedramp.gov with the name and FedRAMP ID of the cloud service offering and the updated email address.

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


class FRR_FSI_12_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-FSI-12: Notification of Changes
    
    **Official Statement:**
    Providers MUST immediately notify FedRAMP of any changes in addressing for their _FedRAMP Security Inbox_ by emailing info@fedramp.gov with the name and FedRAMP ID of the cloud service offering and the updated email address.
    
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
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-FSI-12"
    FRR_NAME = "Notification of Changes"
    FRR_STATEMENT = """Providers MUST immediately notify FedRAMP of any changes in addressing for their _FedRAMP Security Inbox_ by emailing info@fedramp.gov with the name and FedRAMP ID of the cloud service offering and the updated email address."""
    FAMILY = "FSI"
    FAMILY_NAME = "FedRAMP Security Incident"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PM-15", "Contacts with Security Groups and Associations"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-FSI-12 analyzer."""
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
        Analyze Python code for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in application
        code.
        
        Args:
            code: Python source code to analyze
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not code-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in application
        code.
        
        Args:
            code: C# source code to analyze
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not code-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in application
        code.
        
        Args:
            code: Java source code to analyze
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not code-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in application
        code.
        
        Args:
            code: TypeScript/JavaScript source code to analyze
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not code-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in
        infrastructure-as-code templates.
        
        Args:
            code: Bicep IaC code to analyze
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not IaC-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in
        infrastructure-as-code templates.
        
        Args:
            code: Terraform IaC code to analyze
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not IaC-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in CI/CD
        pipelines.
        
        Args:
            code: GitHub Actions YAML workflow
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not CI/CD-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in CI/CD
        pipelines.
        
        Args:
            code: Azure Pipelines YAML
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not CI/CD-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI configuration for FRR-FSI-12 compliance.
        
        This analyzer is NOT APPLICABLE because FRR-FSI-12 requires CSPs to immediately
        notify FedRAMP of FSI email address changes by emailing info@fedramp.gov. This
        is an operational notification requirement that cannot be detected in CI/CD
        pipelines.
        
        Args:
            code: GitLab CI YAML configuration
            file_path: Optional path to the file being analyzed
            
        Returns:
            Empty list (operational requirement, not CI/CD-detectable)
        """
        # NOT APPLICABLE: Operational notification requirement
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get Azure Resource Graph and other queries for evidence collection.
        
        Returns a dict with 'automated_queries' key containing query notes.
        """
        return {
            'automated_queries': [
                "FRR-FSI-12 is an operational requirement for CSPs to immediately notify FedRAMP "
                "of changes to the FedRAMP Security Inbox email address by emailing info@fedramp.gov. "
                "Evidence cannot be collected through automated queries of Azure resources or code "
                "repositories. Evidence should consist of CSP's change management records and "
                "notification procedures."
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get list of evidence artifacts to collect for FRR-FSI-12 compliance.
        
        Returns a dict with 'evidence_artifacts' key containing artifact list.
        """
        return {
            'evidence_artifacts': [
                "1. Change Notification Policy: Documented policy requiring immediate notification "
                "to FedRAMP (info@fedramp.gov) when the FSI email address changes, including required "
                "information (CSO name, FedRAMP ID, updated email address).",
                
                "2. Change Management Records: Records of any historical FSI email address changes, "
                "including change requests, approvals, implementation dates, and corresponding "
                "notifications to FedRAMP.",
                
                "3. Notification Email Records: Copies of emails sent to info@fedramp.gov notifying "
                "FedRAMP of FSI address changes, demonstrating compliance with the immediate "
                "notification requirement and inclusion of required information.",
                
                "4. FedRAMP Acknowledgment Records: Records of FedRAMP acknowledgment or confirmation "
                "of FSI email address change notifications, demonstrating successful communication.",
                
                "5. Contact Management Procedures: Documented procedures for maintaining FSI contact "
                "information currency, including triggers for review (e.g., organizational changes, "
                "email system migrations, personnel changes).",
                
                "6. Change Request Templates: Template or checklist for FSI email address changes, "
                "including automatic reminder to notify FedRAMP with required information (CSO name, "
                "FedRAMP ID, updated email address).",
                
                "7. Historical FSI Addresses: Record of all historical FSI email addresses used for "
                "each cloud service offering, with effective dates and change rationale, demonstrating "
                "continuity of FedRAMP communication channel.",
                
                "8. Integration with Change Management: Evidence that FSI email address changes are "
                "integrated into the CSP's broader change management process, including approval "
                "workflows, communication plans, and FedRAMP notification requirements."
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection.
        
        Returns a dict with 'implementation_notes' key containing guidance.
        """
        return {
            'implementation_notes': (
                "FRR-FSI-12 requires CSPs to immediately notify FedRAMP of any changes to the "
                "FedRAMP Security Inbox (FSI) email address by emailing info@fedramp.gov with the "
                "cloud service offering name, FedRAMP ID, and updated email address. This is an "
                "operational notification requirement that cannot be detected through code analysis, "
                "IaC templates, or CI/CD pipelines.\n\n"
                
                "COMPLIANCE APPROACH:\n"
                "1. Change Notification Policy: Establish clear policy requiring immediate notification "
                "to FedRAMP when the FSI email address changes. Policy should specify:\n"
                "   - Required information: CSO name, FedRAMP ID, updated email address\n"
                "   - Notification recipient: info@fedramp.gov\n"
                "   - Timing: Immediate (within same business day as change)\n"
                "   - Responsible personnel for sending notification\n\n"
                
                "2. Change Management Integration: Integrate FSI email address changes into the CSP's "
                "formal change management process, including:\n"
                "   - Change request approval workflow\n"
                "   - Mandatory FedRAMP notification step\n"
                "   - Automated reminders to notify info@fedramp.gov\n"
                "   - Change completion verification including FedRAMP notification\n\n"
                
                "3. Notification Templates: Create email template for notifying FedRAMP of FSI changes, "
                "ensuring all required information is included:\n"
                "   Subject: 'FSI Email Address Change - [CSO Name]'\n"
                "   Body: CSO Name, FedRAMP ID, Old FSI Address, New FSI Address, Effective Date, "
                "   Contact Person\n\n"
                
                "4. Contact Information Management: Maintain accurate records of current FSI email "
                "addresses for all cloud service offerings, with regular reviews triggered by:\n"
                "   - Organizational changes or restructuring\n"
                "   - Email system migrations or upgrades\n"
                "   - Personnel changes affecting FSI monitoring\n"
                "   - Annual contact information verification\n\n"
                
                "5. Notification Tracking: Track all FSI email address change notifications sent to "
                "FedRAMP, including:\n"
                "   - Date/time of notification\n"
                "   - Method of notification (email to info@fedramp.gov)\n"
                "   - Information included in notification\n"
                "   - FedRAMP acknowledgment or confirmation (if received)\n\n"
                
                "EVIDENCE COLLECTION:\n"
                "Evidence for FRR-FSI-12 consists of change management records and notification "
                "documentation, not code or infrastructure configurations. Key evidence includes:\n"
                "- Policy requiring immediate FedRAMP notification of FSI changes\n"
                "- Change management records for any historical FSI address changes\n"
                "- Copies of notification emails sent to info@fedramp.gov\n"
                "- FedRAMP acknowledgment records (if available)\n"
                "- Contact management procedures and review triggers\n"
                "- Change request templates with FedRAMP notification reminders\n"
                "- Historical FSI address records with effective dates\n"
                "- Integration with broader change management process\n\n"
                
                "TIMING CONSIDERATIONS:\n"
                "The requirement specifies 'immediately' notify FedRAMP. Best practices:\n"
                "- Send notification to info@fedramp.gov within same business day as FSI change\n"
                "- For planned changes, notify FedRAMP in advance when possible\n"
                "- For emergency changes, notify as soon as possible after implementation\n"
                "- Maintain audit trail of notification timing to demonstrate immediacy\n\n"
                
                "RELATIONSHIP TO OTHER REQUIREMENTS:\n"
                "FRR-FSI-12 supports other FSI requirements:\n"
                "- FRR-FSI-09: Establish FSI email address\n"
                "- FRR-FSI-11: Maintain FSI without disruption\n"
                "FRR-FSI-12 ensures FedRAMP always has current FSI contact information to maintain "
                "effective communication with CSPs.\n\n"
                
                "NOT APPLICABLE: This requirement cannot be validated through automated code analysis, "
                "IaC scanning, or CI/CD pipeline checks. Compliance is demonstrated through change "
                "management records, notification documentation, and policy adherence, not code artifacts."
            )
        }
