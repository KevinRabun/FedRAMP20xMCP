"""
FRR-CCM-AG-04: Notify Provider of Concerns

Agencies SHOULD formally notify the provider if the information presented in an _Ongoing Authorization Report_, _Quarterly Review_, or other ongoing _authorization data_ causes significant concerns that may lead the _agency_ to remove the _cloud service offering_ from operation.

Official FedRAMP 20x Requirement
Source: FRR-CCM (Collaborative Continuous Monitoring) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_CCM_AG_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-CCM-AG-04: Notify Provider of Concerns
    
    **Official Statement:**
    Agencies SHOULD formally notify the provider if the information presented in an _Ongoing Authorization Report_, _Quarterly Review_, or other ongoing _authorization data_ causes significant concerns that may lead the _agency_ to remove the _cloud service offering_ from operation.
    
    **Family:** CCM - Collaborative Continuous Monitoring
    
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
    
    FRR_ID = "FRR-CCM-AG-04"
    FRR_NAME = "Notify Provider of Concerns"
    FRR_STATEMENT = """Agencies SHOULD formally notify the provider if the information presented in an _Ongoing Authorization Report_, _Quarterly Review_, or other ongoing _authorization data_ causes significant concerns that may lead the _agency_ to remove the _cloud service offering_ from operation."""
    FAMILY = "CCM"
    FAMILY_NAME = "Collaborative Continuous Monitoring"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-7", "Continuous Monitoring"),
        ("IR-6", "Incident Reporting"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-CCM-AG-04 analyzer."""
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
        Analyze Python code for FRR-CCM-AG-04 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-CCM-AG-04 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-CCM-AG-04 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-CCM-AG-04 compliance using AST.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-CCM-AG-04 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-CCM-AG-04 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-CCM-AG-04 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-CCM-AG-04 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-CCM-AG-04 compliance.
        
        **NOT APPLICABLE:** This is an AGENCY requirement about notifying providers.
        Agencies SHOULD formally notify providers of significant concerns - this is a
        governance/communication requirement for agencies, not a code implementation
        requirement for cloud service providers.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Returns Azure Resource Graph and KQL queries for evidence collection.
        
        Note: This is an AGENCY requirement. Evidence focuses on agency documentation
        of formal notifications sent to providers about significant concerns.
        """
        return [
            # Query 1: Provider tracking of received agency concerns (optional)
            """// Optional: CSP can track formal notifications received from agencies
AppEvents
| where TimeGenerated > ago(180d)
| where Name == 'AgencyNotification' or Name == 'AgencyConcernReceived'
| extend AgencyId = tostring(Properties.agency_id)
| extend SeverityLevel = tostring(Properties.severity)
| where SeverityLevel == 'Significant' or SeverityLevel == 'High'
| project TimeGenerated, AgencyId, Name, Properties
| order by TimeGenerated desc""",
            
            # Query 2: Not applicable - agency-side communication tracking
            """// NOT APPLICABLE: This requirement applies to agency communication
// Agencies must track formal notifications sent to providers
// Provider evidence: Receipt logs, response documentation""",
            
            # Query 3: Provider incident management (related)
            """// Related: Track provider responses to agency concerns
AppEvents
| where TimeGenerated > ago(180d)
| where Name contains 'AgencyConcern' or Name contains 'EscalationResponse'
| extend AgencyId = tostring(Properties.agency_id)
| summarize ResponseCount = count() by AgencyId, bin(TimeGenerated, 30d)
| order by TimeGenerated desc"""
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Returns list of evidence artifacts to collect.
        """
        return [
            "Agency formal notification letters to provider",
            "Agency documentation of significant concerns identified",
            "Agency correspondence regarding potential service removal",
            "Provider receipt acknowledgments of agency notifications",
            "Agency escalation procedures for significant concerns",
            "Agency risk assessment triggering notification",
            "Provider response to agency concerns",
            "Agency decision records on continued use of CSO",
            "Agency communication policy for provider notifications",
            "Timeline of agency-provider communications regarding concerns"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provides recommendations for automated evidence collection.
        """
        return {
            "automated_queries": [
                {
                    "name": "Agency Notification Receipt Tracking",
                    "description": "Optional: Track formal notifications received from agencies",
                    "query": """AppEvents
| where TimeGenerated > ago(180d)
| where Name == 'AgencyNotificationReceived'
| extend AgencyId = tostring(Properties.agency_id)
| summarize NotificationCount = count() by AgencyId, bin(TimeGenerated, 30d)
| order by TimeGenerated desc""",
                    "schedule": "Monthly",
                    "note": "CSP can track but cannot enforce agency notification practices"
                }
            ],
            "evidence_artifacts": [
                {
                    "name": "Agency Notification Letters",
                    "description": "Formal letters from agencies regarding significant concerns",
                    "location": "Agency-provided documentation / secure email archive",
                    "note": "Provider receives these - agency-generated artifact"
                },
                {
                    "name": "Provider Response Documentation",
                    "description": "Provider acknowledgments and responses to agency concerns",
                    "location": "Internal correspondence / customer management system",
                    "note": "CSP should maintain records of all formal agency communications"
                }
            ],
            "implementation_notes": [
                "This is an AGENCY requirement - agencies SHOULD notify providers",
                "Applies when: Agency has significant concerns from reports or reviews",
                "Significant concerns: Issues that may lead to service removal from operation",
                "Provider responsibility: Accept and respond to agency notifications",
                "Agency responsibility: Formally notify provider of significant concerns",
                "'Formally notify' indicates official, documented communication",
                "Notification triggers: Ongoing Authorization Report issues, Quarterly Review findings",
                "Provider can support: Maintain clear escalation contacts for agencies",
                "Provider can support: Acknowledge receipt of agency notifications promptly",
                "Provider can support: Respond to concerns with remediation plans",
                "Evidence source: Agency correspondence and provider receipt logs",
                "This is communication/governance, not technical implementation"
            ]
        }
