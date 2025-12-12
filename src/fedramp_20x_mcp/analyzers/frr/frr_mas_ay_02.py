"""
FRR-MAS-AY-02: Non-Cloud-Based Software

Software produced by cloud service providers that is delivered separately for installation on agency systems and not operated in a shared responsibility model (typically including agents, application clients, mobile applications, etc. that are not fully managed by the cloud service provider) is not a cloud computing product or service and is entirely outside the scope of FedRAMP under the FedRAMP Authorization Act. All such software is therefore not included in the _cloud service offering_ for FedRAMP. For more, see fedramp.gov/scope.

Official FedRAMP 20x Requirement
Source: FRR-MAS (MAS) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_MAS_AY_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-MAS-AY-02: Non-Cloud-Based Software
    
    **Official Statement:**
    Software produced by cloud service providers that is delivered separately for installation on agency systems and not operated in a shared responsibility model (typically including agents, application clients, mobile applications, etc. that are not fully managed by the cloud service provider) is not a cloud computing product or service and is entirely outside the scope of FedRAMP under the FedRAMP Authorization Act. All such software is therefore not included in the _cloud service offering_ for FedRAMP. For more, see fedramp.gov/scope.
    
    **Family:** MAS - MAS
    
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
    
    FRR_ID = "FRR-MAS-AY-02"
    FRR_NAME = "Non-Cloud-Based Software"
    FRR_STATEMENT = """Software produced by cloud service providers that is delivered separately for installation on agency systems and not operated in a shared responsibility model (typically including agents, application clients, mobile applications, etc. that are not fully managed by the cloud service provider) is not a cloud computing product or service and is entirely outside the scope of FedRAMP under the FedRAMP Authorization Act. All such software is therefore not included in the _cloud service offering_ for FedRAMP. For more, see fedramp.gov/scope."""
    FAMILY = "MAS"
    FAMILY_NAME = "MAS"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PM-5", "System Inventory"),
        ("CM-8", "System Component Inventory"),
        ("SA-4", "Acquisition Process"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Assessment scope determination
    ]
    
    def __init__(self):
        """Initialize FRR-MAS-AY-02 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-02 NOT code-detectable: Non-cloud software scope is policy."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-02 NOT code-detectable: Non-cloud software scope is policy."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-02 NOT code-detectable: Non-cloud software scope is policy."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """MAS-AY-02 NOT code-detectable: Non-cloud software scope is policy."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Non-cloud software scope is policy."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Non-cloud software scope is policy."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Non-cloud software scope is policy."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Non-cloud software scope is policy."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Non-cloud software scope is policy."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """KQL queries for non-cloud software documentation."""
        from typing import Dict, Any
        return {
            "automated_queries": [
                "# Query 1: Resources with software deployment\nResources\n| where type contains 'virtualMachines' or type contains 'app'\n| extend SoftwareType = tostring(tags.softwareType)\n| extend DeploymentModel = tostring(tags.deploymentModel)\n| project name, type, SoftwareType, DeploymentModel",
                "# Query 2: Resources marked as non-cloud software\nResources\n| where tags contains 'nonCloudSoftware' or tags contains 'clientSoftware'\n| project name, type, tags",
                "# Query 3: Application installations\nResources\n| where type == 'microsoft.compute/virtualmachines'\n| extend InstallType = tostring(tags.installationType)\n| where InstallType contains 'client' or InstallType contains 'agent'\n| project name, location, InstallType"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """Required evidence artifacts for FRR-MAS-AY-02."""
        from typing import Dict, Any
        return {
            "evidence_artifacts": [
                "Software deployment documentation",
                "Client/agent software inventory with deployment models",
                "Distinction documentation (cloud service vs. non-cloud software)",
                "Software delivery mechanism documentation",
                "Installation and configuration procedures",
                "Shared responsibility model documentation",
                "Out-of-scope software justifications per FedRAMP scope guidance",
                "Agency system installation records"
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """Implementation recommendations for FRR-MAS-AY-02."""
        from typing import Dict, Any
        return {
            "implementation_notes": [
                "Review FedRAMP scope guidance for non-cloud software at https://fedramp.gov/scope",
                "Document all client software, agents, and applications installed on agency systems",
                "Clearly distinguish cloud services from non-cloud software components",
                "Document deployment models (cloud-managed vs. agency-managed)",
                "Identify software not operated under shared responsibility model",
                "Tag resources with deployment model metadata",
                "Exclude non-cloud software from FedRAMP authorization scope documentation"
            ]
        }
