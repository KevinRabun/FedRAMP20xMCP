"""
KSI-AFR-01: Minimum Assessment Scope

Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the scope of the cloud service offering to be assessed for FedRAMP authorization and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-01: Minimum Assessment Scope
    
    **Official Statement:**
    Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the scope of the cloud service offering to be assessed for FedRAMP authorization and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the scope of the cloud ser...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-AFR-01"
    KSI_NAME = "Minimum Assessment Scope"
    KSI_STATEMENT = """Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the scope of the cloud service offering to be assessed for FedRAMP authorization and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = []
    CODE_DETECTABLE = False
    IMPLEMENTATION_STATUS = "NOT_IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-AFR-01 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the sc...
        """
        findings = []
        
        # TODO: Implement Python-specific detection logic
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-AFR-01 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the sc...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-01 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the sc...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-01 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the sc...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-01 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the sc...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-01 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Apply the FedRAMP Minimum Assessment Scope (MAS) to identify and document the sc...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-AFR-01.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Minimum Assessment Scope",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "implementation_effort": "medium",
            "azure_services": [
                {
                    "service": "Azure Policy",
                    "purpose": "Enforce FedRAMP scope tagging and track compliance",
                    "configuration": "Create policy definition requiring 'FedRAMP-Scope' and 'Impact-Level' tags on all resources. Assign policy at subscription or management group level. Configure compliance reporting dashboard."
                },
                {
                    "service": "Azure Resource Graph",
                    "purpose": "Query and inventory all in-scope Azure resources",
                    "configuration": "Use KQL queries to filter resources by FedRAMP scope tags. Export results to CSV/JSON for evidence artifacts. Schedule queries via Azure Automation runbooks."
                },
                {
                    "service": "Azure Monitor",
                    "purpose": "Create workbooks documenting assessment boundaries and network architecture",
                    "configuration": "Design workbooks with sections for resource inventory, network diagrams, data flows, and external connections. Integrate with Resource Graph and Network Watcher for live data."
                },
                {
                    "service": "Azure DevOps",
                    "purpose": "Version-controlled storage for assessment scope documentation",
                    "configuration": "Create wiki pages documenting FedRAMP assessment scope. Use repos for architecture diagrams and data flow documentation. Enable automated updates from Resource Graph queries."
                },
                {
                    "service": "Microsoft Defender for Cloud",
                    "purpose": "Identify all Azure resources and their security posture within scope",
                    "configuration": "Enable Defender for Cloud at subscription level. Use inventory blade to view all resources. Export inventory data via Azure Resource Graph integration."
                }
            ],
            "collection_methods": [
                {
                    "method": "Azure Policy Compliance Reports",
                    "description": "Generate automated compliance reports showing which resources have proper FedRAMP scope tags. Demonstrates enforcement of assessment boundary controls.",
                    "frequency": "Daily",
                    "data_points": [
                        "Total resources in scope (with FedRAMP-Scope=true tag)",
                        "Non-compliant resources (missing required tags)",
                        "Compliance percentage by subscription and resource group",
                        "New resources added to scope in last 24 hours"
                    ]
                },
                {
                    "method": "Azure Resource Graph Inventory Queries",
                    "description": "Use KQL queries to export comprehensive inventory of all in-scope Azure resources, grouped by type and location. Provides evidence of complete assessment scope coverage.",
                    "frequency": "Daily",
                    "data_points": [
                        "Resource name, type, location, resource group",
                        "FedRAMP scope tag values",
                        "Impact level classification",
                        "Subscription ID and hierarchy"
                    ]
                },
                {
                    "method": "Azure Monitor Workbooks",
                    "description": "Interactive workbooks documenting assessment boundaries, network architecture, data flows, and external connections. Provides visual evidence of system boundaries.",
                    "frequency": "Weekly (or after architecture changes)",
                    "data_points": [
                        "Network topology diagrams",
                        "Data flow maps showing internal/external connections",
                        "Resource inventory by service type",
                        "External integration points and APIs"
                    ]
                },
                {
                    "method": "Azure DevOps Version-Controlled Documentation",
                    "description": "Maintain assessment scope documentation in Azure DevOps wiki and repos with full version history. Demonstrates controlled change management for scope updates.",
                    "frequency": "Monthly (or after scope changes)",
                    "data_points": [
                        "Assessment scope definition document",
                        "System architecture diagrams",
                        "Change history and approvals",
                        "Automated updates from Resource Graph queries"
                    ]
                }
            ],
            "implementation_steps": [
                "1. Tag all in-scope Azure resources with 'FedRAMP-Scope: true' and 'Impact-Level: Moderate/High'",
                "2. Create Azure Policy to enforce scope tagging on new resources",
                "3. Build Azure Resource Graph queries to generate resource inventory filtered by scope tags",
                "4. Design Azure Monitor workbook with sections: (a) Resource inventory by service type, (b) Network boundary diagrams, (c) Data flow maps, (d) External connections",
                "5. Store assessment scope documentation in Azure DevOps wiki with automated updates from Resource Graph",
                "6. Generate assessment scope evidence package monthly via Azure Automation runbook"
            ],
            "evidence_artifacts": [
                "Resource inventory report showing all in-scope Azure resources with tags",
                "Network architecture diagram from Azure Monitor workbook",
                "Data flow documentation exported from DevOps wiki",
                "Azure Policy compliance report for scope tagging enforcement",
                "Assessment boundary definition document with version history"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team / System Owner"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Get all in-scope resources by tag",
                "query": """Resources
| where tags['FedRAMP-Scope'] == 'true'
| project name, type, location, resourceGroup, subscriptionId, tags
| order by type asc""",
                "purpose": "Generate resource inventory for assessment scope documentation"
            },
            {
                "query_type": "Azure Policy KQL",
                "query_name": "Scope tagging compliance report",
                "query": """PolicyResources
| where type == 'microsoft.policyinsights/policystates'
| where properties.policyDefinitionName contains 'FedRAMP-Scope-Tagging'
| summarize NonCompliantResources = countif(properties.complianceState == 'NonCompliant'), CompliantResources = countif(properties.complianceState == 'Compliant') by subscriptionId""",
                "purpose": "Verify all resources are properly tagged for scope tracking"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Network boundary connections",
                "query": """AzureNetworkAnalytics_CL
| where SubType_s == 'FlowLog'
| where (DestPublicIPs_s != '' or SrcPublicIPs_s != '')
| summarize ConnectionCount = count() by SrcIP_s, DestIP_s, DestPort_d, AllowedOutFlows_d
| where ConnectionCount > 0
| order by ConnectionCount desc""",
                "purpose": "Document external network connections at assessment boundary"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Azure services in scope",
                "query": """Resources
| where tags['FedRAMP-Scope'] == 'true'
| summarize ResourceCount = count() by type
| order by ResourceCount desc""",
                "purpose": "Identify all Azure service types included in assessment scope"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Retrieve scope documentation history",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wiki/wikis/{wikiId}/pages?path=/FedRAMP/AssessmentScope&includeContent=true&api-version=7.0",
                "purpose": "Access version-controlled assessment scope documentation with change history"
            }
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect.
        
        Returns:
            List of artifact dictionaries
        """
        return [
            {
                "artifact_name": "Resource Inventory Report",
                "artifact_type": "Azure Resource Graph Export",
                "description": "Comprehensive list of all Azure resources in assessment scope with tags, resource groups, and service types",
                "collection_method": "Azure Resource Graph query exported to CSV/JSON via Azure Automation runbook",
                "storage_location": "Azure Storage Account with immutable blob storage for evidence retention"
            },
            {
                "artifact_name": "Network Architecture Diagram",
                "artifact_type": "Azure Monitor Workbook",
                "description": "Visual representation of network boundaries, VNets, subnets, NSGs, and external connections",
                "collection_method": "Azure Monitor workbook exported as PDF via Azure Logic App",
                "storage_location": "Azure DevOps artifacts repository with version tracking"
            },
            {
                "artifact_name": "Assessment Scope Document",
                "artifact_type": "Markdown Documentation",
                "description": "Formal definition of assessment boundaries, included/excluded components, and justifications",
                "collection_method": "Azure DevOps wiki page exported with version history",
                "storage_location": "Azure Repos Git repository with branch protection and audit log"
            },
            {
                "artifact_name": "Scope Tagging Compliance Report",
                "artifact_type": "Azure Policy Report",
                "description": "Policy compliance status showing all resources properly tagged for scope identification",
                "collection_method": "Azure Policy compliance API exported via PowerShell script in Azure Automation",
                "storage_location": "Azure Log Analytics workspace with 12-month retention"
            },
            {
                "artifact_name": "Data Flow Maps",
                "artifact_type": "Network Flow Logs Analysis",
                "description": "Documentation of data flows between in-scope components and external systems",
                "collection_method": "Azure Network Watcher flow logs analyzed with Azure Monitor workbook",
                "storage_location": "Azure Storage Account with network flow logs retention policy"
            }
        ]
    

