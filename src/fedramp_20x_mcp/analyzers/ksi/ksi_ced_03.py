"""
KSI-CED-03: Development and Engineering Education

Require and monitor the effectiveness of role-specific training provided to development and engineering staff that covers best practices for delivering secure software.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CED_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CED-03: Development and Engineering Education
    
    **Official Statement:**
    Require and monitor the effectiveness of role-specific training provided to development and engineering staff that covers best practices for delivering secure software.
    
    **Family:** CED - Cybersecurity Education
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cp-3
    - ir-2
    - ps-6
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Require and monitor the effectiveness of role-specific training provided to development and engineer...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CED-03"
    KSI_NAME = "Development and Engineering Education"
    KSI_STATEMENT = """Require and monitor the effectiveness of role-specific training provided to development and engineering staff that covers best practices for delivering secure software."""
    FAMILY = "CED"
    FAMILY_NAME = "Cybersecurity Education"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cp-3", "Contingency Training"),
        ("ir-2", "Incident Response Training"),
        ("ps-6", "Access Agreements")
    ]
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
        Analyze Python code for KSI-CED-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
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
        Analyze C# code for KSI-CED-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CED-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CED-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CED-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CED-03 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Require and monitor the effectiveness of role-specific training provided to deve...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CED-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CED-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CED-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-CED-03.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Development and Engineering Education",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Viva Learning",
                "GitHub Advanced Security",
                "Azure DevOps",
                "Microsoft Dataverse",
                "Power Automate"
            ],
            "collection_methods": [
                "GitHub Advanced Security or Azure DevOps security scanning to identify code vulnerabilities and trigger remediation training",
                "Microsoft Viva Learning to assign secure coding training (OWASP Top 10, secure SDLC, secrets management)",
                "Power Automate to trigger training when developers commit code with security findings (SQL injection, XSS, secrets)",
                "Microsoft Dataverse to track developer training completion and correlate with code quality metrics (reduced vulnerabilities)",
                "Azure DevOps pull request policies to require secure coding training completion before merge approval"
            ],
            "implementation_steps": [
                "1. Integrate GitHub Advanced Security with Viva Learning: (a) Configure CodeQL, Dependabot, and secret scanning, (b) Create Power Automate flow triggered by HIGH/CRITICAL security findings, (c) Assign OWASP Top 10 training to developers with vulnerable code, (d) Block PR merges until training completed (optional)",
                "2. Create secure coding curriculum in Viva Learning: (a) OWASP Top 10 Web Application Security Risks, (b) Secure SDLC and Threat Modeling, (c) Secrets Management and Key Vault best practices, (d) Container Security and Supply Chain Security, (e) Cloud Security Misconfigurations (Azure, AWS, GCP)",
                "3. Build Microsoft Dataverse Developer Training Table: (a) Columns: DeveloperID, VulnerabilityType, TrainingAssignedDate, CompletionDate, QuizScore, VulnerabilitiesBeforeTraining, VulnerabilitiesAfterTraining, (b) Automate record creation on security finding detection, (c) Track vulnerability reduction post-training",
                "4. Configure Azure DevOps branch policies with training gates: (a) Require 'SecureCodingTrainingCompleted' status check on PRs, (b) Query Viva Learning API to validate training completion, (c) Auto-assign training if developer has open security findings, (d) Track training completion time (target: 7 days)",
                "5. Create Power BI Secure Coding Training Dashboard: (a) Training completion rates by developer and team, (b) Vulnerability trends before and after training, (c) Most common vulnerability types triggering training, (d) Training effectiveness (reduction in repeat vulnerabilities), (e) Time to complete training after vulnerability detection",
                "6. Generate quarterly evidence package: (a) Export Dataverse developer training records with vulnerability correlation, (b) Export GitHub/DevOps security scan results showing vulnerability reduction post-training, (c) Export Viva Learning secure coding course completions, (d) Export Power BI dashboard demonstrating training effectiveness (>= 30% vulnerability reduction)"
            ],
            "evidence_artifacts": [
                "GitHub Advanced Security / Azure DevOps Scanning Results showing developer training assignments triggered by vulnerabilities",
                "Microsoft Viva Learning Secure Coding Training Completion Report for all developers and engineers",
                "Microsoft Dataverse Developer Training Records with vulnerability correlation (before/after training metrics)",
                "Azure DevOps Pull Request Policies requiring secure coding training completion before merge approval",
                "Power BI Secure Coding Training Effectiveness Dashboard showing >= 30% reduction in vulnerabilities post-training"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Engineering Managers / Application Security Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "GitHub REST API",
                "query_name": "Security scanning results triggering developer training",
                "query": "GET https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts?state=open&severity=critical,high",
                "purpose": "Retrieve HIGH/CRITICAL code scanning alerts that trigger secure coding training assignments"
            },
            {
                "query_type": "Microsoft Graph API",
                "query_name": "Viva Learning secure coding training completions",
                "query": "GET https://graph.microsoft.com/v1.0/users/{userId}/learning/courseActivities?$filter=courseType eq 'SecureCoding' and status eq 'completed'",
                "purpose": "Retrieve secure coding training completion records for developers and engineers"
            },
            {
                "query_type": "Microsoft Dataverse Web API",
                "query_name": "Developer training records with vulnerability correlation",
                "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/developer_training_records?$select=developerid,vulnerabilitytype,completiondate,vulnerabilitiesbeforetraining,vulnerabilitiesaftertraining&$filter=completiondate ge {quarterStartDate}",
                "purpose": "Retrieve quarterly developer training records with before/after vulnerability metrics"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Pull request policies with secure coding training gates",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/policy/configurations?api-version=7.0&$filter=type eq 'StatusCheckPolicy'",
                "purpose": "Retrieve PR policies requiring 'SecureCodingTrainingCompleted' status check before merge"
            },
            {
                "query_type": "Power BI REST API",
                "query_name": "Training effectiveness metrics (vulnerability reduction)",
                "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(DeveloperTrainingRecords, DeveloperTrainingRecords[VulnerabilityType], 'AvgVulnerabilitiesBeforeTraining', AVERAGE(DeveloperTrainingRecords[VulnerabilitiesBeforeTraining]), 'AvgVulnerabilitiesAfterTraining', AVERAGE(DeveloperTrainingRecords[VulnerabilitiesAfterTraining]), 'ReductionRate', (AVERAGE(DeveloperTrainingRecords[VulnerabilitiesBeforeTraining]) - AVERAGE(DeveloperTrainingRecords[VulnerabilitiesAfterTraining])) / AVERAGE(DeveloperTrainingRecords[VulnerabilitiesBeforeTraining]))\\\"}]}",
                "purpose": "Calculate vulnerability reduction rates by type after secure coding training (target >= 30% reduction)"
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
                "artifact_name": "GitHub/DevOps Security Scanning Results with Training Triggers",
                "artifact_type": "Security Scan Export",
                "description": "Code scanning alerts (CodeQL, Dependabot, secret scanning) showing vulnerabilities that triggered developer training",
                "collection_method": "GitHub REST API to retrieve HIGH/CRITICAL alerts and correlate with Power Automate training assignments",
                "storage_location": "Azure Storage Account with quarterly exports showing security findings and training correlation"
            },
            {
                "artifact_name": "Viva Learning Secure Coding Training Completion Report",
                "artifact_type": "Microsoft Graph API Export",
                "description": "Training completion records for OWASP Top 10, secure SDLC, secrets management, and container security courses",
                "collection_method": "Microsoft Graph API to retrieve secure coding course activities from Viva Learning",
                "storage_location": "Azure Storage Account with CSV exports organized by developer and course type"
            },
            {
                "artifact_name": "Dataverse Developer Training Records with Vulnerability Metrics",
                "artifact_type": "Microsoft Dataverse Export",
                "description": "Training records with before/after vulnerability counts demonstrating training effectiveness",
                "collection_method": "Microsoft Dataverse Web API to export developer_training_records with vulnerability correlation",
                "storage_location": "Azure Storage Account with JSON exports showing training impact on code quality"
            },
            {
                "artifact_name": "Azure DevOps Pull Request Policies with Training Gates",
                "artifact_type": "Policy Configuration Export",
                "description": "Branch protection policies requiring secure coding training completion before PR merge approval",
                "collection_method": "Azure DevOps REST API to retrieve StatusCheckPolicy configurations with 'SecureCodingTrainingCompleted' requirement",
                "storage_location": "Azure DevOps configuration database with policy exports for compliance auditing"
            },
            {
                "artifact_name": "Power BI Training Effectiveness Dashboard",
                "artifact_type": "Power BI Report",
                "description": "Dashboard showing vulnerability reduction >= 30% post-training, completion rates, and repeat vulnerability trends",
                "collection_method": "Power BI REST API to export dashboard metrics demonstrating measurable improvement in code security",
                "storage_location": "SharePoint with quarterly PDF snapshots for security leadership and FedRAMP evidence"
            }
        ]
    
