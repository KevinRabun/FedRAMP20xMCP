"""
KSI-PIY-07: Supply Chain Risk Management

Document risk management decisions for software supply chain security.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_07_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-07: Supply Chain Risk Management
    
    **Official Statement:**
    Document risk management decisions for software supply chain security.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ca-7.4
    - sc-18
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-PIY-07"
    KSI_NAME = "Supply Chain Risk Management"
    KSI_STATEMENT = """Document risk management decisions for software supply chain security."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ca-7.4", "Risk Monitoring"),
        ("sc-18", "Mobile Code")
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
        Analyze Python code for KSI-PIY-07 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Document risk management decisions for software supply chain security....
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
        Analyze C# code for KSI-PIY-07 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Document risk management decisions for software supply chain security....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-07 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Document risk management decisions for software supply chain security....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-07 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Document risk management decisions for software supply chain security....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-07 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document risk management decisions for software supply chain security....
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-07 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document risk management decisions for software supply chain security....
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-07 compliance.
        
        Detects:
        - Missing SBOM generation
        - Missing dependency tracking
        - Missing supply chain security checks
        """
        findings = []
        lines = code.split('\n')
        
        # Check for SBOM and supply chain security
        has_sbom = bool(re.search(r'(sbom|cyclonedx|spdx|syft)', code, re.IGNORECASE))
        has_dependency_review = bool(re.search(r'(dependency.*(review|check)|dependabot)', code, re.IGNORECASE))
        has_artifact_signing = bool(re.search(r'(sign|sigstore|cosign)', code, re.IGNORECASE))
        has_provenance = bool(re.search(r'(provenance|slsa|attestation)', code, re.IGNORECASE))
        
        if not has_sbom:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing SBOM generation",
                description="No Software Bill of Materials (SBOM) generation detected. KSI-PIY-07 requires SBOM for supply chain risk management.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add SBOM generation: - name: Generate SBOM\n  uses: anchore/sbom-action@v0\n  with:\n    format: cyclonedx-json"
            ))
        
        if not has_dependency_review:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing dependency review",
                description="No dependency review process. KSI-PIY-07 requires tracking and reviewing all dependencies for supply chain security.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add dependency review: - name: Dependency Review\n  uses: actions/dependency-review-action@v3"
            ))
        
        if not has_artifact_signing:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing artifact signing",
                description="No artifact signing detected. KSI-PIY-07 supply chain security requires cryptographic signing of build artifacts.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add artifact signing: - name: Sign Artifacts\n  uses: sigstore/cosign-installer@main"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Supply Chain Risk Management",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": ["GitHub Advanced Security", "Azure DevOps", "Microsoft Defender for Cloud", "Microsoft Dataverse", "Power BI"],
            "collection_methods": [
                "GitHub Advanced Security Dependabot to detect vulnerable dependencies (CVE IDs) with automatic remediation PRs",
                "Azure DevOps Boards to track supply chain risk decisions (approve/mitigate/reject) with risk assessment workflows",
                "Microsoft Defender for Cloud supply chain recommendations to assess third-party integrations and API security",
                "Microsoft Dataverse to maintain approved vendor registry with risk assessments and re-evaluation schedules",
                "Power BI to visualize supply chain risk metrics: Vulnerable dependencies, vendor risk ratings, remediation velocity"
            ],
            "implementation_steps": [
                "1. Enable GitHub Dependabot for dependency scanning: (a) Scan all repositories for vulnerable dependencies (npm, NuGet, Maven, pip), (b) Generate automatic remediation PRs for CVEs, (c) Require security approval for high-risk dependencies before merge, (d) Track time-to-remediate (target < 30 days for Critical CVEs)",
                "2. Create Azure DevOps Supply Chain Risk workflow: (a) Work item type 'Supply Chain Risk Decision' with fields: VendorName, RiskType (Dependency/API/Integration), RiskRating (Critical/High/Medium/Low), Decision (Approve/Mitigate/Reject), Mitigation, ReviewDate, (b) Risk assessment template with NIST 800-161 criteria, (c) Require CISO approval for Critical/High risk decisions",
                "3. Assess with Microsoft Defender for Cloud: (a) Defender supply chain recommendations for third-party API integrations, (b) Assess third-party service security posture (authentication, encryption, logging), (c) Validate third-party compliance certifications (SOC 2, ISO 27001, FedRAMP), (d) Track remediation of supply chain recommendations",
                "4. Maintain vendor registry in Microsoft Dataverse: (a) Table: approved_vendors with columns: vendorid, vendorname, serviceprovided, riskscore, compliancecerts, lastsecurityreview, nextreviewdate, (b) Automate annual vendor re-assessment reminders, (c) Flag vendors with expired certifications or overdue reviews",
                "5. Build Power BI Supply Chain Risk Dashboard: (a) Vulnerable dependencies by severity (Critical/High/Medium/Low), (b) Vendor risk distribution (Critical/High/Medium/Low), (c) Remediation velocity (time from CVE detection to fix), (d) Vendor compliance certification status",
                "6. Generate quarterly evidence package: (a) Export GitHub Dependabot alerts and remediation PRs, (b) Export DevOps Supply Chain Risk Decision work items, (c) Export Defender supply chain recommendations, (d) Export Dataverse approved vendor registry, (e) Export Power BI dashboard showing supply chain risk management"
            ],
            "evidence_artifacts": [
                "GitHub Dependabot Alerts and Remediation PRs showing vulnerable dependency detection and remediation velocity (< 30d for Critical)",
                "Azure DevOps Supply Chain Risk Decision Work Items with risk assessments (NIST 800-161) and CISO approval for Critical/High risks",
                "Microsoft Defender Supply Chain Recommendations assessing third-party API security, authentication, and compliance certifications",
                "Microsoft Dataverse Approved Vendor Registry with risk scores, compliance certifications (SOC 2, ISO 27001), and annual re-assessment tracking",
                "Power BI Supply Chain Risk Dashboard visualizing vulnerable dependencies, vendor risk ratings, and remediation velocity metrics"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Supply Chain Risk Manager / CISO"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "GitHub REST API", "query_name": "Dependabot alerts and remediation PRs", "query": "GET https://api.github.com/repos/{owner}/{repo}/dependabot/alerts?state=open\\nGET https://api.github.com/repos/{owner}/{repo}/pulls?head=dependabot", "purpose": "Retrieve Dependabot vulnerable dependency alerts (CVE IDs) and automatic remediation pull requests"},
            {"query_type": "Azure DevOps REST API", "query_name": "Supply chain risk decisions", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\\nBody: {\\\"query\\\": \\\"SELECT [System.Id], [System.Title], [Custom.VendorName], [Custom.RiskType], [Custom.RiskRating], [Custom.Decision], [Custom.Mitigation] FROM WorkItems WHERE [System.WorkItemType] = 'Supply Chain Risk Decision' ORDER BY [Custom.RiskRating] DESC\\\"}", "purpose": "Retrieve supply chain risk decisions with risk assessments (NIST 800-161), CISO approvals, and mitigation strategies"},
            {"query_type": "Microsoft Defender for Cloud REST API", "query_name": "Supply chain security recommendations", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01&$filter=contains(properties/displayName, 'supply chain') or contains(properties/displayName, 'third-party')", "purpose": "Retrieve Defender supply chain recommendations for third-party API integrations and service security"},
            {"query_type": "Microsoft Dataverse Web API", "query_name": "Approved vendor registry with risk scores", "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/approved_vendors?$select=vendorid,vendorname,serviceprovided,riskscore,compliancecerts,lastsecurityreview,nextreviewdate&$orderby=riskscore desc", "purpose": "Retrieve approved vendor registry with risk scores, compliance certifications, and re-assessment schedules"},
            {"query_type": "Power BI REST API", "query_name": "Supply chain risk metrics", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(SupplyChainRisk, SupplyChainRisk[RiskCategory], 'TotalRisks', COUNT(SupplyChainRisk[RiskID]), 'Critical', COUNTIF(SupplyChainRisk[RiskRating] = 'Critical'), 'High', COUNTIF(SupplyChainRisk[RiskRating] = 'High'), 'AvgRemediationDays', AVERAGE(SupplyChainRisk[RemediationDays]))\\\"}]}", "purpose": "Calculate supply chain risk metrics: Vulnerable dependencies, vendor risk distribution, remediation velocity"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "GitHub Dependabot Alerts and Remediation PRs", "artifact_type": "Dependency Vulnerability Report", "description": "Dependabot alerts showing vulnerable dependencies (CVE IDs) with severity and automatic remediation PRs (< 30d for Critical)", "collection_method": "GitHub REST API to export dependabot alerts and remediation pull requests", "storage_location": "GitHub Security tab with historical vulnerability tracking and remediation velocity"},
            {"artifact_name": "DevOps Supply Chain Risk Decisions", "artifact_type": "Risk Decision Registry", "description": "Supply chain risk decisions with NIST 800-161 assessments, risk ratings (Critical/High/Medium/Low), CISO approvals, and mitigation strategies", "collection_method": "Azure DevOps REST API to export Supply Chain Risk Decision work items", "storage_location": "Azure DevOps database with historical risk decisions and approval audit trail"},
            {"artifact_name": "Defender Supply Chain Recommendations", "artifact_type": "Third-Party Security Assessment", "description": "Defender supply chain recommendations for third-party API integrations: authentication, encryption, logging, compliance certifications", "collection_method": "Microsoft Defender for Cloud REST API to export supply chain security assessments", "storage_location": "Azure Storage Account with quarterly supply chain assessment reports"},
            {"artifact_name": "Dataverse Approved Vendor Registry", "artifact_type": "Vendor Risk Database", "description": "Approved vendor registry with risk scores, compliance certifications (SOC 2, ISO 27001, FedRAMP), and annual re-assessment schedules", "collection_method": "Microsoft Dataverse Web API to export approved_vendors with risk and compliance metadata", "storage_location": "Microsoft Dataverse with automated annual re-assessment reminders and expired certification alerts"},
            {"artifact_name": "Power BI Supply Chain Risk Dashboard", "artifact_type": "Risk Metrics Dashboard", "description": "Dashboard showing vulnerable dependencies by severity, vendor risk distribution, remediation velocity (< 30d for Critical), and compliance certification status", "collection_method": "Power BI REST API to export supply chain risk metrics for executive reporting", "storage_location": "SharePoint with quarterly PDF snapshots for CISO and Board of Directors review"}
        ]
    
