"""
KSI-PIY-04: CISA Secure By Design

Monitor the effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-04: CISA Secure By Design
    
    **Official Statement:**
    Monitor the effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-5
    - au-3.3
    - cm-3.4
    - pl-8
    - pm-7
    - sa-3
    - sa-8
    - sc-4
    - sc-18
    - si-10
    - si-11
    - si-16
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Monitor the effectiveness of building security and privacy considerations into the Software Developm...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-PIY-04"
    KSI_NAME = "CISA Secure By Design"
    KSI_STATEMENT = """Monitor the effectiveness of building security and privacy considerations into the Software Development Lifecycle and aligning with CISA Secure By Design principles."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-5", "Separation of Duties"),
        ("au-3.3", "Limit Personally Identifiable Information Elements"),
        ("cm-3.4", "Security and Privacy Representatives"),
        ("pl-8", "Security and Privacy Architectures"),
        ("pm-7", "Enterprise Architecture"),
        ("sa-3", "System Development Life Cycle"),
        ("sa-8", "Security and Privacy Engineering Principles"),
        ("sc-4", "Information in Shared System Resources"),
        ("sc-18", "Mobile Code"),
        ("si-10", "Information Input Validation"),
        ("si-11", "Error Handling"),
        ("si-16", "Memory Protection")
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
        Analyze Python code for KSI-PIY-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
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
        Analyze C# code for KSI-PIY-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Monitor the effectiveness of building security and privacy considerations into t...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-04 compliance.
        
        Detects:
        - Missing security gates in SDLC
        - Missing SAST/DAST integration
        - Missing secure by design practices
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security scanning integration
        has_sast = bool(re.search(r'(codeql|sonar|semgrep|snyk.*code)', code, re.IGNORECASE))
        has_dast = bool(re.search(r'(zap|burp|dast|dynamic.*scan)', code, re.IGNORECASE))
        has_security_gate = bool(re.search(r'(security.*(gate|check|review)|break.*build)', code, re.IGNORECASE))
        has_threat_model = bool(re.search(r'threat.*(model|analysis)', code, re.IGNORECASE))
        
        if not has_sast:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing SAST integration",
                description="No static application security testing (SAST) detected. KSI-PIY-04 requires security built into SDLC per CISA Secure By Design.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add SAST: - name: CodeQL Analysis\n  uses: github/codeql-action/analyze@v2"
            ))
        
        if not has_security_gate:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing security gate",
                description="No security gate to prevent insecure code from progressing. CISA Secure By Design requires security checks in SDLC.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add security gate: if: steps.security-scan.outputs.vulnerabilities > 0\n  run: exit 1"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "CISA Secure By Design",
            "evidence_type": "code-based",
            "automation_feasibility": "high",
            "azure_services": ["GitHub Advanced Security", "Azure DevOps", "Microsoft Defender for Cloud", "Power BI", "Azure Monitor"],
            "collection_methods": [
                "GitHub Advanced Security to enforce Secure By Design principles with SAST (CodeQL), SCA (Dependabot), and secret scanning in CI/CD",
                "Azure DevOps Secure Development Lifecycle (SDL) templates with mandatory security gates (SAST, DAST, SCA) before production",
                "Microsoft Defender for Cloud to validate secure-by-default configurations in Azure resources (e.g., HTTPS-only, TLS 1.2+, private endpoints)",
                "Power BI to track SDL metrics: Security gate pass rates, vulnerability remediation velocity, SDL training completion",
                "Azure Monitor to track security tool execution (SAST/DAST/SCA scan frequency, findings trends, remediation time)"
            ],
            "implementation_steps": [
                "1. Enable GitHub Advanced Security in CI/CD: (a) CodeQL SAST scanning on every pull request with required status checks, (b) Dependabot SCA scanning with automatic PRs for vulnerable dependencies, (c) Secret scanning with push protection to prevent credential commits, (d) Require security approvals for critical findings before merge",
                "2. Implement Azure DevOps SDL gates: (a) Pre-deployment gate: SAST scan with zero Critical/High findings, (b) Pre-deployment gate: SCA scan with zero Critical vulnerabilities (CVE), (c) Pre-deployment gate: DAST scan with zero Critical web vulnerabilities (OWASP Top 10), (d) Track gate failures and remediation time",
                "3. Enforce Defender secure-by-default configs: (a) Policy: Require HTTPS-only for App Services and Storage Accounts, (b) Policy: Require TLS 1.2+ for all services, (c) Policy: Require private endpoints for PaaS services, (d) Policy: Require managed identity (no connection strings/keys in code), (e) Generate monthly secure config compliance report",
                "4. Build Power BI SDL Metrics Dashboard: (a) Security gate pass rates by service (target >= 95%), (b) Vulnerability remediation velocity: Time from detection to fix (target < 30 days for Critical), (c) SDL training completion rate (target 100% annually), (d) Secure-by-default configuration compliance (target >= 99%)",
                "5. Track with Azure Monitor: (a) Log security tool executions (CodeQL, Dependabot, DAST scan frequency), (b) Track findings trends (new vulnerabilities detected, remediated, open), (c) Alert on security gate failures or stale vulnerabilities (> 90 days open), (d) Generate quarterly SDL effectiveness report",
                "6. Generate quarterly evidence package: (a) Export GitHub Security scan results (SAST, SCA, secrets), (b) Export Azure DevOps SDL gate metrics (pass/fail rates), (c) Export Defender secure config compliance report, (d) Export Power BI SDL dashboard showing >= 95% security gate compliance"
            ],
            "evidence_artifacts": [
                "GitHub Advanced Security Scan Results: SAST (CodeQL), SCA (Dependabot), and secret scanning findings with remediation tracking",
                "Azure DevOps SDL Gate Metrics: Security gate pass/fail rates (SAST, SCA, DAST) with remediation velocity tracking",
                "Microsoft Defender Secure-by-Default Configuration Report: HTTPS-only, TLS 1.2+, private endpoints, managed identity compliance",
                "Power BI SDL Metrics Dashboard: Security gate compliance (>= 95%), remediation velocity (< 30d for Critical), training completion (100%)",
                "Azure Monitor Security Tool Execution Report: SAST/SCA/DAST scan frequency, findings trends, and remediation time tracking"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "DevSecOps Team / Application Security"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "GitHub REST API", "query_name": "Advanced Security scan results", "query": "GET https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts?state=open&tool_name=CodeQL\\nGET https://api.github.com/repos/{owner}/{repo}/dependabot/alerts?state=open\\nGET https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts?state=open", "purpose": "Retrieve GitHub Security scan results: CodeQL SAST findings, Dependabot SCA vulnerabilities, secret scanning alerts"},
            {"query_type": "Azure DevOps REST API", "query_name": "SDL gate pass/fail metrics", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/build/builds?api-version=7.0&statusFilter=completed\\nBody: Filter for builds with security gates (SAST, SCA, DAST) and calculate pass/fail rates", "purpose": "Retrieve DevOps pipeline builds with security gate results (pass/fail) and remediation tracking"},
            {"query_type": "Microsoft Defender for Cloud REST API", "query_name": "Secure-by-default configuration compliance", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2021-06-01&$filter=contains(properties/displayName, 'HTTPS-only') or contains(properties/displayName, 'TLS') or contains(properties/displayName, 'private endpoint')", "purpose": "Retrieve Defender assessments for secure-by-default configurations (HTTPS-only, TLS 1.2+, private endpoints)"},
            {"query_type": "Power BI REST API", "query_name": "SDL metrics and remediation velocity", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(SDLMetrics, SDLMetrics[ServiceName], 'TotalBuilds', COUNT(SDLMetrics[BuildID]), 'SecurityGatePassed', COUNTIF(SDLMetrics[SecurityGateStatus] = 'Pass'), 'AvgRemediationDays', AVERAGE(SDLMetrics[RemediationDays]), 'TrainingComplete', COUNTIF(SDLMetrics[SDLTrainingComplete] = TRUE))\\\"}]}", "purpose": "Calculate SDL metrics: Security gate pass rates (>= 95%), remediation velocity (< 30d for Critical), training completion (100%)"},
            {"query_type": "Azure Monitor KQL", "query_name": "Security tool execution and findings trends", "query": "AzureDevOpsPipelines\n| where PipelineName contains 'Security' or PipelineName contains 'SAST' or PipelineName contains 'SCA'\n| extend ToolType = case(PipelineName contains 'SAST', 'SAST', PipelineName contains 'SCA', 'SCA', PipelineName contains 'DAST', 'DAST', 'Other')\n| summarize TotalScans = count(), CriticalFindings = sumif(FindingCount, Severity == 'Critical'), HighFindings = sumif(FindingCount, Severity == 'High'), AvgRemediationDays = avg(RemediationDays) by ToolType, bin(TimeGenerated, 30d)", "purpose": "Track security tool execution frequency, findings trends, and remediation velocity for SDL effectiveness"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "GitHub Advanced Security Scan Results", "artifact_type": "Code Security Scan Reports", "description": "Complete scan results: CodeQL SAST findings, Dependabot SCA vulnerabilities (CVE IDs), secret scanning alerts with remediation status", "collection_method": "GitHub REST API to export code-scanning, dependabot, and secret-scanning alerts", "storage_location": "GitHub Security tab with historical scan results and automated remediation PRs"},
            {"artifact_name": "DevOps SDL Gate Metrics", "artifact_type": "Security Gate Compliance Report", "description": "SDL gate pass/fail rates (SAST, SCA, DAST) with target >= 95%, remediation velocity (< 30d for Critical), and gate failure root causes", "collection_method": "Azure DevOps REST API to export pipeline builds with security gate results and remediation tracking", "storage_location": "Azure DevOps analytics database with quarterly SDL compliance reports"},
            {"artifact_name": "Defender Secure-by-Default Configuration Report", "artifact_type": "Infrastructure Security Compliance", "description": "Compliance report for secure-by-default configurations: HTTPS-only, TLS 1.2+, private endpoints, managed identity (target >= 99%)", "collection_method": "Microsoft Defender for Cloud REST API to export secure configuration assessments", "storage_location": "Azure Storage Account with monthly secure config compliance snapshots"},
            {"artifact_name": "Power BI SDL Metrics Dashboard", "artifact_type": "SDL Effectiveness Dashboard", "description": "Dashboard showing security gate pass rates (>= 95%), remediation velocity (< 30d Critical), SDL training completion (100%), and secure config compliance (>= 99%)", "collection_method": "Power BI REST API to export SDL metrics for executive reporting", "storage_location": "SharePoint with quarterly PDF snapshots for CISO review"},
            {"artifact_name": "Azure Monitor Security Tool Execution Report", "artifact_type": "Tool Execution and Trends Report", "description": "Report tracking SAST/SCA/DAST scan frequency, findings trends (new/remediated/open), and remediation velocity over time", "collection_method": "Azure Monitor KQL query analyzing pipeline execution logs and security findings", "storage_location": "Azure Log Analytics workspace with quarterly SDL effectiveness summaries"}
        ]
    
