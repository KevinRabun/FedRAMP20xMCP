"""
KSI-AFR-05: Significant Change Notifications

Determine how significant changes will be tracked and how all necessary parties will be notified in alignment with the FedRAMP Significant Change Notifications (SCN) process and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_05_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-05: Significant Change Notifications
    
    **Official Statement:**
    Determine how significant changes will be tracked and how all necessary parties will be notified in alignment with the FedRAMP Significant Change Notifications (SCN) process and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ca-7.4
    - cm-3.4
    - cm-4
    - cm-7.1
    - au-5
    - ca-5
    - ca-7
    - ra-5
    - ra-5.2
    - sa-22
    - si-2
    - si-2.2
    - si-3
    - si-5
    - si-7.7
    - si-10
    - si-11
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-AFR-05"
    KSI_NAME = "Significant Change Notifications"
    KSI_STATEMENT = """Determine how significant changes will be tracked and how all necessary parties will be notified in alignment with the FedRAMP Significant Change Notifications (SCN) process and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ca-7.4", "Risk Monitoring"),
        ("cm-3.4", "Security and Privacy Representatives"),
        ("cm-4", "Impact Analyses"),
        ("cm-7.1", "Periodic Review"),
        ("au-5", "Response to Audit Logging Process Failures"),
        ("ca-5", "Plan of Action and Milestones"),
        ("ca-7", "Continuous Monitoring"),
        ("ra-5", "Vulnerability Monitoring and Scanning"),
        ("ra-5.2", "Update Vulnerabilities to Be Scanned"),
        ("sa-22", "Unsupported System Components"),
        ("si-2", "Flaw Remediation"),
        ("si-2.2", "Automated Flaw Remediation Status"),
        ("si-3", "Malicious Code Protection"),
        ("si-5", "Security Alerts, Advisories, and Directives"),
        ("si-7.7", "Integration of Detection and Response"),
        ("si-10", "Information Input Validation"),
        ("si-11", "Error Handling")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
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
        Analyze Python code for KSI-AFR-05 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how significant changes will be tracked and how all necessary parties ...
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
        Analyze C# code for KSI-AFR-05 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how significant changes will be tracked and how all necessary parties ...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-05 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how significant changes will be tracked and how all necessary parties ...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-05 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Determine how significant changes will be tracked and how all necessary parties ...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-05 compliance.
        
        Detects:
        - Azure Monitor alert rules for change detection
        - Log Analytics queries for vulnerability tracking
        - Action groups for notifications
        """
        findings = []
        lines = code.split('\n')
        
        # Check for monitoring resources
        has_monitor_alerts = 'Microsoft.Insights/metricAlerts' in code or 'Microsoft.Insights/scheduledQueryRules' in code
        has_action_groups = 'Microsoft.Insights/actionGroups' in code
        
        if not has_monitor_alerts:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.MEDIUM,
                title="No Azure Monitor alerts detected",
                description="Bicep should define Azure Monitor alerts for significant change detection and continuous monitoring per ca-7 (Continuous Monitoring).",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add Microsoft.Insights/metricAlerts or Microsoft.Insights/scheduledQueryRules resources to monitor for significant changes.",
                nist_control="ca-7"
            ))
        
        if has_monitor_alerts and not has_action_groups:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.LOW,
                title="Alert rules present but no action groups for notifications",
                description="Azure Monitor alerts should be connected to action groups for stakeholder notifications per si-5 (Security Alerts).",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add Microsoft.Insights/actionGroups resource with email, SMS, or webhook receivers.",
                nist_control="si-5"
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-05 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Determine how significant changes will be tracked and how all necessary parties ...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-05 compliance.
        
        Detects:
        - Security scanning (CodeQL, Snyk, Dependabot)
        - Vulnerability scanning workflows
        - Automated flaw remediation notifications
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security scanning actions
        security_scanners = {
            'github/codeql-action': 'CodeQL security scanning',
            'snyk/actions': 'Snyk vulnerability scanning',
            'aquasecurity/trivy-action': 'Trivy container scanning',
            'anchore/scan-action': 'Anchore container scanning',
            'microsoft/security-devops-action': 'Microsoft Security DevOps'
        }
        
        found_scanners = []
        for i, line in enumerate(lines, 1):
            if 'uses:' in line:
                for scanner, description in security_scanners.items():
                    if scanner in line:
                        found_scanners.append(description)
        
        if not found_scanners:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.MEDIUM,
                title="No automated security scanning detected",
                description="GitHub Actions workflow should include automated security scanning (CodeQL, Snyk, or similar) for change notifications per si-2.2 (Automated Flaw Remediation Status).",
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add security scanning actions like github/codeql-action or snyk/actions to detect vulnerabilities automatically.",
                nist_control="si-2.2"
            ))
        
        # Check for notification mechanisms
        has_notifications = any(
            keyword in code.lower() 
            for keyword in ['slack', 'teams', 'email', 'notify', 'alert', 'webhook']
        )
        
        if found_scanners and not has_notifications:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.LOW,
                title="Security scanning present but no notification mechanism detected",
                description="Workflow has security scanning but lacks explicit notification actions for significant findings per si-5 (Security Alerts, Advisories, and Directives).",
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add notification steps (Slack, Teams, email) to alert stakeholders of significant security findings.",
                nist_control="si-5"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-05 compliance.
        
        Detects:
        - Security scanning tasks (CredScan, Semmle, etc.)
        - Vulnerability assessment tasks
        - Automated compliance checks
        """
        findings = []
        lines = code.split('\n')
        
        # Check for security tasks
        security_tasks = {
            'CredScan': 'Credential scanning',
            'Semmle': 'CodeQL/Semmle security analysis',
            'securityandcompliance': 'Security and compliance scanning',
            'WhiteSource': 'WhiteSource vulnerability scanning',
            'Checkmarx': 'Checkmarx SAST scanning',
            'ContainerScan': 'Container image scanning'
        }
        
        found_tasks = []
        for i, line in enumerate(lines, 1):
            if 'task:' in line.lower():
                for task, description in security_tasks.items():
                    if task.lower() in line.lower():
                        found_tasks.append(description)
        
        if not found_tasks:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                severity=Severity.MEDIUM,
                title="No security scanning tasks detected",
                description="Azure Pipeline should include security scanning tasks (CredScan, Semmle, etc.) for automated vulnerability detection per si-2.2.",
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add security scanning tasks like CredScan@3 or Semmle@1 to detect security issues automatically.",
                nist_control="si-2.2"
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    

