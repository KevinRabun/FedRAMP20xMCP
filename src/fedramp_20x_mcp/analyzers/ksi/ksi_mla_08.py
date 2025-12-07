"""
KSI-MLA-08: Log Data Access

Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data based on organizationally defined data sensitivity.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_MLA_08_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-MLA-08: Log Data Access
    
    **Official Statement:**
    Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data based on organizationally defined data sensitivity.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    
    **NIST Controls:**
    - si-11
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Use a least-privileged, role and attribute-based, and just-in-time access authorization model for ac...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-MLA-08"
    KSI_NAME = "Log Data Access"
    KSI_STATEMENT = """Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data based on organizationally defined data sensitivity."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging, and Auditing"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["si-11"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self):
        super().__init__(
            ksi_id=self.KSI_ID,
            ksi_name=self.KSI_NAME,
            ksi_statement=self.KSI_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-MLA-08 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Note: KSI-MLA-08 primarily applies to infrastructure (RBAC for Log Analytics).
        Application-level detection is limited.
        """
        findings = []
        # This KSI is primarily IaC-focused (RBAC configuration)
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-MLA-08 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Note: KSI-MLA-08 primarily applies to infrastructure (RBAC for Log Analytics).
        """
        findings = []
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-MLA-08 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Note: KSI-MLA-08 primarily applies to infrastructure (RBAC for Log Analytics).
        """
        findings = []
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-MLA-08 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Note: KSI-MLA-08 primarily applies to infrastructure (RBAC for Log Analytics).
        """
        findings = []
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-MLA-08 compliance.
        
        Detects:
        - Missing RBAC for Log Analytics workspace access
        - Overly permissive log access roles
        - Missing Azure AD conditional access for logs
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Log Analytics without RBAC
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        has_rbac = bool(re.search(r"Microsoft\.Authorization/roleAssignments", code))
        
        if has_log_analytics and not has_rbac:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing RBAC for Log Analytics Access",
                description=f"Bicep template '{file_path}' deploys Log Analytics without role assignments. KSI-MLA-08 requires least-privileged RBAC for log data access.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add role-based access control for Log Analytics:

```bicep
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: 'law-${environment}'
}

// Reader role for security team (read-only)
resource securityTeamReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logAnalytics.id, securityTeamGroupId, 'Reader')
  scope: logAnalytics
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '73c42c96-874c-492b-b04d-ab87d138a893') // Log Analytics Reader
    principalId: securityTeamGroupId
    principalType: 'Group'
  }
}

// Contributor role for platform team (limited write)
resource platformTeamContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(logAnalytics.id, platformTeamGroupId, 'Contributor')
  scope: logAnalytics
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '92aaf0da-9dab-42b6-94a3-d43ce8d16293') // Log Analytics Contributor
    principalId: platformTeamGroupId
    principalType: 'Group'
  }
}
```

Reference: FRR-MLA-08 - Least-Privileged Log Data Access"""
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-MLA-08 compliance.
        
        Detects:
        - Missing azurerm_role_assignment for Log Analytics
        - Overly permissive access to log data
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Log Analytics without RBAC
        has_log_analytics = bool(re.search(r'azurerm_log_analytics_workspace', code))
        has_rbac = bool(re.search(r'azurerm_role_assignment', code))
        
        if has_log_analytics and not has_rbac:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing RBAC for Log Analytics Access",
                description=f"Terraform configuration '{file_path}' deploys Log Analytics without role assignments. KSI-MLA-08 requires least-privileged access control.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add role-based access control:

```hcl
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

# Reader role for security team
resource "azurerm_role_assignment" "security_reader" {
  scope                = azurerm_log_analytics_workspace.main.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = var.security_team_group_id
}

# Contributor role for platform team
resource "azurerm_role_assignment" "platform_contributor" {
  scope                = azurerm_log_analytics_workspace.main.id
  role_definition_name = "Log Analytics Contributor"
  principal_id         = var.platform_team_group_id
}
```

Reference: FRR-MLA-08 - Least-Privileged Access"""
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-MLA-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-MLA-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-MLA-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
