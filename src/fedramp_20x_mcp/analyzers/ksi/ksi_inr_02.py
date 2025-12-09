"""
KSI-INR-02: Incident Logging

Maintain a log of incidents and periodically review past incidents for patterns or vulnerabilities.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_INR_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-INR-02: Incident Logging
    
    **Official Statement:**
    Maintain a log of incidents and periodically review past incidents for patterns or vulnerabilities.
    
    **Family:** INR - Incident Response
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ir-3
    - ir-4
    - ir-4.1
    - ir-5
    - ir-8
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Maintain a log of incidents and periodically review past incidents for patterns or vulnerabilities....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-INR-02"
    KSI_NAME = "Incident Logging"
    KSI_STATEMENT = """Maintain a log of incidents and periodically review past incidents for patterns or vulnerabilities."""
    FAMILY = "INR"
    FAMILY_NAME = "Incident Response"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ir-3", "Incident Response Testing"),
        ("ir-4", "Incident Handling"),
        ("ir-4.1", "Automated Incident Handling Processes"),
        ("ir-5", "Incident Monitoring"),
        ("ir-8", "Incident Response Plan")
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
        Analyze Python code for KSI-INR-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Maintain a log of incidents and periodically review past incidents for patterns ...
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
        Analyze C# code for KSI-INR-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Maintain a log of incidents and periodically review past incidents for patterns ...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-INR-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Maintain a log of incidents and periodically review past incidents for patterns ...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-INR-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Maintain a log of incidents and periodically review past incidents for patterns ...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-INR-02 compliance.
        
        Detects:
        - Missing incident tracking resources
        - Missing Azure Monitor alerts for incidents
        - Missing Log Analytics for incident logging
        """
        findings = []
        lines = code.split('\n')
        
        # Check for alert rules (incident detection)
        has_alert_rules = bool(re.search(r"Microsoft\.Insights/(metricAlerts|scheduledQueryRules)", code))
        if not has_alert_rules:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Incident Detection Alerts",
                description=f"Bicep template '{file_path}' does not configure Azure Monitor alerts for incident detection. KSI-INR-02 requires automated incident logging.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add Azure Monitor alerts for incident detection:

```bicep
resource securityAlert 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'security-incident-alert'
  location: location
  properties: {
    displayName: 'Security Incident Detection'
    description: 'Detects security incidents for logging'
    severity: 1  // Critical
    enabled: true
    evaluationFrequency: 'PT5M'
    scopes: [
      logAnalytics.id
    ]
    targetResourceTypes: [
      'Microsoft.OperationalInsights/workspaces'
    ]
    criteria: {
      allOf: [
        {
          query: '''
            SecurityEvent
            | where EventID in (4625, 4648, 4719, 4732)
            | summarize Count=count() by Computer, EventID, bin(TimeGenerated, 5m)
            | where Count > 5
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}
```

Reference: FRR-INR-02 - Incident Logging"""
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-INR-02 compliance.
        
        Detects:
        - Missing azurerm_monitor_scheduled_query_rules_alert
        - Missing incident tracking resources
        """
        findings = []
        lines = code.split('\n')
        
        # Check for alert rules
        has_alerts = bool(re.search(r'azurerm_monitor_(metric_alert|scheduled_query_rules_alert)', code))
        if not has_alerts:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Incident Detection Alerts",
                description=f"Terraform configuration '{file_path}' lacks Azure Monitor alerts for incident detection. KSI-INR-02 requires incident logging.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add Azure Monitor alerts:

```hcl
resource "azurerm_monitor_scheduled_query_rules_alert" "security_incident" {
  name                = "security-incident-detection"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  
  action {
    action_group = [azurerm_monitor_action_group.main.id]
  }
  
  data_source_id = azurerm_log_analytics_workspace.main.id
  description    = "Detects security incidents"
  enabled        = true
  
  query       = <<-QUERY
    SecurityEvent
    | where EventID in (4625, 4648, 4719, 4732)
    | summarize Count=count() by Computer, EventID, bin(TimeGenerated, 5m)
    | where Count > 5
  QUERY
  severity    = 1
  frequency   = 5
  time_window = 5
  
  trigger {
    operator  = "GreaterThan"
    threshold = 0
  }
}
```

Reference: FRR-INR-02"""
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-INR-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-INR-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-INR-02 compliance.
        
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
