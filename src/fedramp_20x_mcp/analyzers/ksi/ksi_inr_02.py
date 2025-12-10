"""
KSI-INR-02: Incident Logging

Maintain a log of incidents and periodically review past incidents for patterns or vulnerabilities.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
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

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Incident Logging",
            "evidence_type": "log-based",
            "automation_feasibility": "high",
            "azure_services": ["Microsoft Sentinel", "Azure DevOps", "Power BI", "Azure Monitor", "Microsoft Dataverse"],
            "collection_methods": [
                "Microsoft Sentinel incident tracking with automated ticket creation and status updates",
                "Azure DevOps Boards to log incidents with severity classification and root cause analysis",
                "Power BI to analyze incident patterns (frequency by type, MTTR, recurring vulnerabilities)",
                "Azure Monitor to track incident metrics (response time, resolution time, SLA compliance)",
                "Microsoft Dataverse to centralize incident history with lessons learned and remediation tracking"
            ],
            "implementation_steps": [
                "1. Configure Microsoft Sentinel incident logging: (a) Create automation rules for incident creation from alerts, (b) Enrich incidents with asset data and user context, (c) Set severity classification (Critical/High/Medium/Low/Informational), (d) Track incident lifecycle (New/Active/Resolved/Closed)",
                "2. Integrate Azure DevOps Boards for incident tracking: (a) Create work item template 'Security Incident' with fields: Incident ID, Date/Time, Severity, Affected Systems, Root Cause, Remediation, Lessons Learned, (b) Bi-directional sync with Sentinel incidents, (c) Link to related alerts, logs, and evidence",
                "3. Build Power BI Incident Pattern Analysis Dashboard: (a) Incident frequency trends by type and severity, (b) Mean Time To Detect (MTTD) and Mean Time To Resolve (MTTR), (c) Recurring vulnerabilities and repeat incidents, (d) Incident heatmap by time/day showing attack patterns",
                "4. Create Microsoft Dataverse Incident History Table: (a) Archive closed incidents with full timeline and evidence, (b) Tag incidents with vulnerability types (CVE IDs, MITRE ATT&CK tactics), (c) Link to lessons learned and preventative controls implemented, (d) Enable quarterly pattern reviews",
                "5. Configure Azure Monitor incident metrics: (a) Track SLA compliance for incident response (< 1 hour acknowledgment, < 24 hours resolution), (b) Alert on SLA breaches, (c) Monitor incident volume spikes, (d) Generate executive incident summary reports",
                "6. Generate monthly evidence package: (a) Export Sentinel incident log with full history, (b) Export Power BI pattern analysis showing recurring themes, (c) Export Dataverse lessons learned documentation, (d) Export SLA compliance metrics"
            ],
            "evidence_artifacts": [
                "Microsoft Sentinel Incident Log with timeline, severity, affected systems, and resolution details",
                "Azure DevOps Security Incident Work Items with root cause analysis and remediation tracking",
                "Power BI Incident Pattern Analysis Dashboard showing trends, MTTR, and recurring vulnerabilities",
                "Microsoft Dataverse Incident History Database with lessons learned and preventative controls",
                "Azure Monitor SLA Compliance Report tracking incident response and resolution timelines"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Security Operations Center (SOC) / Incident Response Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Microsoft Sentinel REST API", "query_name": "Incident log with full history", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01", "purpose": "Retrieve complete incident log with timeline, severity, and resolution status"},
            {"query_type": "Azure DevOps REST API", "query_name": "Security incident work items", "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\\nBody: {\\\"query\\\": \\\"SELECT [System.Id], [System.Title], [Custom.IncidentID], [Custom.Severity], [Custom.RootCause], [Custom.LessonsLearned] FROM WorkItems WHERE [System.WorkItemType] = 'Security Incident' ORDER BY [System.CreatedDate] DESC\\\"}", "purpose": "Retrieve incident tracking work items with root cause and lessons learned"},
            {"query_type": "Power BI REST API", "query_name": "Incident pattern analysis metrics", "query": "POST https://api.powerbi.com/v1.0/myorg/datasets/{datasetId}/executeQueries\\nBody: {\\\"queries\\\": [{\\\"query\\\": \\\"EVALUATE SUMMARIZE(IncidentLog, IncidentLog[IncidentType], 'TotalIncidents', COUNT(IncidentLog[IncidentID]), 'AvgMTTR', AVERAGE(IncidentLog[ResolutionTimeHours]))\\\"}]}", "purpose": "Calculate incident frequency and MTTR by incident type to identify patterns"},
            {"query_type": "Microsoft Dataverse Web API", "query_name": "Incident history with lessons learned", "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/incident_history_records?$select=incidentid,severity,rootcause,lessonslearned,preventativecontrols&$filter=closeddate ge {quarterStartDate}", "purpose": "Retrieve archived incidents with documented lessons learned and preventative measures"},
            {"query_type": "Azure Monitor KQL", "query_name": "Incident SLA compliance tracking", "query": "SecurityIncident\n| extend AcknowledgeTime = datetime_diff('hour', FirstModifiedTime, TimeGenerated), ResolutionTime = datetime_diff('hour', ClosedTime, TimeGenerated)\n| summarize TotalIncidents = count(), SLACompliant = countif(AcknowledgeTime <= 1 and ResolutionTime <= 24), SLABreach = countif(AcknowledgeTime > 1 or ResolutionTime > 24) by bin(TimeGenerated, 30d)\n| extend SLAComplianceRate = round((todouble(SLACompliant) / TotalIncidents) * 100, 2)", "purpose": "Track SLA compliance for incident acknowledgment (1 hour) and resolution (24 hours)"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "Sentinel Incident Log", "artifact_type": "Incident Database Export", "description": "Complete incident log with timeline, severity classification, affected systems, and resolution details", "collection_method": "Microsoft Sentinel REST API to export incident history with full metadata", "storage_location": "Azure Storage Account with 7-year retention for FedRAMP audit requirements"},
            {"artifact_name": "DevOps Security Incident Work Items", "artifact_type": "Work Item Export", "description": "Incident tracking work items with root cause analysis, remediation steps, and lessons learned documentation", "collection_method": "Azure DevOps REST API to export Security Incident work items with full history", "storage_location": "Azure DevOps database with bi-directional Sentinel sync"},
            {"artifact_name": "Power BI Incident Pattern Analysis Dashboard", "artifact_type": "Analytics Report", "description": "Dashboard showing incident trends, MTTR by type, recurring vulnerabilities, and attack pattern heatmaps", "collection_method": "Power BI REST API to export pattern analysis metrics and visualizations", "storage_location": "SharePoint with monthly PDF snapshots for trend analysis and executive reporting"},
            {"artifact_name": "Dataverse Incident History Database", "artifact_type": "Archival Database", "description": "Archived incidents with lessons learned, preventative controls implemented, and MITRE ATT&CK mapping", "collection_method": "Microsoft Dataverse Web API to export incident_history_records with quarterly filter", "storage_location": "Microsoft Dataverse with automated backup for long-term incident pattern analysis"},
            {"artifact_name": "Azure Monitor SLA Compliance Report", "artifact_type": "Performance Metrics", "description": "SLA compliance tracking for incident acknowledgment (< 1 hour) and resolution (< 24 hours) with breach alerts", "collection_method": "Azure Monitor KQL query calculating SLA compliance rates and identifying breaches", "storage_location": "Azure Log Analytics workspace with monthly compliance summaries"}
        ]
    
