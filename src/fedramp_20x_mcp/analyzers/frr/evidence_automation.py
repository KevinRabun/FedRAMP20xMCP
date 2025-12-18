"""
FRR Evidence Automation - Azure-Specific Evidence Collection

Provides production-ready queries and code for automating FRR evidence collection
using Azure services: Log Analytics, Resource Graph, Azure Monitor, and REST APIs.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class EvidenceQuery:
    """Azure query for evidence collection."""
    query_type: str  # "Azure Monitor KQL", "Azure Resource Graph", "PowerShell", "REST API"
    query_name: str
    query: str
    purpose: str
    frequency: str = "daily"  # How often to run
    retention_days: int = 730  # FedRAMP requires 2 years


@dataclass
class EvidenceArtifact:
    """Description of evidence artifact to collect."""
    artifact_name: str
    artifact_type: str  # "JSON", "CSV", "PDF", "Screenshot"
    description: str
    collection_method: str
    storage_location: str
    retention_months: int = 24  # FedRAMP 2 years


@dataclass
class FRREvidenceAutomation:
    """Complete evidence automation recommendations for an FRR."""
    frr_id: str
    frr_name: str
    family: str
    evidence_type: str  # "log-based", "config-based", "process-based", "artifact-based"
    automation_feasibility: str  # "high", "medium", "low"
    azure_services: List[str] = field(default_factory=list)
    collection_methods: List[str] = field(default_factory=list)
    implementation_steps: List[str] = field(default_factory=list)
    queries: List[EvidenceQuery] = field(default_factory=list)
    artifacts: List[EvidenceArtifact] = field(default_factory=list)
    update_frequency: str = "daily"
    responsible_party: str = "Cloud Security Team"
    estimated_effort_hours: int = 0


# =============================================================================
# VDR (Vulnerability Detection and Response) Evidence Queries
# =============================================================================

VDR_EVIDENCE_QUERIES = {
    "FRR-VDR-01": [
        EvidenceQuery(
            query_type="Azure Resource Graph",
            query_name="Defender for Cloud Coverage",
            query="""
securityresources
| where type == "microsoft.security/pricings"
| extend tier = properties.pricingTier
| project subscriptionId, name, tier, freeTrialRemainingTime = properties.freeTrialRemainingTime
| where tier == "Standard"
""",
            purpose="Verify Defender for Cloud is enabled at Standard tier across all subscriptions",
            frequency="daily"
        ),
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Vulnerability Scan Results",
            query="""
SecurityRecommendation
| where RecommendationName contains "vulnerability"
| summarize 
    TotalVulnerabilities = count(),
    Critical = countif(RecommendationSeverity == "High"),
    High = countif(RecommendationSeverity == "Medium"),
    Medium = countif(RecommendationSeverity == "Low")
    by bin(TimeGenerated, 1d), ResourceType
| order by TimeGenerated desc
""",
            purpose="Track vulnerability counts and trends over time",
            frequency="daily"
        ),
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Critical Vulnerability SLA Compliance",
            query="""
SecurityRecommendation
| where RecommendationSeverity == "High"
| where RecommendationState == "Active"
| extend DaysOpen = datetime_diff('day', now(), FirstEvaluationDate)
| where DaysOpen > 15
| project ResourceId, RecommendationName, DaysOpen, FirstEvaluationDate
| order by DaysOpen desc
""",
            purpose="Identify critical vulnerabilities exceeding 15-day SLA (FRR-VDR-01)",
            frequency="daily"
        ),
    ],
    "FRR-VDR-08": [
        EvidenceQuery(
            query_type="Azure Resource Graph",
            query_name="VM Patch Status",
            query="""
resources
| where type == "microsoft.compute/virtualmachines"
| extend 
    patchMode = properties.osProfile.windowsConfiguration.patchSettings.patchMode,
    assessmentMode = properties.osProfile.windowsConfiguration.patchSettings.assessmentMode
| project name, resourceGroup, subscriptionId, patchMode, assessmentMode
| where patchMode != "AutomaticByPlatform" or assessmentMode != "AutomaticByPlatform"
""",
            purpose="Identify VMs without automatic patching configured",
            frequency="daily"
        ),
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Patch Compliance Status",
            query="""
Update
| where TimeGenerated > ago(7d)
| where Classification in ("Critical Updates", "Security Updates")
| summarize 
    MissingCount = countif(UpdateState == "Needed"),
    InstalledCount = countif(UpdateState == "Installed")
    by Computer, Classification
| where MissingCount > 0
| order by MissingCount desc
""",
            purpose="Track patch compliance for critical and security updates",
            frequency="weekly"
        ),
    ],
}


# =============================================================================
# RSC (Recommended Secure Configuration) Evidence Queries
# =============================================================================

RSC_EVIDENCE_QUERIES = {
    "FRR-RSC-01": [
        EvidenceQuery(
            query_type="Azure Resource Graph",
            query_name="Security Baseline Compliance",
            query="""
securityresources
| where type == "microsoft.security/assessments"
| extend 
    status = properties.status.code,
    resourceDetails = properties.resourceDetails
| where status == "Unhealthy"
| project 
    assessmentKey = name,
    displayName = properties.displayName,
    status,
    resourceId = tostring(resourceDetails.Id)
| summarize NonCompliantCount = count() by displayName
| order by NonCompliantCount desc
| take 20
""",
            purpose="Identify top security baseline violations across resources",
            frequency="daily"
        ),
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Configuration Drift Detection",
            query="""
AzureActivity
| where OperationNameValue contains "write" or OperationNameValue contains "delete"
| where ActivityStatusValue == "Success"
| where ResourceProviderValue in (
    "Microsoft.Network", "Microsoft.Compute", "Microsoft.Storage", 
    "Microsoft.KeyVault", "Microsoft.Sql"
)
| project 
    TimeGenerated, 
    Caller, 
    OperationNameValue, 
    ResourceId,
    Properties
| order by TimeGenerated desc
""",
            purpose="Track configuration changes that may affect security baseline",
            frequency="continuous"
        ),
    ],
}


# =============================================================================
# ADS (Audit and Data Security) Evidence Queries  
# =============================================================================

ADS_EVIDENCE_QUERIES = {
    "FRR-ADS-01": [
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Audit Log Completeness",
            query="""
AzureActivity
| where TimeGenerated > ago(1d)
| summarize 
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    DistinctCallers = dcount(Caller)
    by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
""",
            purpose="Verify audit logging is capturing all activities",
            frequency="daily"
        ),
        EvidenceQuery(
            query_type="Azure Resource Graph",
            query_name="Diagnostic Settings Coverage",
            query="""
resources
| where type in (
    "microsoft.keyvault/vaults",
    "microsoft.sql/servers",
    "microsoft.storage/storageaccounts",
    "microsoft.compute/virtualmachines"
)
| join kind=leftouter (
    resourcecontainers
    | where type == "microsoft.insights/diagnosticsettings"
    | project resourceId = tostring(properties.resourceId), hasDiag = true
) on $left.id == $right.resourceId
| where isnull(hasDiag)
| project name, type, resourceGroup, subscriptionId
""",
            purpose="Find resources without diagnostic settings enabled",
            frequency="daily"
        ),
    ],
    "FRR-ADS-02": [
        EvidenceQuery(
            query_type="Azure Resource Graph",
            query_name="Data Encryption at Rest",
            query="""
resources
| where type == "microsoft.storage/storageaccounts"
| extend 
    encryptionServices = properties.encryption.services,
    keySource = properties.encryption.keySource
| project 
    name, 
    resourceGroup,
    blobEncrypted = encryptionServices.blob.enabled,
    fileEncrypted = encryptionServices.file.enabled,
    keySource
""",
            purpose="Verify encryption at rest for storage accounts",
            frequency="daily"
        ),
    ],
}


# =============================================================================
# SCN (Secure Configuration) Evidence Queries
# =============================================================================

SCN_EVIDENCE_QUERIES = {
    "FRR-SCN-01": [
        EvidenceQuery(
            query_type="Azure Resource Graph",
            query_name="Network Security Configuration",
            query="""
resources
| where type == "microsoft.network/networksecuritygroups"
| extend rules = properties.securityRules
| mv-expand rule = rules
| extend 
    direction = rule.properties.direction,
    access = rule.properties.access,
    sourceAddress = rule.properties.sourceAddressPrefix,
    destPort = rule.properties.destinationPortRange
| where access == "Allow" and sourceAddress == "*"
| where destPort in ("22", "3389", "0-65535", "*")
| project name, resourceGroup, direction, destPort, sourceAddress
""",
            purpose="Identify overly permissive NSG rules",
            frequency="daily"
        ),
        EvidenceQuery(
            query_type="Azure Resource Graph",
            query_name="Public IP Exposure",
            query="""
resources
| where type == "microsoft.network/publicipaddresses"
| extend 
    allocationMethod = properties.publicIPAllocationMethod,
    ipAddress = properties.ipAddress,
    associatedResource = properties.ipConfiguration.id
| where isnotempty(ipAddress)
| project name, resourceGroup, ipAddress, associatedResource
""",
            purpose="Track all public IP addresses in use",
            frequency="daily"
        ),
    ],
}


# =============================================================================
# CCM (Configuration Change Management) Evidence Queries
# =============================================================================

CCM_EVIDENCE_QUERIES = {
    "FRR-CCM-01": [
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Change Management Audit Trail",
            query="""
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has_any ("write", "delete", "action")
| where ActivityStatusValue == "Success"
| summarize 
    ChangeCount = count(),
    DistinctResources = dcount(ResourceId)
    by Caller, OperationNameValue
| order by ChangeCount desc
| take 50
""",
            purpose="Track all configuration changes by user",
            frequency="weekly"
        ),
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Unauthorized Change Detection",
            query="""
AzureActivity
| where TimeGenerated > ago(7d)
| where ActivityStatusValue == "Success"
| where OperationNameValue has_any ("write", "delete")
| where Caller !in ("expected-service-principal@domain.com", "automation@domain.com")
| project 
    TimeGenerated, 
    Caller, 
    OperationNameValue, 
    ResourceId,
    CorrelationId
| order by TimeGenerated desc
""",
            purpose="Identify changes made by unexpected identities",
            frequency="daily"
        ),
    ],
}


# =============================================================================
# MAS (Malware and Antivirus) Evidence Queries
# =============================================================================

MAS_EVIDENCE_QUERIES = {
    "FRR-MAS-01": [
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Defender Antimalware Status",
            query="""
ProtectionStatus
| where TimeGenerated > ago(1d)
| summarize 
    ProtectedCount = countif(ProtectionStatus == "Protected"),
    UnprotectedCount = countif(ProtectionStatus != "Protected")
    by Computer
| where UnprotectedCount > 0
""",
            purpose="Identify endpoints without antimalware protection",
            frequency="daily"
        ),
        EvidenceQuery(
            query_type="Azure Monitor KQL",
            query_name="Malware Detection Events",
            query="""
SecurityEvent
| where EventID == 1116 or EventID == 1117
| where TimeGenerated > ago(30d)
| project 
    TimeGenerated,
    Computer,
    ThreatName = extract("Threat Name:(.+?)\\\\n", 1, EventData),
    Action = extract("Action:(.+?)\\\\n", 1, EventData)
| order by TimeGenerated desc
""",
            purpose="Track malware detection and remediation events",
            frequency="daily"
        ),
    ],
}


# =============================================================================
# Evidence Automation Recommendations by FRR Family
# =============================================================================

def get_frr_evidence_automation(frr_id: str) -> Optional[FRREvidenceAutomation]:
    """
    Get evidence automation recommendations for a specific FRR.
    
    Args:
        frr_id: FRR identifier (e.g., "FRR-VDR-01")
        
    Returns:
        FRREvidenceAutomation with queries and recommendations, or None if not found
    """
    # Parse family from FRR ID
    parts = frr_id.split("-")
    if len(parts) < 3:
        return None
    
    family = parts[1].upper()
    
    # Build evidence automation based on family
    automation = _get_family_automation(frr_id, family)
    
    # Add specific queries if available
    query_sources = {
        "VDR": VDR_EVIDENCE_QUERIES,
        "RSC": RSC_EVIDENCE_QUERIES,
        "ADS": ADS_EVIDENCE_QUERIES,
        "SCN": SCN_EVIDENCE_QUERIES,
        "CCM": CCM_EVIDENCE_QUERIES,
        "MAS": MAS_EVIDENCE_QUERIES,
    }
    
    if family in query_sources and frr_id in query_sources[family]:
        automation.queries = query_sources[family][frr_id]
    
    return automation


def _get_family_automation(frr_id: str, family: str) -> FRREvidenceAutomation:
    """Get base evidence automation configuration by family."""
    
    family_configs = {
        "VDR": FRREvidenceAutomation(
            frr_id=frr_id,
            frr_name="Vulnerability Detection and Response",
            family="VDR",
            evidence_type="log-based",
            automation_feasibility="high",
            azure_services=[
                "Microsoft Defender for Cloud",
                "Azure Monitor Log Analytics",
                "Azure Resource Graph",
                "Update Management"
            ],
            collection_methods=[
                "Azure Resource Graph queries",
                "Log Analytics KQL queries",
                "Defender for Cloud REST API",
                "Azure Automation Runbooks"
            ],
            implementation_steps=[
                "Enable Defender for Cloud at Standard tier",
                "Configure Log Analytics workspace with 730-day retention",
                "Deploy Azure Automation account for scheduled queries",
                "Create Logic App for evidence export to blob storage",
                "Set up Azure Function for REST API integration"
            ],
            artifacts=[
                EvidenceArtifact(
                    artifact_name="Vulnerability Scan Report",
                    artifact_type="JSON",
                    description="Daily vulnerability assessment results from Defender for Cloud",
                    collection_method="REST API: /providers/Microsoft.Security/assessments",
                    storage_location="Azure Blob Storage - fedramp-evidence/vdr/"
                ),
                EvidenceArtifact(
                    artifact_name="Patch Compliance Report",
                    artifact_type="JSON",
                    description="Weekly patch status for all VMs",
                    collection_method="Azure Resource Graph + Update Management",
                    storage_location="Azure Blob Storage - fedramp-evidence/vdr/"
                ),
            ],
            update_frequency="daily",
            estimated_effort_hours=16
        ),
        "RSC": FRREvidenceAutomation(
            frr_id=frr_id,
            frr_name="Recommended Secure Configuration",
            family="RSC",
            evidence_type="config-based",
            automation_feasibility="high",
            azure_services=[
                "Azure Policy",
                "Azure Blueprints",
                "Microsoft Defender for Cloud",
                "Azure Resource Graph"
            ],
            collection_methods=[
                "Azure Policy compliance state export",
                "Azure Resource Graph configuration queries",
                "Defender for Cloud secure score API"
            ],
            implementation_steps=[
                "Assign FedRAMP High blueprint to subscriptions",
                "Configure Azure Policy with FedRAMP initiative",
                "Set up compliance state export to Log Analytics",
                "Create Resource Graph queries for drift detection"
            ],
            artifacts=[
                EvidenceArtifact(
                    artifact_name="Policy Compliance State",
                    artifact_type="JSON",
                    description="Azure Policy compliance results for all resources",
                    collection_method="Policy Insights REST API",
                    storage_location="Azure Blob Storage - fedramp-evidence/rsc/"
                ),
            ],
            update_frequency="daily",
            estimated_effort_hours=8
        ),
        "ADS": FRREvidenceAutomation(
            frr_id=frr_id,
            frr_name="Audit and Data Security",
            family="ADS",
            evidence_type="log-based",
            automation_feasibility="high",
            azure_services=[
                "Azure Monitor Log Analytics",
                "Azure Activity Log",
                "Microsoft Entra ID (Azure AD)",
                "Azure Storage"
            ],
            collection_methods=[
                "Log Analytics KQL queries",
                "Activity Log export",
                "Entra ID audit log export",
                "Storage diagnostic logs"
            ],
            implementation_steps=[
                "Configure diagnostic settings on all resources",
                "Set Log Analytics retention to 730 days",
                "Enable Entra ID audit log streaming",
                "Create scheduled export jobs for evidence"
            ],
            artifacts=[
                EvidenceArtifact(
                    artifact_name="Audit Log Export",
                    artifact_type="JSON",
                    description="Complete audit trail from Azure Activity Log",
                    collection_method="Activity Log export to Event Hub/Storage",
                    storage_location="Azure Blob Storage - fedramp-evidence/ads/"
                ),
            ],
            update_frequency="continuous",
            estimated_effort_hours=12
        ),
        "SCN": FRREvidenceAutomation(
            frr_id=frr_id,
            frr_name="Secure Configuration",
            family="SCN",
            evidence_type="config-based",
            automation_feasibility="high",
            azure_services=[
                "Azure Resource Graph",
                "Azure Policy",
                "Azure Firewall",
                "Network Security Groups"
            ],
            collection_methods=[
                "Resource Graph queries",
                "Azure Policy compliance export",
                "Network Watcher diagnostics"
            ],
            implementation_steps=[
                "Deploy Azure Policy for network security",
                "Configure Network Watcher flow logs",
                "Create Resource Graph queries for config audit",
                "Set up automated compliance reporting"
            ],
            artifacts=[
                EvidenceArtifact(
                    artifact_name="Network Configuration Export",
                    artifact_type="JSON",
                    description="NSG rules and firewall configuration",
                    collection_method="Azure Resource Graph",
                    storage_location="Azure Blob Storage - fedramp-evidence/scn/"
                ),
            ],
            update_frequency="daily",
            estimated_effort_hours=10
        ),
        "CCM": FRREvidenceAutomation(
            frr_id=frr_id,
            frr_name="Configuration Change Management",
            family="CCM",
            evidence_type="log-based",
            automation_feasibility="high",
            azure_services=[
                "Azure Activity Log",
                "Azure Monitor Change Analysis",
                "Azure DevOps",
                "GitHub Actions"
            ],
            collection_methods=[
                "Activity Log KQL queries",
                "Change Analysis API",
                "DevOps audit log export"
            ],
            implementation_steps=[
                "Enable Azure Activity Log streaming",
                "Configure Change Analysis for critical resources",
                "Integrate DevOps audit logs",
                "Create change approval workflow"
            ],
            artifacts=[
                EvidenceArtifact(
                    artifact_name="Change Audit Trail",
                    artifact_type="JSON",
                    description="All configuration changes with approvers",
                    collection_method="Activity Log + DevOps Audit",
                    storage_location="Azure Blob Storage - fedramp-evidence/ccm/"
                ),
            ],
            update_frequency="continuous",
            estimated_effort_hours=12
        ),
        "MAS": FRREvidenceAutomation(
            frr_id=frr_id,
            frr_name="Malware and Antivirus",
            family="MAS",
            evidence_type="log-based",
            automation_feasibility="high",
            azure_services=[
                "Microsoft Defender for Endpoint",
                "Microsoft Defender for Cloud",
                "Azure Monitor"
            ],
            collection_methods=[
                "Defender for Endpoint API",
                "Security events from Log Analytics",
                "Defender for Cloud alerts"
            ],
            implementation_steps=[
                "Enable Defender for Endpoint on all VMs",
                "Configure security event collection",
                "Set up malware alert automation",
                "Create incident response workflow"
            ],
            artifacts=[
                EvidenceArtifact(
                    artifact_name="Antimalware Protection Status",
                    artifact_type="JSON",
                    description="Protection status for all endpoints",
                    collection_method="Defender for Endpoint API",
                    storage_location="Azure Blob Storage - fedramp-evidence/mas/"
                ),
            ],
            update_frequency="daily",
            estimated_effort_hours=8
        ),
    }
    
    # Return family-specific or generic config
    if family in family_configs:
        return family_configs[family]
    
    # Generic configuration for other families
    return FRREvidenceAutomation(
        frr_id=frr_id,
        frr_name=f"{family} Requirements",
        family=family,
        evidence_type="config-based",
        automation_feasibility="medium",
        azure_services=[
            "Azure Monitor Log Analytics",
            "Azure Resource Graph",
            "Azure Policy"
        ],
        collection_methods=[
            "Log Analytics KQL queries",
            "Resource Graph queries",
            "Policy compliance export"
        ],
        implementation_steps=[
            "Identify evidence requirements from FRR",
            "Configure appropriate Azure services",
            "Create collection queries",
            "Set up automated export"
        ],
        update_frequency="weekly",
        estimated_effort_hours=16
    )


def get_all_frr_evidence_queries(family: Optional[str] = None) -> Dict[str, List[EvidenceQuery]]:
    """
    Get all evidence queries, optionally filtered by family.
    
    Args:
        family: Optional family code to filter (e.g., "VDR", "RSC")
        
    Returns:
        Dictionary mapping FRR IDs to their evidence queries
    """
    all_queries = {
        **VDR_EVIDENCE_QUERIES,
        **RSC_EVIDENCE_QUERIES,
        **ADS_EVIDENCE_QUERIES,
        **SCN_EVIDENCE_QUERIES,
        **CCM_EVIDENCE_QUERIES,
        **MAS_EVIDENCE_QUERIES,
    }
    
    if family:
        return {
            frr_id: queries 
            for frr_id, queries in all_queries.items() 
            if frr_id.startswith(f"FRR-{family.upper()}-")
        }
    
    return all_queries


def format_evidence_automation_markdown(automation: FRREvidenceAutomation) -> str:
    """Format evidence automation as markdown documentation."""
    
    output = f"""# Evidence Automation for {automation.frr_id}

**Family:** {automation.family} - {automation.frr_name}  
**Evidence Type:** {automation.evidence_type}  
**Automation Feasibility:** {automation.automation_feasibility}  
**Estimated Setup Effort:** {automation.estimated_effort_hours} hours  
**Update Frequency:** {automation.update_frequency}  
**Responsible Party:** {automation.responsible_party}

## Azure Services Required

"""
    
    for service in automation.azure_services:
        output += f"- {service}\n"
    
    output += "\n## Collection Methods\n\n"
    for method in automation.collection_methods:
        output += f"- {method}\n"
    
    output += "\n## Implementation Steps\n\n"
    for i, step in enumerate(automation.implementation_steps, 1):
        output += f"{i}. {step}\n"
    
    if automation.queries:
        output += "\n## Evidence Collection Queries\n\n"
        for query in automation.queries:
            output += f"""### {query.query_name}

**Type:** {query.query_type}  
**Purpose:** {query.purpose}  
**Frequency:** {query.frequency}  
**Retention:** {query.retention_days} days

```kql
{query.query.strip()}
```

"""
    
    if automation.artifacts:
        output += "## Evidence Artifacts\n\n"
        output += "| Artifact | Type | Description | Collection Method | Storage |\n"
        output += "|----------|------|-------------|-------------------|----------|\n"
        for artifact in automation.artifacts:
            output += f"| {artifact.artifact_name} | {artifact.artifact_type} | {artifact.description} | {artifact.collection_method} | {artifact.storage_location} |\n"
    
    return output
