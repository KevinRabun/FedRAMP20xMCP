# KSI Evidence Automation Feature

## Overview

The KSI Evidence Automation feature enables each Key Security Indicator (KSI) to provide detailed recommendations for automating evidence collection. This feature helps organizations efficiently demonstrate FedRAMP 20x compliance by providing:

- **Azure service recommendations** with configuration and cost estimates
- **Evidence collection methods** with schedules and data points
- **Ready-to-use queries** (KQL, Resource Graph, REST API)
- **Evidence artifact specifications** (logs, configs, reports)
- **Storage requirements** with retention policies
- **FRR-ADS API integration** guidance
- **Code examples** (Python, C#, PowerShell, Java, TypeScript)
- **Infrastructure templates** (Bicep, Terraform)

## Architecture

### Base Implementation

All KSI analyzers inherit three new methods from `BaseKSIAnalyzer`:

1. **`get_evidence_automation_recommendations()`** - Returns structured recommendations
2. **`get_evidence_collection_queries()`** - Returns ready-to-use queries
3. **`get_evidence_artifacts()`** - Returns list of evidence to collect

### Default Behavior

KSI analyzers that don't override these methods return a default template indicating manual evidence collection is required.

### Implemented KSIs

Currently implemented for:
- **KSI-IAM-01** (Phishing-Resistant MFA) - log-based evidence
- **KSI-CNA-01** (Restrict Network Traffic) - config-based evidence

## MCP Tools

Three new MCP tools provide access to evidence automation:

### 1. get_ksi_evidence_automation

Get comprehensive evidence automation recommendations for a KSI.

**Usage:**
```
get_ksi_evidence_automation("KSI-IAM-01")
```

**Returns:**
- Evidence type (log-based, config-based, metric-based, etc.)
- Automation feasibility (high, medium, low, manual-only)
- Azure services required (with purpose, configuration, cost)
- Collection methods (with frequency and data points)
- Storage requirements (retention, format, encryption)
- FRR-ADS API integration details
- Implementation effort and prerequisites

### 2. get_ksi_evidence_queries

Get ready-to-use queries for collecting evidence.

**Usage:**
```
get_ksi_evidence_queries("KSI-IAM-01")
```

**Returns:**
- KQL queries for Log Analytics
- Azure Resource Graph queries
- REST API calls for Microsoft Graph
- Query descriptions and schedules

### 3. get_ksi_evidence_artifacts

Get list of evidence artifacts to collect.

**Usage:**
```
get_ksi_evidence_artifacts("KSI-IAM-01")
```

**Returns:**
- Artifact names and types
- Collection methods and frequency
- File formats and retention requirements

## Example: KSI-IAM-01 (Phishing-Resistant MFA)

### Evidence Type
Log-based evidence from Azure AD sign-in logs

### Azure Services
- **Azure AD Sign-in Logs** - Track authentication events with MFA details
- **Azure Monitor / Log Analytics** - Query and analyze authentication logs
- **Azure Blob Storage** - Long-term evidence storage (3+ years)
- **Microsoft Graph API** - Query CA policies and authentication methods

### Collection Methods

1. **Sign-in Log Analysis** (Daily)
   - Authentication methods used (FIDO2, certificate, WHfB)
   - MFA success/failure rates
   - Users bypassing MFA
   - Authentication strength applied

2. **Conditional Access Policy Audit** (On-change + weekly)
   - Policy configurations requiring MFA
   - Authentication strength requirements
   - User/group assignments
   - Policy state (enabled/disabled)

3. **Authentication Methods Report** (Weekly)
   - Users with FIDO2 keys registered
   - Users with certificate-based auth
   - Users with Windows Hello for Business
   - Users without phishing-resistant methods

### Sample Query (KQL)

```kusto
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0  // Successful sign-ins
| extend MfaDetail = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| extend AuthenticationMethod = case(
    MfaDetail contains "FIDO2", "FIDO2 Security Key (Phishing-Resistant)",
    MfaDetail contains "Certificate", "Certificate-Based Auth (Phishing-Resistant)",
    MfaDetail contains "WindowsHello", "Windows Hello for Business (Phishing-Resistant)",
    MfaDetail contains "Authenticator", "Microsoft Authenticator (OTP - Not Phishing-Resistant)",
    MfaDetail contains "SMS", "SMS OTP (Not Phishing-Resistant)",
    "Other/Unknown"
)
| summarize SignInCount = count(), UniqueUsers = dcount(UserPrincipalName) by AuthenticationMethod
| extend ComplianceStatus = case(
    AuthenticationMethod contains "Phishing-Resistant", "Compliant",
    "Non-Compliant"
)
| order by SignInCount desc
```

### Evidence Artifacts

1. **azure-ad-signin-logs-mfa-summary.json** (Daily)
   - 30-day summary of authentication methods used
   - Percentage of phishing-resistant MFA

2. **conditional-access-policies-export.json** (On-change + weekly)
   - Export of all CA policies showing MFA requirements

3. **authentication-methods-report.csv** (Weekly)
   - Per-user report showing registered authentication methods

4. **mfa-non-compliant-users.json** (Weekly)
   - List of users without phishing-resistant MFA

5. **authentication-strength-policies.json** (On-change + weekly)
   - Export of authentication strength policies

## Example: KSI-CNA-01 (Restrict Network Traffic)

### Evidence Type
Config-based evidence from Azure network resources

### Azure Services
- **Azure Resource Graph** - Query NSG rules and firewall policies
- **Azure Network Watcher** - Analyze effective NSG rules
- **Azure Policy** - Enforce and audit network security configurations
- **Azure Blob Storage** - Store network configuration snapshots

### Collection Methods

1. **NSG Rules Audit** (Daily)
   - NSG rules with source = * or 0.0.0.0/0
   - Default deny rules presence
   - Allow-by-exception rules documentation

2. **Azure Firewall Policy Analysis** (On-change + daily)
   - Firewall rule collections
   - Application rules (FQDN-based filtering)
   - Network rules (IP-based filtering)

3. **Service Endpoint Configuration** (Weekly)
   - Enabled service endpoints per subnet
   - Service endpoint policies applied

4. **Network Topology Mapping** (Monthly)
   - VNet peering connections
   - Network traffic isolation

### Sample Query (Resource Graph)

```kusto
Resources
| where type == 'microsoft.network/networksecuritygroups'
| extend nsgName = name
| mv-expand rules = properties.securityRules
| extend ruleName = tostring(rules.name)
| extend direction = tostring(rules.properties.direction)
| extend access = tostring(rules.properties.access)
| extend sourceAddress = tostring(rules.properties.sourceAddressPrefix)
| where access == "Allow"
| extend OverlyPermissive = case(
    sourceAddress in ("*", "0.0.0.0/0", "Internet"), "CRITICAL - Source is ANY/Internet",
    "OK - Specific rules"
)
| project subscriptionId, resourceGroup, nsgName, ruleName, sourceAddress, OverlyPermissive
| order by OverlyPermissive desc
```

## Implementation Guide

### For KSI Analyzer Developers

To add evidence automation to a KSI analyzer:

1. **Override `get_evidence_automation_recommendations()`**
   ```python
   def get_evidence_automation_recommendations(self) -> dict:
       return {
           "ksi_id": self.KSI_ID,
           "ksi_name": self.KSI_NAME,
           "evidence_type": "log-based",  # or "config-based", "metric-based"
           "automation_feasibility": "high",  # or "medium", "low", "manual-only"
           "azure_services": [...],
           "collection_methods": [...],
           "storage_requirements": {...},
           # ... more fields
       }
   ```

2. **Override `get_evidence_collection_queries()`**
   ```python
   def get_evidence_collection_queries(self) -> List[dict]:
       return [
           {
               "name": "Query Name",
               "query_type": "kusto",  # or "resource_graph", "rest_api"
               "query": "KQL or query text",
               "data_source": "Log Analytics - SigninLogs",
               "schedule": "daily",
               "output_format": "json"
           }
       ]
   ```

3. **Override `get_evidence_artifacts()`**
   ```python
   def get_evidence_artifacts(self) -> List[dict]:
       return [
           {
               "artifact_name": "signin-logs.json",
               "artifact_type": "log",
               "description": "Sign-in events with MFA details",
               "collection_method": "KQL query against Log Analytics",
               "format": "json",
               "frequency": "daily",
               "retention": "3 years"
           }
       ]
   ```

## Benefits

1. **Consistency** - Standardized evidence collection across all KSIs
2. **Automation** - Reduces manual evidence gathering effort
3. **Azure-Native** - Leverages Azure services for collection and storage
4. **Compliance** - Meets FRR-ADS requirements for machine-readable evidence
5. **Cost-Effective** - Provides cost estimates for Azure services
6. **Ready-to-Use** - Includes working queries and code examples

## Future Enhancements

1. **Expand Coverage** - Add evidence automation to all 72 KSIs
2. **Multi-Cloud** - Add AWS and GCP evidence collection methods
3. **Automation Templates** - Provide Azure Function apps for automated collection
4. **Dashboard Integration** - Build PowerBI templates for evidence visualization
5. **API Implementation** - Create FRR-ADS API reference implementation

## Testing

Comprehensive tests in `tests/test_ksi_evidence_automation.py`:
- Base method availability
- Structured data validation
- Azure service recommendations
- Query format validation
- Artifact specification completeness
- MCP tool integration

Run tests:
```bash
python tests/test_ksi_evidence_automation.py
```

## Related Files

- **Base Implementation**: `src/fedramp_20x_mcp/analyzers/ksi/base.py`
- **Sample Implementations**: 
  - `src/fedramp_20x_mcp/analyzers/ksi/ksi_iam_01.py`
  - `src/fedramp_20x_mcp/analyzers/ksi/ksi_cna_01.py`
- **MCP Tools**: `src/fedramp_20x_mcp/tools/ksi.py`
- **Tool Registration**: `src/fedramp_20x_mcp/tools/__init__.py`
- **Tests**: `tests/test_ksi_evidence_automation.py`
- **Example**: `examples/evidence_automation_example.py`

## References

- FedRAMP 20x Authorization Data Sharing (FRR-ADS)
- Azure Well-Architected Framework - Security Pillar
- Microsoft Graph API Documentation
- Azure Resource Graph Query Language (KQL)
