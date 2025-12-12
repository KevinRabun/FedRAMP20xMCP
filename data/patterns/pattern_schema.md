# Pattern Library Schema

## Overview

This document defines the YAML schema for detection patterns used in the data-driven FedRAMP 20x analyzer architecture.

## Pattern Types

### 1. Import Pattern
Detects specific imports/using statements

### 2. Function Call Pattern
Detects function/method invocations

### 3. Configuration Pattern
Detects configuration settings or constants

### 4. Decorator/Attribute Pattern
Detects decorators (Python) or attributes (C#/Java)

### 5. Resource Pattern (IaC)
Detects infrastructure resource definitions

### 6. Pipeline Pattern (CI/CD)
Detects pipeline steps or configurations

## YAML Schema

```yaml
pattern_id: string  # Unique identifier (e.g., "iam.mfa.fido2")
name: string  # Human-readable name
description: string  # What this pattern detects
family: string  # Requirement family (IAM, MLA, SVC, etc.)
severity: string  # DEFAULT, HIGH, MEDIUM, LOW, CRITICAL
pattern_type: string  # import, function_call, configuration, decorator, resource, pipeline

# Language-specific detection
languages:
  python:
    ast_queries:  # Preferred: AST-based detection
      - query_type: string  # import, function_call, assignment, decorator, etc.
        target: string  # What to match
        conditions: [string]  # Optional conditions
    regex_fallback: string  # Regex pattern for non-AST scenarios
    positive_indicators: [string]  # Strings that indicate compliance
    negative_indicators: [string]  # Strings that indicate non-compliance
    
  csharp:
    # Same structure as python
    
  java:
    # Same structure
    
  typescript:
    # Same structure
    
  bicep:
    ast_queries:
      - resource_type: string  # e.g., "Microsoft.KeyVault/vaults"
        property_path: string  # e.g., "properties.enableSoftDelete"
        expected_value: any  # Expected configuration value
    regex_fallback: string
    
  terraform:
    ast_queries:
      - resource_type: string  # e.g., "azurerm_key_vault"
        attribute_path: string  # e.g., "soft_delete_enabled"
        expected_value: any
    regex_fallback: string
    
  github_actions:
    ast_queries:
      - step_uses: string  # Action to detect
        with_parameters: [string]  # Required parameters
    regex_fallback: string
    
  azure_pipelines:
    # Similar to github_actions
    
  gitlab_ci:
    # Similar structure

# Finding configuration
finding:
  title_template: string  # Template for finding title (can use {placeholders})
  description_template: string  # Template for description
  remediation_template: string  # Template for remediation steps
  evidence_collection: [string]  # What artifacts to collect
  azure_services: [string]  # Related Azure services

# Pattern relationships
requires_all: [string]  # All of these patterns must match
requires_any: [string]  # At least one of these must match
conflicts_with: [string]  # Finding if these patterns exist together
requires_absence: [string]  # Finding if these patterns are NOT found

# Metadata
tags: [string]  # For categorization/filtering
nist_controls: [string]  # Related NIST controls
related_ksis: [string]  # Related KSI IDs
related_frrs: [string]  # Related FRR IDs
```

## Example Patterns

### Example 1: FIDO2 Import (Positive Pattern)

```yaml
pattern_id: "iam.mfa.fido2_import"
name: "FIDO2 Library Import"
description: "Detects import of FIDO2 library for phishing-resistant MFA"
family: "IAM"
severity: "DEFAULT"
pattern_type: "import"

languages:
  python:
    ast_queries:
      - query_type: "import_statement"
        target: "fido2"
        conditions: []
    regex_fallback: "import\\s+fido2|from\\s+fido2"
    positive_indicators: ["fido2", "WebAuthn"]
    negative_indicators: []
    
  csharp:
    ast_queries:
      - query_type: "using_directive"
        target: "Fido2NetLib"
        conditions: []
    regex_fallback: "using\\s+Fido2NetLib"
    positive_indicators: ["Fido2NetLib"]
    negative_indicators: []

finding:
  title_template: "Phishing-resistant MFA detected (FIDO2)"
  description_template: "FIDO2 library import found, indicating phishing-resistant MFA implementation."
  remediation_template: "N/A - This is a positive finding"
  evidence_collection:
    - "Code implementing FIDO2 authentication flow"
    - "Configuration showing FIDO2 enabled"
  azure_services:
    - "Microsoft Entra ID"
    - "Conditional Access"

tags: ["mfa", "authentication", "positive-finding"]
nist_controls: ["ia-2", "ia-2.1", "ia-2.2"]
related_ksis: ["KSI-IAM-01"]
related_frrs: []
```

### Example 2: Missing MFA Enforcement (Negative Pattern)

```yaml
pattern_id: "iam.mfa.login_without_mfa"
name: "Login Without MFA"
description: "Detects login functions without MFA enforcement"
family: "IAM"
severity: "CRITICAL"
pattern_type: "function_call"

languages:
  python:
    ast_queries:
      - query_type: "function_definition"
        target: "login"
        conditions:
          - "has_decorator:login_required"
          - "not_has_decorator:mfa_required"
          - "not_has_decorator:two_factor_required"
    regex_fallback: "def\\s+\\w*login\\w*\\(.*\\):"
    positive_indicators: []
    negative_indicators: ["mfa", "two_factor", "fido2", "webauthn"]
    
  csharp:
    ast_queries:
      - query_type: "method_declaration"
        target: "Login"
        conditions:
          - "has_attribute:HttpPost"
          - "not_has_attribute:RequireTwoFactor"
    regex_fallback: "public\\s+.*\\s+Login\\s*\\("
    negative_indicators: ["RequireTwoFactor", "MfaRequired"]

finding:
  title_template: "Login without MFA enforcement"
  description_template: "Login functionality detected at line {line_number} without multi-factor authentication. KSI-IAM-01 requires phishing-resistant MFA for all user authentication."
  remediation_template: |
    Implement phishing-resistant MFA:
    - Add @mfa_required decorator
    - Integrate FIDO2/WebAuthn
    - Configure Azure AD Conditional Access
  evidence_collection:
    - "Authentication flow documentation"
    - "MFA configuration export"
    - "Test results showing MFA enforcement"
  azure_services:
    - "Microsoft Entra ID"
    - "Conditional Access"

requires_absence: ["iam.mfa.fido2_import", "iam.mfa.webauthn_import"]
tags: ["mfa", "authentication", "security-gap"]
nist_controls: ["ia-2", "ia-2.1", "ia-2.2", "ia-2.8"]
related_ksis: ["KSI-IAM-01"]
related_frrs: ["FRR-ADS-AC-01"]
```

### Example 3: Local File Logging (Negative Pattern)

```yaml
pattern_id: "mla.logging.local_file"
name: "Local File Logging"
description: "Detects local file-based logging without centralized SIEM"
family: "MLA"
severity: "HIGH"
pattern_type: "function_call"

languages:
  python:
    ast_queries:
      - query_type: "function_call"
        target: "FileHandler"
        conditions: []
      - query_type: "function_call"
        target: "basicConfig"
        conditions:
          - "has_argument:filename"
    regex_fallback: "FileHandler\\(|basicConfig\\(.*filename"
    positive_indicators: []
    negative_indicators: ["AzureLogHandler", "azure.monitor", "applicationinsights"]
    
  csharp:
    ast_queries:
      - query_type: "object_creation"
        target: "FileStream"
        conditions:
          - "file_extension:.log"
    regex_fallback: "new\\s+FileStream.*\\.log"
    negative_indicators: ["ApplicationInsights", "AzureMonitor"]

finding:
  title_template: "Local file logging without centralized SIEM"
  description_template: "Local file-based logging detected at line {line_number} without centralized SIEM integration. FedRAMP requires tamper-resistant centralized logging. Local files can be modified or deleted by attackers."
  remediation_template: |
    Integrate with Azure Monitor/Application Insights:
    
    Python:
    from opencensus.ext.azure.log_exporter import AzureLogHandler
    logger.addHandler(AzureLogHandler(connection_string=os.getenv('APPLICATIONINSIGHTS_CONNECTION_STRING')))
    
    C#:
    builder.Services.AddApplicationInsightsTelemetry();
  evidence_collection:
    - "Log Analytics workspace configuration"
    - "Diagnostic settings for resources"
    - "Sample logs in centralized system"
  azure_services:
    - "Azure Monitor"
    - "Log Analytics"
    - "Application Insights"

requires_absence: ["mla.logging.azure_monitor"]
tags: ["logging", "siem", "security-gap"]
nist_controls: ["au-2", "au-3", "au-6", "au-9"]
related_ksis: ["KSI-MLA-01"]
related_frrs: []
```

### Example 4: Key Vault Configuration (IaC Pattern)

```yaml
pattern_id: "svc.secrets.keyvault_soft_delete"
name: "Key Vault Soft Delete"
description: "Detects Key Vault configuration with soft delete enabled"
family: "SVC"
severity: "HIGH"
pattern_type: "resource"

languages:
  bicep:
    ast_queries:
      - resource_type: "Microsoft.KeyVault/vaults"
        property_path: "properties.enableSoftDelete"
        expected_value: true
    regex_fallback: "resource\\s+\\w+\\s+'Microsoft\\.KeyVault/vaults'"
    
  terraform:
    ast_queries:
      - resource_type: "azurerm_key_vault"
        attribute_path: "soft_delete_enabled"
        expected_value: true
      - resource_type: "azurerm_key_vault"
        attribute_path: "soft_delete_retention_days"
        expected_value: ">=7"
    regex_fallback: "resource\\s+\"azurerm_key_vault\""

finding:
  title_template: "Key Vault missing soft delete protection"
  description_template: "Azure Key Vault resource at line {line_number} does not have soft delete enabled. FedRAMP requires protection against accidental or malicious deletion of secrets."
  remediation_template: |
    Enable soft delete in Key Vault:
    
    Bicep:
    properties: {
      enableSoftDelete: true
      enablePurgeProtection: true
      softDeleteRetentionInDays: 90
    }
    
    Terraform:
    soft_delete_enabled = true
    purge_protection_enabled = true
    soft_delete_retention_days = 90
  evidence_collection:
    - "Key Vault configuration export"
    - "Azure Policy compliance report"
    - "Soft delete test results"
  azure_services:
    - "Azure Key Vault"
    - "Azure Policy"

tags: ["secrets", "key-vault", "protection"]
nist_controls: ["sc-12", "sc-28"]
related_ksis: ["KSI-SVC-01", "KSI-SVC-05"]
related_frrs: []
```

## Pattern Composition

Patterns can be composed using boolean logic:

```yaml
pattern_id: "iam.mfa.complete_enforcement"
name: "Complete MFA Enforcement"
description: "Validates complete MFA implementation"
family: "IAM"
pattern_type: "composite"

requires_all:
  - "iam.mfa.fido2_import"  # Has FIDO2 library
  - "iam.mfa.login_mfa_check"  # Login checks MFA
  - "iam.mfa.session_validation"  # Sessions validate MFA

requires_any:
  - "iam.mfa.azure_ad_integration"  # OR Azure AD
  - "iam.mfa.custom_implementation"  # OR custom impl

conflicts_with:
  - "iam.mfa.totp_only"  # Can't be TOTP-only
  - "iam.mfa.sms_only"  # Can't be SMS-only
```

## Pattern Inheritance

Patterns can inherit from base patterns:

```yaml
pattern_id: "iam.mfa.totp"
extends: "iam.mfa.base"
name: "TOTP MFA (Not Phishing-Resistant)"
severity: "MEDIUM"  # Override severity

languages:
  python:
    ast_queries:
      - query_type: "import_statement"
        target: "pyotp"
```

## Next Steps

1. Create pattern libraries for each family
2. Implement pattern engine to execute patterns
3. Implement pattern compiler to convert YAML to detection logic
4. Build requirement analyzer that loads patterns and metadata
