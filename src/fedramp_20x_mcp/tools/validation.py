"""
Pre-generation validation tools for FedRAMP 20x compliance.

Provides tools for LLMs to self-check configuration values BEFORE generating code.
"""

import re
from typing import Optional


async def validate_fedramp_config_impl(
    code: str,
    file_type: str,
    strict_mode: bool = True
) -> dict:
    """
    Validate Infrastructure as Code against FedRAMP 20x mandatory requirements.
    
    This tool performs PRE-GENERATION validation to catch compliance violations
    before code is finalized. Use this to verify templates meet FedRAMP requirements.
    
    Args:
        code: The IaC code to validate
        file_type: Type of file ("bicep", "terraform")
        strict_mode: If True, enforces ALL mandatory requirements (default: True)
        
    Returns:
        Dictionary with validation results:
        - passed: bool - Whether all validations passed
        - violations: list - List of requirement violations
        - warnings: list - Non-critical issues
        - compliant_values: list - Requirements that passed validation
    """
    file_type_lower = file_type.lower()
    if file_type_lower not in ["bicep", "terraform", "tf"]:
        return {
            "error": f"Unsupported file type: {file_type}. Supported: bicep, terraform"
        }
    
    if file_type_lower == "tf":
        file_type_lower = "terraform"
    
    violations = []
    warnings = []
    compliant = []
    
    # =============================================================================
    # MANDATORY REQUIREMENT 1: Log Analytics Retention = 730 Days
    # =============================================================================
    if file_type_lower == "bicep":
        retention_pattern = r"retentionInDays:\s*(\d+)"
        retention_matches = re.findall(retention_pattern, code)
        
        if retention_matches:
            for retention in retention_matches:
                days = int(retention)
                if days < 730:
                    violations.append({
                        "requirement": "KSI-MLA-01/MLA-02: Log Analytics Retention",
                        "expected": "730 days (2 years)",
                        "found": f"{days} days",
                        "severity": "CRITICAL",
                        "fix": f"Change retentionInDays from {days} to 730"
                    })
                elif days == 730:
                    compliant.append({
                        "requirement": "KSI-MLA-01/MLA-02: Log Analytics Retention",
                        "value": "730 days",
                        "status": "COMPLIANT"
                    })
                else:
                    compliant.append({
                        "requirement": "KSI-MLA-01/MLA-02: Log Analytics Retention",
                        "value": f"{days} days (exceeds minimum)",
                        "status": "COMPLIANT"
                    })
    
    elif file_type_lower == "terraform":
        retention_pattern = r"retention_in_days\s*=\s*(\d+)"
        retention_matches = re.findall(retention_pattern, code)
        
        if retention_matches:
            for retention in retention_matches:
                days = int(retention)
                if days < 730:
                    violations.append({
                        "requirement": "KSI-MLA-01/MLA-02: Log Analytics Retention",
                        "expected": "730 days (2 years)",
                        "found": f"{days} days",
                        "severity": "CRITICAL",
                        "fix": f"Change retention_in_days from {days} to 730"
                    })
                elif days == 730:
                    compliant.append({
                        "requirement": "KSI-MLA-01/MLA-02: Log Analytics Retention",
                        "value": "730 days",
                        "status": "COMPLIANT"
                    })
    
    # =============================================================================
    # MANDATORY REQUIREMENT 2: Customer-Managed Keys (CMK)
    # =============================================================================
    if file_type_lower == "bicep":
        # Check Storage Accounts
        storage_pattern = r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts"
        if re.search(storage_pattern, code):
            # Check for platform-managed keys (VIOLATION)
            pmk_pattern = r"keySource:\s*['\"]Microsoft\.Storage['\"]"
            if re.search(pmk_pattern, code):
                violations.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Storage",
                    "expected": "keySource: 'Microsoft.Keyvault'",
                    "found": "keySource: 'Microsoft.Storage' (platform-managed)",
                    "severity": "CRITICAL",
                    "fix": "Configure Customer-Managed Keys with Key Vault"
                })
            
            # Check for CMK (COMPLIANT)
            cmk_pattern = r"keySource:\s*['\"]Microsoft\.Keyvault['\"]"
            if re.search(cmk_pattern, code):
                compliant.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Storage",
                    "value": "Customer-Managed Keys configured",
                    "status": "COMPLIANT"
                })
        
        # Check Cosmos DB
        cosmos_pattern = r"resource\s+\w+\s+'Microsoft\.DocumentDB/databaseAccounts"
        if re.search(cosmos_pattern, code):
            # Check for missing keyVaultKeyUri (VIOLATION)
            if not re.search(r"keyVaultKeyUri:", code):
                violations.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Cosmos DB",
                    "expected": "keyVaultKeyUri: 'https://{vault}.vault.azure.net/keys/{key}/{version}'",
                    "found": "Missing keyVaultKeyUri property",
                    "severity": "CRITICAL",
                    "fix": "Add keyVaultKeyUri property with Key Vault key reference"
                })
            else:
                compliant.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Cosmos DB",
                    "value": "keyVaultKeyUri configured",
                    "status": "COMPLIANT"
                })
    
    elif file_type_lower == "terraform":
        # Check Storage Accounts
        storage_pattern = r'resource\s+"azurerm_storage_account"'
        if re.search(storage_pattern, code):
            # Check for missing customer_managed_key block (VIOLATION)
            if not re.search(r"customer_managed_key\s*\{", code):
                violations.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Storage",
                    "expected": "customer_managed_key block configured",
                    "found": "Missing customer_managed_key block",
                    "severity": "CRITICAL",
                    "fix": "Add customer_managed_key block with Key Vault key reference"
                })
            else:
                compliant.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Storage",
                    "value": "Customer-Managed Keys configured",
                    "status": "COMPLIANT"
                })
        
        # Check Cosmos DB
        cosmos_pattern = r"resource\s+\w+\s+'Microsoft\.DocumentDB/databaseAccounts"
        if re.search(cosmos_pattern, code):
            # Check for missing keyVaultKeyUri (VIOLATION)
            if not re.search(r"keyVaultKeyUri:", code):
                violations.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Cosmos DB",
                    "expected": "keyVaultKeyUri: 'https://{vault}.vault.azure.net/keys/{key}/{version}'",
                    "found": "Missing keyVaultKeyUri property",
                    "severity": "CRITICAL",
                    "fix": "Add keyVaultKeyUri property with Key Vault key reference"
                })
            else:
                compliant.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Cosmos DB",
                    "value": "keyVaultKeyUri configured",
                    "status": "COMPLIANT"
                })
    
    elif file_type_lower == "terraform":
        # Check Storage Accounts
        storage_pattern = r'resource\s+"azurerm_storage_account"'
        if re.search(storage_pattern, code):
            # Check for missing customer_managed_key block (VIOLATION)
            if not re.search(r"customer_managed_key\s*\{", code):
                violations.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Storage",
                    "expected": "customer_managed_key block configured",
                    "found": "Missing customer_managed_key block",
                    "severity": "CRITICAL",
                    "fix": "Add customer_managed_key block with Key Vault key reference"
                })
            else:
                compliant.append({
                    "requirement": "KSI-SVC-06: Customer-Managed Keys for Storage",
                    "value": "Customer-Managed Keys configured",
                    "status": "COMPLIANT"
                })
    
    # =============================================================================
    # MANDATORY REQUIREMENT 3: Key Vault Premium SKU
    # =============================================================================
    if file_type_lower == "bicep":
        keyvault_pattern = r"resource\s+\w+\s+'Microsoft\.KeyVault/vaults"
        if re.search(keyvault_pattern, code):
            # Check for standard SKU (VIOLATION)
            standard_sku_pattern = r"name:\s*['\"]standard['\"]"
            if re.search(standard_sku_pattern, code, re.IGNORECASE):
                violations.append({
                    "requirement": "KSI-SVC-06: Key Vault Premium SKU",
                    "expected": "name: 'premium' (FIPS 140-2 Level 2 HSM)",
                    "found": "name: 'standard'",
                    "severity": "CRITICAL",
                    "fix": "Change Key Vault SKU from 'standard' to 'premium'"
                })
            
            # Check for premium SKU (COMPLIANT)
            premium_sku_pattern = r"name:\s*['\"]premium['\"]"
            if re.search(premium_sku_pattern, code, re.IGNORECASE):
                compliant.append({
                    "requirement": "KSI-SVC-06: Key Vault Premium SKU",
                    "value": "Premium SKU (FIPS 140-2 Level 2 HSM)",
                    "status": "COMPLIANT"
                })
            
            # Check for enabledForDiskEncryption
            if not re.search(r"enabledForDiskEncryption:\s*true", code):
                warnings.append({
                    "requirement": "Key Vault enabledForDiskEncryption",
                    "expected": "true",
                    "found": "false or missing",
                    "severity": "HIGH",
                    "note": "Required for Disk Encryption Sets"
                })
            else:
                compliant.append({
                    "requirement": "Key Vault enabledForDiskEncryption",
                    "value": "true",
                    "status": "COMPLIANT"
                })
    
    # =============================================================================
    # MANDATORY REQUIREMENT 4: Disable Local Authentication (KSI-IAM-01, KSI-IAM-03)
    # =============================================================================
    if file_type_lower == "bicep":
        # Check Cosmos DB disableLocalAuth
        cosmos_pattern = r"resource\s+\w+\s+'Microsoft\.DocumentDB/databaseAccounts"
        if re.search(cosmos_pattern, code):
            if re.search(r"disableLocalAuth:\s*false", code):
                violations.append({
                    "requirement": "KSI-IAM-01/IAM-03: Cosmos DB Disable Local Auth",
                    "expected": "disableLocalAuth: true (enforce Azure AD authentication)",
                    "found": "disableLocalAuth: false",
                    "severity": "CRITICAL",
                    "fix": "Change disableLocalAuth from false to true"
                })
            elif re.search(r"disableLocalAuth:\s*true", code):
                compliant.append({
                    "requirement": "KSI-IAM-01/IAM-03: Cosmos DB Disable Local Auth",
                    "value": "Azure AD authentication enforced",
                    "status": "COMPLIANT"
                })
            else:
                warnings.append({
                    "requirement": "KSI-IAM-01/IAM-03: Cosmos DB Disable Local Auth",
                    "expected": "disableLocalAuth: true",
                    "found": "Property missing (defaults to false)",
                    "severity": "HIGH",
                    "note": "Add disableLocalAuth: true to enforce Azure AD authentication"
                })
        
        # Check Storage Account allowSharedKeyAccess
        storage_pattern = r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts"
        if re.search(storage_pattern, code):
            if re.search(r"allowSharedKeyAccess:\s*false", code):
                compliant.append({
                    "requirement": "KSI-IAM-01/IAM-03: Storage Disable Shared Key",
                    "value": "Shared key access disabled",
                    "status": "COMPLIANT"
                })
    
    elif file_type_lower == "terraform":
        # Check Cosmos DB local_authentication_disabled
        cosmos_pattern = r"resource\s+['\"]azurerm_cosmosdb_account['\"]"
        if re.search(cosmos_pattern, code):
            if re.search(r"local_authentication_disabled\s*=\s*false", code):
                violations.append({
                    "requirement": "KSI-IAM-01/IAM-03: Cosmos DB Disable Local Auth",
                    "expected": "local_authentication_disabled = true",
                    "found": "local_authentication_disabled = false",
                    "severity": "CRITICAL",
                    "fix": "Change local_authentication_disabled from false to true"
                })
            elif re.search(r"local_authentication_disabled\s*=\s*true", code):
                compliant.append({
                    "requirement": "KSI-IAM-01/IAM-03: Cosmos DB Disable Local Auth",
                    "value": "Azure AD authentication enforced",
                    "status": "COMPLIANT"
                })
    
    # =============================================================================
    # MANDATORY REQUIREMENT 5: Public Access Disabled
    # =============================================================================
    if file_type_lower == "bicep":
        # Check for enabled public access (VIOLATION)
        public_access_pattern = r"publicNetworkAccess:\s*['\"]Enabled['\"]"
        if re.search(public_access_pattern, code):
            violations.append({
                "requirement": "KSI-CNA: Public Access Disabled",
                "expected": "publicNetworkAccess: 'Disabled'",
                "found": "publicNetworkAccess: 'Enabled'",
                "severity": "CRITICAL",
                "fix": "Disable public access and configure Private Endpoints"
            })
        
        # Check for disabled public access (COMPLIANT if Private Endpoints exist)
        disabled_public_pattern = r"publicNetworkAccess:\s*['\"]Disabled['\"]"
        if re.search(disabled_public_pattern, code):
            # Check if Private Endpoints are configured
            private_endpoint_pattern = r"resource\s+\w+\s+'Microsoft\.Network/privateEndpoints"
            has_private_endpoints = bool(re.search(private_endpoint_pattern, code))
            
            if has_private_endpoints:
                compliant.append({
                    "requirement": "KSI-CNA-01/CNA-03: Public Access Disabled with Private Endpoints",
                    "value": "Public access disabled with Private Endpoints configured",
                    "status": "COMPLIANT"
                })
            else:
                violations.append({
                    "requirement": "KSI-CNA-01/CNA-03: Private Endpoints Required",
                    "expected": "Private Endpoints configured when publicNetworkAccess: 'Disabled'",
                    "found": "publicNetworkAccess: 'Disabled' but NO Private Endpoints found",
                    "severity": "CRITICAL",
                    "fix": "Add Private Endpoints (Microsoft.Network/privateEndpoints) - resources are INACCESSIBLE without them"
                })
    
    elif file_type_lower == "terraform":
        # Check for Terraform public_network_access_enabled = false
        public_access_disabled = r"public_network_access_enabled\s*=\s*false"
        if re.search(public_access_disabled, code):
            # Check if Private Endpoints are configured
            private_endpoint_pattern = r'resource\s+"azurerm_private_endpoint"'
            has_private_endpoints = bool(re.search(private_endpoint_pattern, code))
            
            if has_private_endpoints:
                compliant.append({
                    "requirement": "KSI-CNA-01/CNA-03: Public Access Disabled with Private Endpoints",
                    "value": "Public access disabled with Private Endpoints configured",
                    "status": "COMPLIANT"
                })
            else:
                violations.append({
                    "requirement": "KSI-CNA-01/CNA-03: Private Endpoints Required",
                    "expected": "Private Endpoints configured when public_network_access_enabled = false",
                    "found": "public_network_access_enabled = false but NO Private Endpoints found",
                    "severity": "CRITICAL",
                    "fix": "Add Private Endpoints (azurerm_private_endpoint) - resources are INACCESSIBLE without them"
                })
    
    # =============================================================================
    # MANDATORY REQUIREMENT 6: Diagnostic Settings
    # =============================================================================
    has_resources = False
    has_diagnostics = False
    
    if file_type_lower == "bicep":
        resource_pattern = r"resource\s+\w+\s+'Microsoft\.(Storage|KeyVault|Sql|Compute|DocumentDB)"
        has_resources = bool(re.search(resource_pattern, code))
        
        diag_pattern = r"resource\s+\w+\s+'Microsoft\.Insights/diagnosticSettings"
        has_diagnostics = bool(re.search(diag_pattern, code))
    elif file_type_lower == "terraform":
        resource_pattern = r'resource\s+"azurerm_(storage_account|key_vault|sql_server|virtual_machine|cosmosdb_account)"'
        has_resources = bool(re.search(resource_pattern, code))
        
        diag_pattern = r'resource\s+"azurerm_monitor_diagnostic_setting"'
        has_diagnostics = bool(re.search(diag_pattern, code))
    
    if has_resources and not has_diagnostics:
        violations.append({
            "requirement": "KSI-MLA-01: Diagnostic Settings",
            "expected": "Diagnostic settings configured for all resources",
            "found": "Missing diagnostic settings",
            "severity": "HIGH",
            "fix": "Add diagnostic settings to send logs to Log Analytics"
        })
    elif has_diagnostics:
        compliant.append({
            "requirement": "KSI-MLA-01: Diagnostic Settings",
            "value": "Diagnostic settings configured",
            "status": "COMPLIANT"
        })
    
    # =============================================================================
    # VALIDATION SUMMARY
    # =============================================================================
    passed = len(violations) == 0
    
    if strict_mode and len(warnings) > 0:
        passed = False
    
    return {
        "passed": passed,
        "total_violations": len(violations),
        "total_warnings": len(warnings),
        "total_compliant": len(compliant),
        "violations": violations,
        "warnings": warnings,
        "compliant_values": compliant,
        "summary": _format_validation_summary(passed, violations, warnings, compliant)
    }


def _format_validation_summary(passed: bool, violations: list, warnings: list, compliant: list) -> str:
    """Format a human-readable validation summary."""
    lines = []
    
    if passed:
        lines.append("✅ VALIDATION PASSED - All FedRAMP 20x requirements met\n")
    else:
        lines.append("❌ VALIDATION FAILED - Compliance violations detected\n")
    
    lines.append(f"\n**Results:**")
    lines.append(f"- ✅ Compliant: {len(compliant)}")
    lines.append(f"- ❌ Violations: {len(violations)}")
    lines.append(f"- ⚠️  Warnings: {len(warnings)}")
    
    if violations:
        lines.append("\n**CRITICAL VIOLATIONS (MUST FIX):**")
        for v in violations:
            lines.append(f"\n- **{v['requirement']}**")
            lines.append(f"  - Expected: {v['expected']}")
            lines.append(f"  - Found: {v['found']}")
            lines.append(f"  - Fix: {v['fix']}")
    
    if warnings:
        lines.append("\n**WARNINGS (SHOULD FIX):**")
        for w in warnings:
            lines.append(f"\n- **{w['requirement']}**")
            lines.append(f"  - Expected: {w['expected']}")
            lines.append(f"  - Found: {w['found']}")
    
    if compliant:
        lines.append("\n**COMPLIANT CONFIGURATIONS:**")
        for c in compliant:
            lines.append(f"- ✅ {c['requirement']}: {c['value']}")
    
    if not passed:
        lines.append("\n**⚠️  ACTION REQUIRED: Fix all violations before deploying to production.**")
    
    return "\n".join(lines)
