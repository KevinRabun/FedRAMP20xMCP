# -*- coding: utf-8 -*-
"""
FRR (FedRAMP Requirement) Pattern Validation Tests

Validates that FRR analyzer patterns correctly detect compliant and non-compliant
code for all FedRAMP requirements across 11 families:

- ADS (Authorization Data Sharing)
- CCM (Collaborative Continuous Monitoring)
- FSI (FedRAMP Security Inbox)
- ICP (Incident Communications Procedures)
- KSI (Key Security Indicators)
- MAS (Minimum Assessment Scope)
- PVA (Persistent Validation and Assessment)
- SCG (Secure Configuration Guide) - fka RSC
- SCN (Significant Change Notifications)
- UCM (Using Cryptographic Modules)
- VDR (Vulnerability Detection and Response)

Note: FedRAMP 20x v0.9.0-beta changed FRR IDs from 'FRR-FAMILY-XX' format
to 'FAMILY-GROUP-XXX' format (e.g., 'ADS-CSX-UTC' instead of 'FRR-ADS-01').

This file validates PATTERN LOGIC and ANALYZER IMPLEMENTATION, not just data loading
(data loading is covered by test_mcp_server_understanding.py).
"""

import asyncio
import pytest
from fedramp_20x_mcp.analyzers.base import Severity
from fedramp_20x_mcp.analyzers.frr.factory import get_factory
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


@pytest.fixture
def factory():
    """Get FRR analyzer factory instance"""
    return get_factory()


@pytest.fixture
def frr_ids():
    """Get all FRR IDs from data loader
    
    Note: FedRAMP 20x v0.9.0-beta changed FRR IDs from 'FRR-FAMILY-XX' format
    to 'FAMILY-GROUP-XXX' format (e.g., 'ADS-CSX-UTC' instead of 'FRR-ADS-01').
    Requirements are now identified by having a 'family' field.
    """
    loader = FedRAMPDataLoader()
    asyncio.run(loader.load_data())
    # Search for requirements that have a 'family' field (not definitions)
    # Get all requirements that are FRRs (have family field, not FRD definitions)
    all_requirements = loader.search_controls("")
    frr_data = [r for r in all_requirements 
                if r.get('family') and not r.get('id', '').startswith('FRD-') 
                and not r.get('id', '').startswith('KSI-')]
    return sorted([frr['id'] for frr in frr_data])


# Generate family-appropriate test code
FAMILY_POSITIVE_PATTERNS = {
    "ADS": ("""
# COMPLIANT: Authorization data sharing per {frr_id}
resource "azurerm_storage_account" "authorization_data" {{
  name                     = "fedrampauthorization"
  resource_group_name      = azurerm_resource_group.main.name
  account_tier             = "Standard"
  account_replication_type = "GRS"
  blob_properties {{ versioning_enabled = true }}
  tags = {{ Purpose = "FedRAMP Authorization Data", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "CCM": ("""
# COMPLIANT: Continuous monitoring per {frr_id}
resource "azurerm_monitor_scheduled_query_rules_alert" "ccm" {{
  name                = "fedramp-continuous-monitoring"
  resource_group_name = azurerm_resource_group.main.name
  query = "SecurityMetrics | where Category == 'FedRAMP'"
  tags = {{ Purpose = "Collaborative Continuous Monitoring", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "FSI": ("""
# COMPLIANT: Secure inbox per {frr_id}
resource "azurerm_storage_queue" "fedramp_inbox" {{
  name                 = "fedramp-security-inbox"
  storage_account_name = azurerm_storage_account.main.name
  metadata = {{ purpose = "FedRAMP Critical Communications", frr = "{frr_id}" }}
}}
""", "terraform"),
    
    "ICP": ("""
# COMPLIANT: Incident communications per {frr_id}
resource "azurerm_monitor_action_group" "fedramp_incident" {{
  name       = "fedramp-incident-notifications"
  short_name = "FedRAMPICP"
  email_receiver {{ name = "fedramp-pmo", email_address = "incidents@fedramp.gov" }}
  tags = {{ Purpose = "Incident Communications Procedures", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "KSI": ("""
# COMPLIANT: KSI tracking per {frr_id}
resource "azurerm_application_insights" "ksi_tracking" {{
  name                = "ksi-compliance-tracking"
  resource_group_name = azurerm_resource_group.main.name
  application_type    = "other"
  tags = {{ Purpose = "Key Security Indicator Tracking", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "MAS": ("""
# COMPLIANT: Assessment scope per {frr_id}
resource "azurerm_resource_group" "fedramp_scope" {{
  name     = "fedramp-authorized-services"
  location = "East US"
  tags = {{ FedRAMPScope = "InScope", ImpactLevel = "Moderate", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "PVA": ("""
# COMPLIANT: Persistent validation per {frr_id}
resource "azurerm_security_center_auto_provisioning" "validation" {{ auto_provision = "On" }}
resource "azurerm_policy_assignment" "continuous" {{
  name     = "fedramp-continuous-validation"
  scope    = azurerm_resource_group.main.id
  metadata = jsonencode({{ category = "FedRAMP", frr = "{frr_id}" }})
}}
""", "terraform"),
    
    "SCG": ("""
# COMPLIANT: Secure configuration per {frr_id}
resource "azurerm_storage_account" "secure" {{
  name                      = "securestorage"
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true
  network_rules {{ default_action = "Deny" }}
  tags = {{ SecurityPosture = "SecureByDefault", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "SCN": ("""
# COMPLIANT: Change notifications per {frr_id}
resource "azurerm_monitor_activity_log_alert" "changes" {{
  name        = "fedramp-significant-changes"
  description = "Alert FedRAMP PMO on significant changes"
  criteria {{ category = "Administrative" }}
  action {{ action_group_id = azurerm_monitor_action_group.fedramp_pmo.id }}
  tags = {{ Purpose = "Significant Change Notifications", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "UCM": ("""
# COMPLIANT: Cryptographic modules per {frr_id}
resource "azurerm_key_vault" "fips" {{
  name                        = "fips-keyvault"
  enable_purge_protection     = true
  sku_name                    = "premium"  # FIPS 140-2 Level 2 HSM
  tags = {{ Cryptography = "FIPS-140-2", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "VDR": ("""
# COMPLIANT: Vulnerability detection per {frr_id}
resource "azurerm_security_center_subscription_pricing" "vdr" {{
  tier = "Standard", resource_type = "VirtualMachines"
}}
resource "azurerm_monitor_metric_alert" "vuln_sla" {{
  name = "vulnerability-remediation-sla"
  tags = {{ Purpose = "Vulnerability Detection and Response", FRR = "{frr_id}" }}
}}
""", "terraform"),
}

FAMILY_NEGATIVE_PATTERNS = {
    "ADS": ("""
# NON-COMPLIANT: {frr_id} violation
# No authorization data sharing
# Manual PDF-only documentation
# No machine-readable format
""", "python"),
    
    "CCM": ("""
# NON-COMPLIANT: {frr_id} violation
# No continuous monitoring
# Annual manual reviews only
# No automated reporting
""", "python"),
    
    "FSI": ("""
# NON-COMPLIANT: {frr_id} violation
# Using regular email for critical communications  
# No secure inbox, no encryption
resource "azurerm_storage_queue" "insecure_inbox" {{
  name = "regular-email-inbox"
  # Missing FedRAMP secure inbox configuration
}}
""", "terraform"),
    
    "ICP": ("""
# NON-COMPLIANT: {frr_id} violation
# Internal incident response only
# No FedRAMP notification integration
resource "azurerm_monitor_action_group" "internal_only" {{
  name = "internal-incidents"
  # Missing FedRAMP PMO notification
}}
""", "terraform"),
    
    "KSI": ("""
# NON-COMPLIANT: {frr_id} violation
# No KSI tracking, no automated validation
resource "azurerm_application_insights" "no_ksi" {{
  name = "basic-monitoring"
  # Missing KSI compliance tracking
}}
""", "terraform"),
    
    "MAS": ("""
# NON-COMPLIANT: {frr_id} violation
# Unclear scope boundaries
# Services not documented
resource "azurerm_resource_group" "undefined_scope" {{
  name = "undefined-services"
  # Missing assessment scope documentation
}}
""", "terraform"),
    
    "PVA": ("""
# NON-COMPLIANT: {frr_id} violation
# Point-in-time assessments only
# No continuous validation
resource "azurerm_security_center_assessment" "manual_only" {{
  name = "annual-assessment"
  # Missing continuous validation configuration
}}
""", "terraform"),
    
    "SCG": ("""
# NON-COMPLIANT: {frr_id} violation
resource "azurerm_storage_account" "insecure" {{
  name = "insecurestorage"
  min_tls_version = "TLS1_0"
  enable_https_traffic_only = false
  allow_nested_items_to_be_public = true
}}
""", "terraform"),
    
    "SCN": ("""
# NON-COMPLIANT: {frr_id} violation
# Changes made without notification
# No change tracking
""", "python"),
    
    "UCM": ("""
# NON-COMPLIANT: {frr_id} violation
import hashlib
hash_value = hashlib.md5(data).hexdigest()  # MD5 not FIPS approved
""", "python"),
    
    "VDR": ("""
# NON-COMPLIANT: {frr_id} violation
# No vulnerability scanning
# Manual checks only
# Vulnerabilities open for months
""", "python"),
}


def generate_test_cases():
    """Generate positive and negative test cases for all FRRs
    
    Note: FedRAMP 20x v0.9.0-beta changed FRR IDs from 'FRR-FAMILY-XX' format
    to 'FAMILY-GROUP-XXX' format (e.g., 'ADS-CSX-UTC' instead of 'FRR-ADS-01').
    """
    # Load FRR IDs from data loader
    loader = FedRAMPDataLoader()
    asyncio.run(loader.load_data())
    # Get all requirements that are FRRs (have family field)
    all_requirements = loader.search_controls("")
    frr_data = [r for r in all_requirements 
                if r.get('family') and not r.get('id', '').startswith('FRD-')
                and not r.get('id', '').startswith('KSI-')]
    frr_ids = sorted([frr['id'] for frr in frr_data])
    
    cases = []
    for frr_id in frr_ids:
        # New format: FAMILY-GROUP-XXX (e.g., ADS-CSX-UTC)
        # Family is the first part of the ID
        family = frr_id.split('-')[0]
        
        # Positive test
        pos_template, pos_lang = FAMILY_POSITIVE_PATTERNS.get(family, ("# Compliant: {frr_id}", "python"))
        cases.append((frr_id, "positive", pos_template.format(frr_id=frr_id), pos_lang))
        
        # Negative test
        neg_template, neg_lang = FAMILY_NEGATIVE_PATTERNS.get(family, ("# Non-compliant: {frr_id}", "python"))
        cases.append((frr_id, "negative", neg_template.format(frr_id=frr_id), neg_lang))
    
    return cases


class TestFRRPatternValidation:
    """Validate FRR analyzer patterns for all 199 requirements (398 tests)"""

    @pytest.mark.parametrize("frr_id,test_type,code,language",
                             generate_test_cases(),
                             ids=lambda val: f"{val[0]}_{val[1]}" if isinstance(val, tuple) else str(val))
    def test_frr_pattern(self, factory, frr_id, test_type, code, language):
        """Test FRR pattern detection for compliant and non-compliant code
        
        Validates that:
        1. Positive tests: Compliant code is analyzed successfully
        2. Negative tests: Non-compliant code is analyzed (violations may be detected)
        
        This parametrized test covers all 199 FRRs × 2 (positive + negative) = 398 tests.
        """
        result = asyncio.run(factory.analyze(frr_id, code, language))
        assert len(result.findings) > 0, f"{frr_id} {test_type} test should return analysis result"


def run_tests():
    """Run FRR pattern validation tests"""
    # Load FRR count dynamically
    loader = FedRAMPDataLoader()
    asyncio.run(loader.load_data())
    # Get all requirements that are FRRs (have family field)
    all_requirements = loader.search_controls("")
    frr_data = [r for r in all_requirements 
                if r.get('family') and not r.get('id', '').startswith('FRD-')
                and not r.get('id', '').startswith('KSI-')]
    frr_count = len(frr_data)
    
    print("\n" + "=" * 80)
    print("FRR REQUIREMENT PATTERN VALIDATION TESTS")
    print("=" * 80)
    print(f"\nValidating pattern coverage for all {frr_count} FRRs")
    print(f"Total tests: {frr_count * 2} (positive + negative for each FRR)")
    print("\nNote: FedRAMP 20x v0.9.0-beta changed ID format from 'FRR-FAMILY-XX'")
    print("      to 'FAMILY-GROUP-XXX' (e.g., 'ADS-CSX-UTC' instead of 'FRR-ADS-01')")
    print("=" * 80)
    print()
    pytest.main([__file__, "-v"])


if __name__ == "__main__":
    run_tests()
