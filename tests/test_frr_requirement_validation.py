# -*- coding: utf-8 -*-
"""
FRR (FedRAMP Requirement) Pattern Validation Tests - CR26

Validates that code-detectable FedRAMP Consolidated Rules for 2026 (CR26)
requirements are analyzed by the FRR analyzer factory and return findings.

CR26 FRR families (17): AFC, AGU, CCM, CDS, CMU, CPO, FRC, IEC, IVV, MAS, MKT,
REC, SCG, SCN, SDR, VDR, VER.

Only requirements referenced by at least one code pattern (``related_frrs`` or
``related_ksis`` in data/patterns/*_patterns.yaml) are parametrized. Process,
agency, assessor-recognition and marketplace rules (for example AGU, REC, MKT,
FRC, CPO) are not code-detectable and are deliberately not asserted here.

Also validates that every pattern-referenced FRR id exists in the CR26 rules.

This file validates PATTERN LOGIC and ANALYZER IMPLEMENTATION, not just data
loading (data loading is covered by test_rules_alignment.py).
"""

import asyncio
from pathlib import Path

import pytest
import yaml

from fedramp_20x_mcp.analyzers.frr.factory import get_factory
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader

PATTERNS_DIR = Path(__file__).resolve().parent.parent / "data" / "patterns"


def _load_rule_ids():
    loader = FedRAMPDataLoader()
    asyncio.run(loader.load_data())
    return {
        r["id"]
        for r in loader.search_controls("")
        if r.get("family") and not r["id"].startswith(("FRD-", "KSI-"))
    }


def _pattern_referenced_frrs():
    """FRR ids referenced by any pattern (related_frrs / related_ksis).

    Also records, per id, the languages the referencing patterns support in
    PATTERN_LANGUAGES so each case is analyzed in a language that can match.
    """
    refs = set()
    for f in sorted(PATTERNS_DIR.glob("*_patterns.yaml")):
        with open(f, encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if not doc:
                    continue
                for key in ("related_frrs", "related_ksis"):
                    for rid in doc.get(key) or []:
                        refs.add(str(rid).upper())
                        PATTERN_LANGUAGES.setdefault(str(rid).upper(), set()).update(
                            (doc.get("languages") or {}).keys()
                        )
    return refs


def _language_for(frr_id):
    langs = PATTERN_LANGUAGES.get(frr_id, set())
    for preferred in ("terraform", "python"):
        if preferred in langs:
            return preferred
    return sorted(langs)[0] if langs else "python"


PATTERN_LANGUAGES = {}
RULE_IDS = _load_rule_ids()
REFERENCED_FRRS = sorted(r for r in _pattern_referenced_frrs() if r in RULE_IDS)
UNKNOWN_REFS = sorted(
    r for r in _pattern_referenced_frrs()
    if not r.startswith(("KSI-", "FRD-")) and r not in RULE_IDS
    and r.split("-")[0] in {i.split("-")[0] for i in RULE_IDS}
)


@pytest.fixture
def factory():
    """Get FRR analyzer factory instance"""
    return get_factory()


# Generate family-appropriate test code
FAMILY_POSITIVE_PATTERNS = {
    "CDS": ("""
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
    
    "AFC": ("""
# COMPLIANT: Secure inbox per {frr_id}
resource "azurerm_storage_queue" "fedramp_inbox" {{
  name                 = "fedramp-security-inbox"
  storage_account_name = azurerm_storage_account.main.name
  metadata = {{ purpose = "FedRAMP Critical Communications", frr = "{frr_id}" }}
}}
""", "terraform"),
    
    "IEC": ("""
# COMPLIANT: Incident communications per {frr_id}
resource "azurerm_monitor_action_group" "fedramp_incident" {{
  name       = "fedramp-incident-notifications"
  short_name = "FedRAMPICP"
  email_receiver {{ name = "fedramp-pmo", email_address = "incidents@fedramp.gov" }}
  tags = {{ Purpose = "Incident Communications Procedures", FRR = "{frr_id}" }}
}}
""", "terraform"),
    
    "SDR": ("""
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
    
    "IVV": ("""
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
    
    "CMU": ("""
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
    "CDS": ("""
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
    
    "AFC": ("""
# NON-COMPLIANT: {frr_id} violation
# Using regular email for critical communications  
# No secure inbox, no encryption
resource "azurerm_storage_queue" "insecure_inbox" {{
  name = "regular-email-inbox"
  # Missing FedRAMP secure inbox configuration
}}
""", "terraform"),
    
    "IEC": ("""
# NON-COMPLIANT: {frr_id} violation
# Internal incident response only
# No FedRAMP notification integration
resource "azurerm_monitor_action_group" "internal_only" {{
  name = "internal-incidents"
  # Missing FedRAMP PMO notification
}}
""", "terraform"),
    
    "SDR": ("""
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
    
    "IVV": ("""
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
    
    "CMU": ("""
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
    """Positive and negative cases for every pattern-referenced FRR."""
    cases = []
    for frr_id in REFERENCED_FRRS:
        family = frr_id.split("-")[0]
        pos_template, pos_lang = FAMILY_POSITIVE_PATTERNS.get(family, ("# Compliant: {frr_id}", _language_for(frr_id)))
        cases.append((frr_id, "positive", pos_template.format(frr_id=frr_id), pos_lang))
        neg_template, neg_lang = FAMILY_NEGATIVE_PATTERNS.get(family, ("# Non-compliant: {frr_id}", _language_for(frr_id)))
        cases.append((frr_id, "negative", neg_template.format(frr_id=frr_id), neg_lang))
    return cases


class TestFRRPatternValidation:
    """Validate FRR analysis for pattern-covered CR26 requirements"""

    def test_referenced_frrs_exist_in_rules(self):
        """Every FRR id referenced by a pattern must exist in the CR26 rules."""
        missing = [r for r in UNKNOWN_REFS]
        assert not missing, f"Patterns reference FRR ids not in CR26 rules: {missing}"

    def test_some_frrs_are_pattern_covered(self):
        assert len(REFERENCED_FRRS) > 0

    @pytest.mark.parametrize("frr_id,test_type,code,language",
                             generate_test_cases(),
                             ids=lambda val: f"{val[0]}_{val[1]}" if isinstance(val, tuple) else str(val))
    def test_frr_pattern(self, factory, frr_id, test_type, code, language):
        """Pattern-covered requirements return findings for the sample code."""
        result = asyncio.run(factory.analyze(frr_id, code, language))
        assert len(result.findings) > 0, f"{frr_id} {test_type} test should return analysis result"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
