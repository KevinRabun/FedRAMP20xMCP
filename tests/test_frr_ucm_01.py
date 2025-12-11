"""
Tests for FRR-UCM-01: Cryptographic Module Documentation
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_ucm_01 import FRR_UCM_01_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_complete_crypto_documentation():
    """Test that complete crypto documentation passes."""
    analyzer = FRR_UCM_01_Analyzer()
    content = """
# Security Documentation

## Cryptographic Modules

We use the following NIST CMVP validated cryptographic modules to protect federal customer data:

- **BouncyCastle FIPS for Java** (Certificate #4616)
- **Azure Key Vault Premium HSM** (Certificate #3980) 
- **OpenSSL FIPS Module** (Certificate #4282)

All modules are FIPS 140-2 validated. Azure Key Vault represents an update stream
of the validated HSM module, maintained by Microsoft.

For more information, see: https://csrc.nist.gov/projects/cryptographic-module-validation-program
"""
    findings = analyzer.analyze_documentation(content, "SECURITY.md")
    assert len(findings) == 0, f"Complete documentation should have no findings, got {len(findings)}"
    print("[PASS] test_complete_crypto_documentation PASSED")


def test_missing_cmvp_reference():
    """Test detection of missing CMVP reference."""
    analyzer = FRR_UCM_01_Analyzer()
    content = """
# Security

## Cryptography

We use strong encryption to protect data:
- AES-256 for data at rest
- TLS 1.3 for data in transit
- RSA-2048 for key exchange

All cryptographic operations use industry-standard libraries.
"""
    findings = analyzer.analyze_documentation(content, "README.md")
    assert len(findings) >= 1, "Should detect missing CMVP reference"
    assert any('CMVP' in f.title for f in findings), "Should flag missing CMVP reference"
    print("[PASS] test_missing_cmvp_reference PASSED")


def test_missing_module_names():
    """Test detection of missing specific module names."""
    analyzer = FRR_UCM_01_Analyzer()
    content = """
# Cryptographic Modules

We use FIPS 140-2 validated cryptographic modules as required by FedRAMP.
All encryption is performed using NIST-approved algorithms.

CMVP validation certificates are maintained for all modules.
"""
    findings = analyzer.analyze_documentation(content, "docs/crypto.md")
    assert len(findings) >= 1, "Should detect missing module names"
    assert any('module names' in f.title.lower() for f in findings), "Should flag missing module names"
    print("[PASS] test_missing_module_names PASSED")


def test_missing_validation_status():
    """Test detection of missing validation status."""
    analyzer = FRR_UCM_01_Analyzer()
    content = """
# Cryptographic Modules

## Modules Used

- BouncyCastle FIPS for Java
- Azure Key Vault
- AWS KMS

These modules are used across our services to provide cryptographic protection
as required by CMVP guidelines.
"""
    findings = analyzer.analyze_documentation(content, "SECURITY.md")
    assert len(findings) >= 1, "Should detect missing validation status"
    assert any('validation status' in f.title.lower() for f in findings), "Should flag missing validation status"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("[PASS] test_missing_validation_status PASSED")


def test_no_crypto_documentation():
    """Test detection when no crypto documentation exists."""
    analyzer = FRR_UCM_01_Analyzer()
    project_files = [
        "src/main.py",
        "src/utils.py",
        "tests/test_main.py",
        "package.json"
    ]
    findings = analyzer.check_missing_crypto_documentation(project_files)
    assert len(findings) >= 1, "Should detect missing documentation"
    assert any('Missing' in f.title for f in findings), "Should flag missing documentation"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("[PASS] test_no_crypto_documentation PASSED")


def test_non_documentation_file_ignored():
    """Test that non-documentation files are ignored."""
    analyzer = FRR_UCM_01_Analyzer()
    content = """
import hashlib

def hash_data(data):
    return hashlib.sha256(data).hexdigest()
"""
    findings = analyzer.analyze_documentation(content, "src/crypto.py")
    assert len(findings) == 0, "Non-documentation files should be ignored"
    print("[PASS] test_non_documentation_file_ignored PASSED")


def test_partial_documentation():
    """Test detection of partial but incomplete documentation."""
    analyzer = FRR_UCM_01_Analyzer()
    content = """
# README

## Cryptographic Modules

Our application uses cryptographic modules for data protection.

We follow FIPS 140-2 guidelines and use validated modules where possible.
"""
    findings = analyzer.analyze_documentation(content, "README.md")
    # Should have findings for missing module names, CMVP reference, and validation status
    assert len(findings) >= 2, f"Should detect multiple issues in partial documentation, got {len(findings)}"
    print("[PASS] test_partial_documentation PASSED")


def test_analyzer_metadata():
    """Test FRR-UCM-01 analyzer metadata."""
    analyzer = FRR_UCM_01_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-UCM-01", "FRR_ID should be FRR-UCM-01"
    assert analyzer.FAMILY == "UCM", "Family should be UCM"
    assert analyzer.FRR_NAME == "Cryptographic Module Documentation", "Name mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Keyword should be MUST"
    assert analyzer.IMPACT_LOW == True, "Impact Low should be True"
    assert analyzer.IMPACT_MODERATE == True, "Impact Moderate should be True"
    assert analyzer.IMPACT_HIGH == True, "Impact High should be True"
    
    # Check evidence automation
    evidence = analyzer.get_evidence_automation_recommendations()
    assert evidence['frr_id'] == "FRR-UCM-01", "Evidence FRR ID mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def run_all_tests():
    """Run all FRR-UCM-01 tests."""
    test_functions = [
        ("Complete crypto documentation", test_complete_crypto_documentation),
        ("Missing CMVP reference", test_missing_cmvp_reference),
        ("Missing module names", test_missing_module_names),
        ("Missing validation status", test_missing_validation_status),
        ("No crypto documentation", test_no_crypto_documentation),
        ("Non-documentation file ignored", test_non_documentation_file_ignored),
        ("Partial documentation", test_partial_documentation),
        ("Analyzer metadata", test_analyzer_metadata),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-UCM-01 Tests ({len(test_functions)} tests)")
    print("=" * 70 + "\n")
    
    for test_name, test_func in test_functions:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_name} ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"Test Results: {passed}/{len(test_functions)} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\nALL TESTS PASSED [PASS]\n")
    else:
        print(f"\nSOME TESTS FAILED [FAIL]\n")
        exit(1)


if __name__ == "__main__":
    run_all_tests()
