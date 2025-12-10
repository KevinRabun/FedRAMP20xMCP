"""
Tests for FRR-RSC-04: Secure Defaults on Provisioning
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_rsc_04 import FRR_RSC_04_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_bicep_insecure_admin_username():
    """Test detection of insecure default admin username in Bicep."""
    analyzer = FRR_RSC_04_Analyzer()
    code = """
resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: 'myserver'
  location: 'eastus'
  properties: {
    administratorLogin: 'admin'
    administratorLoginPassword: sqlPassword
  }
}
"""
    findings = analyzer.analyze_bicep(code, "main.bicep")
    assert len(findings) > 0, "Should detect insecure admin username"
    # Check that we have a HIGH severity finding about insecure admin username
    high_findings = [f for f in findings if f.severity == Severity.HIGH and "default admin username" in f.title.lower()]
    assert len(high_findings) > 0, "Should have HIGH severity finding about default admin username"
    print("✓ test_bicep_insecure_admin_username PASSED")


def test_bicep_missing_aad_auth():
    """Test detection of SQL Server without Azure AD authentication."""
    analyzer = FRR_RSC_04_Analyzer()
    code = """
resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: 'myserver'
  location: 'eastus'
  properties: {
    administratorLogin: 'sqladmin123'
    administratorLoginPassword: sqlPassword
  }
}
"""
    findings = analyzer.analyze_bicep(code, "main.bicep")
    assert len(findings) > 0, "Should detect missing Azure AD authentication"
    assert any("azure ad" in f.title.lower() for f in findings)
    print("✓ test_bicep_missing_aad_auth PASSED")


def test_terraform_admin_without_mfa():
    """Test detection of admin IAM user without MFA requirement."""
    analyzer = FRR_RSC_04_Analyzer()
    code = """
resource "aws_iam_user" "admin_user" {
  name = "admin-user"
  path = "/admin/"
}

resource "aws_iam_user_policy_attachment" "admin_attach" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""
    findings = analyzer.analyze_terraform(code, "iam.tf")
    assert len(findings) > 0, "Should detect admin user without MFA"
    assert any("mfa" in f.title.lower() for f in findings)
    assert findings[0].severity == Severity.HIGH
    print("✓ test_terraform_admin_without_mfa PASSED")


def test_terraform_weak_password_policy():
    """Test detection of weak password policy."""
    analyzer = FRR_RSC_04_Analyzer()
    code = """
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_numbers               = true
  require_symbols               = true
}
"""
    findings = analyzer.analyze_terraform(code, "password_policy.tf")
    assert len(findings) > 0, "Should detect weak password length"
    assert any("password" in f.title.lower() for f in findings)
    print("✓ test_terraform_weak_password_policy PASSED")


def test_bicep_secure_config():
    """Test that secure Bicep configuration passes."""
    analyzer = FRR_RSC_04_Analyzer()
    code = """
resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: 'myserver'
  location: 'eastus'
  properties: {
    administratorLogin: 'org_specific_admin_username'
    administratorLoginPassword: sqlPassword
    azureADOnlyAuthentication: true
  }
}
"""
    findings = analyzer.analyze_bicep(code, "main.bicep")
    # Should not flag issues with secure config
    assert len([f for f in findings if f.severity == Severity.HIGH]) == 0, "Secure config should not have HIGH findings"
    print("✓ test_bicep_secure_config PASSED")


def test_analyzer_metadata():
    """Test FRR-RSC-04 analyzer metadata."""
    analyzer = FRR_RSC_04_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-RSC-04", "FRR_ID should be FRR-RSC-04"
    assert analyzer.FAMILY == "RSC", "Family should be RSC"
    assert analyzer.FRR_NAME == "Secure Defaults on Provisioning", "Name mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Keyword should be MUST"
    assert analyzer.IMPACT_LOW == True, "Impact Low should be True"
    assert analyzer.IMPACT_MODERATE == True, "Impact Moderate should be True"
    assert analyzer.IMPACT_HIGH == True, "Impact High should be True"
    assert analyzer.CODE_DETECTABLE == "Partial", "Code detectable should be Partial"
    
    print("✓ test_analyzer_metadata PASSED")


def test_evidence_automation_recommendations():
    """Test evidence automation recommendations."""
    analyzer = FRR_RSC_04_Analyzer()
    
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert recommendations['frr_id'] == "FRR-RSC-04", "FRR_ID mismatch"
    assert recommendations['code_detectable'] == "Partial", "Should be Partial"
    assert len(recommendations['evidence_artifacts']) > 0, "Should have evidence artifacts"
    assert len(recommendations['manual_validation_steps']) > 0, "Should have validation steps"
    
    print("✓ test_evidence_automation_recommendations PASSED")


def run_all_tests():
    """Run all FRR-RSC-04 tests."""
    test_functions = [
        ("Bicep insecure admin username", test_bicep_insecure_admin_username),
        ("Bicep missing AAD auth", test_bicep_missing_aad_auth),
        ("Terraform admin without MFA", test_terraform_admin_without_mfa),
        ("Terraform weak password policy", test_terraform_weak_password_policy),
        ("Bicep secure config", test_bicep_secure_config),
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence automation recommendations", test_evidence_automation_recommendations),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-RSC-04 Tests ({len(test_functions)} tests)")
    print("=" * 70 + "\n")
    
    for test_name, test_func in test_functions:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_name} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_name} ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"Test Results: {passed}/{len(test_functions)} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\nALL TESTS PASSED ✓\n")
    else:
        print(f"\nSOME TESTS FAILED ✗\n")
        print("TODO: Implement remaining tests to achieve 100% pass rate")
        exit(1)


if __name__ == "__main__":
    run_all_tests()
