"""
Test configuration file analysis functionality for C# analyzer.

Tests the appsettings.json security analysis capabilities including:
- Hardcoded secrets detection
- Connection string security
- Logging configuration
- HTTPS/HSTS settings
- Environment-specific validation
"""

import json
import tempfile
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from src.fedramp_20x_mcp.analyzers.base import Severity


def create_temp_appsettings(config: dict, filename: str = "appsettings.json") -> Path:
    """Create temporary appsettings.json file for testing."""
    temp_dir = Path(tempfile.mkdtemp())
    config_file = temp_dir / filename
    
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    
    # Create a dummy .csproj file so project root detection works
    csproj = temp_dir / "Test.csproj"
    csproj.write_text("<Project></Project>")
    
    # Create dummy C# file in the project
    cs_file = temp_dir / "Program.cs"
    cs_file.write_text("using System;")
    
    return cs_file


def test_hardcoded_secret_detection():
    """Test detection of hardcoded secrets in configuration files."""
    print("\n=== Test: Hardcoded Secret Detection ===")
    
    config = {
        "ConnectionStrings": {
            "Database": "Server=myserver;Database=mydb;User Id=admin;Password=MySecretP@ssw0rd123;"
        },
        "AzureStorage": {
            "AccountKey": "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890+AbCdEfGhIjKlMnOpQrStUvWxYz=="
        },
        "ApiSettings": {
            "ApiKey": "sk-live-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        }
    }
    
    cs_file = create_temp_appsettings(config)
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should detect hardcoded secrets
    secret_findings = [f for f in result.findings if "secret" in f.title.lower() or "password" in f.title.lower()]
    
    assert len(secret_findings) >= 2, f"Expected at least 2 secret findings, got {len(secret_findings)}"
    assert any(f.severity == Severity.HIGH for f in secret_findings), "Expected HIGH severity for hardcoded secrets"
    
    print(f"✅ PASS - Detected {len(secret_findings)} hardcoded secrets")
    for finding in secret_findings[:3]:
        print(f"  - {finding.title}: {finding.description}")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def test_connection_string_security():
    """Test connection string security validation."""
    print("\n=== Test: Connection String Security ===")
    
    config = {
        "ConnectionStrings": {
            "InsecureDB": "Server=myserver;Database=mydb;User Id=admin;Password=test123;Encrypt=false;",
            "SecureDB": "Server=myserver.database.windows.net;Database=mydb;Authentication=Active Directory Default;Encrypt=true;"
        }
    }
    
    cs_file = create_temp_appsettings(config)
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should detect unencrypted connection
    encryption_findings = [f for f in result.findings if "encrypt" in f.description.lower()]
    
    assert len(encryption_findings) >= 1, f"Expected encryption findings, got {len(encryption_findings)}"
    assert any(f.severity == Severity.HIGH for f in encryption_findings), "Expected HIGH severity for unencrypted connection"
    
    print(f"✅ PASS - Detected {len(encryption_findings)} connection security issues")
    for finding in encryption_findings:
        print(f"  - {finding.title}: {finding.description}")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def test_production_logging_configuration():
    """Test production logging configuration validation."""
    print("\n=== Test: Production Logging Configuration ===")
    
    config = {
        "Logging": {
            "LogLevel": {
                "Default": "Debug",
                "Microsoft.AspNetCore": "Trace"
            }
        }
    }
    
    cs_file = create_temp_appsettings(config, "appsettings.Production.json")
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should detect verbose logging in production
    logging_findings = [f for f in result.findings if "logging" in f.title.lower() or "debug" in f.description.lower()]
    
    assert len(logging_findings) >= 1, f"Expected logging findings, got {len(logging_findings)}"
    
    print(f"✅ PASS - Detected {len(logging_findings)} logging configuration issues")
    for finding in logging_findings:
        print(f"  - {finding.title}: {finding.description}")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.Production.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def test_https_configuration():
    """Test HTTPS endpoint configuration validation."""
    print("\n=== Test: HTTPS Configuration ===")
    
    config = {
        "Kestrel": {
            "Endpoints": {
                "Http": {
                    "Url": "http://*:80"
                }
            }
        }
    }
    
    cs_file = create_temp_appsettings(config, "appsettings.Production.json")
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should detect missing HTTPS endpoint in production
    https_findings = [f for f in result.findings if "https" in f.title.lower() or "https" in f.description.lower()]
    
    assert len(https_findings) >= 1, f"Expected HTTPS findings, got {len(https_findings)}"
    assert any(f.severity == Severity.HIGH for f in https_findings), "Expected HIGH severity for missing HTTPS"
    
    print(f"✅ PASS - Detected {len(https_findings)} HTTPS configuration issues")
    for finding in https_findings:
        print(f"  - {finding.title}: {finding.description}")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.Production.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def test_hsts_configuration():
    """Test HSTS MaxAge configuration validation."""
    print("\n=== Test: HSTS Configuration ===")
    
    config = {
        "Hsts": {
            "MaxAge": 86400  # Only 1 day (should be 1 year = 31536000)
        }
    }
    
    cs_file = create_temp_appsettings(config)
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should detect short HSTS MaxAge
    hsts_findings = [f for f in result.findings if "hsts" in f.title.lower() or "maxage" in f.description.lower()]
    
    assert len(hsts_findings) >= 1, f"Expected HSTS findings, got {len(hsts_findings)}"
    
    print(f"✅ PASS - Detected {len(hsts_findings)} HSTS configuration issues")
    for finding in hsts_findings:
        print(f"  - {finding.title}: {finding.description}")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def test_application_insights_missing():
    """Test detection of missing Application Insights in production."""
    print("\n=== Test: Application Insights Missing ===")
    
    config = {
        "Logging": {
            "LogLevel": {
                "Default": "Information"
            }
        }
    }
    
    cs_file = create_temp_appsettings(config, "appsettings.Production.json")
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should detect missing Application Insights in production
    appinsights_findings = [f for f in result.findings if "application insights" in f.description.lower()]
    
    assert len(appinsights_findings) >= 1, f"Expected Application Insights findings, got {len(appinsights_findings)}"
    
    print(f"✅ PASS - Detected {len(appinsights_findings)} Application Insights issues")
    for finding in appinsights_findings:
        print(f"  - {finding.title}: {finding.description}")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.Production.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def test_key_vault_reference():
    """Test that Key Vault references don't trigger false positives."""
    print("\n=== Test: Key Vault References (No False Positives) ===")
    
    config = {
        "ConnectionStrings": {
            "Database": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-connection)"
        },
        "AzureStorage": {
            "AccountKey": "${STORAGE_KEY}"  # Environment variable reference
        }
    }
    
    cs_file = create_temp_appsettings(config)
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should NOT detect secrets for Key Vault/environment variable references
    secret_findings = [f for f in result.findings if "secret" in f.title.lower() and "accountkey" in f.description.lower()]
    
    assert len(secret_findings) == 0, f"Expected no false positives for Key Vault references, got {len(secret_findings)}"
    
    print("✅ PASS - No false positives for Key Vault/environment variable references")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def test_managed_identity_connection():
    """Test that managed identity connections don't trigger warnings."""
    print("\n=== Test: Managed Identity Connections (No Warnings) ===")
    
    config = {
        "ConnectionStrings": {
            "Database": "Server=myserver.database.windows.net;Database=mydb;Authentication=Active Directory Default;"
        }
    }
    
    cs_file = create_temp_appsettings(config)
    
    analyzer = CSharpAnalyzer()
    code = "using Microsoft.Extensions.Configuration;"
    result = analyzer.analyze(code, str(cs_file))
    
    # Should NOT detect password issues for managed identity
    password_findings = [f for f in result.findings if "password" in f.title.lower() and "database" in f.description.lower()]
    
    assert len(password_findings) == 0, f"Expected no warnings for managed identity, got {len(password_findings)}"
    
    print("✅ PASS - No warnings for managed identity authentication")
    
    # Cleanup
    cs_file.parent.joinpath("appsettings.json").unlink(missing_ok=True)
    cs_file.parent.joinpath("Test.csproj").unlink(missing_ok=True)
    cs_file.unlink(missing_ok=True)
    cs_file.parent.rmdir()


def run_all_tests():
    """Run all configuration analysis tests."""
    print("\n" + "="*80)
    print("Running Configuration Analysis Tests for C# Analyzer")
    print("="*80)
    
    tests = [
        test_hardcoded_secret_detection,
        test_connection_string_security,
        test_production_logging_configuration,
        test_https_configuration,
        test_hsts_configuration,
        test_application_insights_missing,
        test_key_vault_reference,
        test_managed_identity_connection,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ FAIL - {test.__name__}: {str(e)}")
            failed += 1
        except Exception as e:
            print(f"\n❌ ERROR - {test.__name__}: {str(e)}")
            failed += 1
    
    print("\n" + "="*80)
    print(f"Test Results: {passed}/{len(tests)} passed, {failed}/{len(tests)} failed")
    print("="*80)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
