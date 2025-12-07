"""
Test KSI-centric analyzer architecture with self-contained KSI files.

Tests:
1. KSI-IAM-06 analyzer metadata verification
2. Python detection for suspicious activity
3. C# detection for account lockout
4. Java detection for Spring Security
5. TypeScript detection for Passport.js
6. Bicep detection for Azure Monitor alerts
7. Terraform detection for monitoring
8. Factory registration and discovery
"""

import sys
import io
import os

# Set UTF-8 encoding for stdout (Windows compatibility)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.ksi.ksi_iam_06 import KSI_IAM_06_Analyzer
from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from src.fedramp_20x_mcp.analyzers.base import Severity


def test_ksi_iam_06_metadata():
    """Test KSI-IAM-06 metadata is correct from official source."""
    print("\n=== Test 1: KSI-IAM-06 Metadata Verification ===")
    
    analyzer = KSI_IAM_06_Analyzer()
    metadata = analyzer.get_metadata()
    
    # Verify official data
    assert metadata['ksi_id'] == "KSI-IAM-06", "KSI ID mismatch"
    assert metadata['ksi_name'] == "Suspicious Activity", "KSI name mismatch"
    assert "Automatically disable or otherwise secure accounts" in metadata['statement'], "Statement mismatch"
    assert metadata['family'] == "IAM", "Family mismatch"
    assert metadata['family_name'] == "Identity and Access Management", "Family name mismatch"
    assert metadata['impact']['low'] == True, "Low impact mismatch"
    assert metadata['impact']['moderate'] == True, "Moderate impact mismatch"
    assert "ac-2" in metadata['controls'], "Missing NIST control ac-2"
    assert "ac-7" in metadata['controls'], "Missing NIST control ac-7"
    
    print("✓ All metadata verified against official FedRAMP 20x source")
    print(f"  KSI: {metadata['ksi_id']} - {metadata['ksi_name']}")
    print(f"  NIST Controls: {', '.join(metadata['controls'])}")
    return True


def test_python_detection():
    """Test Python detection for KSI-IAM-06."""
    print("\n=== Test 2: Python Detection (Django AXES) ===")
    
    analyzer = KSI_IAM_06_Analyzer()
    
    # Test code with missing AXES_FAILURE_LIMIT
    code = """
import axes
from django.conf import settings

INSTALLED_APPS = [
    'django.contrib.auth',
    'axes',
]
"""
    
    result = analyzer.analyze(code, "python", "settings.py")
    
    assert len(result.findings) > 0, "Should detect missing AXES_FAILURE_LIMIT"
    assert result.ksi_id == "KSI-IAM-06", "KSI ID mismatch in result"
    
    finding = result.findings[0]
    assert finding.severity == Severity.HIGH, "Should be HIGH severity"
    assert "AXES_FAILURE_LIMIT" in finding.title, "Finding title should mention AXES_FAILURE_LIMIT"
    
    print(f"✓ Detected {len(result.findings)} issue(s)")
    print(f"  Issue: {finding.title}")
    print(f"  Severity: {finding.severity.value}")
    return True


def test_csharp_detection():
    """Test C# detection for KSI-IAM-06."""
    print("\n=== Test 3: C# Detection (ASP.NET Core Identity) ===")
    
    analyzer = KSI_IAM_06_Analyzer()
    
    # Test code with lockout disabled
    code = """
services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    // Missing: options.Lockout.MaxFailedAccessAttempts
    // Missing: options.Lockout.DefaultLockoutTimeSpan
});
"""
    
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    assert len(result.findings) > 0, "Should detect missing lockout configuration"
    
    # Check for specific findings
    titles = [f.title for f in result.findings]
    assert any("MaxFailedAccessAttempts" in t for t in titles), "Should detect missing MaxFailedAccessAttempts"
    assert any("lockout" in t.lower() for t in titles), "Should detect lockout issues"
    
    print(f"✓ Detected {len(result.findings)} issue(s)")
    for finding in result.findings:
        print(f"  - {finding.title} ({finding.severity.value})")
    return True


def test_java_detection():
    """Test Java detection for KSI-IAM-06."""
    print("\n=== Test 4: Java Detection (Spring Security) ===")
    
    analyzer = KSI_IAM_06_Analyzer()
    
    # Test code with missing account lock status
    code = """
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        // TODO: Add account lock status check
        return new org.springframework.security.core.userdetails.User(
            user.getUsername(),
            user.getPassword(),
            getAuthorities(user)
        );
    }
}
"""
    
    result = analyzer.analyze(code, "java", "CustomUserDetailsService.java")
    
    assert len(result.findings) > 0, "Should detect missing account lock status"
    
    finding = result.findings[0]
    assert "account lock" in finding.title.lower() or "account" in finding.title.lower(), \
        "Should detect missing account lock mechanism"
    
    print(f"✓ Detected {len(result.findings)} issue(s)")
    print(f"  Issue: {finding.title}")
    return True


def test_typescript_detection():
    """Test TypeScript detection for KSI-IAM-06."""
    print("\n=== Test 5: TypeScript Detection (Passport.js) ===")
    
    analyzer = KSI_IAM_06_Analyzer()
    
    # Test code without rate limiting
    code = """
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';

passport.use(new LocalStrategy(
    async (username, password, done) => {
        const user = await User.findOne({ username });
        if (!user || !await user.validatePassword(password)) {
            return done(null, false);
        }
        return done(null, user);
    }
));

app.post('/login', passport.authenticate('local'));
"""
    
    result = analyzer.analyze(code, "typescript", "auth.ts")
    
    assert len(result.findings) > 0, "Should detect missing rate limiting"
    
    has_rate_limit_finding = any("rate limit" in f.title.lower() for f in result.findings)
    has_lockout_finding = any("lockout" in f.title.lower() for f in result.findings)
    
    assert has_rate_limit_finding or has_lockout_finding, "Should detect missing rate limiting or lockout"
    
    print(f"✓ Detected {len(result.findings)} issue(s)")
    for finding in result.findings:
        print(f"  - {finding.title}")
    return True


def test_bicep_detection():
    """Test Bicep detection for KSI-IAM-06."""
    print("\n=== Test 6: Bicep Detection (Azure Monitor Alerts) ===")
    
    analyzer = KSI_IAM_06_Analyzer()
    
    # Test code without failed sign-in monitoring
    code = """
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2021-06-01' = {
  name: 'my-workspace'
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
  }
}

// Missing: Alert rule for failed sign-ins
"""
    
    result = analyzer.analyze(code, "bicep", "monitoring.bicep")
    
    assert len(result.findings) > 0, "Should detect missing sign-in monitoring"
    
    finding = result.findings[0]
    assert "sign" in finding.title.lower() or "monitor" in finding.title.lower(), \
        "Should detect missing sign-in monitoring"
    
    print(f"✓ Detected {len(result.findings)} issue(s)")
    print(f"  Issue: {finding.title}")
    return True


def test_terraform_detection():
    """Test Terraform detection for KSI-IAM-06."""
    print("\n=== Test 7: Terraform Detection (Azure Monitor) ===")
    
    analyzer = KSI_IAM_06_Analyzer()
    
    # Test code with Log Analytics but no alerts
    code = """
resource "azurerm_log_analytics_workspace" "main" {
  name                = "my-workspace"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
}

# TODO: Add monitoring for failed sign-in attempts
"""
    
    result = analyzer.analyze(code, "terraform", "monitoring.tf")
    
    assert len(result.findings) > 0, "Should detect missing alert rules"
    
    finding = result.findings[0]
    assert "alert" in finding.title.lower() or "monitor" in finding.title.lower(), \
        "Should detect missing monitoring alerts"
    
    print(f"✓ Detected {len(result.findings)} issue(s)")
    print(f"  Issue: {finding.title}")
    return True


def test_factory_registration():
    """Test factory registration and discovery."""
    print("\n=== Test 8: Factory Registration ===")
    
    factory = get_factory()
    
    # Check KSI-IAM-06 is registered
    ksi_list = factory.list_ksis()
    assert "KSI-IAM-06" in ksi_list, "KSI-IAM-06 should be registered"
    
    # Get analyzer via factory
    analyzer = factory.get_analyzer("KSI-IAM-06")
    assert analyzer is not None, "Should retrieve analyzer from factory"
    assert analyzer.ksi_id == "KSI-IAM-06", "Analyzer KSI ID should match"
    
    # Get metadata via factory
    metadata = factory.get_ksi_metadata("KSI-IAM-06")
    assert metadata is not None, "Should retrieve metadata from factory"
    assert metadata['ksi_name'] == "Suspicious Activity", "Metadata should match"
    
    print(f"✓ Factory registered {len(ksi_list)} KSI(s)")
    print(f"  Registered: {', '.join(ksi_list)}")
    return True


def test_factory_analyze():
    """Test factory analyze functionality."""
    print("\n=== Test 9: Factory Analysis ===")
    
    factory = get_factory()
    
    # Analyze code with weak lockout
    code = """
services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    options.Lockout.MaxFailedAccessAttempts = 20; // Too high!
});
"""
    
    result = factory.analyze("KSI-IAM-06", code, "csharp", "Startup.cs")
    
    assert result is not None, "Factory should return analysis result"
    assert len(result.findings) > 0, "Should detect weak lockout threshold"
    
    finding = result.findings[0]
    assert "20" in finding.description, "Should mention the weak threshold value"
    
    print(f"✓ Factory analysis detected {len(result.findings)} issue(s)")
    print(f"  Issue: {finding.title}")
    return True


def run_all_tests():
    """Run all KSI analyzer architecture tests."""
    print("=" * 70)
    print("KSI-CENTRIC ANALYZER ARCHITECTURE TESTS")
    print("=" * 70)
    print("\nTesting self-contained KSI analyzers with embedded metadata")
    print("and multi-language support (Python, C#, Java, TypeScript, Bicep, Terraform)")
    
    tests = [
        ("Metadata Verification", test_ksi_iam_06_metadata),
        ("Python Detection", test_python_detection),
        ("C# Detection", test_csharp_detection),
        ("Java Detection", test_java_detection),
        ("TypeScript Detection", test_typescript_detection),
        ("Bicep Detection", test_bicep_detection),
        ("Terraform Detection", test_terraform_detection),
        ("Factory Registration", test_factory_registration),
        ("Factory Analysis", test_factory_analyze),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                print(f"✗ {name} FAILED")
        except Exception as e:
            failed += 1
            print(f"✗ {name} FAILED: {str(e)}")
    
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {passed}/{len(tests)} passed")
    if failed == 0:
        print("✓ ALL TESTS PASSED - KSI-centric architecture working correctly!")
        print("\nArchitecture Benefits Demonstrated:")
        print("  ✓ Self-contained KSI files with embedded official metadata")
        print("  ✓ Single file per KSI (ksi_iam_06.py) contains ALL language support")
        print("  ✓ Python, C#, Java, TypeScript, Bicep, Terraform in one analyzer")
        print("  ✓ No external lookups needed - all KSI info in the file")
        print("  ✓ Factory pattern for easy registration and discovery")
        print("  ✓ Verified against official FedRAMP 20x source (version 25.11C)")
    else:
        print(f"✗ {failed} TEST(S) FAILED")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
