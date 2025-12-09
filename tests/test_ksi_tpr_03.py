#!/usr/bin/env python3
"""
Comprehensive tests for KSI-TPR-03 (Supply Chain Risk Management)

Tests AST-first analysis for:
- Python: HTTP package sources, missing integrity checks
- C#: HTTP NuGet sources, disabled signature validation
- Java: HTTP Maven repos, missing dependency verification
- TypeScript: HTTP npm registries, missing package-lock.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_http_source():
    """Test Python HTTP package source (HIGH)"""
    code = """
import subprocess
subprocess.run(['pip', 'install', '--index-url', 'http://pypi.org/simple', 'requests'])
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'python')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "HTTP" in result.findings[0].title
    print("[PASS] Python HTTP source detected (HIGH)")


def test_python_requirements_no_hash():
    """Test requirements.txt without hashes (MEDIUM)"""
    code = """requests==2.28.0
flask>=2.0.0
django<4.0
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'python', file_path='requirements.txt')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    # Should detect missing hashes
    has_hash_finding = any('hash' in f.title.lower() or 'integrity' in f.title.lower() for f in result.findings)
    assert has_hash_finding, "Should detect missing hash verification"
    print("[PASS] Python missing hashes detected")


def test_python_secure():
    """Test Python with HTTPS (passes)"""
    code = """
import subprocess
subprocess.run(['pip', 'install', 'requests'])  # Default HTTPS
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'python')
    
    # Should not detect HTTP issues
    http_findings = [f for f in result.findings if 'HTTP' in f.title and f.severity == Severity.HIGH]
    assert len(http_findings) == 0, f"Should not detect HTTP issues, got {len(http_findings)}"
    print("[PASS] Python HTTPS passes")


def test_csharp_http_nuget():
    """Test C# HTTP NuGet source (HIGH)"""
    code = """
<configuration>
  <packageSources>
    <add key="MySource" value="http://myserver/nuget" />
  </packageSources>
</configuration>
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'csharp', file_path='nuget.config')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "HTTP" in result.findings[0].title or "NuGet" in result.findings[0].title
    print("[PASS] C# HTTP NuGet source detected (HIGH)")


def test_csharp_disabled_signature():
    """Test C# disabled signature validation (MEDIUM)"""
    code = """
<configuration>
  <config>
    <add key="signatureValidationMode" value="none" />
  </config>
</configuration>
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'csharp', file_path='nuget.config')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    # Should detect disabled signature validation
    has_sig_finding = any('signature' in f.title.lower() for f in result.findings)
    assert has_sig_finding, "Should detect disabled signature validation"
    print("[PASS] C# disabled signature validation detected")


def test_csharp_secure():
    """Test C# with HTTPS (passes)"""
    code = """
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'csharp', file_path='nuget.config')
    
    # Should not detect HTTP issues
    http_findings = [f for f in result.findings if 'HTTP' in f.title and f.severity == Severity.HIGH]
    assert len(http_findings) == 0, f"Should not detect HTTP issues, got {len(http_findings)}"
    print("[PASS] C# HTTPS passes")


def test_java_http_maven():
    """Test Java HTTP Maven repository (HIGH)"""
    code = """
<repositories>
  <repository>
    <id>custom-repo</id>
    <url>http://repo.example.com/maven2</url>
  </repository>
</repositories>
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'java', file_path='pom.xml')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "HTTP" in result.findings[0].title or "Maven" in result.findings[0].title
    print("[PASS] Java HTTP Maven repo detected (HIGH)")


def test_java_secure():
    """Test Java with HTTPS (passes)"""
    code = """
<repositories>
  <repository>
    <id>central</id>
    <url>https://repo.maven.apache.org/maven2</url>
  </repository>
</repositories>
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'java', file_path='pom.xml')
    
    # Should not detect HTTP issues
    http_findings = [f for f in result.findings if 'HTTP' in f.title and f.severity == Severity.HIGH]
    assert len(http_findings) == 0, f"Should not detect HTTP issues, got {len(http_findings)}"
    print("[PASS] Java HTTPS passes")


def test_typescript_http_registry():
    """Test TypeScript HTTP npm registry (HIGH)"""
    code = """
{
  "publishConfig": {
    "registry": "http://registry.npmjs.org"
  }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'typescript', file_path='package.json')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "HTTP" in result.findings[0].title or "registry" in result.findings[0].title
    print("[PASS] TypeScript HTTP registry detected (HIGH)")


def test_typescript_secure():
    """Test TypeScript with HTTPS (passes)"""
    code = """
{
  "publishConfig": {
    "registry": "https://registry.npmjs.org"
  }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-TPR-03', code, 'typescript', file_path='package.json')
    
    # Should not detect HTTP issues
    http_findings = [f for f in result.findings if 'HTTP' in f.title and f.severity == Severity.HIGH]
    assert len(http_findings) == 0, f"Should not detect HTTP issues, got {len(http_findings)}"
    print("[PASS] TypeScript HTTPS passes")


if __name__ == '__main__':
    print("=" * 80)
    print("KSI-TPR-03 COMPREHENSIVE TEST SUITE")
    print("Testing: Supply Chain Risk Management")
    print("=" * 80)
    print()
    
    tests = [
        ("Python HTTP source", test_python_http_source),
        ("Python requirements no hash", test_python_requirements_no_hash),
        ("Python secure", test_python_secure),
        ("C# HTTP NuGet", test_csharp_http_nuget),
        ("C# disabled signature", test_csharp_disabled_signature),
        ("C# secure", test_csharp_secure),
        ("Java HTTP Maven", test_java_http_maven),
        ("Java secure", test_java_secure),
        ("TypeScript HTTP registry", test_typescript_http_registry),
        ("TypeScript secure", test_typescript_secure),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            failed += 1
    
    print()
    print("=" * 80)
    print(f"Total: {len(tests)} | Passed: {passed} | Failed: {failed}")
    if failed == 0:
        print("ALL KSI-TPR-03 TESTS PASSED [PASS]")
    else:
        print(f"TESTS FAILED: {failed}/{len(tests)} [FAIL]")
    print("=" * 80)
    
    sys.exit(0 if failed == 0 else 1)
