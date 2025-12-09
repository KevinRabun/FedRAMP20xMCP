"""
Tests for KSI-CMT-03 Enhanced Analyzer: Automated Testing and Validation

Test coverage:
- Python: pytest/unittest detection, test functions, assertions
- C#: xUnit/NUnit/MSTest detection, test methods, assertions
- Java: JUnit/TestNG detection, test methods, assertions
- JavaScript: Jest/Mocha detection, test functions, assertions
"""

import sys
sys.path.insert(0, 'src')

from fedramp_20x_mcp.analyzers.ksi.ksi_cmt_03 import KSI_CMT_03_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_missing_test_framework():
    """Test detection of test file without framework import."""
    code = """
def test_feature():
    result = feature_function()
    assert result == expected
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "python", "test_feature.py")
    
    print(f"\n[Python Missing Framework] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues == 1
    assert any("Without Testing Framework" in f.title for f in result.findings)
    assert result.findings[0].severity == Severity.MEDIUM
    print("[PASS] Python missing test framework detected")


def test_python_with_pytest():
    """Test detection when pytest is imported."""
    code = """
import pytest

def test_feature():
    result = feature_function()
    assert result is not None
    assert result.status == 'success'
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "python", "test_feature.py")
    
    print(f"\n[Python With Pytest] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    # Should pass - has framework and test with assertion
    assert result.total_issues == 0
    print("[PASS] Python with pytest recognized correctly")


def test_python_test_without_assertions():
    """Test detection of test function without assertions."""
    code = """
import pytest

def test_feature():
    result = feature_function()
    # Missing assertions!
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "python", "test_feature.py")
    
    print(f"\n[Python Test Without Assertions] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues == 1
    assert any("Without Assertions" in f.title for f in result.findings)
    assert result.findings[0].severity == Severity.HIGH
    print("[PASS] Python test without assertions detected")


def test_csharp_missing_test_framework():
    """Test detection of C# test file without framework."""
    code = """
public class FeatureTest
{
    public void TestFeature()
    {
        var result = FeatureMethod();
        Assert.Equal(expected, result);
    }
}
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "csharp", "FeatureTest.cs")
    
    print(f"\n[C# Missing Framework] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues == 1
    assert any("Without Testing Framework" in f.title for f in result.findings)
    print("[PASS] C# missing test framework detected")


def test_csharp_with_xunit():
    """Test detection when xUnit is used."""
    code = """
using Xunit;

public class FeatureTest
{
    [Fact]
    public void TestFeature()
    {
        var result = FeatureMethod();
        Assert.NotNull(result);
        Assert.Equal("expected", result.Status);
    }
}
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "csharp", "FeatureTest.cs")
    
    print(f"\n[C# With xUnit] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    # Should pass - has framework and test with assertions
    assert result.total_issues == 0
    print("[PASS] C# with xUnit recognized correctly")


def test_csharp_test_without_assertions():
    """Test detection of C# test method without assertions."""
    code = """
using Xunit;

public class FeatureTest
{
    [Fact]
    public void TestFeature()
    {
        var result = FeatureMethod();
        // Missing assertions!
    }
}
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "csharp", "FeatureTest.cs")
    
    print(f"\n[C# Test Without Assertions] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues == 1
    assert any("Without Assertions" in f.title for f in result.findings)
    assert result.findings[0].severity == Severity.HIGH
    print("[PASS] C# test without assertions detected")


def test_java_missing_test_framework():
    """Test detection of Java test file without framework."""
    code = """
public class FeatureTest {
    public void testFeature() {
        Result result = featureMethod();
        assertEquals(expected, result);
    }
}
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "java", "FeatureTest.java")
    
    print(f"\n[Java Missing Framework] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues == 1
    assert any("Without Testing Framework" in f.title for f in result.findings)
    print("[PASS] Java missing test framework detected")


def test_java_with_junit():
    """Test detection when JUnit is used."""
    code = """
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class FeatureTest {
    @Test
    public void testFeature() {
        Result result = featureMethod();
        assertNotNull(result);
        assertEquals("expected", result.getStatus());
    }
}
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "java", "FeatureTest.java")
    
    print(f"\n[Java With JUnit] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    # Should pass - has framework and test with assertions
    assert result.total_issues == 0
    print("[PASS] Java with JUnit recognized correctly")


def test_java_test_without_assertions():
    """Test detection of Java test method without assertions."""
    code = """
import org.junit.jupiter.api.Test;

public class FeatureTest {
    @Test
    public void testFeature() {
        Result result = featureMethod();
        // Missing assertions!
    }
}
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "java", "FeatureTest.java")
    
    print(f"\n[Java Test Without Assertions] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues == 1
    assert any("Without Assertions" in f.title for f in result.findings)
    assert result.findings[0].severity == Severity.HIGH
    print("[PASS] Java test without assertions detected")


def test_javascript_missing_test_framework():
    """Test detection of JavaScript test file without framework."""
    code = """
describe('Feature', () => {
  it('should work correctly', () => {
    const result = featureFunction();
    expect(result).toBeDefined();
  });
});
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "javascript", "feature.test.js")
    
    print(f"\n[JavaScript Missing Framework] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues == 1
    assert any("Without Testing Framework" in f.title for f in result.findings)
    print("[PASS] JavaScript missing test framework detected")


def test_javascript_with_jest():
    """Test detection when Jest is used."""
    code = """
import { describe, it, expect } from 'jest';

describe('Feature', () => {
  it('should work correctly', () => {
    const result = featureFunction();
    expect(result).toBeDefined();
    expect(result.status).toBe('success');
  });
});
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "javascript", "feature.test.js")
    
    print(f"\n[JavaScript With Jest] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    # Should pass - has framework and test with assertions
    assert result.total_issues == 0
    print("[PASS] JavaScript with Jest recognized correctly")


def test_javascript_test_without_assertions():
    """Test detection of JavaScript test without assertions."""
    code = """
import { describe, it, expect } from 'vitest';

describe('Feature', () => {
  it('should work correctly', () => {
    const result = featureFunction();
    // Missing assertions!
  });
});
"""
    analyzer = KSI_CMT_03_Analyzer()
    result = analyzer.analyze(code, "javascript", "feature.test.js")
    
    print(f"\n[JavaScript Test Without Assertions] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    # We detect both describe and it blocks without assertions
    assert result.total_issues == 2
    assert all("Without Assertions" in f.title for f in result.findings)
    assert all(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] JavaScript test without assertions detected")


def test_factory_function():
    """Test factory function returns correct instance."""
    from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    factory = get_factory()
    assert factory is not None
    
    # Test factory can create analyzer
    analyzer = factory.get_analyzer("KSI-CMT-03")
    assert analyzer is not None
    print("[PASS] Factory function works correctly")


if __name__ == "__main__":
    print("\n=== KSI-CMT-03 Enhanced Analyzer Tests ===\n")
    
    tests = [
        ("Python missing framework", test_python_missing_test_framework),
        ("Python with pytest", test_python_with_pytest),
        ("Python test without assertions", test_python_test_without_assertions),
        ("C# missing framework", test_csharp_missing_test_framework),
        ("C# with xUnit", test_csharp_with_xunit),
        ("C# test without assertions", test_csharp_test_without_assertions),
        ("Java missing framework", test_java_missing_test_framework),
        ("Java with JUnit", test_java_with_junit),
        ("Java test without assertions", test_java_test_without_assertions),
        ("JavaScript missing framework", test_javascript_missing_test_framework),
        ("JavaScript with Jest", test_javascript_with_jest),
        ("JavaScript test without assertions", test_javascript_test_without_assertions),
        ("Factory function", test_factory_function),
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
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} test(s) failed")
    print(f"{'='*60}\n")
    
    sys.exit(0 if failed == 0 else 1)

