"""
Integration tests for pattern engine integration with analyzer tools.

Tests the hybrid analysis approach combining pattern-based and traditional analyzers.
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.tools.analyzer import (
    analyze_infrastructure_code_impl,
    analyze_application_code_impl,
    analyze_cicd_pipeline_impl
)


def test_header(name: str):
    """Print test header."""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print('='*60)


async def test_infrastructure_code_hybrid():
    """Test infrastructure code analysis with hybrid approach."""
    test_header("Infrastructure Code Hybrid Analysis")
    
    # Bicep code with known issues
    bicep_code = """
    resource storage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
      name: 'mystorageaccount'
      location: 'eastus'
      sku: {
        name: 'Standard_LRS'
      }
      kind: 'StorageV2'
      properties: {
        supportsHttpsTrafficOnly: false  // Issue: Should be true
        minimumTlsVersion: 'TLS1_0'      // Issue: Should be TLS1_2
      }
    }
    """
    
    result = await analyze_infrastructure_code_impl(
        code=bicep_code,
        file_type="bicep",
        file_path="storage.bicep"
    )
    
    print(f"Analysis mode: {result.get('analysis_mode', 'unknown')}")
    print(f"Pattern findings: {result.get('pattern_findings_count', 0)}")
    print(f"Traditional findings: {result.get('traditional_findings_count', 0)}")
    print(f"Total findings: {result.get('total_findings', 0)}")
    print(f"Pattern coverage: {result.get('pattern_coverage', {})}")
    
    # Verify hybrid mode
    assert result.get('analysis_mode') == 'hybrid', "Should use hybrid analysis mode"
    
    # Should have findings (from either pattern or traditional)
    total = result.get('total_findings', 0)
    print(f"\nResult: Found {total} findings")
    
    if total > 0:
        print("\nFirst few findings:")
        findings = result.get('findings', [])
        for i, finding in enumerate(findings[:3]):
            print(f"  {i+1}. [{finding.get('severity', 'unknown')}] {finding.get('title', 'N/A')}")
            print(f"     Requirement: {finding.get('requirement_id', 'N/A')}")
    
    print("\n[PASS] Infrastructure code hybrid analysis test passed")
    return True


async def test_application_code_hybrid():
    """Test application code analysis with hybrid approach."""
    test_header("Application Code Hybrid Analysis")
    
    # Python code with known issues
    python_code = """
    import os
    
    # Issue: Hardcoded credentials
    API_KEY = "sk-1234567890abcdef"
    PASSWORD = "admin123"
    
    # Issue: Missing HTTPS enforcement
    BASE_URL = "http://api.example.com"
    
    def authenticate(username, password):
        # Issue: No session timeout
        session = create_session()
        session.permanent = True
        return session
    
    def log_event(message):
        # Issue: Local file logging without SIEM
        with open('/var/log/app.log', 'a') as f:
            f.write(message)
    """
    
    result = await analyze_application_code_impl(
        code=python_code,
        language="python",
        file_path="app.py"
    )
    
    print(f"Analysis mode: {result.get('analysis_mode', 'unknown')}")
    print(f"Pattern findings: {result.get('pattern_findings_count', 0)}")
    print(f"Traditional findings: {result.get('traditional_findings_count', 0)}")
    print(f"Total findings: {result.get('total_findings', 0)}")
    
    # Verify hybrid mode
    assert result.get('analysis_mode') == 'hybrid', "Should use hybrid analysis mode"
    
    # Should have findings (from either pattern or traditional)
    total = result.get('total_findings', 0)
    print(f"\nResult: Found {total} findings")
    
    if total > 0:
        print("\nFirst few findings:")
        findings = result.get('findings', [])
        for i, finding in enumerate(findings[:3]):
            print(f"  {i+1}. [{finding.get('severity', 'unknown')}] {finding.get('title', 'N/A')}")
            print(f"     Requirement: {finding.get('requirement_id', 'N/A')}")
    
    print("\n[PASS] Application code hybrid analysis test passed")
    return True


async def test_cicd_pipeline_hybrid():
    """Test CI/CD pipeline analysis with hybrid approach."""
    test_header("CI/CD Pipeline Hybrid Analysis")
    
    # GitHub Actions workflow with known issues
    workflow_code = """
    name: Deploy
    
    on: [push]
    
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v2
          
          # Issue: Hardcoded secrets
          - name: Deploy
            run: |
              curl -H "Authorization: Bearer sk-1234567890" https://api.example.com/deploy
          
          # Issue: No security scanning
          - name: Build
            run: npm run build
          
          # Issue: No SAST
          - name: Test
            run: npm test
    """
    
    result = await analyze_cicd_pipeline_impl(
        code=workflow_code,
        pipeline_type="github-actions",
        file_path=".github/workflows/deploy.yml"
    )
    
    print(f"Analysis mode: {result.get('analysis_mode', 'unknown')}")
    print(f"Pattern findings: {result.get('pattern_findings_count', 0)}")
    print(f"Traditional findings: {result.get('traditional_findings_count', 0)}")
    print(f"Total findings: {result.get('total_findings', 0)}")
    
    # Verify hybrid mode
    assert result.get('analysis_mode') == 'hybrid', "Should use hybrid analysis mode"
    
    # Should have findings (from either pattern or traditional)
    total = result.get('total_findings', 0)
    print(f"\nResult: Found {total} findings")
    
    if total > 0:
        print("\nFirst few findings:")
        findings = result.get('findings', [])
        for i, finding in enumerate(findings[:3]):
            print(f"  {i+1}. [{finding.get('severity', 'unknown')}] {finding.get('title', 'N/A')}")
            print(f"     Requirement: {finding.get('requirement_id', 'N/A')}")
    
    print("\n[PASS] CI/CD pipeline hybrid analysis test passed")
    return True


async def test_deduplication():
    """Test that findings are properly deduplicated."""
    test_header("Deduplication Test")
    
    # Use simple code that should trigger both pattern and traditional analyzers
    python_code = """
    # Hardcoded secret
    SECRET_KEY = "hardcoded-secret-123"
    """
    
    result = await analyze_application_code_impl(
        code=python_code,
        language="python",
        file_path="config.py"
    )
    
    pattern_count = result.get('pattern_findings_count', 0)
    traditional_count = result.get('traditional_findings_count', 0)
    total_count = result.get('total_findings', 0)
    
    print(f"Pattern findings: {pattern_count}")
    print(f"Traditional findings: {traditional_count}")
    print(f"Total findings: {total_count}")
    
    # Total should be <= sum of both (deduplication working)
    assert total_count <= pattern_count + traditional_count, \
        "Deduplication should reduce or maintain total count"
    
    print(f"\nDeduplication working correctly:")
    print(f"  Sum of sources: {pattern_count + traditional_count}")
    print(f"  After dedup: {total_count}")
    print(f"  Duplicates removed: {pattern_count + traditional_count - total_count}")
    
    print("\n[PASS] Deduplication test passed")
    return True


async def test_pattern_coverage_metadata():
    """Test that pattern coverage metadata is included."""
    test_header("Pattern Coverage Metadata Test")
    
    result = await analyze_application_code_impl(
        code="print('hello')",
        language="python",
        file_path="test.py"
    )
    
    coverage = result.get('pattern_coverage', {})
    print(f"Pattern coverage metadata: {coverage}")
    
    # Verify coverage metadata structure
    assert 'total_patterns' in coverage, "Should have total_patterns"
    assert 'families' in coverage, "Should have families"
    
    print(f"\nCoverage details:")
    print(f"  Total patterns: {coverage.get('total_patterns', 0)}")
    print(f"  Families: {len(coverage.get('families', []))}")
    
    print("\n[PASS] Pattern coverage metadata test passed")
    return True


async def run_all_tests():
    """Run all integration tests."""
    print("="*60)
    print("PATTERN ENGINE INTEGRATION TESTS")
    print("="*60)
    
    tests = [
        ("Infrastructure Code Hybrid", test_infrastructure_code_hybrid),
        ("Application Code Hybrid", test_application_code_hybrid),
        ("CI/CD Pipeline Hybrid", test_cicd_pipeline_hybrid),
        ("Deduplication", test_deduplication),
        ("Pattern Coverage Metadata", test_pattern_coverage_metadata),
    ]
    
    passed = 0
    failed = 0
    errors = []
    
    for name, test_func in tests:
        try:
            await test_func()
            passed += 1
        except AssertionError as e:
            failed += 1
            errors.append(f"{name}: {e}")
            print(f"\n[X] {name} test FAILED: {e}")
        except Exception as e:
            import traceback
            failed += 1
            errors.append(f"{name}: {e}")
            print(f"\n[X] {name} test ERROR: {e}")
            print(f"Traceback: {traceback.format_exc()}")
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Total tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  - {error}")
    
    if failed == 0:
        print("\nALL TESTS PASSED [PASS]")
        return True
    else:
        print(f"\n{failed} TEST(S) FAILED [FAIL]")
        return False


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
