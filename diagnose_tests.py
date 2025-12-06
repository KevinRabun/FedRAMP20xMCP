"""
Diagnostic script to debug dependency checking tests.
Run this to understand why tests are failing.
"""
import os
import tempfile
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.cve_fetcher import CVEFetcher

def test_cve_fetcher_directly():
    """Test CVE fetcher in isolation."""
    print("\n=== Testing CVE Fetcher Directly ===")
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("❌ GITHUB_TOKEN not set!")
        print("   Set it with: $env:GITHUB_TOKEN = 'your_token_here'")
        return False
    
    print(f"✓ GITHUB_TOKEN found (length: {len(token)})")
    
    fetcher = CVEFetcher(token)
    
    # Test 1: Get latest version (should work now)
    print("\n1. Testing get_latest_version()...")
    try:
        latest = fetcher.get_latest_version("System.Text.Json", "nuget")
        print(f"   System.Text.Json latest: {latest}")
        if latest and latest >= "10.0.0":
            print("   ✓ PASS - Got current version from NuGet API")
        else:
            print(f"   ❌ FAIL - Expected >= 10.0.0, got {latest}")
            return False
    except Exception as e:
        print(f"   ❌ FAIL - Exception: {e}")
        return False
    
    # Test 2: Check vulnerabilities for old version
    print("\n2. Testing get_package_vulnerabilities()...")
    try:
        vulns = fetcher.get_package_vulnerabilities("System.Text.Json", "nuget", "5.0.0")
        print(f"   System.Text.Json 5.0.0 has {len(vulns)} vulnerabilities")
        if vulns:
            print(f"   First vulnerability: {vulns[0].get('summary', 'N/A')}")
            print("   ✓ PASS - Found vulnerabilities for old version")
        else:
            print("   ⚠ WARNING - No vulnerabilities found (may be temporary API issue)")
    except Exception as e:
        print(f"   ❌ FAIL - Exception: {e}")
        return False
    
    print("\n✓ CVE Fetcher working correctly\n")
    return True

def test_analyzer_with_temp_project():
    """Test analyzer with temporary project like the tests do."""
    print("\n=== Testing Analyzer with Temporary Project ===")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        print(f"Temp directory: {temp_path}")
        
        # Create .csproj
        csproj_content = """<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="System.Text.Json" Version="6.0.0" />
    <PackageReference Include="Azure.Identity" Version="1.5.0" />
  </ItemGroup>
</Project>"""
        
        csproj_path = temp_path / "TestProject.csproj"
        csproj_path.write_text(csproj_content)
        print(f"✓ Created {csproj_path}")
        
        # Create .cs file
        cs_content = "using System;\n\npublic class Test { }"
        cs_path = temp_path / "Test.cs"
        cs_path.write_text(cs_content)
        print(f"✓ Created {cs_path}")
        
        # Run analyzer
        print("\nRunning analyzer...")
        analyzer = CSharpAnalyzer()
        result = analyzer.analyze(cs_content, str(cs_path))
        
        print(f"\nResults:")
        print(f"  Total findings: {len(result.findings)}")
        
        # Check for outdated findings
        outdated = [f for f in result.findings if "outdated" in f.title.lower()]
        print(f"  Outdated package findings: {len(outdated)}")
        if outdated:
            for f in outdated:
                print(f"    - {f.title} (severity: {f.severity.value})")
        else:
            print("    ❌ PROBLEM: No outdated findings!")
            print("    Expected to find System.Text.Json 6.0.0 and Azure.Identity 1.5.0 as outdated")
        
        # Check for vulnerability findings
        vuln = [f for f in result.findings if "vulnerable" in f.title.lower()]
        print(f"  Vulnerability findings: {len(vuln)}")
        if vuln:
            for f in vuln:
                print(f"    - {f.title} (severity: {f.severity.value})")
        
        # Debug: Check all findings
        if result.findings:
            print(f"\n  All findings:")
            for f in result.findings:
                print(f"    - {f.requirement_id}: {f.title}")
        else:
            print("  ❌ PROBLEM: No findings at all!")
        
        return len(outdated) >= 2  # Should find both packages as outdated

def main():
    print("="*60)
    print("FedRAMP20xMCP Dependency Checking Diagnostic")
    print("="*60)
    
    # Test 1: CVE fetcher
    if not test_cve_fetcher_directly():
        print("\n❌ CVE Fetcher test failed. Fix this first.")
        return 1
    
    # Test 2: Analyzer integration
    if not test_analyzer_with_temp_project():
        print("\n❌ Analyzer integration test failed.")
        print("\nPossible issues:")
        print("1. _find_csproj_files() not finding the .csproj")
        print("2. _parse_csproj() not extracting packages")
        print("3. _check_package_vulnerabilities() not being called")
        print("4. CVE fetcher returning data but findings not being created")
        return 1
    
    print("\n✓ All diagnostic tests passed!")
    print("\nThe tests should work. If they're still failing:")
    print("1. Make sure GITHUB_TOKEN is set in test environment")
    print("2. Run: python -m pytest tests/test_dependency_checking.py -v -s")
    print("   (The -s flag shows print statements)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
