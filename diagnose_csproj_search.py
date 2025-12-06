"""Diagnostic script to test FULL dependency analysis flow."""
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer

# Test with temporary directory like the tests do
with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    
    # Create .csproj with OUTDATED packages (like test 2)
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
    
    cs_path = temp_path / "TestFile.cs"
    cs_path.write_text("using System;\n\npublic class Test { }")
    
    print("=" * 60)
    print("TEST: Full Analyzer Flow (Outdated Packages)")
    print("=" * 60)
    print(f"Created: {csproj_path}")
    print(f"Created: {cs_path}")
    print()
    
    # Run analyzer exactly like the test does
    analyzer = CSharpAnalyzer()
    code = cs_path.read_text()
    result = analyzer.analyze(code, str(cs_path))
    
    print(f"\nTotal findings: {len(result.findings)}")
    
    # Check for outdated package findings
    outdated_findings = [f for f in result.findings if "outdated" in f.title.lower()]
    print(f"Outdated package findings: {len(outdated_findings)}")
    
    if outdated_findings:
        print("\n✓ SUCCESS: Found outdated packages:")
        for finding in outdated_findings:
            print(f"  - {finding.title}")
            print(f"    Severity: {finding.severity}")
            print(f"    Requirement: {finding.requirement_id}")
    else:
        print("\n✗ FAILURE: No outdated package findings")
        print("\nAll findings:")
        for finding in result.findings:
            print(f"  - {finding.title} ({finding.requirement_id})")

