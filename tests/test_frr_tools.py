"""
Tests for FRR (FedRAMP Requirements) tools.

These tests verify that the FRR analysis tools work correctly for
code analysis, evidence automation, and requirement metadata.
"""
import asyncio
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from fedramp_20x_mcp.tools.frr import (
    analyze_frr_code_impl,
    analyze_frr_family_impl,
    list_frrs_by_family_impl,
    get_frr_metadata_impl,
    get_frr_evidence_automation_impl,
    get_frr_implementation_status_impl
)


async def test_analyze_frr_vdr_01_github_actions():
    """Test FRR-VDR-01 analysis on GitHub Actions workflow."""
    print("\n" + "=" * 80)
    print("Test: FRR-VDR-01 Analysis - GitHub Actions")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    # GitHub Actions workflow without vulnerability scanning
    code = """
name: Build and Deploy
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker image
        run: docker build -t myapp:latest .
      - name: Deploy
        run: echo "Deploying..."
"""
    
    result = await analyze_frr_code_impl(
        frr_id="FRR-VDR-01",
        code=code,
        language="github-actions",
        file_path=".github/workflows/deploy.yml",
        data_loader=loader
    )
    
    assert "FRR-VDR-01" in result
    assert "Vulnerability Detection" in result
    assert "VDR" in result
    print("✓ FRR-VDR-01 GitHub Actions analysis successful")
    print(f"Result length: {len(result)} characters")


async def test_analyze_frr_vdr_01_bicep():
    """Test FRR-VDR-01 analysis on Bicep infrastructure code."""
    print("\n" + "=" * 80)
    print("Test: FRR-VDR-01 Analysis - Bicep")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    # Bicep template without Defender for Cloud
    code = """
resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myVM'
  location: resourceGroup().location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
  }
}
"""
    
    result = await analyze_frr_code_impl(
        frr_id="FRR-VDR-01",
        code=code,
        language="bicep",
        file_path="main.bicep",
        data_loader=loader
    )
    
    assert "FRR-VDR-01" in result
    assert "findings" in result.lower() or "issue" in result.lower()
    print("✓ FRR-VDR-01 Bicep analysis successful")
    print(f"Result length: {len(result)} characters")


async def test_list_frrs_by_family_vdr():
    """Test listing all VDR family FRRs."""
    print("\n" + "=" * 80)
    print("Test: List FRRs by Family - VDR")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    result = await list_frrs_by_family_impl("VDR", loader)
    
    assert "VDR" in result
    assert "FRR-VDR-01" in result
    assert "Vulnerability Detection" in result
    print("✓ List VDR FRRs successful")
    print(f"Result length: {len(result)} characters")


async def test_list_frrs_by_family_rsc():
    """Test listing all RSC family FRRs."""
    print("\n" + "=" * 80)
    print("Test: List FRRs by Family - RSC")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    result = await list_frrs_by_family_impl("RSC", loader)
    
    assert "RSC" in result
    # RSC analyzers not yet implemented, so we expect "not yet implemented" or similar
    print("✓ List RSC FRRs successful")
    print(f"Result length: {len(result)} characters")


async def test_get_frr_metadata():
    """Test getting FRR-VDR-01 metadata."""
    print("\n" + "=" * 80)
    print("Test: Get FRR Metadata")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    result = await get_frr_metadata_impl("FRR-VDR-01", loader)
    
    assert "FRR-VDR-01" in result
    assert "Vulnerability Detection" in result
    assert "VDR" in result
    assert "NIST" in result or "nist" in result.lower()
    print("✓ Get FRR metadata successful")
    print(f"Result length: {len(result)} characters")


async def test_get_frr_evidence_automation():
    """Test getting FRR-VDR-01 evidence automation recommendations."""
    print("\n" + "=" * 80)
    print("Test: Get FRR Evidence Automation")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    result = await get_frr_evidence_automation_impl("FRR-VDR-01", loader)
    
    assert "FRR-VDR-01" in result
    assert "Evidence" in result or "evidence" in result.lower()
    assert "Azure" in result or "azure" in result.lower()
    print("✓ Get FRR evidence automation successful")
    print(f"Result length: {len(result)} characters")


async def test_analyze_frr_family_vdr():
    """Test analyzing code against entire VDR family."""
    print("\n" + "=" * 80)
    print("Test: Analyze FRR Family - VDR")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    code = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm test
"""
    
    result = await analyze_frr_family_impl(
        family="VDR",
        code=code,
        language="github-actions",
        file_path=".github/workflows/ci.yml",
        data_loader=loader
    )
    
    assert "VDR" in result
    assert "Family" in result
    print("✓ Analyze VDR family successful")
    print(f"Result length: {len(result)} characters")


async def test_get_frr_implementation_status():
    """Test getting FRR implementation status summary."""
    print("\n" + "=" * 80)
    print("Test: Get FRR Implementation Status")
    print("=" * 80)
    
    loader = FedRAMPDataLoader()
    await loader.load_data()
    
    result = await get_frr_implementation_status_impl(loader)
    
    assert "FRR" in result or "Implementation" in result
    assert "Status" in result or "status" in result
    print("✓ Get FRR implementation status successful")
    print(f"Result length: {len(result)} characters")


async def run_all_tests():
    """Run all FRR tool tests."""
    print("\n" + "="*80)
    print("FedRAMP 20x MCP - FRR Tools Test Suite")
    print("="*80)
    
    tests = [
        ("Analyze FRR-VDR-01 GitHub Actions", test_analyze_frr_vdr_01_github_actions),
        ("Analyze FRR-VDR-01 Bicep", test_analyze_frr_vdr_01_bicep),
        ("List VDR Family FRRs", test_list_frrs_by_family_vdr),
        ("List RSC Family FRRs", test_list_frrs_by_family_rsc),
        ("Get FRR Metadata", test_get_frr_metadata),
        ("Get FRR Evidence Automation", test_get_frr_evidence_automation),
        ("Analyze VDR Family", test_analyze_frr_family_vdr),
        ("Get FRR Implementation Status", test_get_frr_implementation_status),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            await test_func()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"\nX FAILED: {test_name}")
            print(f"Error: {str(e)}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*80)
    print(f"Test Results: {passed}/{len(tests)} passed, {failed} failed")
    print("="*80)
    
    if failed > 0:
        exit(1)


if __name__ == "__main__":
    asyncio.run(run_all_tests())
