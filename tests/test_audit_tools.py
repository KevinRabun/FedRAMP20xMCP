"""Quick test script for audit tools."""
import asyncio
import io

# Set UTF-8 encoding for stdout

from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from fedramp_20x_mcp.tools.audit import (
    get_ksi_coverage_summary_impl,
    get_ksi_coverage_status_impl,
    get_coverage_disclaimer
)

async def main():
    """Test audit tools."""
    print("Loading data...")
    loader = FedRAMPDataLoader()
    data = await loader.load_data()
    
    print("\n" + "="*80)
    print("TEST 1: Coverage Summary")
    print("="*80)
    summary = await get_ksi_coverage_summary_impl(loader)
    print(summary[:800])  # First 800 chars
    
    print("\n" + "="*80)
    print("TEST 2: Specific KSI Status (KSI-IAM-01)")
    print("="*80)
    status = await get_ksi_coverage_status_impl('KSI-IAM-01', loader)
    print(status)
    
    print("\n" + "="*80)
    print("TEST 3: Invalid KSI (should show error)")
    print("="*80)
    invalid = await get_ksi_coverage_status_impl('KSI-INVALID-99', loader)
    print(invalid)
    
    print("\n" + "="*80)
    print("TEST 4: Disclaimer Text")
    print("="*80)
    disclaimer = get_coverage_disclaimer()
    print(disclaimer)
    
    print("\n[OK] All audit tool tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
