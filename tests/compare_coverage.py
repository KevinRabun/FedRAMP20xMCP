import sys
import asyncio
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.ksi.factory import get_factory as get_ksi_factory
from fedramp_20x_mcp.analyzers.pattern_tool_adapter import analyze_with_patterns

async def compare_coverage():
    bicep_code = """
    resource storage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
      name: 'mystorageaccount'
      location: 'eastus'
      properties: {
        supportsHttpsTrafficOnly: false
        minimumTlsVersion: 'TLS1_0'
      }
    }
    """
    
    # Pattern engine
    pattern_result = await analyze_with_patterns(bicep_code, "bicep", "storage.bicep")
    pattern_reqs = {f.requirement_id for f in pattern_result.findings}
    
    # Traditional analyzers
    ksi_factory = get_ksi_factory()
    traditional_reqs = set()
    for ksi_id in ksi_factory.list_ksis():
        result = ksi_factory.analyze(ksi_id, bicep_code, "bicep", "storage.bicep")
        if result and result.findings:
            traditional_reqs.update(f.requirement_id for f in result.findings)
    
    print(f"Pattern engine requirements ({len(pattern_reqs)}): {sorted(pattern_reqs)}")
    print(f"\nTraditional requirements ({len(traditional_reqs)}): {sorted(traditional_reqs)}")
    print(f"\nMissing from patterns ({len(traditional_reqs - pattern_reqs)}): {sorted(traditional_reqs - pattern_reqs)}")
    print(f"\nPattern-only ({len(pattern_reqs - traditional_reqs)}): {sorted(pattern_reqs - traditional_reqs)}")

asyncio.run(compare_coverage())
