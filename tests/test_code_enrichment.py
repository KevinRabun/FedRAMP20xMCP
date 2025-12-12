"""
Test Code Enrichment Module

Tests for adding KSI/FRR requirement comments to generated code.
"""
import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from fedramp_20x_mcp.tools.code_enrichment import (
    get_requirement_header,
    enrich_bicep_template,
    enrich_csharp_code,
    get_inline_requirement_comment,
    add_requirement_tags
)


async def setup_data_loader():
    """Setup and load data into the data loader."""
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    return data_loader


def test_bicep_enrichment(data_loader):
    """Test enriching Bicep template with KSI/FRR comments."""
    print("\n" + "=" * 80)
    print("TEST: Bicep Template Enrichment")
    print("=" * 80)
    
    original_bicep = """// Simple Key Vault resource
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-fedramp-prod'
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'premium'
    }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    enablePurgeProtection: true
  }
  tags: {
    Environment: 'Production'
  }
}
"""
    
    enriched = enrich_bicep_template(
        original_bicep,
        ksi_ids=["KSI-SVC-01"],
        frr_ids=["FRR-RSC-01"],
        data_loader=data_loader
    )
    
    enriched = add_requirement_tags(
        enriched,
        ksi_ids=["KSI-SVC-01"],
        frr_ids=["FRR-RSC-01"],
        language="bicep"
    )
    
    print("\nOriginal Bicep:")
    print("-" * 80)
    print(original_bicep)
    
    print("\nEnriched Bicep:")
    print("-" * 80)
    print(enriched)
    
    # Verify KSI ID appears in comments
    assert "KSI-SVC-01" in enriched, "KSI ID not found in enriched template"
    assert "FRR-RSC-01" in enriched, "FRR ID not found in enriched template"
    print("\n[PASS] Bicep enrichment test passed!")


def test_csharp_enrichment(data_loader):
    """Test enriching C# code with KSI/FRR comments."""
    print("\n" + "=" * 80)
    print("TEST: C# Code Enrichment")
    print("=" * 80)
    
    original_csharp = """using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace FedrampCompliance
{
    public class SecretManager
    {
        private readonly SecretClient _client;
        
        public SecretManager(string vaultUri)
        {
            _client = new SecretClient(
                new Uri(vaultUri),
                new DefaultAzureCredential()
            );
        }
        
        public async Task<string> GetSecretAsync(string name)
        {
            KeyVaultSecret secret = await _client.GetSecretAsync(name);
            return secret.Value;
        }
    }
}
"""
    
    enriched = enrich_csharp_code(
        original_csharp,
        ksi_ids=["KSI-SVC-01", "KSI-IAM-01"],
        frr_ids=None,
        data_loader=data_loader
    )
    
    print("\nOriginal C#:")
    print("-" * 80)
    print(original_csharp)
    
    print("\nEnriched C#:")
    print("-" * 80)
    print(enriched)
    
    # Verify KSI IDs appear in comments
    assert "KSI-SVC-01" in enriched, "KSI-SVC-01 not found in enriched code"
    assert "KSI-IAM-01" in enriched, "KSI-IAM-01 not found in enriched code"
    print("\n[PASS] C# enrichment test passed!")


def test_requirement_header(data_loader):
    """Test generating requirement header comment block."""
    print("\n" + "=" * 80)
    print("TEST: Requirement Header Generation")
    print("=" * 80)
    
    header = get_requirement_header(
        ksi_ids=["KSI-IAM-01"],
        frr_ids=["FRR-VDR-01"],
        data_loader=data_loader,
        language="bicep"
    )
    
    print("\nGenerated Header:")
    print("-" * 80)
    print(header)
    
    assert "KSI-IAM-01" in header, "KSI ID not in header"
    assert "FRR-VDR-01" in header, "FRR ID not in header"
    assert "Phishing-Resistant MFA" in header, "KSI name not in header"
    print("\n[PASS] Header generation test passed!")


def test_inline_comment(data_loader):
    """Test generating inline requirement comments."""
    print("\n" + "=" * 80)
    print("TEST: Inline Requirement Comment")
    print("=" * 80)
    
    comment = get_inline_requirement_comment(
        "KSI-SVC-01",
        data_loader,
        language="bicep",
        compact=True
    )
    
    print(f"\nCompact Comment: {comment}")
    
    comment_full = get_inline_requirement_comment(
        "KSI-SVC-01",
        data_loader,
        language="bicep",
        compact=False
    )
    
    print(f"Full Comment: {comment_full}")
    
    assert "KSI-SVC-01" in comment, "KSI ID not in comment"
    print("\n[PASS] Inline comment test passed!")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("TESTING: Code Enrichment Module")
    print("=" * 80)
    
    try:
        # Setup data loader
        data_loader = asyncio.run(setup_data_loader())
        
        # Run tests
        test_requirement_header(data_loader)
        test_inline_comment(data_loader)
        test_bicep_enrichment(data_loader)
        test_csharp_enrichment(data_loader)
        
        print("\n" + "=" * 80)
        print("ALL TESTS PASSED [OK]")
        print("=" * 80)
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
