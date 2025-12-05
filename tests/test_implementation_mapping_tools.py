"""
Tests for KSI implementation mapping tools.

Tests the get_ksi_implementation_matrix and generate_implementation_checklist tools.
"""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from fedramp_20x_mcp.tools.enhancements import (
    get_ksi_implementation_matrix_impl,
    generate_implementation_checklist_impl
)
import asyncio


async def test_get_ksi_implementation_matrix():
    """Test getting implementation matrix for a KSI family."""
    print("\n=== Testing get_ksi_implementation_matrix ===")
    
    loader = FedRAMPDataLoader()
    
    # Test valid family - IAM
    print("\n1. Testing valid family (IAM)...")
    result = await get_ksi_implementation_matrix_impl("IAM", loader)
    
    assert "IAM Implementation Matrix" in result, "Should have IAM matrix title"
    assert "Identity and Access Management" in result, "Should have family name"
    assert "KSI-IAM-01" in result, "Should have KSI-IAM-01"
    assert "Microsoft Entra ID" in result, "Should recommend Microsoft Entra ID"
    assert "Complexity" in result, "Should have complexity column"
    assert "Priority" in result, "Should have priority column"
    assert "Estimated Effort" in result, "Should have effort column"
    assert "Phase 1: Foundation" in result, "Should have implementation phases"
    assert "Quick Start Guide" in result, "Should have quick start guide"
    print("[PASS] Valid family IAM works correctly")
    
    # Test another valid family - MLA
    print("\n2. Testing valid family (MLA)...")
    result = await get_ksi_implementation_matrix_impl("MLA", loader)
    
    assert "MLA Implementation Matrix" in result, "Should have MLA matrix title"
    assert "Monitoring, Logging, and Auditing" in result, "Should have family name"
    assert "KSI-MLA-01" in result, "Should have KSI-MLA-01"
    assert "Azure Monitor" in result or "Log Analytics" in result, "Should recommend Azure monitoring services"
    print("[PASS] Valid family MLA works correctly")
    
    # Test case insensitive
    print("\n3. Testing case insensitive (lowercase)...")
    result = await get_ksi_implementation_matrix_impl("iam", loader)
    assert "IAM Implementation Matrix" in result, "Should handle lowercase"
    print("[PASS] Case insensitive works")
    
    # Test invalid family
    print("\n4. Testing invalid family...")
    result = await get_ksi_implementation_matrix_impl("INVALID", loader)
    
    assert "No KSIs found for family" in result, "Should show error for invalid family"
    assert "Available KSI Families" in result, "Should list available families"
    print("[PASS] Invalid family handled correctly")
    
    # Test content structure
    print("\n5. Testing content structure...")
    result = await get_ksi_implementation_matrix_impl("CNA", loader)
    
    assert "## Implementation Matrix" in result, "Should have matrix section"
    assert "## Suggested Implementation Order" in result, "Should have implementation order"
    assert "## Quick Start Guide" in result, "Should have quick start"
    assert "## Key Dependencies" in result, "Should have dependencies"
    assert "## Common Challenges" in result, "Should have challenges"
    assert "Azure Kubernetes Service" in result or "AKS" in result, "CNA should mention AKS"
    print("[PASS] Content structure is correct")
    
    print("\n[PASS] All get_ksi_implementation_matrix tests passed!")


async def test_generate_implementation_checklist():
    """Test generating implementation checklist for a KSI."""
    print("\n=== Testing generate_implementation_checklist ===")
    
    loader = FedRAMPDataLoader()
    
    # Test valid KSI
    print("\n1. Testing valid KSI (KSI-IAM-01)...")
    result = await generate_implementation_checklist_impl("KSI-IAM-01", loader)
    
    assert "Implementation Checklist: KSI-IAM-01" in result, "Should have checklist title"
    assert "## Pre-Implementation Checklist" in result, "Should have pre-implementation section"
    assert "### Prerequisites" in result, "Should have prerequisites"
    assert "### Planning" in result, "Should have planning section"
    assert "## Implementation Steps" in result, "Should have implementation steps"
    assert "### Step 1: Infrastructure Deployment" in result, "Should have step 1"
    assert "### Step 2: Azure Service Configuration" in result, "Should have step 2"
    assert "### Step 3: Code Deployment" in result, "Should have step 3"
    assert "### Step 4: Testing & Validation" in result, "Should have step 4"
    assert "### Step 5: Documentation" in result, "Should have step 5"
    assert "### Step 6: Evidence Collection Setup" in result, "Should have step 6"
    assert "### Step 7: Integration with FRR-ADS" in result, "Should have step 7"
    assert "## Post-Implementation Checklist" in result, "Should have post-implementation"
    assert "## Troubleshooting Common Issues" in result, "Should have troubleshooting"
    assert "## Success Criteria" in result, "Should have success criteria"
    assert "[ ]" in result, "Should have checkboxes"
    print("[PASS] Valid KSI checklist generated correctly")
    
    # Test IAM family specific content
    print("\n2. Testing IAM family-specific content...")
    result = await generate_implementation_checklist_impl("KSI-IAM-01", loader)
    
    assert "Microsoft Entra ID" in result, "Should mention Microsoft Entra ID for IAM"
    assert "Conditional Access" in result or "MFA" in result, "Should mention IAM-specific features"
    print("[PASS] IAM-specific content included")
    
    # Test MLA family specific content
    print("\n3. Testing MLA family-specific content...")
    result = await generate_implementation_checklist_impl("KSI-MLA-01", loader)
    
    assert "Microsoft Sentinel" in result or "Azure Monitor" in result, "Should mention monitoring services for MLA"
    assert "Log Analytics" in result, "Should mention Log Analytics for MLA"
    print("[PASS] MLA-specific content included")
    
    # Test SVC family specific content
    print("\n4. Testing SVC family-specific content...")
    result = await generate_implementation_checklist_impl("KSI-SVC-06", loader)
    
    assert "Azure Key Vault" in result, "Should mention Key Vault for SVC (secrets)"
    assert "secret" in result.lower(), "Should discuss secrets for SVC-06"
    print("[PASS] SVC-specific content included")
    
    # Test code snippets
    print("\n5. Testing code snippets...")
    result = await generate_implementation_checklist_impl("KSI-IAM-01", loader)
    
    assert "```bash" in result or "```" in result, "Should have code blocks"
    assert "az group create" in result or "az deployment" in result, "Should have Azure CLI commands"
    print("[PASS] Code snippets included")
    
    # Test related tools section
    print("\n6. Testing related tools...")
    result = await generate_implementation_checklist_impl("KSI-IAM-01", loader)
    
    assert "## Related Tools" in result, "Should have related tools section"
    assert "get_implementation_examples" in result, "Should reference related tool"
    assert "get_infrastructure_code_for_ksi" in result, "Should reference IaC tool"
    print("[PASS] Related tools section included")
    
    # Test invalid KSI
    print("\n7. Testing invalid KSI...")
    result = await generate_implementation_checklist_impl("KSI-INVALID-99", loader)
    
    assert "not found" in result, "Should show error for invalid KSI"
    print("[PASS] Invalid KSI handled correctly")
    
    print("\n[PASS] All generate_implementation_checklist tests passed!")


async def test_matrix_covers_all_families():
    """Test that matrix tool works for all KSI families."""
    print("\n=== Testing matrix covers all KSI families ===")
    
    loader = FedRAMPDataLoader()
    
    families = ["IAM", "MLA", "AFR", "CNA", "SVC", "RPL", "TPR", "INR", "PIY", "CMT"]
    
    for family in families:
        print(f"\nTesting {family} family...")
        result = await get_ksi_implementation_matrix_impl(family, loader)
        assert f"{family} Implementation Matrix" in result, f"Should have {family} matrix"
        assert "## Implementation Matrix" in result, f"Should have matrix section for {family}"
        print(f"[PASS] {family} family works")
    
    print("\n[PASS] All families supported!")


async def test_checklist_azure_focus():
    """Test that checklists are Azure-focused."""
    print("\n=== Testing Azure focus in checklists ===")
    
    loader = FedRAMPDataLoader()
    
    test_ksis = ["KSI-IAM-01", "KSI-MLA-01", "KSI-AFR-01", "KSI-CNA-04"]
    
    for ksi_id in test_ksis:
        print(f"\nTesting Azure focus for {ksi_id}...")
        result = await generate_implementation_checklist_impl(ksi_id, loader)
        
        # Check for Azure-specific content
        azure_terms = ["Azure", "Microsoft", "Entra", "Bicep", "az ", "azurerm"]
        found_azure = any(term in result for term in azure_terms)
        
        assert found_azure, f"{ksi_id} should have Azure-specific content"
        print(f"[PASS] {ksi_id} is Azure-focused")
    
    print("\n[PASS] All checklists are Azure-focused!")


async def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("Testing KSI Implementation Mapping Tools")
    print("="*60)
    
    try:
        await test_get_ksi_implementation_matrix()
        await test_generate_implementation_checklist()
        await test_matrix_covers_all_families()
        await test_checklist_azure_focus()
        
        print("\n" + "="*60)
        print("[PASS] ALL TESTS PASSED!")
        print("="*60)
        return 0
        
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n[FAIL] UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
