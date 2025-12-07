"""
Quick test to verify Java and TypeScript template integration.
"""
import io

# Set UTF-8 encoding for stdout (Windows compatibility)

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.templates import get_code_template
from fedramp_20x_mcp.tools.evidence import get_evidence_collection_code_impl

async def test_new_languages():
    """Test that Java and TypeScript templates work."""
    
    print("\n=== Testing New Language Support ===\n")
    
    # Load data
    loader = get_data_loader()
    await loader.load_data()
    
    # Test Java
    print("Testing Java template...")
    result = await get_evidence_collection_code_impl(
        'KSI-IAM-01', 
        loader, 
        get_code_template, 
        'java'
    )
    assert len(result) > 1000, "Java template too short"
    assert "java" in result.lower(), "Java template missing language marker"
    assert "Azure SDK" in result or "azure" in result.lower(), "Java template missing Azure references"
    print(f"[OK] Java template: {len(result)} chars")
    
    # Test TypeScript
    print("Testing TypeScript template...")
    result = await get_evidence_collection_code_impl(
        'KSI-MLA-01', 
        loader, 
        get_code_template, 
        'typescript'
    )
    assert len(result) > 1000, "TypeScript template too short"
    assert "typescript" in result.lower() or "javascript" in result.lower(), "TypeScript template missing language marker"
    assert "Azure SDK" in result or "azure" in result.lower(), "TypeScript template missing Azure references"
    print(f"[OK] TypeScript template: {len(result)} chars")
    
    # Test JavaScript alias (should map to TypeScript)
    print("Testing JavaScript alias...")
    result = await get_evidence_collection_code_impl(
        'KSI-IAM-01', 
        loader, 
        get_code_template, 
        'javascript'
    )
    assert len(result) > 1000, "JavaScript template too short"
    print(f"[OK] JavaScript alias works: {len(result)} chars")
    
    # Test invalid language
    print("Testing invalid language...")
    result = await get_evidence_collection_code_impl(
        'KSI-IAM-01', 
        loader, 
        get_code_template, 
        'ruby'
    )
    assert "not supported" in result, "Should reject unsupported language"
    print(f"[OK] Invalid language properly rejected")
    
    print("\n=== All Language Tests Passed ===\n")

if __name__ == "__main__":
    asyncio.run(test_new_languages())
