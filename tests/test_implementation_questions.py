"""Test the generate_implementation_questions tool."""

import asyncio
import sys

# Add src directory to path

from fedramp_20x_mcp.server import mcp, data_loader

async def test_generate_questions_requirement():
    """Test generating questions for a requirement."""
    print("\n=== Test 1: Generate questions for FRR-CCM-01 ===")
    
    # Load data first
    await data_loader.load_data()
    
    # Find the generate_implementation_questions tool
    tools = await mcp.list_tools()
    tool_names = [tool.name for tool in tools]
    
    if 'generate_implementation_questions' not in tool_names:
        print("[FAIL] FAILED: Tool 'generate_implementation_questions' not found")
        print(f"Available tools: {', '.join(tool_names)}")
        return False
    
    print("[PASS] Tool found")
    
    # Call the tool with a requirement ID
    result = await mcp.call_tool('generate_implementation_questions', {'requirement_id': 'FRR-CCM-01'})
    
    if result and len(result) > 0:
        content = str(result[0])
        if 'Implementation Questions for FRR-CCM-01' in content:
            print("[PASS] Generated questions for requirement FRR-CCM-01")
            print(f"[PASS] Output length: {len(content)} characters")
            
            # Check for key sections
            if 'Strategic Questions for Product Managers' in content:
                print("[PASS] Contains PM questions")
            if 'Technical Questions for Engineers' in content:
                print("[PASS] Contains engineer questions")
            if 'Azure-Specific Considerations' in content:
                print("[PASS] Contains Azure-specific questions")
            if 'Decision Framework' in content:
                print("[PASS] Contains decision framework")
            
            return True
        else:
            print(f"[FAIL] FAILED: Unexpected output format")
            print(f"First 200 chars: {content[:200]}")
            return False
    else:
        print("[FAIL] FAILED: No result returned")
        return False

async def test_generate_questions_ksi():
    """Test generating questions for a KSI."""
    print("\n=== Test 2: Generate questions for KSI-IAM-01 ===")
    
    # Call the tool with a KSI ID
    result = await mcp.call_tool('generate_implementation_questions', {'requirement_id': 'KSI-IAM-01'})
    
    if result and len(result) > 0:
        content = str(result[0])
        if 'Implementation Questions for KSI-IAM-01' in content:
            print("[PASS] Generated questions for KSI-IAM-01")
            print(f"[PASS] Output length: {len(content)} characters")
            return True
        else:
            print(f"[FAIL] FAILED: Unexpected output format")
            print(f"First 200 chars: {content[:200]}")
            return False
    else:
        print("[FAIL] FAILED: No result returned")
        return False

async def test_invalid_id():
    """Test handling of invalid requirement ID."""
    print("\n=== Test 3: Handle invalid requirement ID ===")
    
    result = await mcp.call_tool('generate_implementation_questions', {'requirement_id': 'INVALID-ID-999'})
    
    if result and len(result) > 0:
        content = str(result[0])
        if 'not found' in content:
            print("[PASS] Correctly handles invalid ID")
            return True
        else:
            print(f"[FAIL] FAILED: Should return error message for invalid ID")
            print(f"Got: {content[:200]}")
            return False
    else:
        print("[FAIL] FAILED: No result returned")
        return False

async def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing generate_implementation_questions tool")
    print("=" * 60)
    
    results = []
    
    results.append(await test_generate_questions_requirement())
    results.append(await test_generate_questions_ksi())
    results.append(await test_invalid_id())
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {sum(results)}/{len(results)} tests passed")
    print("=" * 60)
    
    if all(results):
        print("[OK] All tests passed!")
        return 0
    else:
        print("[FAIL] Some tests failed")
        return 1

if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
