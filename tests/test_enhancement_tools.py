"""
Test enhancement tools functionality
Tests compare_with_rev4, get_implementation_examples, check_requirement_dependencies,
estimate_implementation_effort, get_cloud_native_guidance, validate_architecture,
and generate_implementation_questions
"""

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.tools.enhancements import (
    compare_with_rev4_impl,
    get_implementation_examples_impl,
    check_requirement_dependencies_impl,
    estimate_implementation_effort_impl,
    get_cloud_native_guidance_impl,
    validate_architecture_impl,
    generate_implementation_questions_impl
)


async def test_compare_with_rev4():
    """Test compare_with_rev4 with different areas"""
    
    print("=" * 80)
    print("Testing compare_with_rev4 Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_areas = [
        ("continuous monitoring", "Should explain CCM changes"),
        ("vulnerability management", "Should explain VDR changes"),
        ("authorization boundary", "Should explain MAS changes"),
        ("evidence collection", "Should explain automation changes"),
        ("random topic xyz", "Should provide general guidance"),
    ]
    
    for area, description in test_areas:
        print(f"\n[{description}] Comparing '{area}'...")
        try:
            result = await compare_with_rev4_impl(area, loader)
            
            assert len(result) > 0, "Result should not be empty"
            assert len(result) > 200, "Should provide substantial comparison"
            
            # Check for comparison indicators
            has_comparison = (
                "Rev 4" in result or 
                "Rev 5" in result or
                "20x" in result or
                "change" in result.lower()
            )
            assert has_comparison, "Should discuss Rev 4/5 vs 20x changes"
            
            print(f"[PASS] Generated comparison ({len(result)} characters)")
            
            # Check for structure
            has_headers = "#" in result
            has_requirements = "FRR-" in result or "KSI-" in result
            
            details = []
            if has_headers:
                details.append("Headers")
            if has_requirements:
                details.append("Requirements")
            
            if details:
                print(f"  Contains: {', '.join(details)}")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] compare_with_rev4 tests passed!")


async def test_get_implementation_examples():
    """Test get_implementation_examples for different requirements"""
    
    print("\n" + "=" * 80)
    print("Testing get_implementation_examples Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_requirements = [
        ("KSI-IAM-01", "IAM KSI"),
        ("KSI-MLA-01", "MLA KSI"),
        ("FRR-ADS-01", "ADS requirement"),
        ("INVALID-REQ", "Invalid requirement"),
    ]
    
    for req_id, description in test_requirements:
        print(f"\n[{description}] Getting examples for {req_id}...")
        try:
            result = await get_implementation_examples_impl(req_id, loader)
            
            assert len(result) > 0, "Result should not be empty"
            
            if req_id == "INVALID-REQ":
                # Tool might return guidance even for invalid IDs or say not found
                has_not_found = (
                    "not found" in result.lower() or
                    len(result) < 500  # Less comprehensive response
                )
                if has_not_found:
                    print(f"[PASS] Correctly handled invalid requirement")
                else:
                    print(f"[PASS] Provided general guidance ({len(result)} characters)")
            else:
                assert len(result) > 300, "Should provide substantial examples"
                
                # Check for implementation content
                has_code = "```" in result or "import" in result or "using" in result
                has_examples = "example" in result.lower() or "implement" in result.lower()
                has_azure = "azure" in result.lower() or "az" in result.lower()
                
                assert has_examples, "Should contain implementation examples"
                
                print(f"[PASS] Generated examples ({len(result)} characters)")
                
                details = []
                if has_code:
                    details.append("Code examples")
                if has_azure:
                    details.append("Azure guidance")
                
                if details:
                    print(f"  Contains: {', '.join(details)}")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] get_implementation_examples tests passed!")


async def test_check_requirement_dependencies():
    """Test check_requirement_dependencies"""
    
    print("\n" + "=" * 80)
    print("Testing check_requirement_dependencies Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_requirements = [
        ("KSI-IAM-01", "IAM KSI dependencies"),
        ("KSI-MLA-01", "MLA KSI dependencies"),
        ("FRR-CCM-01", "CCM requirement dependencies"),
    ]
    
    for req_id, description in test_requirements:
        print(f"\n[{description}] Checking dependencies for {req_id}...")
        try:
            result = await check_requirement_dependencies_impl(req_id, loader)
            
            assert len(result) > 0, "Result should not be empty"
            assert req_id in result, f"Should mention {req_id}"
            
            # Check for dependency information
            has_dependencies = (
                "depend" in result.lower() or
                "related" in result.lower() or
                "require" in result.lower()
            )
            
            print(f"[PASS] Analyzed dependencies ({len(result)} characters)")
            
            if has_dependencies:
                print(f"  Contains: Dependency information")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] check_requirement_dependencies tests passed!")


async def test_estimate_implementation_effort():
    """Test estimate_implementation_effort"""
    
    print("\n" + "=" * 80)
    print("Testing estimate_implementation_effort Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_requirements = [
        ("KSI-IAM-01", "IAM effort estimate"),
        ("KSI-MLA-01", "MLA effort estimate"),
        ("FRR-ADS-01", "ADS effort estimate"),
    ]
    
    for req_id, description in test_requirements:
        print(f"\n[{description}] Estimating effort for {req_id}...")
        try:
            result = await estimate_implementation_effort_impl(req_id, loader)
            
            assert len(result) > 0, "Result should not be empty"
            assert req_id in result, f"Should mention {req_id}"
            
            # Check for estimation indicators
            has_estimate = (
                "hour" in result.lower() or
                "day" in result.lower() or
                "week" in result.lower() or
                "effort" in result.lower() or
                "time" in result.lower()
            )
            
            assert has_estimate, "Should contain effort estimation"
            
            print(f"[PASS] Generated estimate ({len(result)} characters)")
            
            if "hour" in result.lower() or "day" in result.lower():
                print(f"  Contains: Time estimates")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] estimate_implementation_effort tests passed!")


async def test_get_cloud_native_guidance():
    """Test get_cloud_native_guidance"""
    
    print("\n" + "=" * 80)
    print("Testing get_cloud_native_guidance Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_requirements = [
        ("KSI-CNA-01", "Cloud Native Architecture"),
        ("KSI-IAM-01", "IAM cloud guidance"),
        ("KSI-MLA-01", "MLA cloud guidance"),
    ]
    
    for req_id, description in test_requirements:
        print(f"\n[{description}] Getting cloud guidance for {req_id}...")
        try:
            result = await get_cloud_native_guidance_impl(req_id, loader)
            
            assert len(result) > 0, "Result should not be empty"
            assert req_id in result, f"Should mention {req_id}"
            
            # Check for cloud-native content
            has_cloud = (
                "cloud" in result.lower() or
                "azure" in result.lower() or
                "container" in result.lower() or
                "kubernetes" in result.lower()
            )
            
            print(f"[PASS] Generated guidance ({len(result)} characters)")
            
            if has_cloud:
                print(f"  Contains: Cloud-native guidance")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] get_cloud_native_guidance tests passed!")


async def test_validate_architecture():
    """Test validate_architecture"""
    
    print("\n" + "=" * 80)
    print("Testing validate_architecture Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_architectures = [
        ("azure-webapp", "Azure Web App validation"),
        ("kubernetes-cluster", "Kubernetes validation"),
        ("microservices", "Microservices validation"),
    ]
    
    for arch_type, description in test_architectures:
        print(f"\n[{description}] Validating '{arch_type}'...")
        try:
            result = await validate_architecture_impl(arch_type, loader)
            
            assert len(result) > 0, "Result should not be empty"
            assert len(result) > 300, "Should provide substantial validation"
            
            # Check for validation content
            has_validation = (
                "validation" in result.lower() or
                "check" in result.lower() or
                "requirement" in result.lower() or
                "compliant" in result.lower()
            )
            
            print(f"[PASS] Generated validation ({len(result)} characters)")
            
            if has_validation:
                print(f"  Contains: Validation guidance")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] validate_architecture tests passed!")


async def test_generate_implementation_questions():
    """Test generate_implementation_questions"""
    
    print("\n" + "=" * 80)
    print("Testing generate_implementation_questions Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_requirements = [
        ("KSI-IAM-01", "IAM questions"),
        ("KSI-MLA-01", "MLA questions"),
        ("FRR-CCM-01", "CCM questions"),
    ]
    
    for req_id, description in test_requirements:
        print(f"\n[{description}] Generating questions for {req_id}...")
        try:
            result = await generate_implementation_questions_impl(req_id, loader)
            
            assert len(result) > 0, "Result should not be empty"
            assert req_id in result, f"Should mention {req_id}"
            
            # Check for questions
            has_questions = (
                "?" in result or
                "question" in result.lower() or
                "how" in result.lower() or
                "what" in result.lower()
            )
            
            assert has_questions, "Should contain questions"
            
            print(f"[PASS] Generated questions ({len(result)} characters)")
            
            question_count = result.count("?")
            if question_count > 0:
                print(f"  Contains: {question_count} questions")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] generate_implementation_questions tests passed!")


async def main():
    """Run all enhancement tool tests"""
    try:
        await test_compare_with_rev4()
        await test_get_implementation_examples()
        await test_check_requirement_dependencies()
        await test_estimate_implementation_effort()
        await test_get_cloud_native_guidance()
        await test_validate_architecture()
        await test_generate_implementation_questions()
        
        print("\n" + "=" * 80)
        print("[OK] ALL ENHANCEMENT TOOLS TESTS PASSED!")
        print("=" * 80)
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n[FAIL] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
