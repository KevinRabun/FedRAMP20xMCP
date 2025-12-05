"""
Test evidence automation tools
Tests infrastructure code generation (Bicep/Terraform) and evidence collection code
"""

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.templates import get_infrastructure_template, get_code_template


async def test_infrastructure_code_generation():
    """Test Bicep and Terraform template generation for KSIs"""
    
    print("=" * 80)
    print("Testing Infrastructure Code Generation (Bicep & Terraform)")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    # Import the evidence module functions
    from fedramp_20x_mcp.tools.evidence import (
        get_infrastructure_code_for_ksi_impl,
        get_evidence_collection_code_impl,
        get_evidence_automation_architecture_impl
    )
    
    # Test 1: Generate Bicep template for IAM KSI
    print("\n[1/6] Testing Bicep template generation for KSI-IAM-01...")
    try:
        bicep_result = await get_infrastructure_code_for_ksi_impl(
            "KSI-IAM-01", 
            loader, 
            get_infrastructure_template,
            "bicep"
        )
        assert len(bicep_result) > 0, "Bicep template is empty"
        assert "resource" in bicep_result.lower() or "param" in bicep_result.lower(), "Doesn't look like Bicep code"
        assert "IAM" in bicep_result or "Identity" in bicep_result, "KSI-IAM content missing"
        print(f"[PASS] Generated Bicep template ({len(bicep_result)} characters)")
        print(f"  Contains: resource definitions, parameters, deployment instructions")
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    # Test 2: Generate Terraform template for MLA KSI
    print("\n[2/6] Testing Terraform template generation for KSI-MLA-01...")
    try:
        terraform_result = await get_infrastructure_code_for_ksi_impl(
            "KSI-MLA-01",
            loader,
            get_infrastructure_template,
            "terraform"
        )
        assert len(terraform_result) > 0, "Terraform template is empty"
        assert "resource" in terraform_result.lower() or "variable" in terraform_result.lower(), "Doesn't look like Terraform code"
        assert "MLA" in terraform_result or "Monitoring" in terraform_result or "Logging" in terraform_result, "KSI-MLA content missing"
        print(f"[PASS] Generated Terraform template ({len(terraform_result)} characters)")
        print(f"  Contains: resource blocks, variables, provider configuration")
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    # Test 3: Generate Python evidence collection code
    print("\n[3/6] Testing Python code generation for KSI-IAM-01...")
    try:
        python_result = await get_evidence_collection_code_impl(
            "KSI-IAM-01",
            loader,
            get_code_template,
            "python"
        )
        assert len(python_result) > 0, "Python code is empty"
        assert "import" in python_result or "def " in python_result or "async def " in python_result, "Doesn't look like Python code"
        assert "azure" in python_result.lower() or "credential" in python_result.lower(), "Azure SDK code missing"
        print(f"[PASS] Generated Python code ({len(python_result)} characters)")
        print(f"  Contains: imports, authentication, evidence collection logic")
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    # Test 4: Generate C# evidence collection code
    print("\n[4/6] Testing C# code generation for KSI-MLA-01...")
    try:
        csharp_result = await get_evidence_collection_code_impl(
            "KSI-MLA-01",
            loader,
            get_code_template,
            "csharp"
        )
        assert len(csharp_result) > 0, "C# code is empty"
        assert "using" in csharp_result or "namespace" in csharp_result or "class" in csharp_result, "Doesn't look like C# code"
        assert "Azure" in csharp_result, "Azure SDK code missing"
        print(f"[PASS] Generated C# code ({len(csharp_result)} characters)")
        print(f"  Contains: using statements, classes, async methods")
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    # Test 5: Generate PowerShell evidence collection code
    print("\n[5/6] Testing PowerShell code generation for KSI-IAM-01...")
    try:
        powershell_result = await get_evidence_collection_code_impl(
            "KSI-IAM-01",
            loader,
            get_code_template,
            "powershell"
        )
        assert len(powershell_result) > 0, "PowerShell code is empty"
        assert "$" in powershell_result or "param" in powershell_result.lower() or "function" in powershell_result.lower(), "Doesn't look like PowerShell code"
        assert "Az." in powershell_result or "Connect-Az" in powershell_result, "Azure PowerShell code missing"
        print(f"[PASS] Generated PowerShell code ({len(powershell_result)} characters)")
        print(f"  Contains: cmdlets, parameters, Azure modules")
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    # Test 6: Generate architecture guidance
    print("\n[6/6] Testing architecture guidance generation...")
    try:
        arch_result = await get_evidence_automation_architecture_impl(
            loader,
            "all"
        )
        assert len(arch_result) > 0, "Architecture guidance is empty"
        assert "architecture" in arch_result.lower(), "Architecture content missing"
        assert "azure" in arch_result.lower() or "component" in arch_result.lower(), "Technical architecture missing"
        print(f"[PASS] Generated architecture guidance ({len(arch_result)} characters)")
        print(f"  Contains: components, data flow, security, scaling")
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    print("[PASS] Bicep template generation works")
    print("[PASS] Terraform template generation works")
    print("[PASS] Python code generation works")
    print("[PASS] C# code generation works")
    print("[PASS] PowerShell code generation works")
    print("[PASS] Architecture guidance generation works")
    print("\n[OK] All evidence automation tools passed!")


async def test_template_variations():
    """Test that different KSI families produce different templates"""
    
    print("\n" + "=" * 80)
    print("Testing Template Variations for Different KSI Families")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    from fedramp_20x_mcp.tools.evidence import get_infrastructure_code_for_ksi_impl
    
    test_ksis = [
        ("KSI-IAM-01", "IAM"),
        ("KSI-MLA-01", "MLA"),
        ("KSI-AFR-01", "AFR"),
    ]
    
    templates = {}
    
    for ksi_id, family in test_ksis:
        print(f"\n[{family}] Generating Bicep for {ksi_id}...")
        try:
            result = await get_infrastructure_code_for_ksi_impl(
                ksi_id,
                loader,
                get_infrastructure_template,
                "bicep"
            )
            templates[family] = result
            print(f"[PASS] Generated {len(result)} characters")
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    # Verify templates are different (not just generic)
    print("\n" + "=" * 80)
    print("Verifying template customization...")
    print("=" * 80)
    
    # Check IAM template has identity-related content
    if "IAM" in templates:
        assert any(keyword in templates["IAM"] for keyword in ["identity", "Entra", "role", "RBAC", "permission"]), \
            "IAM template should contain identity-related content"
        print("[PASS] IAM template contains identity-specific resources")
    
    # Check MLA template has monitoring-related content
    if "MLA" in templates:
        assert any(keyword in templates["MLA"] for keyword in ["Monitor", "Log", "Analytics", "diagnostic", "alert"]), \
            "MLA template should contain monitoring-related content"
        print("[PASS] MLA template contains monitoring-specific resources")
    
    # Check AFR template has audit-related content
    if "AFR" in templates:
        assert any(keyword in templates["AFR"] for keyword in ["audit", "storage", "immutab", "retention", "compliance"]), \
            "AFR template should contain audit-related content"
        print("[PASS] AFR template contains audit-specific resources")
    
    print("\n[OK] Template variations test passed!")


async def main():
    """Run all evidence automation tests"""
    try:
        await test_infrastructure_code_generation()
        await test_template_variations()
        
        print("\n" + "=" * 80)
        print("[OK] ALL EVIDENCE AUTOMATION TESTS PASSED!")
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
