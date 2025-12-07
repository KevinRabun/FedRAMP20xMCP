"""
Test suite for FedRAMP 20x MCP Server infrastructure and code templates.

This module tests that all Bicep, Terraform, and code templates load correctly
and contain expected content.
"""

import sys

# Add src to path

from fedramp_20x_mcp.templates import (
    load_template, 
    get_infrastructure_template, 
    get_code_template
)

def test_load_bicep_templates():
    """Test that all Bicep templates load successfully."""
    print("\n=== Testing Bicep Templates ===\n")
    
    templates = ["afr", "cna", "generic", "iam", "mla", "rpl", "svc"]
    
    for template_name in templates:
        try:
            content = load_template("bicep", template_name)
            assert len(content) > 0, f"{template_name}: Empty content"
            
            # Check for Bicep syntax markers
            assert "param" in content or "resource" in content or "module" in content, \
                f"{template_name}: Missing Bicep keywords"
            
            print(f"[OK] bicep/{template_name}.txt: {len(content)} chars")
        except Exception as e:
            print(f"[FAIL] bicep/{template_name}.txt: {e}")
            raise
    
    print(f"\n[DATA] Loaded {len(templates)}/7 Bicep templates")

def test_load_terraform_templates():
    """Test that all Terraform templates load successfully."""
    print("\n=== Testing Terraform Templates ===\n")
    
    templates = ["afr", "cna", "generic", "iam", "mla", "rpl", "svc"]
    
    for template_name in templates:
        try:
            content = load_template("terraform", template_name)
            assert len(content) > 0, f"{template_name}: Empty content"
            
            # Check for Terraform syntax markers
            assert "resource" in content or "provider" in content or "variable" in content, \
                f"{template_name}: Missing Terraform keywords"
            
            print(f"[OK] terraform/{template_name}.txt: {len(content)} chars")
        except Exception as e:
            print(f"[FAIL] terraform/{template_name}.txt: {e}")
            raise
    
    print(f"\n[DATA] Loaded {len(templates)}/7 Terraform templates")

def test_load_code_templates():
    """Test that all code templates load successfully."""
    print("\n=== Testing Code Templates ===\n")
    
    templates = [
        "generic_csharp",
        "generic_powershell",
        "generic_python",
        "generic_java",
        "generic_typescript",
        "iam_csharp",
        "iam_powershell",
        "iam_python",
        "mla_python",
    ]
    
    for template_name in templates:
        try:
            content = load_template("code", template_name)
            assert len(content) > 0, f"{template_name}: Empty content"
            
            # Check for programming language markers
            language_markers = {
                "python": ["def ", "import ", "class ", "async "],
                "csharp": ["using ", "namespace ", "class ", "public "],
                "powershell": ["param", "function ", "$", "Write-"],
                "java": ["import ", "class ", "public ", "private "],
                "typescript": ["import ", "class ", "interface ", "async ", "const "],
            }
            
            # Determine language from template name
            if "python" in template_name:
                markers = language_markers["python"]
            elif "csharp" in template_name:
                markers = language_markers["csharp"]
            elif "powershell" in template_name:
                markers = language_markers["powershell"]
            elif "java" in template_name:
                markers = language_markers["java"]
            elif "typescript" in template_name:
                markers = language_markers["typescript"]
            else:
                markers = []
            
            if markers:
                has_marker = any(marker in content for marker in markers)
                assert has_marker, f"{template_name}: Missing language-specific markers"
            
            print(f"[OK] code/{template_name}.txt: {len(content)} chars")
        except Exception as e:
            print(f"[FAIL] code/{template_name}.txt: {e}")
            raise
    
    print(f"\n[DATA] Loaded {len(templates)}/9 code templates")

def test_get_infrastructure_template():
    """Test get_infrastructure_template function with all families."""
    print("\n=== Testing get_infrastructure_template ===\n")
    
    families = ["IAM", "MLA", "AFR", "CNA", "RPL", "SVC", "PIY"]
    infra_types = ["bicep", "terraform"]
    
    for infra_type in infra_types:
        print(f"\nTesting {infra_type}:")
        for family in families:
            try:
                content = get_infrastructure_template(family, infra_type)
                assert len(content) > 0, f"{family}/{infra_type}: Empty content"
                
                # Check for appropriate syntax
                if infra_type == "bicep":
                    assert "param" in content or "resource" in content or "module" in content
                else:  # terraform
                    assert "resource" in content or "provider" in content or "variable" in content
                
                # PIY should fall back to generic since no specific template exists
                if family == "PIY":
                    print(f"[OK] {family} ({infra_type}): {len(content)} chars (using generic fallback)")
                else:
                    print(f"[OK] {family} ({infra_type}): {len(content)} chars")
                    
            except Exception as e:
                print(f"[FAIL] {family} ({infra_type}): {e}")
                raise

def test_get_code_template():
    """Test get_code_template function with all families and languages."""
    print("\n=== Testing get_code_template ===\n")
    
    families = ["IAM", "MLA", "AFR", "CNA", "RPL", "SVC", "PIY"]
    languages = ["python", "csharp", "powershell", "java", "typescript"]
    
    for language in languages:
        print(f"\nTesting {language}:")
        for family in families:
            try:
                content = get_code_template(family, language)
                assert len(content) > 0, f"{family}/{language}: Empty content"
                
                # Check for language-specific markers
                language_markers = {
                    "python": ["def ", "import ", "class ", "async "],
                    "csharp": ["using ", "namespace ", "class ", "public "],
                    "powershell": ["param", "function ", "$", "Write-"],
                    "java": ["import ", "class ", "public ", "private "],
                    "typescript": ["import ", "class ", "interface ", "async ", "const "],
                }
                
                markers = language_markers[language]
                has_marker = any(marker in content for marker in markers)
                assert has_marker, f"{family}/{language}: Missing language markers"
                
                # Check if using specific or generic template
                if family in ["IAM", "MLA"] and language == "python":
                    print(f"[OK] {family} ({language}): {len(content)} chars (family-specific)")
                elif family == "IAM" and language in ["csharp", "powershell"]:
                    print(f"[OK] {family} ({language}): {len(content)} chars (family-specific)")
                else:
                    print(f"[OK] {family} ({language}): {len(content)} chars (using generic)")
                    
            except Exception as e:
                print(f"[FAIL] {family} ({language}): {e}")
                raise

def test_template_content_quality():
    """Test that templates contain expected quality markers."""
    print("\n=== Testing Template Content Quality ===\n")
    
    # Test Bicep templates
    print("Bicep templates:")
    for family in ["iam", "mla", "afr", "cna"]:
        content = load_template("bicep", family)
        
        # Should have parameters
        assert "param" in content, f"{family}: Missing param declarations"
        
        # Should have resources
        assert "resource" in content or "module" in content, \
            f"{family}: Missing resource/module declarations"
        
        # Should have comments/documentation
        assert "//" in content or "/*" in content, \
            f"{family}: Missing comments/documentation"
        
        print(f"[OK] {family}: Has params, resources, and documentation")
    
    # Test Terraform templates
    print("\nTerraform templates:")
    for family in ["iam", "mla", "afr", "cna"]:
        content = load_template("terraform", family)
        
        # Should have provider or resource
        assert "provider" in content or "resource" in content, \
            f"{family}: Missing provider/resource blocks"
        
        # Should have variables or locals
        assert "variable" in content or "locals" in content or "var." in content, \
            f"{family}: Missing variables/locals"
        
        # Should have comments
        assert "#" in content, f"{family}: Missing comments"
        
        print(f"[OK] {family}: Has provider/resource, variables, and comments")
    
    # Test code templates
    print("\nCode templates:")
    content = load_template("code", "iam_python")
    assert "import" in content, "iam_python: Missing imports"
    assert "def " in content or "class " in content, "iam_python: Missing functions/classes"
    assert "#" in content or '"""' in content, "iam_python: Missing comments/docstrings"
    print(f"[OK] iam_python: Has imports, functions/classes, and documentation")
    
    content = load_template("code", "iam_csharp")
    assert "using" in content, "iam_csharp: Missing using statements"
    assert "class " in content or "public " in content, "iam_csharp: Missing classes/methods"
    assert "//" in content or "/*" in content, "iam_csharp: Missing comments"
    print(f"[OK] iam_csharp: Has using statements, classes, and documentation")
    
    content = load_template("code", "iam_powershell")
    assert "param" in content or "function" in content, "iam_powershell: Missing functions"
    assert "$" in content, "iam_powershell: Missing PowerShell variables"
    assert "#" in content or "<#" in content, "iam_powershell: Missing comments"
    print(f"[OK] iam_powershell: Has functions, variables, and documentation")

def test_template_sizes():
    """Test that templates are within reasonable size ranges."""
    print("\n=== Testing Template Size Ranges ===\n")
    
    all_sizes = {
        'bicep': [],
        'terraform': [],
        'code': []
    }
    
    # Bicep templates
    for family in ["afr", "cna", "generic", "iam", "mla", "rpl", "svc"]:
        content = load_template("bicep", family)
        size = len(content)
        all_sizes['bicep'].append(size)
        assert 500 < size < 100000, f"bicep/{family}: Size {size} outside reasonable bounds"
    
    # Terraform templates
    for family in ["afr", "cna", "generic", "iam", "mla", "rpl", "svc"]:
        content = load_template("terraform", family)
        size = len(content)
        all_sizes['terraform'].append(size)
        assert 500 < size < 100000, f"terraform/{family}: Size {size} outside reasonable bounds"
    
    # Code templates
    for template in ["generic_csharp", "generic_powershell", "generic_python", 
                     "iam_csharp", "iam_powershell", "iam_python", "mla_python"]:
        content = load_template("code", template)
        size = len(content)
        all_sizes['code'].append(size)
        assert 200 < size < 100000, f"code/{template}: Size {size} outside reasonable bounds"
    
    # Print statistics
    for category, sizes in all_sizes.items():
        avg_size = sum(sizes) / len(sizes)
        min_size = min(sizes)
        max_size = max(sizes)
        print(f"[DATA] {category.capitalize()} templates:")
        print(f"   Average: {avg_size:.0f} chars")
        print(f"   Range: {min_size}-{max_size} chars")
    
    print(f"\n[OK] All templates within reasonable size ranges")

def test_fallback_behavior():
    """Test that fallback to generic templates works correctly."""
    print("\n=== Testing Fallback Behavior ===\n")
    
    # Test infrastructure fallback (PIY has no specific templates)
    bicep_piy = get_infrastructure_template("PIY", "bicep")
    bicep_generic = load_template("bicep", "generic")
    assert bicep_piy == bicep_generic, "PIY should fallback to generic Bicep"
    print("[OK] PIY Bicep falls back to generic")
    
    terraform_piy = get_infrastructure_template("PIY", "terraform")
    terraform_generic = load_template("terraform", "generic")
    assert terraform_piy == terraform_generic, "PIY should fallback to generic Terraform"
    print("[OK] PIY Terraform falls back to generic")
    
    # Test code fallback (AFR has no specific code templates)
    code_afr_python = get_code_template("AFR", "python")
    code_generic_python = load_template("code", "generic_python")
    assert code_afr_python == code_generic_python, "AFR Python should fallback to generic"
    print("[OK] AFR Python falls back to generic")
    
    code_cna_csharp = get_code_template("CNA", "csharp")
    code_generic_csharp = load_template("code", "generic_csharp")
    assert code_cna_csharp == code_generic_csharp, "CNA C# should fallback to generic"
    print("[OK] CNA C# falls back to generic")

if __name__ == "__main__":
    print("=" * 60)
    print("FedRAMP 20x MCP Server - Template Tests")
    print("=" * 60)
    
    try:
        test_load_bicep_templates()
        test_load_terraform_templates()
        test_load_code_templates()
        test_get_infrastructure_template()
        test_get_code_template()
        test_template_content_quality()
        test_template_sizes()
        test_fallback_behavior()
        
        print("\n" + "=" * 60)
        print("[OK] ALL TEMPLATE TESTS PASSED")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
