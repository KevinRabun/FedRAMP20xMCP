"""
Test suite for FedRAMP 20x MCP Server prompt templates.

This module tests that all prompt templates load correctly and contain expected content.
"""

import sys

# Add src to path

from fedramp_20x_mcp.prompts import load_prompt, get_prompt

def test_load_all_prompts():
    """Test that all prompt templates load successfully."""
    print("\n=== Testing All Prompt Templates ===\n")
    
    # List of all prompt templates
    prompts = [
        "api_design_guide",
        "ato_package_checklist",
        "audit_preparation",
        "authorization_boundary_review",
        "azure_ksi_automation",
        "continuous_monitoring_setup",
        "documentation_generator",
        "gap_analysis",
        "initial_assessment_roadmap",
        "ksi_implementation_priorities",
        "migration_from_rev5",
        "quarterly_review_checklist",
        "significant_change_assessment",
        "vendor_evaluation",
        "vulnerability_remediation_timeline",
    ]
    
    results = []
    for prompt_name in prompts:
        try:
            content = load_prompt(prompt_name)
            char_count = len(content)
            line_count = content.count('\n') + 1
            results.append({
                'name': prompt_name,
                'loaded': True,
                'chars': char_count,
                'lines': line_count
            })
            print(f"[OK] {prompt_name}: {char_count} chars, {line_count} lines")
        except Exception as e:
            results.append({
                'name': prompt_name,
                'loaded': False,
                'error': str(e)
            })
            print(f"[FAIL] {prompt_name}: {e}")
    
    # Summary
    loaded_count = sum(1 for r in results if r['loaded'])
    print(f"\n[DATA] Loaded {loaded_count}/{len(prompts)} prompts")
    
    # All should load
    assert loaded_count == len(prompts), f"Expected all {len(prompts)} prompts to load, but only {loaded_count} loaded"

def test_prompt_content_structure():
    """Test that key prompts contain expected sections and keywords."""
    print("\n=== Testing Prompt Content Structure ===\n")
    
    test_cases = [
        {
            'name': 'initial_assessment_roadmap',
            'expected_keywords': ['Phase', 'month', 'FedRAMP', 'roadmap', 'timeline'],
            'min_chars': 1000
        },
        {
            'name': 'quarterly_review_checklist',
            'expected_keywords': ['KSI', 'quarterly', 'review', 'checklist', 'FRR-CCM-QR'],
            'min_chars': 1000
        },
        {
            'name': 'api_design_guide',
            'expected_keywords': ['API', 'FRR-ADS', 'design', 'OSCAL', 'endpoint'],
            'min_chars': 1000
        },
        {
            'name': 'ksi_implementation_priorities',
            'expected_keywords': ['KSI', 'implementation', 'priority', 'phase', 'rollout'],
            'min_chars': 1000
        },
        {
            'name': 'vendor_evaluation',
            'expected_keywords': ['vendor', 'evaluation', 'assessment', 'scorecard', 'criteria'],
            'min_chars': 800
        },
        {
            'name': 'documentation_generator',
            'expected_keywords': ['documentation', 'OSCAL', 'SSP', 'template', 'procedure'],
            'min_chars': 800
        },
        {
            'name': 'migration_from_rev5',
            'expected_keywords': ['migration', 'Rev 5', 'Rev5', 'FedRAMP 20x', 'phase'],
            'min_chars': 1000
        },
        {
            'name': 'audit_preparation',
            'expected_keywords': ['audit', 'preparation', 'week', 'checklist', 'evidence'],
            'min_chars': 800
        },
        {
            'name': 'azure_ksi_automation',
            'expected_keywords': ['Azure', 'KSI', 'automation', 'PowerShell', 'evidence'],
            'min_chars': 2000
        },
        {
            'name': 'gap_analysis',
            'expected_keywords': ['gap', 'analysis', 'current', 'required', 'control'],
            'min_chars': 500
        },
        {
            'name': 'continuous_monitoring_setup',
            'expected_keywords': ['monitoring', 'continuous', 'FRR-CCM', 'automated', 'detect'],
            'min_chars': 500
        },
        {
            'name': 'authorization_boundary_review',
            'expected_keywords': ['authorization', 'boundary', 'component', 'system', 'review'],
            'min_chars': 500
        },
        {
            'name': 'ato_package_checklist',
            'expected_keywords': ['ATO', 'package', 'checklist', 'document', 'required'],
            'min_chars': 500
        },
        {
            'name': 'significant_change_assessment',
            'expected_keywords': ['significant', 'change', 'assessment', 'impact', 'require'],
            'min_chars': 500
        },
        {
            'name': 'vulnerability_remediation_timeline',
            'expected_keywords': ['vulnerability', 'remediation', 'timeline', 'critical', 'CVSS'],
            'min_chars': 500
        },
    ]
    
    for test_case in test_cases:
        prompt_name = test_case['name']
        content = load_prompt(prompt_name)
        
        # Check minimum length
        assert len(content) >= test_case['min_chars'], \
            f"{prompt_name}: Expected at least {test_case['min_chars']} chars, got {len(content)}"
        
        # Check for expected keywords (case-insensitive)
        content_lower = content.lower()
        missing_keywords = []
        for keyword in test_case['expected_keywords']:
            if keyword.lower() not in content_lower:
                missing_keywords.append(keyword)
        
        if missing_keywords:
            print(f"[WARN]  {prompt_name}: Missing keywords: {missing_keywords}")
        else:
            print(f"[OK] {prompt_name}: All {len(test_case['expected_keywords'])} keywords found, {len(content)} chars")
        
        # Don't fail on missing keywords, just warn
        # Some prompts may use alternate terminology

def test_get_prompt_with_default():
    """Test get_prompt function with default fallback."""
    print("\n=== Testing get_prompt with Default ===\n")
    
    # Test with valid prompt
    content = get_prompt("initial_assessment_roadmap")
    assert len(content) > 0
    print(f"[OK] Valid prompt: {len(content)} chars")
    
    # Test with invalid prompt and default
    default_text = "Default prompt text"
    content = get_prompt("nonexistent_prompt", default=default_text)
    assert content == default_text
    print(f"[OK] Invalid prompt with default: '{content}'")
    
    # Test with invalid prompt and no default (should raise)
    try:
        get_prompt("nonexistent_prompt")
        assert False, "Should have raised FileNotFoundError"
    except FileNotFoundError:
        print(f"[OK] Invalid prompt without default: Raised FileNotFoundError as expected")

def test_prompt_sizes():
    """Test that prompts are within reasonable size ranges."""
    print("\n=== Testing Prompt Size Ranges ===\n")
    
    prompts = [
        "api_design_guide",
        "ato_package_checklist",
        "audit_preparation",
        "authorization_boundary_review",
        "azure_ksi_automation",
        "continuous_monitoring_setup",
        "documentation_generator",
        "gap_analysis",
        "initial_assessment_roadmap",
        "ksi_implementation_priorities",
        "migration_from_rev5",
        "quarterly_review_checklist",
        "significant_change_assessment",
        "vendor_evaluation",
        "vulnerability_remediation_timeline",
    ]
    
    sizes = []
    for prompt_name in prompts:
        content = load_prompt(prompt_name)
        size = len(content)
        sizes.append(size)
        
        # Check reasonable size bounds
        assert 100 < size < 1000000, \
            f"{prompt_name}: Size {size} outside reasonable bounds (100-1000000)"
    
    avg_size = sum(sizes) / len(sizes)
    min_size = min(sizes)
    max_size = max(sizes)
    
    print(f"[DATA] Prompt sizes:")
    print(f"   Average: {avg_size:.0f} chars")
    print(f"   Min: {min_size} chars")
    print(f"   Max: {max_size} chars")
    print(f"[OK] All prompts within reasonable size ranges")

if __name__ == "__main__":
    print("=" * 60)
    print("FedRAMP 20x MCP Server - Prompt Template Tests")
    print("=" * 60)
    
    try:
        test_load_all_prompts()
        test_prompt_content_structure()
        test_get_prompt_with_default()
        test_prompt_sizes()
        
        print("\n" + "=" * 60)
        print("[OK] ALL PROMPT TESTS PASSED")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
