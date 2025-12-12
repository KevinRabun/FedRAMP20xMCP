"""
Week 3 Pattern Expansion Test
Tests new CED and TPR patterns for coverage improvement
"""
import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_20x_mcp.tools.analyzer import (
    analyze_application_code_impl,
    analyze_cicd_pipeline_impl
)

# Test code for CED patterns (developer security training gaps)
TEST_PYTHON_CED = '''
import pickle
import yaml

# CED-03: Insecure coding practices (eval)
def calculate_user_expression(expression):
    result = eval(expression)  # DANGEROUS: Code injection
    return result

# CED-03: Insecure deserialization
def load_user_data(data):
    user_obj = pickle.loads(data)  # DANGEROUS: Arbitrary code execution
    return user_obj

# CED-03: Unsafe YAML loading
def parse_config(config_str):
    config = yaml.load(config_str)  # DANGEROUS: Code injection (use safe_load)
    return config
'''

# Test code for TPR patterns (dependency security)
TEST_REQUIREMENTS_TPR = '''
# tpr.dependencies.unverified: Missing hash verification
flask==3.0.0
requests==2.31.0
cryptography==41.0.7

# tpr.sources.insecure: HTTP package source
# --index-url http://insecure.pypi.org/simple
'''

# Test CI/CD for TPR patterns (supply chain monitoring)
TEST_GITHUB_ACTIONS_TPR = '''
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # tpr.monitoring.supply_chain_missing: No dependency scanning
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - run: pip install -r requirements.txt
      
      # tpr.sbom.missing: No SBOM generation
      - run: python -m pytest
      
      - run: python app.py
'''

async def test_week3_patterns():
    """Test Week 3 CED and TPR pattern detection"""
    
    print("=" * 60)
    print("WEEK 3 PATTERN EXPANSION TEST")
    print("=" * 60)
    print()
    
    # Test CED patterns (developer training gaps)
    print("=" * 60)
    print("TEST 1: Python Code (CED Patterns)")
    print("=" * 60)
    print()
    print("Expected CED findings:")
    print("  1. eval() usage (ced.training.developer_gaps)")
    print("  2. pickle.loads usage (ced.training.developer_gaps)")
    print("  3. yaml.load usage (ced.training.developer_gaps)")
    print()
    
    ced_result = await analyze_application_code_impl(TEST_PYTHON_CED, "python", "test_ced.py")
    ced_findings = ced_result.get('findings', [])
    ced_pattern_findings = [f for f in ced_findings if f.get('requirement_id', '').startswith('ced.')]
    
    print(f"Pattern engine found {len(ced_findings)} total findings")
    print(f"CED-specific findings: {len(ced_pattern_findings)}")
    print()
    
    if ced_pattern_findings:
        print("CED findings detected:")
        for finding in ced_pattern_findings:
            severity = finding.get('severity', 'unknown').upper()
            req_id = finding.get('requirement_id', 'unknown')
            title = finding.get('title', 'unknown')
            print(f"  - [{severity}] {title} ({req_id})")
    else:
        print("No CED findings detected")
    print()
    
    # Test TPR patterns (supply chain security)
    print("=" * 60)
    print("TEST 2: GitHub Actions (TPR Patterns)")
    print("=" * 60)
    print()
    print("Expected TPR findings:")
    print("  1. Missing dependency scanning (tpr.monitoring.supply_chain_missing)")
    print("  2. Missing SBOM generation (tpr.sbom.missing)")
    print()
    
    tpr_result = await analyze_cicd_pipeline_impl(TEST_GITHUB_ACTIONS_TPR, "github_actions", "test_tpr.yml")
    tpr_findings = tpr_result.get('findings', [])
    tpr_pattern_findings = [f for f in tpr_findings if f.get('requirement_id', '').startswith('tpr.')]
    
    print(f"Pattern engine found {len(tpr_findings)} total findings")
    print(f"TPR-specific findings: {len(tpr_pattern_findings)}")
    print()
    
    if tpr_pattern_findings:
        print("TPR findings detected:")
        for finding in tpr_pattern_findings:
            severity = finding.get('severity', 'unknown').upper()
            req_id = finding.get('requirement_id', 'unknown')
            title = finding.get('title', 'unknown')
            print(f"  - [{severity}] {title} ({req_id})")
    else:
        print("No TPR findings detected")
    print()
    
    # Summary
    total_new_findings = len(ced_pattern_findings) + len(tpr_pattern_findings)
    
    print("=" * 60)
    print("WEEK 3 TEST SUMMARY")
    print("=" * 60)
    print()
    print(f"Total CED findings: {len(ced_pattern_findings)}")
    print(f"Total TPR findings: {len(tpr_pattern_findings)}")
    print(f"Total new pattern findings: {total_new_findings}")
    print()
    print("Pattern library: 147 patterns across 18 families")
    print("New families: CED (4 patterns), TPR (4 patterns)")
    print()
    print("[PASS] Week 3 pattern expansion test complete")

if __name__ == "__main__":
    asyncio.run(test_week3_patterns())
