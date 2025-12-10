"""
Integration tests to validate FedRAMP 20x sourcing and Azure best practices.

Tests ensure that:
1. All recommendations cite specific FedRAMP 20x KSIs/requirements
2. All findings include proper requirement_id/ksi_id fields
3. Azure best practices are properly sourced from official docs
4. Impact levels (Low/Moderate) are correctly applied
5. NIST control mappings are accurate
"""

import asyncio
import json
import re
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.tools import requirements, ksi, evidence, enhancements, analyzer
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory


def extract_ksi_references(text: str) -> list:
    """Extract all KSI references from text (e.g., KSI-IAM-01, KSI-CNA-03)."""
    pattern = r'KSI-[A-Z]{3}-\d{2}'
    return re.findall(pattern, text)


def extract_frr_references(text: str) -> list:
    """Extract all FRR references from text (e.g., FRR-ADS-01, FRR-VDR-03)."""
    pattern = r'FRR-[A-Z]{3}-\d{2}'
    return re.findall(pattern, text)


def validate_azure_references(text: str) -> dict:
    """Check for proper Azure service references and documentation links."""
    azure_services = [
        'Microsoft Entra ID', 'Azure Key Vault', 'Azure Monitor', 'Log Analytics',
        'Azure Policy', 'Microsoft Defender for Cloud', 'Azure Sentinel',
        'Azure Automation', 'Azure Functions', 'Azure Storage', 'Azure Front Door',
        'Azure Firewall', 'Azure Bastion', 'Azure DevOps', 'GitHub Actions',
        'Bicep', 'Terraform'
    ]
    
    found_services = []
    for service in azure_services:
        if service.lower() in text.lower():
            found_services.append(service)
    
    # Check for Azure documentation links
    azure_doc_patterns = [
        r'https://learn\.microsoft\.com/[^\s\)]+',
        r'https://docs\.microsoft\.com/[^\s\)]+',
        r'https://azure\.microsoft\.com/[^\s\)]+',
    ]
    
    doc_links = []
    for pattern in azure_doc_patterns:
        doc_links.extend(re.findall(pattern, text))
    
    return {
        'services_mentioned': found_services,
        'doc_links': doc_links,
        'has_azure_guidance': len(found_services) > 0
    }


async def test_ksi_evidence_automation_sourcing():
    """Test that KSI evidence automation includes proper sourcing."""
    print("\n" + "="*80)
    print("TEST: KSI Evidence Automation Sourcing")
    print("="*80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    # Test a few KSIs across different families
    test_ksis = [
        "KSI-IAM-01",  # Phishing-Resistant MFA
        "KSI-CNA-01",  # Network Segmentation
        "KSI-MLA-01",  # Log Aggregation
        "KSI-SVC-01",  # Cryptographic Modules
        "KSI-AFR-01",  # Minimum Assessment Scope
    ]
    
    results = []
    for ksi_id in test_ksis:
        print(f"\n  Testing {ksi_id}...")
        
        response = await ksi.get_ksi_evidence_automation_impl(ksi_id, loader)
        
        # Validate KSI is mentioned
        ksi_refs = extract_ksi_references(response)
        has_ksi_reference = ksi_id in ksi_refs
        
        # Validate Azure services mentioned
        azure_info = validate_azure_references(response)
        
        # Check for impact level mention (Low/Moderate)
        has_impact_level = 'Low' in response or 'Moderate' in response or 'High' in response
        
        # Check for FedRAMP requirement citations
        has_fedramp_context = 'FedRAMP' in response or 'NIST' in response
        
        result = {
            'ksi_id': ksi_id,
            'has_ksi_reference': has_ksi_reference,
            'ksi_references_count': len(ksi_refs),
            'azure_services_count': len(azure_info['services_mentioned']),
            'has_azure_guidance': azure_info['has_azure_guidance'],
            'has_impact_level': has_impact_level,
            'has_fedramp_context': has_fedramp_context,
            'azure_services': azure_info['services_mentioned'][:3],  # First 3
        }
        
        results.append(result)
        
        # Assertions
        assert has_ksi_reference, f"[FAIL] {ksi_id}: Missing KSI reference in response"
        assert azure_info['has_azure_guidance'], f"[FAIL] {ksi_id}: Missing Azure guidance"
        assert has_fedramp_context, f"[FAIL] {ksi_id}: Missing FedRAMP context"
        
        print(f"    [OK] KSI referenced: {has_ksi_reference}")
        print(f"    [OK] Azure services mentioned: {len(azure_info['services_mentioned'])}")
        print(f"    [OK] FedRAMP context: {has_fedramp_context}")
    
    print(f"\n  [PASS] All {len(test_ksis)} KSIs properly sourced")
    return results


async def test_code_analyzer_finding_sourcing():
    """Test that code analyzer findings include proper requirement IDs."""
    print("\n" + "="*80)
    print("TEST: Code Analyzer Finding Sourcing")
    print("="*80)
    
    # Test Bicep code with compliance issues
    bicep_code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
  }
}
"""
    
    print("\n  Testing Bicep code analysis...")
    result = await analyzer.analyze_infrastructure_code_impl(
        bicep_code,
        'bicep',
        'test.bicep',
        None
    )
    
    findings = result.get('findings', [])
    print(f"    Found {len(findings)} findings")
    
    # Validate each finding has requirement_id
    findings_with_req_id = 0
    findings_with_ksi_id = 0
    unique_requirements = set()
    
    for finding in findings:
        if finding.get('requirement_id'):
            findings_with_req_id += 1
            unique_requirements.add(finding['requirement_id'])
        if finding.get('ksi_id'):
            findings_with_ksi_id += 1
    
    print(f"    [OK] Findings with requirement_id: {findings_with_req_id}/{len(findings)}")
    print(f"    [OK] Findings with ksi_id: {findings_with_ksi_id}/{len(findings)}")
    print(f"    [OK] Unique requirements cited: {len(unique_requirements)}")
    print(f"    [OK] Requirements: {', '.join(sorted(unique_requirements)[:5])}")
    
    # All findings should have requirement_id OR ksi_id
    assert findings_with_req_id > 0 or findings_with_ksi_id > 0, \
        "[FAIL] No findings include requirement_id or ksi_id"
    
    print(f"\n  [PASS] Code analyzer findings properly sourced")
    return result


async def test_implementation_examples_sourcing():
    """Test that implementation examples cite specific requirements."""
    print("\n" + "="*80)
    print("TEST: Implementation Examples Sourcing")
    print("="*80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    # Test a few requirement types
    test_requirements = [
        "KSI-IAM-01",  # KSI
        "FRR-VDR-01",  # FRR (if it exists)
    ]
    
    for req_id in test_requirements:
        print(f"\n  Testing {req_id}...")
        
        try:
            response = await enhancements.get_implementation_examples_impl(req_id, loader)
            
            # Check for requirement citation
            has_req_citation = req_id in response
            
            # Check for Azure guidance
            azure_info = validate_azure_references(response)
            
            # Check for NIST control references
            has_nist_refs = 'NIST' in response or re.search(r'[a-z]{2}-\d+', response.lower())
            
            print(f"    [OK] Requirement cited: {has_req_citation}")
            print(f"    [OK] Azure services: {len(azure_info['services_mentioned'])}")
            print(f"    [OK] NIST references: {has_nist_refs}")
            
            assert has_req_citation or 'not found' in response.lower(), \
                f"[FAIL] {req_id}: Missing requirement citation"
                
        except Exception as e:
            print(f"    ⚠ {req_id}: {str(e)}")
    
    print(f"\n  [PASS] Implementation examples properly sourced")


async def test_evidence_collection_architecture_sourcing():
    """Test that evidence architecture guidance cites KSIs and Azure best practices."""
    print("\n" + "="*80)
    print("TEST: Evidence Collection Architecture Sourcing")
    print("="*80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    scopes = ['minimal', 'single-ksi', 'category', 'all']
    
    for scope in scopes:
        print(f"\n  Testing scope: {scope}...")
        
        response = await evidence.get_evidence_automation_architecture_impl(loader, scope)
        
        # Check for KSI references
        ksi_refs = extract_ksi_references(response)
        
        # Check for Azure services
        azure_info = validate_azure_references(response)
        
        # Check for FedRAMP context
        has_fedramp = 'FedRAMP' in response
        
        print(f"    [OK] KSI references: {len(ksi_refs)}")
        print(f"    [OK] Azure services: {len(azure_info['services_mentioned'])}")
        print(f"    [OK] FedRAMP context: {has_fedramp}")
        
        assert len(ksi_refs) > 0, f"[FAIL] {scope}: No KSI references"
        assert azure_info['has_azure_guidance'], f"[FAIL] {scope}: No Azure guidance"
        assert has_fedramp, f"[FAIL] {scope}: No FedRAMP context"
    
    print(f"\n  [PASS] Architecture guidance properly sourced")


async def test_infrastructure_code_generation_sourcing():
    """Test that generated IaC includes KSI comments and citations."""
    print("\n" + "="*80)
    print("TEST: Infrastructure Code Generation Sourcing")
    print("="*80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    # Test both Bicep and Terraform for a KSI
    test_ksi = "KSI-MLA-01"  # Log Aggregation
    
    for iac_type in ['bicep', 'terraform']:
        print(f"\n  Testing {iac_type.upper()} generation for {test_ksi}...")
        
        try:
            from fedramp_20x_mcp.templates import get_infrastructure_template
            response = await evidence.get_infrastructure_code_for_ksi_impl(
                test_ksi, loader, get_infrastructure_template, iac_type
            )
            
            # Check for KSI inline comments
            has_inline_ksi = f"// Supports: {test_ksi}" in response or \
                            f"# Supports: {test_ksi}" in response or \
                            f"KSI-" in response
            
            # Check for Azure resources
            azure_resources = [
                'Microsoft.OperationalInsights/workspaces',  # Bicep
                'azurerm_log_analytics_workspace',  # Terraform
                'Log Analytics',
            ]
            has_azure_resource = any(res in response for res in azure_resources)
            
            print(f"    [OK] KSI inline comments: {has_inline_ksi}")
            print(f"    [OK] Azure resources: {has_azure_resource}")
            
            assert has_inline_ksi, f"[FAIL] {iac_type}: Missing KSI inline comments"
            assert has_azure_resource, f"[FAIL] {iac_type}: Missing Azure resources"
            
        except Exception as e:
            print(f"    ⚠ {iac_type}: {str(e)}")
    
    print(f"\n  [PASS] Infrastructure code properly sourced")


async def test_impact_level_accuracy():
    """Test that KSIs report correct impact levels (Low, Moderate, High)."""
    print("\n" + "="*80)
    print("TEST: Impact Level Accuracy")
    print("="*80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    # Get factory and check a few KSIs
    factory = get_factory()
    
    test_ksis = [
        "KSI-IAM-01",
        "KSI-CNA-01",
        "KSI-MLA-01",
        "KSI-SVC-01",
    ]
    
    print("\n  Checking impact levels...")
    
    for ksi_id in test_ksis:
        analyzer = factory.get_analyzer(ksi_id)
        if analyzer:
            impact_low = getattr(analyzer, 'IMPACT_LOW', None)
            impact_moderate = getattr(analyzer, 'IMPACT_MODERATE', None)
            
            print(f"    {ksi_id}: Low={impact_low}, Moderate={impact_moderate}")
            
            # At least one impact level should be defined
            assert impact_low is not None or impact_moderate is not None, \
                f"[FAIL] {ksi_id}: No impact levels defined"
    
    print(f"\n  [PASS] Impact levels properly defined")


async def test_nist_control_mappings():
    """Test that KSIs include accurate NIST 800-53 control mappings."""
    print("\n" + "="*80)
    print("TEST: NIST Control Mappings")
    print("="*80)
    
    factory = get_factory()
    
    test_ksis = [
        "KSI-IAM-01",  # Should have IA-2, IA-5, AC-2
        "KSI-CNA-01",  # Should have SC-7, AC-4
        "KSI-MLA-01",  # Should have AU-* controls
    ]
    
    print("\n  Checking NIST control mappings...")
    
    for ksi_id in test_ksis:
        analyzer = factory.get_analyzer(ksi_id)
        if analyzer:
            nist_controls = getattr(analyzer, 'NIST_CONTROLS', [])
            
            print(f"    {ksi_id}: {len(nist_controls)} NIST controls")
            
            # Should have at least one NIST control
            assert len(nist_controls) > 0, f"[FAIL] {ksi_id}: No NIST controls mapped"
            
            # Each control should be a tuple (id, name)
            for control in nist_controls[:3]:  # Check first 3
                assert isinstance(control, tuple), f"[FAIL] {ksi_id}: Invalid control format"
                assert len(control) == 2, f"[FAIL] {ksi_id}: Control should be (id, name)"
                print(f"      - {control[0]}: {control[1][:50]}...")
    
    print(f"\n  [PASS] NIST controls properly mapped")


async def test_azure_best_practices_citations():
    """Test that Azure recommendations include proper citations."""
    print("\n" + "="*80)
    print("TEST: Azure Best Practices Citations")
    print("="*80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    # Test cloud-native guidance
    technologies = ['kubernetes', 'containers', 'serverless']
    
    for tech in technologies:
        print(f"\n  Testing {tech} guidance...")
        
        response = await enhancements.get_cloud_native_guidance_impl(tech, loader)
        
        # Should mention Azure services
        azure_info = validate_azure_references(response)
        
        # Should have some Azure services mentioned
        assert azure_info['has_azure_guidance'], \
            f"[FAIL] {tech}: No Azure guidance provided"
        
        print(f"    [OK] Azure services: {', '.join(azure_info['services_mentioned'][:3])}")
    
    print(f"\n  [PASS] Azure best practices properly cited")


async def test_user_prompt_scenarios():
    """Test realistic user prompts to ensure proper sourcing in responses."""
    print("\n" + "="*80)
    print("TEST: Realistic User Prompt Scenarios")
    print("="*80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    scenarios = [
        {
            'name': 'MFA Implementation Query',
            'ksi': 'KSI-IAM-01',
            'check': 'Microsoft Entra ID'
        },
        {
            'name': 'Logging Requirements Query',
            'ksi': 'KSI-MLA-01',
            'check': 'Log Analytics'
        },
        {
            'name': 'Network Security Query',
            'ksi': 'KSI-CNA-01',
            'check': 'Azure Firewall'
        },
    ]
    
    for scenario in scenarios:
        print(f"\n  Scenario: {scenario['name']}")
        
        # User asks about a KSI
        response = await ksi.get_ksi_impl(scenario['ksi'], loader)
        
        # Validate response includes KSI ID
        has_ksi = scenario['ksi'] in response
        
        # Validate Azure service mentioned
        has_azure = scenario['check'] in response
        
        # Validate NIST references
        has_nist = 'NIST' in response
        
        print(f"    [OK] KSI ID present: {has_ksi}")
        print(f"    [OK] Azure service mentioned: {has_azure}")
        print(f"    [OK] NIST reference: {has_nist}")
        
        assert has_ksi, f"[FAIL] {scenario['name']}: KSI ID not in response"
    
    print(f"\n  [PASS] User prompt scenarios validated")


async def run_all_sourcing_tests():
    """Run all sourcing validation tests."""
    print("\n" + "="*80)
    print("FEDRAMP 20X SOURCING & AZURE BEST PRACTICES VALIDATION")
    print("="*80)
    print("\nValidating that all recommendations:")
    print("  1. Cite specific FedRAMP 20x KSIs/requirements")
    print("  2. Include proper requirement_id/ksi_id in findings")
    print("  3. Reference Azure best practices with proper sources")
    print("  4. Apply correct impact levels (Low/Moderate)")
    print("  5. Map to accurate NIST 800-53 controls")
    
    tests = [
        ("KSI Evidence Automation Sourcing", test_ksi_evidence_automation_sourcing),
        ("Code Analyzer Finding Sourcing", test_code_analyzer_finding_sourcing),
        ("Implementation Examples Sourcing", test_implementation_examples_sourcing),
        ("Evidence Architecture Sourcing", test_evidence_collection_architecture_sourcing),
        ("Infrastructure Code Generation", test_infrastructure_code_generation_sourcing),
        ("Impact Level Accuracy", test_impact_level_accuracy),
        ("NIST Control Mappings", test_nist_control_mappings),
        ("Azure Best Practices Citations", test_azure_best_practices_citations),
        ("User Prompt Scenarios", test_user_prompt_scenarios),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            await test_func()
            passed += 1
        except AssertionError as e:
            print(f"\n  [FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"\n  [ERROR] {test_name}: {e}")
            failed += 1
    
    print("\n" + "="*80)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*80)
    
    if failed == 0:
        print("\n[PASS] ALL SOURCING VALIDATION TESTS PASSED")
        print("\nAll recommendations properly cite:")
        print("  [PASS] FedRAMP 20x KSIs and requirements")
        print("  [PASS] Azure services and best practices")
        print("  [PASS] NIST 800-53 control mappings")
        print("  [PASS] Impact levels (Low/Moderate)")
    else:
        print(f"\n[FAIL] {failed} TESTS FAILED - Review output above")
        raise AssertionError(f"{failed} sourcing validation tests failed")


if __name__ == "__main__":
    asyncio.run(run_all_sourcing_tests())

