"""
Test Evidence Automation Features for KSI Analyzers

Tests the new evidence automation capabilities added to KSI analyzers
and the corresponding MCP tools.
"""

import sys
import os

# Add the parent directory to the path so we can import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from src.fedramp_20x_mcp.analyzers.ksi.ksi_iam_01 import KSI_IAM_01_Analyzer
from src.fedramp_20x_mcp.analyzers.ksi.ksi_cna_01 import KSI_CNA_01_Analyzer
from src.fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from src.fedramp_20x_mcp.tools.ksi import (
    get_ksi_evidence_automation_impl,
    get_ksi_evidence_queries_impl,
    get_ksi_evidence_artifacts_impl
)
import asyncio


def test_base_analyzer_methods():
    """Test that base evidence automation methods are available."""
    print("\n=== Test: Base Analyzer Methods ===")
    
    analyzer = KSI_IAM_01_Analyzer()
    
    # Test method existence
    assert hasattr(analyzer, 'get_evidence_automation_recommendations'), "Missing get_evidence_automation_recommendations method"
    assert hasattr(analyzer, 'get_evidence_collection_queries'), "Missing get_evidence_collection_queries method"
    assert hasattr(analyzer, 'get_evidence_artifacts'), "Missing get_evidence_artifacts method"
    
    print("OK: All base methods present")


def test_iam_01_evidence_automation():
    """Test KSI-IAM-01 evidence automation implementation."""
    print("\n=== Test: KSI-IAM-01 Evidence Automation ===")
    
    analyzer = KSI_IAM_01_Analyzer()
    
    # Get recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    
    # Validate structure
    assert recommendations['ksi_id'] == 'KSI-IAM-01', "Wrong KSI ID"
    assert recommendations['ksi_name'] == 'Phishing-Resistant MFA', "Wrong KSI name"
    assert recommendations['evidence_type'] == 'log-based', "Wrong evidence type"
    assert recommendations['automation_feasibility'] == 'high', "Wrong automation feasibility"
    assert len(recommendations['azure_services']) > 0, "No Azure services defined"
    assert len(recommendations['collection_methods']) > 0, "No collection methods defined"
    
    # Check for specific Azure services
    service_names = [svc['service'] for svc in recommendations['azure_services']]
    assert 'Azure AD Sign-in Logs' in service_names, "Missing Azure AD Sign-in Logs"
    assert 'Azure Monitor / Log Analytics' in service_names, "Missing Log Analytics"
    
    print(f"OK: Found {len(recommendations['azure_services'])} Azure services")
    print(f"OK: Found {len(recommendations['collection_methods'])} collection methods")


def test_iam_01_evidence_queries():
    """Test KSI-IAM-01 evidence collection queries."""
    print("\n=== Test: KSI-IAM-01 Evidence Queries ===")
    
    analyzer = KSI_IAM_01_Analyzer()
    queries = analyzer.get_evidence_collection_queries()
    
    assert len(queries) > 0, "No queries defined"
    
    # Validate query structure
    for query in queries:
        assert 'name' in query, "Query missing name"
        assert 'query_type' in query, "Query missing type"
        assert 'query' in query, "Query missing query text"
        assert 'data_source' in query, "Query missing data source"
        assert 'schedule' in query, "Query missing schedule"
        assert 'output_format' in query, "Query missing output format"
    
    # Check for specific query types
    query_types = [q['query_type'] for q in queries]
    assert 'kusto' in query_types, "No KQL queries found"
    assert 'rest_api' in query_types, "No REST API queries found"
    
    print(f"OK: Found {len(queries)} evidence collection queries")
    print(f"   - KQL queries: {query_types.count('kusto')}")
    print(f"   - REST API queries: {query_types.count('rest_api')}")


def test_iam_01_evidence_artifacts():
    """Test KSI-IAM-01 evidence artifacts."""
    print("\n=== Test: KSI-IAM-01 Evidence Artifacts ===")
    
    analyzer = KSI_IAM_01_Analyzer()
    artifacts = analyzer.get_evidence_artifacts()
    
    assert len(artifacts) > 0, "No artifacts defined"
    
    # Validate artifact structure
    for artifact in artifacts:
        assert 'artifact_name' in artifact, "Artifact missing name"
        assert 'artifact_type' in artifact, "Artifact missing type"
        assert 'description' in artifact, "Artifact missing description"
        assert 'collection_method' in artifact, "Artifact missing collection method"
        assert 'format' in artifact, "Artifact missing format"
        assert 'frequency' in artifact, "Artifact missing frequency"
        assert 'retention' in artifact, "Artifact missing retention"
    
    # Check artifact types
    artifact_types = set(a['artifact_type'] for a in artifacts)
    print(f"OK: Found {len(artifacts)} evidence artifacts")
    print(f"   - Types: {', '.join(artifact_types)}")


def test_cna_01_evidence_automation():
    """Test KSI-CNA-01 evidence automation implementation."""
    print("\n=== Test: KSI-CNA-01 Evidence Automation ===")
    
    analyzer = KSI_CNA_01_Analyzer()
    
    # Get recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    
    # Validate structure
    assert recommendations['ksi_id'] == 'KSI-CNA-01', "Wrong KSI ID"
    assert recommendations['ksi_name'] == 'Restrict Network Traffic', "Wrong KSI name"
    assert recommendations['evidence_type'] == 'config-based', "Wrong evidence type"
    assert recommendations['automation_feasibility'] == 'high', "Wrong automation feasibility"
    
    # Check for Azure Resource Graph
    service_names = [svc['service'] for svc in recommendations['azure_services']]
    assert 'Azure Resource Graph' in service_names, "Missing Azure Resource Graph"
    assert 'Azure Network Watcher' in service_names, "Missing Network Watcher"
    
    print(f"OK: Found {len(recommendations['azure_services'])} Azure services")
    print(f"OK: Found {len(recommendations['collection_methods'])} collection methods")


def test_cna_01_evidence_queries():
    """Test KSI-CNA-01 evidence collection queries."""
    print("\n=== Test: KSI-CNA-01 Evidence Queries ===")
    
    analyzer = KSI_CNA_01_Analyzer()
    queries = analyzer.get_evidence_collection_queries()
    
    assert len(queries) > 0, "No queries defined"
    
    # Check for Resource Graph queries
    query_types = [q['query_type'] for q in queries]
    assert 'resource_graph' in query_types, "No Resource Graph queries found"
    
    # Check for NSG-specific queries
    query_names = [q['name'].lower() for q in queries]
    nsg_queries = [name for name in query_names if 'nsg' in name]
    assert len(nsg_queries) > 0, "No NSG-specific queries found"
    
    print(f"OK: Found {len(queries)} evidence collection queries")
    print(f"   - Resource Graph queries: {query_types.count('resource_graph')}")
    print(f"   - NSG-related queries: {len(nsg_queries)}")


async def test_evidence_automation_tool():
    """Test the MCP tool for evidence automation."""
    print("\n=== Test: Evidence Automation MCP Tool ===")
    
    # Create data loader
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    
    # Test KSI-IAM-01
    result = await get_ksi_evidence_automation_impl("KSI-IAM-01", data_loader)
    
    assert "Evidence Automation: KSI-IAM-01" in result, "Missing title"
    assert "Phishing-Resistant MFA" in result, "Missing KSI name"
    assert "Azure Services Required" in result, "Missing Azure services section"
    assert "Evidence Collection Methods" in result, "Missing collection methods section"
    assert "Storage Requirements" in result, "Missing storage requirements"
    
    print("OK: Evidence automation tool returns structured output")
    
    # Test invalid KSI
    result = await get_ksi_evidence_automation_impl("KSI-INVALID-99", data_loader)
    assert "not found" in result.lower(), "Should return error for invalid KSI"
    
    print("OK: Tool handles invalid KSI IDs")


async def test_evidence_queries_tool():
    """Test the MCP tool for evidence queries."""
    print("\n=== Test: Evidence Queries MCP Tool ===")
    
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    
    # Test KSI-IAM-01
    result = await get_ksi_evidence_queries_impl("KSI-IAM-01", data_loader)
    
    assert "Evidence Collection Queries: KSI-IAM-01" in result, "Missing title"
    assert "Query 1:" in result, "Missing query sections"
    assert "```" in result, "Missing code blocks for queries"
    
    print("OK: Evidence queries tool returns formatted queries")


async def test_evidence_artifacts_tool():
    """Test the MCP tool for evidence artifacts."""
    print("\n=== Test: Evidence Artifacts MCP Tool ===")
    
    data_loader = FedRAMPDataLoader()
    await data_loader.load_data()
    
    # Test KSI-IAM-01
    result = await get_ksi_evidence_artifacts_impl("KSI-IAM-01", data_loader)
    
    assert "Evidence Artifacts: KSI-IAM-01" in result, "Missing title"
    assert "Artifacts" in result, "Missing artifacts section"
    assert "Collection Method:" in result, "Missing collection method details"
    
    print("OK: Evidence artifacts tool returns structured list")


def test_factory_evidence_automation():
    """Test evidence automation via factory."""
    print("\n=== Test: Factory Evidence Automation Access ===")
    
    factory = get_factory()
    
    # Get analyzers with evidence automation
    analyzers_with_automation = []
    for ksi_id, analyzer in factory._analyzers.items():
        if not analyzer.RETIRED:
            recommendations = analyzer.get_evidence_automation_recommendations()
            if recommendations.get('automation_feasibility') != 'manual-only':
                analyzers_with_automation.append(ksi_id)
    
    print(f"OK: Found {len(analyzers_with_automation)} KSIs with evidence automation")
    print(f"   Examples: {', '.join(analyzers_with_automation[:5])}")
    
    assert len(analyzers_with_automation) >= 2, "Should have at least 2 KSIs with automation"


def test_default_implementation():
    """Test that all active KSIs have evidence automation implemented."""
    print("\n=== Test: Default Implementation ===")
    
    factory = get_factory()
    
    # Count active KSIs with automation
    active_with_automation = 0
    active_without_automation = []
    
    for ksi_id, analyzer in factory._analyzers.items():
        if not analyzer.RETIRED:
            recommendations = analyzer.get_evidence_automation_recommendations()
            if recommendations.get('automation_feasibility') != 'manual-only':
                active_with_automation += 1
            else:
                active_without_automation.append(ksi_id)
    
    # All 65 active KSIs should have evidence automation
    if len(active_without_automation) > 0:
        print(f"FAIL: {len(active_without_automation)} active KSIs missing automation: {', '.join(active_without_automation[:5])}")
        assert False, f"{len(active_without_automation)} active KSIs without automation"
    else:
        print(f"OK: All {active_with_automation} active KSIs have evidence automation implemented")


def test_evidence_automation_completeness():
    """Test that evidence automation is comprehensive."""
    print("\n=== Test: Evidence Automation Completeness ===")
    
    analyzer = KSI_IAM_01_Analyzer()
    
    # Get all three evidence methods
    recommendations = analyzer.get_evidence_automation_recommendations()
    queries = analyzer.get_evidence_collection_queries()
    artifacts = analyzer.get_evidence_artifacts()
    
    # Validate cross-references
    assert len(queries) > 0, "Should have queries"
    assert len(artifacts) > 0, "Should have artifacts"
    
    # Check that collection methods reference queryable data
    collection_methods = recommendations.get('collection_methods', [])
    assert len(collection_methods) > 0, "Should have collection methods"
    
    # Display collection methods
    for method in collection_methods:
        print(f"   - Collection method: {method['method']}")
    
    print(f"OK: Evidence automation has {len(collection_methods)} methods, {len(queries)} queries, {len(artifacts)} artifacts")


async def run_all_tests():
    """Run all tests."""
    print("\n" + "="*70)
    print("KSI EVIDENCE AUTOMATION TEST SUITE")
    print("="*70)
    
    tests_passed = 0
    tests_failed = 0
    
    test_functions = [
        # Synchronous tests
        ("Base Analyzer Methods", test_base_analyzer_methods, False),
        ("IAM-01 Evidence Automation", test_iam_01_evidence_automation, False),
        ("IAM-01 Evidence Queries", test_iam_01_evidence_queries, False),
        ("IAM-01 Evidence Artifacts", test_iam_01_evidence_artifacts, False),
        ("CNA-01 Evidence Automation", test_cna_01_evidence_automation, False),
        ("CNA-01 Evidence Queries", test_cna_01_evidence_queries, False),
        ("Factory Evidence Automation", test_factory_evidence_automation, False),
        ("Default Implementation", test_default_implementation, False),
        ("Evidence Automation Completeness", test_evidence_automation_completeness, False),
        
        # Async tests
        ("Evidence Automation Tool", test_evidence_automation_tool, True),
        ("Evidence Queries Tool", test_evidence_queries_tool, True),
        ("Evidence Artifacts Tool", test_evidence_artifacts_tool, True),
    ]
    
    for test_name, test_func, is_async in test_functions:
        try:
            if is_async:
                await test_func()
            else:
                test_func()
            tests_passed += 1
        except AssertionError as e:
            print(f"FAIL: {test_name} - {e}")
            tests_failed += 1
        except Exception as e:
            print(f"ERROR: {test_name} - {e}")
            tests_failed += 1
    
    print("\n" + "="*70)
    print(f"TEST RESULTS: {tests_passed} passed, {tests_failed} failed")
    print("="*70)
    
    if tests_failed == 0:
        print("\nALL TESTS PASSED ✓")
        return 0
    else:
        print(f"\n{tests_failed} TEST(S) FAILED ✗")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
