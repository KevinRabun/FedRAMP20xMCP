"""
Tests for FRR-ADS-01: Public Information

Tests that providers MUST publicly share up-to-date information about the 
cloud service offering in both human-readable and machine-readable formats.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.frr.frr_ads_01 import FRR_ADS_01_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_analyzer_metadata():
    """Test FRR-ADS-01 analyzer metadata completeness."""
    analyzer = FRR_ADS_01_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-ADS-01", "FRR_ID should be FRR-ADS-01"
    assert analyzer.FAMILY == "ADS", "Family should be ADS"
    assert analyzer.FAMILY_NAME == "Authorization Data Sharing", "Family name mismatch"
    assert analyzer.FRR_NAME == "Public Information", "FRR name mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Primary keyword should be MUST"
    assert analyzer.IMPACT_LOW == True, "Should apply to Low impact systems"
    assert analyzer.IMPACT_MODERATE == True, "Should apply to Moderate impact systems"
    assert analyzer.IMPACT_HIGH == True, "Should apply to High impact systems"
    assert len(analyzer.NIST_CONTROLS) > 0, "NIST controls should be specified"
    assert len(analyzer.RELATED_KSIS) > 0, "Related KSIs should be specified"
    assert analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED", "Status should be IMPLEMENTED"
    
    print("[PASS] test_analyzer_metadata passed")


def test_documentation_analysis_missing_machine_readable():
    """Test detection of missing machine-readable formats."""
    analyzer = FRR_ADS_01_Analyzer()
    
    doc_content = """
    # Service Offering
    
    This is our cloud service. It is FedRAMP authorized.
    Available at Low and Moderate impact levels.
    """
    
    findings = analyzer.analyze_documentation(doc_content, "README.md")
    
    # Should find missing machine-readable format
    assert len(findings) > 0, "Should detect missing machine-readable format"
    assert any("machine-readable" in f.title.lower() for f in findings), \
        "Should specifically mention missing machine-readable format"
    assert any(f.severity == Severity.MEDIUM for f in findings), \
        "Missing machine-readable format should be MEDIUM severity"
    
    print("[PASS] test_documentation_analysis_missing_machine_readable passed")


def test_documentation_analysis_missing_service_info():
    """Test that documentation is checked for completeness."""
    analyzer = FRR_ADS_01_Analyzer()
    
    # Documentation with keywords that trigger analysis but missing key info
    # Note: "offering" is in the filename to trigger analysis
    doc_with_minimal_info = "This is a service offering document with over 100 characters to pass the minimum length check for analysis and detection of missing elements required by FedRAMP."
    
    findings = analyzer.analyze_documentation(doc_with_minimal_info, "offering-info.md")
    
    # This should trigger at least one finding due to missing service info or machine-readable format
    assert len(findings) >= 1, f"Should detect issues in incomplete documentation, got {len(findings)} findings"
    
    print("[PASS] test_documentation_analysis_missing_service_info passed")


def test_documentation_analysis_compliant():
    """Test compliant documentation with both formats."""
    analyzer = FRR_ADS_01_Analyzer()
    
    compliant_doc = """
    # Cloud Service Offering
    
    ## Overview
    This is our FedRAMP authorized cloud service offering. 
    
    ## Service Details
    - Service Name: CloudPlatform Pro
    - FedRAMP Authorization: YES (Moderate Impact Level)
    - Authorization Boundary: [description]
    - Authorized Services: [list]
    
    ## Machine-Readable Formats
    Our service documentation is available in:
    - OSCAL System Security Plan (SSP)
    - JSON schema definitions in OpenAPI format
    - YAML service catalog
    """
    
    findings = analyzer.analyze_documentation(compliant_doc, "service-offering.md")
    
    # Compliant doc should have fewer/no high-severity findings
    high_severity = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0, "Compliant documentation should not have HIGH severity findings"
    
    print("[PASS] test_documentation_analysis_compliant passed")


def test_python_not_applicable():
    """Test that Python analysis returns empty (not code-detectable)."""
    analyzer = FRR_ADS_01_Analyzer()
    
    python_code = """
    def publish_documentation():
        # This would be code that publishes docs
        pass
    """
    
    findings = analyzer.analyze_python(python_code, "publish.py")
    assert len(findings) == 0, "FRR-ADS-01 is not code-detectable in Python"
    
    print("[PASS] test_python_not_applicable passed")


def test_csharp_not_applicable():
    """Test that C# analysis returns empty (not code-detectable)."""
    analyzer = FRR_ADS_01_Analyzer()
    
    csharp_code = """
    public class DocumentationPublisher {
        public void PublishDocs() { }
    }
    """
    
    findings = analyzer.analyze_csharp(csharp_code, "Publisher.cs")
    assert len(findings) == 0, "FRR-ADS-01 is not code-detectable in C#"
    
    print("[PASS] test_csharp_not_applicable passed")


def test_bicep_not_applicable():
    """Test that Bicep analysis returns empty (not IaC-detectable)."""
    analyzer = FRR_ADS_01_Analyzer()
    
    bicep_code = """
    resource staticSite 'Microsoft.Web/staticSites@2021-01-15' = {
      name: 'myDocSite'
      location: resourceGroup().location
    }
    """
    
    findings = analyzer.analyze_bicep(bicep_code, "site.bicep")
    assert len(findings) == 0, "FRR-ADS-01 is not IaC-detectable"
    
    print("[PASS] test_bicep_not_applicable passed")


def test_terraform_not_applicable():
    """Test that Terraform analysis returns empty (not IaC-detectable)."""
    analyzer = FRR_ADS_01_Analyzer()
    
    terraform_code = """
    resource "azurerm_static_web_app" "docs" {
      name = "documentation"
    }
    """
    
    findings = analyzer.analyze_terraform(terraform_code, "main.tf")
    assert len(findings) == 0, "FRR-ADS-01 is not IaC-detectable"
    
    print("[PASS] test_terraform_not_applicable passed")


def test_evidence_automation_recommendations():
    """Test evidence automation recommendations are complete."""
    analyzer = FRR_ADS_01_Analyzer()
    
    recommendations = analyzer.get_evidence_automation_recommendations()
    
    # Verify required fields
    assert recommendations['frr_id'] == "FRR-ADS-01", "Should reference correct FRR"
    assert 'automation_feasibility' in recommendations, "Should specify automation feasibility"
    assert 'azure_services' in recommendations, "Should list Azure services"
    assert len(recommendations['azure_services']) > 0, "Should recommend Azure services"
    assert 'collection_methods' in recommendations, "Should describe collection methods"
    assert 'implementation_steps' in recommendations, "Should provide implementation steps"
    assert 'evidence_artifacts' in recommendations, "Should describe evidence artifacts"
    
    print("[PASS] test_evidence_automation_recommendations passed")


def test_evidence_collection_queries():
    """Test evidence collection queries are provided."""
    analyzer = FRR_ADS_01_Analyzer()
    
    queries = analyzer.get_evidence_collection_queries()
    
    assert isinstance(queries, list), "Should return list of queries"
    assert len(queries) > 0, "Should provide evidence collection queries"
    
    # Verify each query has required structure
    for query in queries:
        assert 'method_type' in query, "Query should specify method type"
        assert 'name' in query, "Query should have a name"
        assert 'description' in query, "Query should have a description"
        assert 'purpose' in query, "Query should specify purpose"
    
    print("[PASS] test_evidence_collection_queries passed")


def test_evidence_artifacts():
    """Test evidence artifacts are properly described."""
    analyzer = FRR_ADS_01_Analyzer()
    
    artifacts = analyzer.get_evidence_artifacts()
    
    assert isinstance(artifacts, list), "Should return list of artifacts"
    assert len(artifacts) > 0, "Should provide evidence artifacts"
    
    # Verify structure
    for artifact in artifacts:
        assert 'artifact_name' in artifact, "Artifact should have a name"
        assert 'artifact_type' in artifact, "Artifact should specify type"
        assert 'description' in artifact, "Artifact should have description"
        assert 'collection_method' in artifact, "Artifact should specify collection method"
        assert 'storage_location' in artifact, "Artifact should specify storage location"
    
    # Verify minimum artifacts
    artifact_names = [a['artifact_name'] for a in artifacts]
    assert any('Inventory' in name for name in artifact_names), \
        "Should include documentation inventory artifact"
    assert any('Marketplace' in name for name in artifact_names), \
        "Should include FedRAMP Marketplace listing"
    assert any('OSCAL' in name or 'Machine' in name for name in artifact_names), \
        "Should include machine-readable format artifact"
    
    print("[PASS] test_evidence_artifacts passed")


def test_nist_controls_present():
    """Test that NIST controls are properly documented."""
    analyzer = FRR_ADS_01_Analyzer()
    
    assert len(analyzer.NIST_CONTROLS) > 0, "NIST controls should be specified"
    
    # Each control should be a tuple of (id, name)
    for control in analyzer.NIST_CONTROLS:
        assert isinstance(control, tuple), "Control should be tuple"
        assert len(control) == 2, "Control should have ID and name"
        control_id, control_name = control
        assert isinstance(control_id, str), "Control ID should be string"
        assert isinstance(control_name, str), "Control name should be string"
        assert len(control_id) > 0, "Control ID should not be empty"
        assert len(control_name) > 0, "Control name should not be empty"
    
    print("[PASS] test_nist_controls_present passed")


def test_related_ksis_present():
    """Test that related KSIs are documented."""
    analyzer = FRR_ADS_01_Analyzer()
    
    assert len(analyzer.RELATED_KSIS) > 0, "Related KSIs should be specified"
    
    for ksi in analyzer.RELATED_KSIS:
        assert isinstance(ksi, str), "KSI should be string"
        assert ksi.startswith("KSI-"), "KSI should start with 'KSI-'"
        assert len(ksi) > 4, "KSI ID should be properly formatted"
    
    print("[PASS] test_related_ksis_present passed")


def test_no_todo_markers():
    """Test that there are no incomplete TODO markers in code."""
    analyzer = FRR_ADS_01_Analyzer()
    
    # Get the class source
    import inspect
    source = inspect.getsource(FRR_ADS_01_Analyzer)
    
    # Should not have TODO in implementation (acceptable in docstrings for future enhancements)
    lines = source.split('\n')
    for i, line in enumerate(lines):
        # Skip docstring TODOs
        if '"""' in line or "'''" in line:
            continue
        # Check for code TODOs in critical methods
        if 'def analyze' in line or 'def get_evidence' in line:
            # Next few lines shouldn't have TODO
            for j in range(i, min(i+5, len(lines))):
                assert 'TODO' not in lines[j], f"Line {j+1} has unimplemented TODO"
    
    print("[PASS] test_no_todo_markers passed")


def run_all_tests():
    """Run all FRR-ADS-01 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Documentation: missing machine-readable", test_documentation_analysis_missing_machine_readable),
        ("Documentation: missing service info", test_documentation_analysis_missing_service_info),
        ("Documentation: compliant", test_documentation_analysis_compliant),
        ("Python not applicable", test_python_not_applicable),
        ("C# not applicable", test_csharp_not_applicable),
        ("Bicep not applicable", test_bicep_not_applicable),
        ("Terraform not applicable", test_terraform_not_applicable),
        ("Evidence automation recommendations", test_evidence_automation_recommendations),
        ("Evidence collection queries", test_evidence_collection_queries),
        ("Evidence artifacts", test_evidence_artifacts),
        ("NIST controls present", test_nist_controls_present),
        ("Related KSIs present", test_related_ksis_present),
        ("No TODO markers", test_no_todo_markers),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 80)
    print(f"FRR-ADS-01: Public Information - Comprehensive Test Suite")
    print("=" * 80 + "\n")
    
    for test_name, test_func in test_functions:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_name} ERROR: {str(e)}")
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"Test Results: {passed}/{len(test_functions)} passed, {failed} failed")
    print("=" * 80 + "\n")
    
    if failed == 0:
        print("ALL TESTS PASSED [PASS]\n")
        return 0
    else:
        print(f"SOME TESTS FAILED [FAIL]\n")
        return 1


if __name__ == "__main__":
    exit(run_all_tests())
