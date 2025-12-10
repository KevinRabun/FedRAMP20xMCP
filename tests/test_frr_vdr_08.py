"""
Tests for FRR-VDR-08: Evaluate Internet-Reachability

Verifies detection of internet-facing resources in IaC.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_08 import FRR_VDR_08_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_bicep_public_ip_detected():
    """Test detection of Public IP in Bicep."""
    code = """
    resource publicIp 'Microsoft.Network/publicIPAddresses@2021-02-01' = {
      name: 'myPublicIP'
      location: resourceGroup().location
      properties: {
        publicIPAllocationMethod: 'Static'
      }
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_bicep(code, "main.bicep")
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].requirement_id == "FRR-VDR-08" or findings[0].ksi_id == "FRR-VDR-08"
    assert findings[0].severity == Severity.HIGH
    assert "Public IP address" in findings[0].title
    print("✓ test_bicep_public_ip_detected passed")


def test_bicep_load_balancer_internet_facing():
    """Test detection of internet-facing Load Balancer."""
    code = """
    resource lb 'Microsoft.Network/loadBalancers@2021-02-01' = {
      name: 'myLoadBalancer'
      location: resourceGroup().location
      properties: {
        frontendIPConfigurations: [
          {
            name: 'publicFrontend'
            properties: {
              publicIPAddress: {
                id: publicIp.id
              }
            }
          }
        ]
      }
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_bicep(code, "lb.bicep")
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.HIGH
    assert "Load Balancer" in findings[0].title
    print("✓ test_bicep_load_balancer_internet_facing passed")


def test_bicep_nsg_allows_all_internet():
    """Test detection of NSG rules allowing 0.0.0.0/0."""
    code = """
    resource nsg 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
      name: 'myNSG'
      location: resourceGroup().location
      properties: {
        securityRules: [
          {
            name: 'AllowSSH'
            properties: {
              priority: 100
              direction: 'Inbound'
              access: 'Allow'
              protocol: 'Tcp'
              sourceAddressPrefix: '0.0.0.0/0'
              sourcePortRange: '*'
              destinationAddressPrefix: '*'
              destinationPortRange: '22'
            }
          }
        ]
      }
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_bicep(code, "nsg.bicep")
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.HIGH
    assert "NSG rule" in findings[0].title or "permissive" in findings[0].title.lower()
    print("✓ test_bicep_nsg_allows_all_internet passed")


def test_bicep_vm_without_nsg():
    """Test detection of VM with public IP but no NSG."""
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2021-03-01' = {
      name: 'myVM'
      location: resourceGroup().location
      properties: {
        hardwareProfile: {
          vmSize: 'Standard_DS1_v2'
        }
        networkProfile: {
          networkInterfaces: [
            {
              id: nic.id
              properties: {
                primary: true
                ipConfigurations: [
                  {
                    name: 'ipconfig1'
                    properties: {
                      publicIPAddress: {
                        id: publicIp.id
                      }
                    }
                  }
                ]
              }
            }
          ]
        }
      }
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_bicep(code, "vm.bicep")
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}: {[f.title for f in findings]}"
    assert findings[0].severity == Severity.HIGH
    assert "VM" in findings[0].title and ("NSG" in findings[0].title or "Network Security Group" in findings[0].title)
    print("✓ test_bicep_vm_without_nsg passed")


def test_bicep_application_gateway():
    """Test detection of Application Gateway (internet-facing)."""
    code = """
    resource appGw 'Microsoft.Network/applicationGateways@2021-02-01' = {
      name: 'myAppGateway'
      location: resourceGroup().location
      properties: {
        sku: {
          name: 'WAF_v2'
          tier: 'WAF_v2'
        }
      }
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_bicep(code, "appgw.bicep")
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.MEDIUM
    assert "Application Gateway" in findings[0].title
    print("✓ test_bicep_application_gateway passed")


def test_terraform_azure_public_ip():
    """Test detection of Azure Public IP in Terraform."""
    code = """
    resource "azurerm_public_ip" "example" {
      name                = "myPublicIP"
      location            = azurerm_resource_group.example.location
      resource_group_name = azurerm_resource_group.example.name
      allocation_method   = "Static"
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_terraform(code, "main.tf")
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.HIGH
    assert "Azure Public IP" in findings[0].title or "Public IP" in findings[0].title
    print("✓ test_terraform_azure_public_ip passed")


def test_terraform_azure_nsg_wildcard():
    """Test detection of Azure NSG with wildcard source."""
    code = """
    resource "azurerm_network_security_group" "example" {
      name                = "myNSG"
      location            = azurerm_resource_group.example.location
      resource_group_name = azurerm_resource_group.example.name
      
      security_rule {
        name                       = "allow-rdp"
        priority                   = 100
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        source_port_range          = "*"
        destination_port_range     = "3389"
        source_address_prefix      = "*"
        destination_address_prefix = "*"
      }
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_terraform(code, "nsg.tf")
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.HIGH
    assert "NSG" in findings[0].title
    print("✓ test_terraform_azure_nsg_wildcard passed")


def test_no_findings_for_private_config():
    """Test that private-only configs don't trigger findings."""
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2021-03-01' = {
      name: 'privateVM'
      location: resourceGroup().location
      properties: {
        hardwareProfile: {
          vmSize: 'Standard_DS1_v2'
        }
        networkProfile: {
          networkInterfaces: [
            {
              id: nic.id
            }
          ]
        }
      }
    }
    """
    
    analyzer = FRR_VDR_08_Analyzer()
    findings = analyzer.analyze_bicep(code, "private.bicep")
    
    assert len(findings) == 0, f"Expected 0 findings for private config, got {len(findings)}"
    print("✓ test_no_findings_for_private_config passed")


def test_analyzer_metadata():
    """Test analyzer metadata attributes."""
    analyzer = FRR_VDR_08_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-08"
    assert analyzer.FRR_NAME == "Evaluate Internet-Reachability"
    assert analyzer.FAMILY == "VDR"
    assert analyzer.PRIMARY_KEYWORD == "MUST"
    assert analyzer.IMPACT_LOW is True
    assert analyzer.IMPACT_MODERATE is True
    assert analyzer.IMPACT_HIGH is True
    assert analyzer.CODE_DETECTABLE is True
    assert analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED"
    assert len(analyzer.NIST_CONTROLS) >= 3
    assert len(analyzer.RELATED_KSIS) >= 2
    
    print("✓ test_analyzer_metadata passed")


def test_evidence_automation_recommendations():
    """Test evidence automation recommendations."""
    analyzer = FRR_VDR_08_Analyzer()
    recommendations = analyzer.get_evidence_automation_recommendations()
    
    assert recommendations["frr_id"] == "FRR-VDR-08"
    assert recommendations["primary_keyword"] == "MUST"
    assert len(recommendations["impact_levels"]) == 3
    assert "Azure Resource Graph" in recommendations["azure_services"]
    assert len(recommendations["collection_methods"]) >= 3
    assert len(recommendations["evidence_artifacts"]) >= 3
    
    print("✓ test_evidence_automation_recommendations passed")


def test_evidence_collection_queries():
    """Test evidence collection queries."""
    analyzer = FRR_VDR_08_Analyzer()
    queries = analyzer.get_evidence_collection_queries()
    
    assert len(queries) >= 4, f"Expected at least 4 queries, got {len(queries)}"
    
    # Check for Azure Resource Graph queries
    arg_queries = [q for q in queries if q["query_type"] == "Azure Resource Graph KQL"]
    assert len(arg_queries) >= 2, "Should have at least 2 ARG queries"
    
    # Verify query structure
    for query in queries:
        assert "query_type" in query
        assert "query_name" in query
        assert "query" in query
        assert "purpose" in query
    
    print("✓ test_evidence_collection_queries passed")


def test_evidence_artifacts():
    """Test evidence artifacts descriptions."""
    analyzer = FRR_VDR_08_Analyzer()
    artifacts = analyzer.get_evidence_artifacts()
    
    assert len(artifacts) >= 4, f"Expected at least 4 artifacts, got {len(artifacts)}"
    
    # Verify artifact structure
    for artifact in artifacts:
        assert "artifact_name" in artifact
        assert "artifact_type" in artifact
        assert "description" in artifact
        assert "collection_method" in artifact
        assert "storage_location" in artifact
    
    print("✓ test_evidence_artifacts passed")


def run_all_tests():
    """Run all tests."""
    print("\nRunning FRR-VDR-08 Analyzer Tests")
    print("=" * 50)
    
    tests = [
        test_bicep_public_ip_detected,
        test_bicep_load_balancer_internet_facing,
        test_bicep_nsg_allows_all_internet,
        test_bicep_vm_without_nsg,
        test_bicep_application_gateway,
        test_terraform_azure_public_ip,
        test_terraform_azure_nsg_wildcard,
        test_no_findings_for_private_config,
        test_analyzer_metadata,
        test_evidence_automation_recommendations,
        test_evidence_collection_queries,
        test_evidence_artifacts
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f"✗ {test.__name__} failed: {e}")
            import traceback
            traceback.print_exc()
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("ALL TESTS PASSED ✓")
        return 0
    else:
        print(f"FAILURES DETECTED ({failed} tests failed)")
        return 1


if __name__ == '__main__':
    exit_code = run_all_tests()
    sys.exit(exit_code)
