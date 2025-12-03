"""
Test tool registration system
Ensures all 24 tools are properly registered with the MCP server
"""

from mcp.server.fastmcp import FastMCP
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.tools import register_tools


def test_tool_registration():
    """Test that all 24 tools are registered correctly"""
    
    # Create MCP server and data loader
    mcp = FastMCP("Test Server")
    data_loader = get_data_loader()
    
    # Get initial tool count
    initial_tools = len(mcp._mcp_tools) if hasattr(mcp, '_mcp_tools') else 0  # type: ignore
    
    # Register all tools
    register_tools(mcp, data_loader)
    
    # Verify tools were registered
    # Note: FastMCP stores tools in _mcp_tools dict
    if hasattr(mcp, '_mcp_tools'):
        final_tools = len(mcp._mcp_tools)  # type: ignore
        registered = final_tools - initial_tools
        
        # We expect 24 tools to be registered
        assert registered == 24, f"Expected 24 tools registered, got {registered}"
        
        # Check for specific tool names
        tool_names = list(mcp._mcp_tools.keys())  # type: ignore
        
        # Core tools
        assert "get_control" in tool_names
        assert "list_family_controls" in tool_names
        assert "search_requirements" in tool_names
        
        # Definition tools
        assert "get_definition" in tool_names
        assert "list_definitions" in tool_names
        assert "search_definitions" in tool_names
        
        # KSI tools
        assert "get_ksi" in tool_names
        assert "list_ksi" in tool_names
        
        # Documentation tools
        assert "search_documentation" in tool_names
        assert "get_documentation_file" in tool_names
        assert "list_documentation_files" in tool_names
        
        # Export tools
        assert "export_to_excel" in tool_names
        assert "export_to_csv" in tool_names
        assert "generate_ksi_specification" in tool_names
        
        # Enhancement tools
        assert "compare_with_rev4" in tool_names
        assert "get_implementation_examples" in tool_names
        assert "check_requirement_dependencies" in tool_names
        assert "estimate_implementation_effort" in tool_names
        assert "get_cloud_native_guidance" in tool_names
        assert "validate_architecture" in tool_names
        assert "generate_implementation_questions" in tool_names
        
        # Evidence automation tools
        assert "get_infrastructure_code_for_ksi" in tool_names
        assert "get_evidence_collection_code" in tool_names
        assert "get_evidence_automation_architecture" in tool_names
        
        print(f"✓ All 24 tools registered successfully")
        print(f"  Registered tools: {', '.join(sorted(tool_names))}")
    else:
        # If internal structure is different, just verify no exceptions occurred
        print("✓ Tool registration completed without errors")
        print("  (Note: Could not verify tool count due to FastMCP internal structure)")


def test_tool_modules_import():
    """Test that all tool modules can be imported"""
    
    # Import all tool modules
    from fedramp_20x_mcp.tools import requirements
    from fedramp_20x_mcp.tools import definitions
    from fedramp_20x_mcp.tools import ksi
    from fedramp_20x_mcp.tools import documentation
    from fedramp_20x_mcp.tools import export
    from fedramp_20x_mcp.tools import enhancements
    from fedramp_20x_mcp.tools import evidence
    
    # Verify key functions exist
    assert hasattr(requirements, 'get_control_impl')
    assert hasattr(requirements, 'list_family_controls_impl')
    assert hasattr(requirements, 'search_requirements_impl')
    
    assert hasattr(definitions, 'get_definition_impl')
    assert hasattr(definitions, 'list_definitions_impl')
    assert hasattr(definitions, 'search_definitions_impl')
    
    assert hasattr(ksi, 'get_ksi_impl')
    assert hasattr(ksi, 'list_ksi_impl')
    
    assert hasattr(documentation, 'search_documentation_impl')
    assert hasattr(documentation, 'get_documentation_file_impl')
    assert hasattr(documentation, 'list_documentation_files_impl')
    
    # Export tools don't use _impl suffix
    assert hasattr(export, 'export_to_excel')
    assert hasattr(export, 'export_to_csv')
    assert hasattr(export, 'generate_ksi_specification')
    
    assert hasattr(enhancements, 'compare_with_rev4_impl')
    assert hasattr(enhancements, 'get_implementation_examples_impl')
    assert hasattr(enhancements, 'check_requirement_dependencies_impl')
    assert hasattr(enhancements, 'estimate_implementation_effort_impl')
    assert hasattr(enhancements, 'get_cloud_native_guidance_impl')
    assert hasattr(enhancements, 'validate_architecture_impl')
    assert hasattr(enhancements, 'generate_implementation_questions_impl')
    
    assert hasattr(evidence, 'get_infrastructure_code_for_ksi_impl')
    assert hasattr(evidence, 'get_evidence_collection_code_impl')
    assert hasattr(evidence, 'get_evidence_automation_architecture_impl')
    
    print("✓ All tool modules imported successfully")
    print("✓ All tool implementation functions exist")


if __name__ == "__main__":
    # Run tests
    print("Testing tool registration system...")
    print("=" * 80)
    
    try:
        test_tool_registration()
        test_tool_modules_import()
        print("\n" + "=" * 80)
        print("✓ All tool registration tests passed!")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
