"""
Tests for AST utilities module.

Validates tree-sitter parsing, symbol tables, and data flow analysis.
"""

import sys
from fedramp_20x_mcp.analyzers.ast_utils import (
    create_parser,
    create_symbol_table,
    CodeLanguage,
    Symbol,
    DataFlowAnalyzer,
    PatternMatcher
)


def test_python_ast_parsing():
    """Test basic Python AST parsing."""
    print("TEST: Python AST Parsing")
    
    code = """
def get_password():
    password = "hardcoded_secret"
    return password

def main():
    pwd = get_password()
    print(pwd)
"""
    
    parser = create_parser("python")
    tree = parser.parse(code)
    
    # Find function definitions
    functions = parser.find_nodes_by_type(tree.root_node, "function_definition")
    assert len(functions) == 2, f"Expected 2 functions, got {len(functions)}"
    
    # Find function calls
    calls = parser.find_function_calls(tree.root_node, ["get_password", "print"])
    assert len(calls) >= 1, f"Expected at least 1 call, got {len(calls)}"
    
    print(f"  [PASS] Found {len(functions)} functions")
    print(f"  [PASS] Found {len(calls)} function calls")
    print()


def test_csharp_ast_parsing():
    """Test basic C# AST parsing."""
    print("TEST: C# AST Parsing")
    
    code = """
public class Example
{
    private string password = "hardcoded";
    
    public string GetPassword()
    {
        return password;
    }
    
    public void LogPassword()
    {
        Console.WriteLine(GetPassword());
    }
}
"""
    
    parser = create_parser("csharp")
    tree = parser.parse(code)
    
    # Find method declarations
    methods = parser.find_nodes_by_type(tree.root_node, "method_declaration")
    assert len(methods) == 2, f"Expected 2 methods, got {len(methods)}"
    
    # Find field declarations
    fields = parser.find_nodes_by_type(tree.root_node, "field_declaration")
    assert len(fields) == 1, f"Expected 1 field, got {len(fields)}"
    
    print(f"  [PASS] Found {len(methods)} methods")
    print(f"  [PASS] Found {len(fields)} fields")
    print()


def test_java_ast_parsing():
    """Test basic Java AST parsing."""
    print("TEST: Java AST Parsing")
    
    code = """
public class Example {
    private String apiKey = "hardcoded_key";
    
    public String getApiKey() {
        return apiKey;
    }
    
    public void sendRequest() {
        String key = getApiKey();
        HttpClient.post(key);
    }
}
"""
    
    parser = create_parser("java")
    tree = parser.parse(code)
    
    # Find method declarations
    methods = parser.find_nodes_by_type(tree.root_node, "method_declaration")
    assert len(methods) == 2, f"Expected 2 methods, got {len(methods)}"
    
    # Find field declarations
    fields = parser.find_nodes_by_type(tree.root_node, "field_declaration")
    assert len(fields) == 1, f"Expected 1 field, got {len(fields)}"
    
    print(f"  [PASS] Found {len(methods)} methods")
    print(f"  [PASS] Found {len(fields)} fields")
    print()


def test_javascript_ast_parsing():
    """Test basic JavaScript AST parsing."""
    print("TEST: JavaScript AST Parsing")
    
    code = """
function getPassword() {
    const password = "hardcoded_secret";
    return password;
}

function main() {
    const pwd = getPassword();
    console.log(pwd);
}
"""
    
    parser = create_parser("javascript")
    tree = parser.parse(code)
    
    # Find function declarations
    functions = parser.find_nodes_by_type(tree.root_node, "function_declaration")
    assert len(functions) == 2, f"Expected 2 functions, got {len(functions)}"
    
    # Find lexical declarations (const/let)
    declarations = parser.find_nodes_by_type(tree.root_node, "lexical_declaration")
    assert len(declarations) >= 2, f"Expected at least 2 declarations, got {len(declarations)}"
    
    print(f"  [PASS] Found {len(functions)} functions")
    print(f"  [PASS] Found {len(declarations)} variable declarations")
    print()


def test_symbol_table():
    """Test symbol table construction."""
    print("TEST: Symbol Table")
    
    st = create_symbol_table("python")
    
    # Add symbols
    st.add_symbol(Symbol("password", "variable", 1, 0, "global", is_sensitive=True))
    st.add_symbol(Symbol("username", "variable", 2, 0, "global", is_sensitive=False))
    
    st.enter_scope("function:main")
    st.add_symbol(Symbol("local_var", "variable", 5, 4, "function:main"))
    
    # Lookup symbols
    pwd_symbol = st.lookup("password")
    assert pwd_symbol is not None, "Failed to lookup 'password'"
    assert pwd_symbol.is_sensitive, "'password' should be marked sensitive"
    
    local_symbol = st.lookup("local_var")
    assert local_symbol is not None, "Failed to lookup 'local_var'"
    assert local_symbol.scope == "function:main", "Wrong scope for local_var"
    
    # Get sensitive symbols
    sensitive = st.get_sensitive_symbols()
    assert len(sensitive) == 1, f"Expected 1 sensitive symbol, got {len(sensitive)}"
    
    print(f"  [PASS] Symbol table operations work")
    print(f"  [PASS] Found {len(sensitive)} sensitive symbols")
    print()


def test_data_flow_analyzer():
    """Test data flow taint analysis."""
    print("TEST: Data Flow Analysis")
    
    st = create_symbol_table("python")
    st.add_symbol(Symbol("password", "variable", 1, 0, "global"))
    st.add_symbol(Symbol("user_input", "variable", 2, 0, "global"))
    st.add_symbol(Symbol("safe_var", "variable", 3, 0, "global"))
    
    dfa = DataFlowAnalyzer(st)
    
    # Mark password as tainted
    dfa.mark_tainted("password")
    assert dfa.is_tainted("password"), "'password' should be tainted"
    assert not dfa.is_tainted("safe_var"), "'safe_var' should not be tainted"
    
    # Test taint propagation through assignment
    dfa.analyze_assignment("pwd_copy", "password")
    assert dfa.is_tainted("pwd_copy"), "Taint should propagate to 'pwd_copy'"
    
    print(f"  [PASS] Taint tracking works")
    print(f"  [PASS] Taint propagation through assignments works")
    print()


def test_pattern_matching():
    """Test structural pattern matching."""
    print("TEST: Pattern Matching")
    
    code = """
def process_data(data):
    if validate(data):
        return transform(data)
    return None
"""
    
    parser = create_parser("python")
    tree = parser.parse(code)
    matcher = PatternMatcher(parser)
    
    # Find all function definitions
    pattern = {"type": "function_definition"}
    matches = matcher.find_pattern(tree.root_node, pattern)
    assert len(matches) == 1, f"Expected 1 function definition, got {len(matches)}"
    
    # Find if statements
    pattern = {"type": "if_statement"}
    matches = matcher.find_pattern(tree.root_node, pattern)
    assert len(matches) == 1, f"Expected 1 if statement, got {len(matches)}"
    
    print(f"  [PASS] Pattern matching works")
    print(f"  [PASS] Found structural patterns in AST")
    print()


if __name__ == "__main__":
    print("=" * 60)
    print("AST UTILITIES TEST SUITE")
    print("=" * 60)
    print()
    
    try:
        test_python_ast_parsing()
        test_csharp_ast_parsing()
        test_java_ast_parsing()
        test_javascript_ast_parsing()
        test_symbol_table()
        test_data_flow_analyzer()
        test_pattern_matching()
        
        print("=" * 60)
        print("ALL TESTS PASSED [PASS]")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
