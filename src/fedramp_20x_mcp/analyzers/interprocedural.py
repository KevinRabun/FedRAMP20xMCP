"""
Inter-procedural Analysis Module.

Analyzes data flow across function boundaries:
1. Call graph construction
2. Parameter-to-argument mapping
3. Return value tracking
4. Global variable modifications
5. Cross-function taint propagation
6. Transitive closure of data flows
"""

from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from .ast_utils import ASTParser, SymbolTable, CodeLanguage, Symbol
from .semantic_analysis import SemanticAnalyzer, SecurityContext, TypeInfo
from tree_sitter import Node


@dataclass
class CallSite:
    """Represents a function call location."""
    caller: str  # Function making the call
    callee: str  # Function being called
    arguments: List[str]  # Argument variable names
    line_number: int
    return_var: Optional[str] = None  # Variable receiving return value


@dataclass
class FunctionSummary:
    """Summary of function behavior for inter-procedural analysis."""
    name: str
    parameters: List[str]
    returns_sensitive: bool = False
    modifies_globals: Set[str] = field(default_factory=set)
    tainted_params: Set[int] = field(default_factory=set)  # Indices of tainted parameters
    tainted_return: bool = False  # Return value is tainted


@dataclass
class DataFlowEdge:
    """Edge in inter-procedural data flow graph."""
    source_func: str
    source_var: str
    target_func: str
    target_var: str
    edge_type: str  # "call", "return", "global"
    is_tainted: bool = False


class CallGraph:
    """
    Call graph for inter-procedural analysis.
    
    Tracks:
    - Function call relationships
    - Call sites with arguments
    - Return value flows
    - Global variable access
    """
    
    def __init__(self):
        """Initialize empty call graph."""
        self.nodes: Set[str] = set()  # Function names
        self.edges: List[Tuple[str, str]] = []  # (caller, callee)
        self.call_sites: List[CallSite] = []
        self.function_summaries: Dict[str, FunctionSummary] = {}
    
    def add_function(self, func_name: str):
        """Add function node to graph."""
        self.nodes.add(func_name)
        if func_name not in self.function_summaries:
            self.function_summaries[func_name] = FunctionSummary(
                name=func_name,
                parameters=[]
            )
    
    def add_call(self, caller: str, callee: str, arguments: List[str], 
                 line_number: int, return_var: Optional[str] = None):
        """Add function call edge."""
        self.edges.append((caller, callee))
        self.call_sites.append(CallSite(
            caller=caller,
            callee=callee,
            arguments=arguments,
            line_number=line_number,
            return_var=return_var
        ))
    
    def get_callees(self, func_name: str) -> List[str]:
        """Get functions called by this function."""
        return [callee for caller, callee in self.edges if caller == func_name]
    
    def get_callers(self, func_name: str) -> List[str]:
        """Get functions that call this function."""
        return [caller for caller, callee in self.edges if callee == func_name]
    
    def get_call_sites_for_function(self, func_name: str) -> List[CallSite]:
        """Get all call sites within a function."""
        return [cs for cs in self.call_sites if cs.caller == func_name]
    
    def get_call_sites_to_function(self, func_name: str) -> List[CallSite]:
        """Get all call sites calling this function."""
        return [cs for cs in self.call_sites if cs.callee == func_name]
    
    def is_reachable(self, from_func: str, to_func: str) -> bool:
        """Check if to_func is reachable from from_func in call graph."""
        visited = set()
        stack = [from_func]
        
        while stack:
            current = stack.pop()
            if current == to_func:
                return True
            
            if current in visited:
                continue
            visited.add(current)
            
            stack.extend(self.get_callees(current))
        
        return False


class InterProceduralAnalyzer:
    """
    Performs inter-procedural data flow analysis.
    
    Tracks data flow across function calls:
    1. Build call graph
    2. Compute function summaries (taint, side effects)
    3. Propagate taint through calls
    4. Track return value flows
    5. Analyze global variable modifications
    """
    
    def __init__(self, language: CodeLanguage):
        """Initialize inter-procedural analyzer."""
        self.language = language
        self.parser = ASTParser(language)
        self.semantic_analyzer = SemanticAnalyzer(language)
        self.call_graph = CallGraph()
        self.current_function: Optional[str] = None
    
    def analyze(self, code: str) -> Dict[str, Any]:
        """
        Perform complete inter-procedural analysis.
        
        Returns:
        - call_graph: Call graph structure
        - function_summaries: Summary of each function's behavior
        - taint_flows: Inter-procedural taint flows
        - vulnerabilities: Security issues found
        """
        tree = self.parser.parse(code)
        code_bytes = bytes(code, "utf8")
        
        # Phase 1: Build call graph
        self._build_call_graph(tree.root_node, code_bytes, code)
        
        # Phase 2: Compute function summaries
        self._compute_function_summaries(tree.root_node, code_bytes, code)
        
        # Phase 3: Propagate taint inter-procedurally
        taint_flows = self._propagate_taint_interprocedural()
        
        # Phase 4: Find vulnerabilities (sensitive data to dangerous sinks)
        vulnerabilities = self._find_interprocedural_vulnerabilities(code)
        
        return {
            "call_graph": self.call_graph,
            "function_summaries": self.call_graph.function_summaries,
            "taint_flows": taint_flows,
            "vulnerabilities": vulnerabilities
        }
    
    def _build_call_graph(self, root_node: Node, code_bytes: bytes, code: str):
        """Build call graph from AST."""
        # Find all function definitions
        func_types = {
            CodeLanguage.PYTHON: "function_definition",
            CodeLanguage.CSHARP: "method_declaration",
            CodeLanguage.JAVA: "method_declaration",
            CodeLanguage.JAVASCRIPT: "function_declaration",
            CodeLanguage.TYPESCRIPT: "function_declaration",
        }
        
        func_type = func_types.get(self.language)
        if not func_type:
            return
        
        func_nodes = self.parser.find_nodes_by_type(root_node, func_type)
        
        # Add all functions to graph
        for func_node in func_nodes:
            func_name = self._extract_function_name(func_node, code_bytes)
            if func_name:
                self.call_graph.add_function(func_name)
                
                # Extract parameters
                params = self._extract_parameters(func_node, code_bytes)
                self.call_graph.function_summaries[func_name].parameters = params
        
        # Find all function calls within each function
        for func_node in func_nodes:
            func_name = self._extract_function_name(func_node, code_bytes)
            if not func_name:
                continue
            
            self.current_function = func_name
            
            # Find calls within this function
            call_nodes = self.parser.find_nodes_by_type(func_node, "call")
            
            for call_node in call_nodes:
                callee_name = self._extract_call_name(call_node, code_bytes)
                if not callee_name:
                    continue
                
                # Extract arguments
                arguments = self._extract_call_arguments(call_node, code_bytes)
                
                # Check if return value is assigned
                return_var = self._find_return_variable(call_node, code_bytes, code)
                
                self.call_graph.add_call(
                    caller=func_name,
                    callee=callee_name,
                    arguments=arguments,
                    line_number=call_node.start_point[0] + 1,
                    return_var=return_var
                )
    
    def _extract_function_name(self, func_node: Node, code_bytes: bytes) -> Optional[str]:
        """Extract function name from function definition."""
        for child in func_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child, code_bytes)
        return None
    
    def _extract_parameters(self, func_node: Node, code_bytes: bytes) -> List[str]:
        """Extract parameter names from function definition."""
        params = []
        
        for child in func_node.children:
            if "parameter" in child.type:
                for param_node in child.children:
                    if param_node.type == "identifier":
                        param_name = self.parser.get_node_text(param_node, code_bytes)
                        params.append(param_name)
        
        return params
    
    def _extract_call_name(self, call_node: Node, code_bytes: bytes) -> Optional[str]:
        """Extract function name from call expression."""
        for child in call_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child, code_bytes)
            elif child.type == "attribute":
                # Handle method calls like obj.method()
                return self.parser.get_node_text(child, code_bytes)
        return None
    
    def _extract_call_arguments(self, call_node: Node, code_bytes: bytes) -> List[str]:
        """Extract argument variable names from call."""
        arguments = []
        
        for child in call_node.children:
            if "argument" in child.type:
                # Extract identifiers from arguments
                for arg_child in child.children:
                    if arg_child.type == "identifier":
                        arg_name = self.parser.get_node_text(arg_child, code_bytes)
                        arguments.append(arg_name)
        
        return arguments
    
    def _find_return_variable(self, call_node: Node, code_bytes: bytes, code: str) -> Optional[str]:
        """Find if call result is assigned to a variable."""
        # Check if call_node is right side of assignment
        parent = call_node.parent
        if parent and parent.type == "assignment":
            # Find left side (target)
            for child in parent.children:
                if child.type == "identifier" and child != call_node:
                    return self.parser.get_node_text(child, code_bytes)
        
        return None
    
    def _compute_function_summaries(self, root_node: Node, code_bytes: bytes, code: str):
        """Compute summaries for each function."""
        # Use semantic analyzer to get type and security info
        semantic_results = self.semantic_analyzer.analyze(code)
        types = semantic_results["types"]
        
        # Mark functions that return sensitive data
        for func_name, summary in self.call_graph.function_summaries.items():
            # Check if any parameter is sensitive
            for i, param in enumerate(summary.parameters):
                if param in types:
                    type_info = types[param]
                    if type_info.security_context in (SecurityContext.SECRET, SecurityContext.PII):
                        summary.tainted_params.add(i)
            
            # Check if function name suggests sensitive return
            name_lower = func_name.lower()
            sensitive_names = ["password", "secret", "token", "key", "credential", "ssn"]
            if any(s in name_lower for s in sensitive_names):
                summary.returns_sensitive = True
                summary.tainted_return = True
    
    def _propagate_taint_interprocedural(self) -> List[DataFlowEdge]:
        """Propagate taint across function boundaries."""
        flows = []
        
        # Iterate through call sites
        for call_site in self.call_graph.call_sites:
            caller_summary = self.call_graph.function_summaries.get(call_site.caller)
            callee_summary = self.call_graph.function_summaries.get(call_site.callee)
            
            if not caller_summary or not callee_summary:
                continue
            
            # Check if any arguments are tainted
            for i, arg in enumerate(call_site.arguments):
                # Check if argument is tainted in caller
                # For now, assume variables with sensitive names are tainted
                arg_lower = arg.lower()
                is_tainted = any(s in arg_lower for s in 
                               ["password", "secret", "token", "key", "ssn"])
                
                if is_tainted:
                    # Taint flows from argument to parameter
                    if i < len(callee_summary.parameters):
                        param = callee_summary.parameters[i]
                        flows.append(DataFlowEdge(
                            source_func=call_site.caller,
                            source_var=arg,
                            target_func=call_site.callee,
                            target_var=param,
                            edge_type="call",
                            is_tainted=True
                        ))
                        
                        # Mark parameter as tainted
                        callee_summary.tainted_params.add(i)
            
            # Check if return value is tainted
            if callee_summary.tainted_return and call_site.return_var:
                flows.append(DataFlowEdge(
                    source_func=call_site.callee,
                    source_var="<return>",
                    target_func=call_site.caller,
                    target_var=call_site.return_var,
                    edge_type="return",
                    is_tainted=True
                ))
        
        return flows
    
    def _find_interprocedural_vulnerabilities(self, code: str) -> List[Dict[str, Any]]:
        """Find security vulnerabilities through inter-procedural analysis."""
        vulnerabilities = []
        
        # Dangerous sink functions
        sinks = {"print", "log", "console.log", "logger.info", "post", "send"}
        
        # Track which variables are tainted through data flow
        tainted_vars = {}  # {(func, var): True}
        
        # Mark all sensitive parameter names and return values as tainted
        for func_name, summary in self.call_graph.function_summaries.items():
            for param in summary.parameters:
                param_lower = param.lower()
                if any(s in param_lower for s in 
                      ["password", "secret", "token", "key", "ssn"]):
                    tainted_vars[(func_name, param)] = True
        
        # Propagate taint through data flows
        for flow in self._propagate_taint_interprocedural():
            if flow.is_tainted:
                tainted_vars[(flow.target_func, flow.target_var)] = True
        
        # Also check return values from sensitive functions
        for func_name, summary in self.call_graph.function_summaries.items():
            if summary.returns_sensitive or summary.tainted_return:
                # Any variable receiving return from this function is tainted
                for call_site in self.call_graph.call_sites:
                    if call_site.callee == func_name and call_site.return_var:
                        tainted_vars[(call_site.caller, call_site.return_var)] = True
        
        # Check if tainted data reaches sinks through function calls
        for call_site in self.call_graph.call_sites:
            if call_site.callee in sinks:
                # Check if any argument is tainted
                for arg in call_site.arguments:
                    # Check both by name and by taint tracking
                    arg_lower = arg.lower()
                    is_sensitive_name = any(s in arg_lower for s in 
                          ["password", "secret", "token", "key", "ssn", "pwd"])
                    is_tracked_tainted = (call_site.caller, arg) in tainted_vars
                    
                    if is_sensitive_name or is_tracked_tainted:
                        vulnerabilities.append({
                            "type": "sensitive_data_leak",
                            "severity": "CRITICAL",
                            "function": call_site.caller,
                            "sink": call_site.callee,
                            "variable": arg,
                            "line": call_site.line_number,
                            "description": f"Sensitive data '{arg}' passed to {call_site.callee}()"
                        })
        
        return vulnerabilities


def analyze_interprocedural(code: str, language: str = "python") -> Dict[str, Any]:
    """
    Convenience function for inter-procedural analysis.
    
    Args:
        code: Source code to analyze
        language: Programming language ("python", "csharp", "java", etc.)
    
    Returns:
        Dictionary with call_graph, function_summaries, taint_flows, vulnerabilities
    """
    lang_map = {
        "python": CodeLanguage.PYTHON,
        "csharp": CodeLanguage.CSHARP,
        "c#": CodeLanguage.CSHARP,
        "java": CodeLanguage.JAVA,
        "javascript": CodeLanguage.JAVASCRIPT,
        "typescript": CodeLanguage.TYPESCRIPT,
    }
    
    lang = lang_map.get(language.lower())
    if not lang:
        raise ValueError(f"Unsupported language: {language}")
    
    analyzer = InterProceduralAnalyzer(lang)
    return analyzer.analyze(code)
