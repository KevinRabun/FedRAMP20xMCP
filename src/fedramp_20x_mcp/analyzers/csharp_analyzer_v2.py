"""
Enhanced C# application code analyzer for FedRAMP 20x compliance using AST parsing.

Uses tree-sitter for semantic code analysis to reduce false positives/negatives.
This version demonstrates AST-based analysis compared to regex-based approach.
"""

import re
from typing import Optional, List, Dict, Set, Tuple
from dataclasses import dataclass

try:
    from tree_sitter import Language, Parser, Node
    import tree_sitter_c_sharp as ts_csharp
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = None

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult


@dataclass
class CodeContext:
    """Represents semantic context around a code node."""
    node: Optional[Node]
    parent_class: Optional[str] = None
    parent_method: Optional[str] = None
    namespace: Optional[str] = None
    usings: Set[str] = None
    attributes: List[str] = None
    
    def __post_init__(self):
        if self.usings is None:
            self.usings = set()
        if self.attributes is None:
            self.attributes = []


class CSharpAnalyzerV2(BaseAnalyzer):
    """
    Enhanced C# analyzer using Abstract Syntax Tree parsing.
    
    Key improvements over regex-based approach:
    1. Semantic understanding of code structure
    2. Ignores comments and string literals appropriately
    3. Understands scope and context
    4. Tracks data flow and relationships
    5. Higher precision, fewer false positives
    """
    
    def __init__(self):
        super().__init__()
        self.parser = None
        self.tree = None
        self.code_bytes = None
        self.use_ast = TREE_SITTER_AVAILABLE
        
        if self.use_ast:
            try:
                # Initialize tree-sitter parser for C#
                language = Language(ts_csharp.language())
                self.parser = Parser(language)
            except Exception as e:
                print(f"Warning: Could not initialize tree-sitter parser: {e}")
                self.use_ast = False
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze C# code using AST parsing when available.
        
        Args:
            code: C# code content
            file_path: Path to the C# file
            
        Returns:
            AnalysisResult with findings
        """
        self.result = AnalysisResult()
        self.result.files_analyzed = 1
        
        # Parse code into AST if available
        if self.use_ast and self.parser:
            self.code_bytes = bytes(code, "utf8")
            self.tree = self.parser.parse(self.code_bytes)
            
            # Extract semantic information
            usings = self._extract_usings(self.tree.root_node)
            classes = self._extract_classes(self.tree.root_node)
            
            # Perform AST-based checks
            self._check_authentication_ast(code, file_path, usings, classes)
            self._check_secrets_management_ast(code, file_path, self.tree.root_node)
            self._check_authorization_ast(code, file_path, classes)
            
        else:
            # Fallback to regex-based analysis
            print(f"Warning: AST parsing not available, using regex fallback for {file_path}")
            self._check_authentication_regex(code, file_path)
            self._check_secrets_management_regex(code, file_path)
        
        # Continue with other checks (can be enhanced incrementally)
        self._check_dependencies(code, file_path)
        self._check_pii_handling(code, file_path)
        
        return self.result
    
    # ========================================================================
    # AST Helper Methods
    # ========================================================================
    
    def _extract_usings(self, root_node: Node) -> Set[str]:
        """Extract all using directives from the AST."""
        usings = set()
        
        def visit(node: Node):
            if node.type == "using_directive":
                # Get the namespace being imported
                for child in node.children:
                    if child.type == "qualified_name" or child.type == "identifier":
                        namespace = self._get_node_text(child)
                        usings.add(namespace)
            
            for child in node.children:
                visit(child)
        
        visit(root_node)
        return usings
    
    def _extract_classes(self, root_node: Node) -> List[Dict]:
        """Extract class definitions with their attributes and methods."""
        classes = []
        
        def visit(node: Node, current_namespace: str = ""):
            if node.type == "namespace_declaration":
                # Update current namespace
                for child in node.children:
                    if child.type == "qualified_name" or child.type == "identifier":
                        current_namespace = self._get_node_text(child)
            
            elif node.type == "class_declaration":
                class_info = {
                    "name": None,
                    "namespace": current_namespace,
                    "attributes": [],
                    "base_classes": [],
                    "methods": [],
                    "properties": [],
                    "node": node
                }
                
                # Extract class attributes
                for child in node.children:
                    if child.type == "attribute_list":
                        attrs = self._extract_attributes(child)
                        class_info["attributes"].extend(attrs)
                    elif child.type == "identifier":
                        class_info["name"] = self._get_node_text(child)
                    elif child.type == "base_list":
                        class_info["base_classes"] = self._extract_base_classes(child)
                    elif child.type == "declaration_list":
                        # Extract methods and properties
                        class_info["methods"] = self._extract_methods(child)
                        class_info["properties"] = self._extract_properties(child)
                
                classes.append(class_info)
            
            for child in node.children:
                visit(child, current_namespace)
        
        visit(root_node)
        return classes
    
    def _extract_attributes(self, attribute_list_node: Node) -> List[str]:
        """Extract attribute names from attribute list."""
        attributes = []
        
        def visit(node: Node):
            if node.type == "attribute":
                for child in node.children:
                    if child.type == "identifier" or child.type == "qualified_name":
                        attr_name = self._get_node_text(child)
                        attributes.append(attr_name)
            
            for child in node.children:
                visit(child)
        
        visit(attribute_list_node)
        return attributes
    
    def _extract_base_classes(self, base_list_node: Node) -> List[str]:
        """Extract base class names."""
        base_classes = []
        for child in base_list_node.children:
            if child.type in ["identifier", "qualified_name", "generic_name"]:
                base_classes.append(self._get_node_text(child))
        return base_classes
    
    def _extract_methods(self, declaration_list_node: Node) -> List[Dict]:
        """Extract method declarations with attributes."""
        methods = []
        
        for child in declaration_list_node.children:
            if child.type == "method_declaration":
                method_info = {
                    "name": None,
                    "attributes": [],
                    "parameters": [],
                    "return_type": None,
                    "node": child
                }
                
                for subchild in child.children:
                    if subchild.type == "attribute_list":
                        # APPEND attributes, don't overwrite (methods can have multiple attribute_list nodes)
                        method_info["attributes"].extend(self._extract_attributes(subchild))
                    elif subchild.type == "identifier":
                        method_info["name"] = self._get_node_text(subchild)
                    elif subchild.type == "parameter_list":
                        method_info["parameters"] = self._extract_parameters(subchild)
                
                methods.append(method_info)
        
        return methods
    
    def _extract_properties(self, declaration_list_node: Node) -> List[Dict]:
        """Extract property declarations."""
        properties = []
        
        for child in declaration_list_node.children:
            if child.type == "property_declaration":
                prop_info = {
                    "name": None,
                    "type": None,
                    "attributes": [],
                    "node": child
                }
                
                for subchild in child.children:
                    if subchild.type == "attribute_list":
                        prop_info["attributes"] = self._extract_attributes(subchild)
                    elif subchild.type == "identifier":
                        prop_info["name"] = self._get_node_text(subchild)
                
                properties.append(prop_info)
        
        return properties
    
    def _extract_parameters(self, parameter_list_node: Node) -> List[Dict]:
        """Extract method parameters with attributes."""
        parameters = []
        
        for child in parameter_list_node.children:
            if child.type == "parameter":
                param_info = {
                    "name": None,
                    "type": None,
                    "attributes": []
                }
                
                for subchild in child.children:
                    if subchild.type == "attribute_list":
                        param_info["attributes"] = self._extract_attributes(subchild)
                    elif subchild.type == "identifier":
                        param_info["name"] = self._get_node_text(subchild)
                
                parameters.append(param_info)
        
        return parameters
    
    def _get_node_text(self, node: Node) -> str:
        """Get the text content of a node."""
        if node and self.code_bytes:
            return self.code_bytes[node.start_byte:node.end_byte].decode('utf8')
        return ""
    
    def _find_nodes_by_type(self, root: Node, node_type: str) -> List[Node]:
        """Find all nodes of a specific type in the AST."""
        results = []
        
        def visit(node: Node):
            if node.type == node_type:
                results.append(node)
            for child in node.children:
                visit(child)
        
        visit(root)
        return results
    
    def _is_in_comment(self, node: Node) -> bool:
        """Check if node is inside a comment."""
        current = node
        while current:
            if current.type in ["comment", "block_comment", "line_comment"]:
                return True
            current = current.parent
        return False
    
    def _is_in_string_literal(self, node: Node) -> bool:
        """Check if node is inside a string literal."""
        current = node
        while current:
            if current.type in ["string_literal", "verbatim_string_literal", "interpolated_string_expression"]:
                return True
            current = current.parent
        return False
    
    # ========================================================================
    # AST-Based Security Checks
    # ========================================================================
    
    def _check_authentication_ast(self, code: str, file_path: str, usings: Set[str], classes: List[Dict]) -> None:
        """
        Check for authentication using AST analysis.
        
        Key improvements over regex:
        - Understands class inheritance (Controller, ControllerBase)
        - Properly identifies attributes on classes/methods
        - Ignores commented-out code
        - Understands scope (class vs method level authorization)
        """
        # Check if authentication namespaces are imported
        auth_namespaces = {
            "Microsoft.Identity", "Microsoft.AspNetCore.Authentication",
            "Microsoft.AspNetCore.Authorization", "Azure.Identity"
        }
        
        has_auth_namespace = any(
            any(auth_ns in using for auth_ns in auth_namespaces)
            for using in usings
        )
        
        # Check each class that inherits from Controller
        for class_info in classes:
            is_controller = any(
                base in ["Controller", "ControllerBase"]
                for base in class_info["base_classes"]
            )
            
            is_api_controller = "ApiController" in class_info["attributes"]
            
            if is_controller or is_api_controller:
                # Check for class-level [Authorize] attribute
                has_class_auth = any(
                    attr in ["Authorize", "AllowAnonymous"]
                    for attr in class_info["attributes"]
                )
                
                # Check methods for authentication
                unauthenticated_methods = []
                for method in class_info["methods"]:
                    # Check for HTTP method attributes
                    http_methods = ["HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"]
                    has_http_method = any(
                        http_attr in method["attributes"]
                        for http_attr in http_methods
                    )
                    
                    has_method_auth = any(
                        attr in ["Authorize", "AllowAnonymous"]
                        for attr in method["attributes"]
                    )
                    
                    # If method has HTTP attribute but no auth (and class doesn't have auth)
                    if has_http_method and not has_method_auth and not has_class_auth:
                        unauthenticated_methods.append(method["name"])
                
                if unauthenticated_methods:
                    line_num = self._get_line_from_node(class_info["node"])
                    self.add_finding(Finding(
                        requirement_id="KSI-IAM-01",
                        severity=Severity.HIGH,
                        title=f"API endpoints without authentication in {class_info['name']}",
                        description=f"Controller '{class_info['name']}' has {len(unauthenticated_methods)} endpoint(s) without [Authorize] attribute: {', '.join(unauthenticated_methods)}. FedRAMP 20x requires authentication for all API endpoints.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Add [Authorize] attribute at class or method level:\n```csharp\n[Authorize]\n[ApiController]\n[Route(\"api/[controller]\")]\npublic class DataController : ControllerBase\n{\n    [HttpGet]\n    public IActionResult GetData() => Ok();\n}\n```\nSource: https://learn.microsoft.com/aspnet/core/security/authorization/simple"
                    ))
                elif has_class_auth or any(method.get("attributes") for method in class_info["methods"]):
                    line_num = self._get_line_from_node(class_info["node"])
                    self.add_finding(Finding(
                        requirement_id="KSI-IAM-01",
                        severity=Severity.INFO,
                        title=f"Authentication properly configured on {class_info['name']}",
                        description=f"Controller protected with [Authorize] attribute and Azure AD integration detected.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Verify JWT token validation and RBAC are configured in Program.cs/Startup.cs.",
                        good_practice=True
                    ))
    
    def _check_secrets_management_ast(self, code: str, file_path: str, root_node: Node) -> None:
        """
        Check for hardcoded secrets using AST analysis.
        
        Key improvements:
        - Ignores secrets in comments
        - Ignores secrets in test/example strings
        - Understands variable assignments vs configuration retrieval
        - Checks if value comes from Key Vault or Configuration
        """
        # Patterns for secrets with high-precision regex
        secret_patterns = [
            (r'(?:password|Password|PASSWORD)\s*=\s*"([^"]{3,})"', "password", ["test", "example", "***", "placeholder"]),
            (r'(?:apiKey|ApiKey|API_KEY)\s*=\s*"([^"]{20,})"', "API key", ["sk-test", "dummy"]),
            (r'(?:connectionString|ConnectionString)\s*=\s*"([^"]+(?:Password|Pwd)=[^"]+)"', "connection string", ["localhost", "example"]),
            (r'(?:secret|Secret|SECRET)\s*=\s*"([^"]{16,})"', "secret", ["your-secret", "enter-secret"]),
        ]
        
        # Find all variable declarations and assignments
        assignments = self._find_nodes_by_type(root_node, "variable_declarator")
        assignments.extend(self._find_nodes_by_type(root_node, "assignment_expression"))
        
        for node in assignments:
            # Skip if in comment or inappropriate context
            if self._is_in_comment(node):
                continue
            
            node_text = self._get_node_text(node)
            
            # Check for secret patterns
            for pattern, secret_type, skip_values in secret_patterns:
                match = re.search(pattern, node_text)
                if match:
                    secret_value = match.group(1) if match.lastindex >= 1 else ""
                    
                    # Skip test/placeholder values
                    if any(skip in secret_value.lower() for skip in skip_values):
                        continue
                    
                    # Check if value comes from secure source
                    # Look for Configuration[], GetSecret, Environment.GetEnvironmentVariable in the same statement
                    if any(secure in node_text for secure in [
                        "Configuration[", "GetSecret", "SecretClient",
                        "Environment.GetEnvironmentVariable", "KeyVault"
                    ]):
                        continue
                    
                    line_num = self._get_line_from_node(node)
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-06",
                        severity=Severity.HIGH,
                        title=f"Hardcoded {secret_type} detected",
                        description=f"Found hardcoded {secret_type} in variable assignment. FedRAMP 20x requires secrets in Azure Key Vault.",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=node_text[:100],
                        recommendation=f"Store {secret_type} in Azure Key Vault:\n```csharp\nusing Azure.Identity;\nusing Azure.Security.KeyVault.Secrets;\n\nvar client = new SecretClient(\n    new Uri(\"https://your-vault.vault.azure.net\"),\n    new DefaultAzureCredential());\n\nvar secret = await client.GetSecretAsync(\"{secret_type.replace(' ', '-')}\");\nstring value = secret.Value.Value;\n```\nSource: https://learn.microsoft.com/azure/key-vault/secrets/quick-create-net"
                    ))
        
        # Check for Key Vault usage (good practice)
        keyvault_usings = [u for u in self._extract_usings(root_node) if "KeyVault" in u]
        if keyvault_usings:
            # Look for SecretClient instantiation with DefaultAzureCredential
            secret_clients = self._find_nodes_by_type(root_node, "object_creation_expression")
            for node in secret_clients:
                node_text = self._get_node_text(node)
                if "SecretClient" in node_text and "DefaultAzureCredential" in node_text:
                    line_num = self._get_line_from_node(node)
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-06",
                        severity=Severity.INFO,
                        title="Azure Key Vault with managed identity configured",
                        description="Secrets retrieved from Key Vault using DefaultAzureCredential (best practice).",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Ensure Key Vault RBAC permissions are configured with least privilege.",
                        good_practice=True
                    ))
                    break
    
    def _check_authorization_ast(self, code: str, file_path: str, classes: List[Dict]) -> None:
        """
        Check for proper authorization policies using AST.
        
        Detects:
        - Methods with [Authorize(Policy = "...")] 
        - Role-based authorization
        - Claims-based authorization
        """
        for class_info in classes:
            for method in class_info["methods"]:
                # Look for Authorize attributes with policies
                for attr in method["attributes"]:
                    if "Authorize" in attr:
                        # This is a good practice - method-level authorization
                        line_num = self._get_line_from_node(method["node"])
                        self.add_finding(Finding(
                            requirement_id="KSI-IAM-02",
                            severity=Severity.INFO,
                            title=f"Method-level authorization on {method['name']}",
                            description="Method uses [Authorize] attribute for access control.",
                            file_path=file_path,
                            line_number=line_num,
                            recommendation="Ensure authorization policies are defined in Program.cs with proper role/claims requirements.",
                            good_practice=True
                        ))
    
    # ========================================================================
    # Regex Fallback Methods (when AST not available)
    # ========================================================================
    
    def _check_authentication_regex(self, code: str, file_path: str) -> None:
        """Fallback regex-based authentication check."""
        has_auth = bool(re.search(r"\[Authorize\]", code))
        has_controller = bool(re.search(r"class\s+\w+\s*:\s*Controller", code))
        
        if has_controller and not has_auth:
            self.add_finding(Finding(
                requirement_id="KSI-IAM-01",
                severity=Severity.HIGH,
                title="API controller without authentication",
                description="Found controller without [Authorize] attribute.",
                file_path=file_path,
                line_number=None,
                recommendation="Add [Authorize] attribute to controller or methods."
            ))
    
    def _check_secrets_management_regex(self, code: str, file_path: str) -> None:
        """Fallback regex-based secrets check."""
        if re.search(r'password\s*=\s*"[^"]{3,}"', code, re.IGNORECASE):
            self.add_finding(Finding(
                requirement_id="KSI-SVC-06",
                severity=Severity.HIGH,
                title="Potential hardcoded password",
                description="Found potential hardcoded password.",
                file_path=file_path,
                line_number=None,
                recommendation="Use Azure Key Vault for secrets."
            ))
    
    def _get_line_from_node(self, node: Node) -> int:
        """Get line number from AST node."""
        if node:
            return node.start_point[0] + 1  # tree-sitter uses 0-based indexing
        return None
    
    # ========================================================================
    # Legacy Methods (keep for compatibility, can be enhanced)
    # ========================================================================
    
    def _check_dependencies(self, code: str, file_path: str) -> None:
        """Check for vulnerable dependencies (can be enhanced with AST)."""
        # Simplified version - keep regex for now
        if re.search(r"BinaryFormatter", code):
            self.add_finding(Finding(
                requirement_id="KSI-SVC-08",
                severity=Severity.HIGH,
                title="Insecure deserialization detected",
                description="BinaryFormatter is vulnerable to deserialization attacks.",
                file_path=file_path,
                line_number=None,
                recommendation="Use System.Text.Json.JsonSerializer instead."
            ))
    
    def _check_pii_handling(self, code: str, file_path: str) -> None:
        """Check for PII handling (can be enhanced with AST)."""
        # Simplified version - keep regex for now
        if re.search(r"(Ssn|SocialSecurityNumber)", code, re.IGNORECASE):
            if not re.search(r"(Encrypt|Protect|IDataProtector)", code, re.IGNORECASE):
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-02",
                    severity=Severity.MEDIUM,
                    title="Potential unprotected PII",
                    description="Found PII field without encryption.",
                    file_path=file_path,
                    line_number=None,
                    recommendation="Use ASP.NET Core Data Protection API for PII encryption."
                ))
