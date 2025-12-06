"""
Enhanced C# application code analyzer for FedRAMP 20x compliance using AST parsing.

Uses tree-sitter for semantic code analysis to reduce false positives/negatives.
Provides semantic understanding of code structure, ignores comments/strings, and
tracks data flow for higher precision analysis.
"""

import re
import json
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Set, Tuple, Any, TYPE_CHECKING
from dataclasses import dataclass
from pathlib import Path
from packaging import version

# Always import at runtime
try:
    from tree_sitter import Language, Parser, Node as TreeSitterNode
    import tree_sitter_c_sharp as ts_csharp
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    # Type stubs for when tree-sitter is not available
    if not TYPE_CHECKING:
        TreeSitterNode = Any
        Language = Any
        Parser = Any
        ts_csharp = None

from .base import BaseAnalyzer, Finding, Severity, AnalysisResult
from ..cve_fetcher import CVEFetcher


@dataclass
class CodeContext:
    """Represents semantic context around a code node."""
    node: Any  # TreeSitterNode type
    parent_class: Optional[str] = None
    parent_method: Optional[str] = None
    namespace: Optional[str] = None
    usings: Optional[Set[str]] = None
    attributes: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.usings is None:
            self.usings = set()
        if self.attributes is None:
            self.attributes = []


@dataclass
class DataFlowNode:
    """Represents a node in the data flow graph."""
    name: str
    node_type: str  # 'variable', 'parameter', 'property', 'method', 'return'
    is_sensitive: bool
    sensitivity_type: Optional[str] = None  # 'pii', 'password', 'token', 'secret'
    declared_in: Optional[str] = None  # class or method name
    line_number: Optional[int] = None
    propagated_from: Optional[List[str]] = None  # Track where sensitivity came from
    
    def __post_init__(self):
        if self.propagated_from is None:
            self.propagated_from = []


@dataclass
class MethodSignature:
    """Represents a method signature for call graph analysis."""
    class_name: str
    method_name: str
    parameters: List[Dict]
    return_type: Optional[str]
    has_sensitive_data: bool = False
    sensitive_params: Optional[Set[str]] = None
    returns_sensitive: bool = False
    
    def __post_init__(self):
        if self.sensitive_params is None:
            self.sensitive_params = set()


@dataclass
class NuGetPackage:
    """Represents a NuGet package reference."""
    name: str
    version: str
    is_vulnerable: bool = False
    vulnerabilities: Optional[List[Dict]] = None
    is_outdated: bool = False
    latest_version: Optional[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class CSharpAnalyzer(BaseAnalyzer):
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
            self._check_error_handling_ast(code, file_path, self.tree.root_node)  # Tier 1.1: AST-enhanced
            self._check_input_validation_ast(code, file_path, classes)  # Tier 1.2: AST-enhanced
            self._check_secure_coding_practices_ast(code, file_path, self.tree.root_node)  # Tier 1.3: AST-enhanced
            self._check_entity_framework_security_ast(code, file_path, self.tree.root_node)  # Phase A: EF Security
            self._check_aspnet_middleware_security_ast(code, file_path, self.tree.root_node)  # Phase B: Middleware Security
            self._check_azure_integration_security_ast(code, file_path, self.tree.root_node)  # Phase C: Azure Integration
            self._check_least_privilege_authorization_ast(code, file_path, classes)  # Tier 2.1: AST-enhanced
            self._check_session_management_ast(code, file_path, self.tree.root_node)  # Tier 2.2: AST-enhanced
            self._check_logging_implementation_ast(code, file_path, self.tree.root_node)  # Tier 2.3: AST-enhanced
            
            # Data flow analysis (cross-method tracking)
            self._check_data_flow_violations(code, file_path, classes)
            
        else:
            # Fallback to regex-based analysis
            print(f"Warning: AST parsing not available, using regex fallback for {file_path}")
            self._check_authentication_regex(code, file_path)
            self._check_secrets_management_regex(code, file_path)
            self._check_error_handling(code, file_path)  # Use regex fallback
            self._check_input_validation(code, file_path)  # Use regex fallback
            self._check_secure_coding(code, file_path)  # Use regex fallback
        
        # Continue with other checks (can be enhanced incrementally)
        self._check_dependencies(code, file_path)
        self._check_pii_handling(code, file_path)
        self._check_logging(code, file_path)
        
        # Phase 2: Application Security
        self._check_service_account_management(code, file_path)
        self._check_microservices_security(code, file_path)
        
        # Phase 3: Secure Coding Practices
        # _check_error_handling and _check_input_validation now called above based on AST availability
        self._check_secure_coding(code, file_path)
        self._check_secure_coding(code, file_path)
        self._check_data_classification(code, file_path)
        self._check_privacy_controls(code, file_path)
        self._check_service_mesh(code, file_path)
        self._check_least_privilege(code, file_path)
        self._check_session_management(code, file_path)
        
        # Phase 4: Monitoring and Observability
        self._check_security_monitoring(code, file_path)
        self._check_anomaly_detection(code, file_path)
        self._check_performance_monitoring(code, file_path)
        self._check_incident_response(code, file_path)
        
        # Phase 5: DevSecOps Automation
        self._check_configuration_management(code, file_path)
        
        # Configuration file analysis (cross-file check)
        self._analyze_project_configuration(file_path)
        
        # Dependency vulnerability analysis (cross-file check)
        self._analyze_project_dependencies(file_path)
        
        self._check_version_control(code, file_path)
        self._check_automated_testing(code, file_path)
        self._check_audit_logging(code, file_path)
        self._check_log_integrity(code, file_path)
        self._check_key_management(code, file_path)
        
        return self.result
    
    # ========================================================================
    # AST Helper Methods
    # ========================================================================
    
    def _has_data_annotations(self, code: str, usings: Optional[Set[str]] = None) -> bool:
        """Check if code uses Data Annotations for validation."""
        if usings and 'System.ComponentModel.DataAnnotations' in usings:
            return True
        return bool(re.search(r'\[(Required|StringLength|Range|RegularExpression|MaxLength|MinLength|EmailAddress|Phone|Url|CreditCard|Compare|DataType)\]', code))
    
    def _has_fluent_validation(self, code: str, usings: Optional[Set[str]] = None) -> bool:
        """Check if code uses FluentValidation library."""
        if usings:
            for using in usings:
                if 'FluentValidation' in using:
                    return True
        return bool(re.search(r'(RuleFor|AbstractValidator|ValidationResult|AddFluentValidation)', code))
    
    def _extract_fluent_validators(self, root_node: TreeSitterNode) -> Dict[str, Dict]:
        """
        Extract FluentValidation validator classes and their validation rules.
        
        Returns dict mapping model names to validator info:
        {
            "CreateUserRequest": {
                "validator_class": "CreateUserRequestValidator",
                "rules": ["Username", "Email", "Password"],
                "has_rules": True
            }
        }
        """
        validators = {}
        
        def visit(node: TreeSitterNode):
            if node.type == "class_declaration":
                class_name = None
                base_classes = []
                has_rules = False
                validated_properties = []
                
                for child in node.children:
                    if child.type == "identifier":
                        class_name = self._get_node_text(child)
                    elif child.type == "base_list":
                        # Extract base classes to find AbstractValidator<T>
                        base_text = self._get_node_text(child)
                        if "AbstractValidator" in base_text:
                            # Extract generic type parameter
                            match = re.search(r'AbstractValidator<(\w+)>', base_text)
                            if match:
                                model_name = match.group(1)
                                base_classes.append(model_name)
                    elif child.type == "declaration_list":
                        # Look for RuleFor statements in constructor or methods
                        body_text = self._get_node_text(child)
                        if "RuleFor" in body_text:
                            has_rules = True
                            # Extract property names from RuleFor(x => x.PropertyName)
                            for match in re.finditer(r'RuleFor\s*\(\s*\w+\s*=>\s*\w+\.(\w+)\s*\)', body_text):
                                validated_properties.append(match.group(1))
                
                if base_classes and has_rules:
                    for model_name in base_classes:
                        validators[model_name] = {
                            "validator_class": class_name,
                            "rules": validated_properties,
                            "has_rules": has_rules
                        }
            
            for child in node.children:
                visit(child)
        
        visit(root_node)
        return validators
    
    def _check_fluent_validation_registration(self, code: str) -> bool:
        """Check if FluentValidation is registered in DI container."""
        patterns = [
            r'AddFluentValidation\s*\(',
            r'AddValidatorsFromAssembly\s*\(',
            r'AddValidatorsFromAssemblyContaining\s*\(',
            r'services\.AddTransient<IValidator',
            r'services\.AddScoped<IValidator',
        ]
        return any(re.search(pattern, code) for pattern in patterns)
    
    def _has_data_protection_api(self, code: str, usings: Optional[Set[str]] = None) -> bool:
        """Check if code uses ASP.NET Core Data Protection API."""
        if usings and 'Microsoft.AspNetCore.DataProtection' in usings:
            return True
        return bool(re.search(r'(IDataProtector|IDataProtectionProvider|CreateProtector|Protect\(|Unprotect\()', code))
    
    def _has_application_insights(self, code: str, usings: Optional[Set[str]] = None) -> bool:
        """Check if code uses Application Insights."""
        if usings and 'Microsoft.ApplicationInsights' in usings:
            return True
        return bool(re.search(r'(TelemetryClient|AddApplicationInsightsTelemetry|ITelemetryInitializer)', code))
    
    def _is_development_environment_check(self, code: str, context_window: int = 300) -> bool:
        """Check if code is within a development environment conditional."""
        patterns = [
            r'if\s*\(\s*env\.IsDevelopment\(\)',
            r'if\s*\(\s*Environment\.IsDevelopment\(\)',
            r'if\s*\(\s*builder\.Environment\.IsDevelopment\(\)',
            r'#if\s+DEBUG',
        ]
        return any(re.search(pattern, code) for pattern in patterns)
    
    # ========================================================================
    # Configuration Analysis Helpers
    # ========================================================================
    
    def _find_appsettings_files(self, file_path: str) -> List[Path]:
        """Find appsettings.json files in the project directory."""
        try:
            file_dir = Path(file_path).parent
            project_root = file_dir
            
            # Try to find project root (look for .csproj or solution file)
            while project_root.parent != project_root:
                if list(project_root.glob("*.csproj")) or list(project_root.glob("*.sln")):
                    break
                project_root = project_root.parent
            
            # Find all appsettings*.json files
            settings_files = []
            settings_files.extend(project_root.glob("appsettings.json"))
            settings_files.extend(project_root.glob("appsettings.*.json"))
            
            return settings_files
        except Exception:
            return []
    
    def _analyze_configuration_file(self, config_path: Path) -> List[Dict]:
        """Analyze a configuration file for security issues."""
        issues = []
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Check for hardcoded secrets
            secrets_found = self._check_config_secrets(config, config_path.name)
            issues.extend(secrets_found)
            
            # Check logging configuration
            logging_issues = self._check_config_logging(config, config_path.name)
            issues.extend(logging_issues)
            
            # Check connection strings
            connstr_issues = self._check_config_connection_strings(config, config_path.name)
            issues.extend(connstr_issues)
            
            # Check HTTPS configuration
            https_issues = self._check_config_https(config, config_path.name)
            issues.extend(https_issues)
            
        except json.JSONDecodeError:
            issues.append({
                "type": "parse_error",
                "message": f"Invalid JSON in {config_path.name}",
                "severity": "medium"
            })
        except Exception as e:
            issues.append({
                "type": "error",
                "message": f"Error analyzing {config_path.name}: {str(e)}",
                "severity": "low"
            })
        
        return issues
    
    def _check_config_secrets(self, config: dict, filename: str) -> List[Dict]:
        """Check for hardcoded secrets in configuration."""
        issues = []
        
        def check_value(key: str, value: Any, path: str = ""):
            """Recursively check configuration values for secrets."""
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, dict):
                for k, v in value.items():
                    check_value(k, v, current_path)
            elif isinstance(value, str):
                key_lower = key.lower()
                
                # Check for secret-like keys with non-empty values
                if any(secret_word in key_lower for secret_word in ['password', 'secret', 'apikey', 'api_key', 'token', 'connectionstring']):
                    if value and not value.startswith('${') and not value.startswith('$('):
                        # Check if it's a placeholder or environment variable reference
                        if not any(placeholder in value.lower() for placeholder in ['<', '>', 'your-', 'placeholder', 'changeme', 'todo']):
                            issues.append({
                                "type": "hardcoded_secret",
                                "path": current_path,
                                "message": f"Potential hardcoded secret in '{current_path}'",
                                "severity": "high",
                                "filename": filename
                            })
        
        for key, value in config.items():
            check_value(key, value)
        
        return issues
    
    def _check_config_logging(self, config: dict, filename: str) -> List[Dict]:
        """Check logging configuration for security issues."""
        issues = []
        
        # Check if logging is configured
        logging_config = config.get('Logging', {})
        
        if not logging_config:
            issues.append({
                "type": "missing_logging",
                "message": "No logging configuration found",
                "severity": "medium",
                "filename": filename
            })
            return issues
        
        # Check log levels
        log_levels = logging_config.get('LogLevel', {})
        default_level = log_levels.get('Default', '').lower()
        
        # Check for overly verbose logging in production configs
        if 'production' in filename.lower() or 'prod' in filename.lower():
            if default_level in ['debug', 'trace']:
                issues.append({
                    "type": "verbose_logging",
                    "message": f"Debug/Trace logging enabled in production config ({filename})",
                    "severity": "medium",
                    "filename": filename
                })
        
        # Check for Application Insights configuration
        app_insights = config.get('ApplicationInsights', {})
        if not app_insights and 'production' in filename.lower():
            issues.append({
                "type": "missing_app_insights",
                "message": "Application Insights not configured in production",
                "severity": "low",
                "filename": filename
            })
        
        return issues
    
    def _check_config_connection_strings(self, config: dict, filename: str) -> List[Dict]:
        """Check connection string configuration."""
        issues = []
        
        conn_strings = config.get('ConnectionStrings', {})
        
        for name, conn_str in conn_strings.items():
            if not isinstance(conn_str, str):
                continue
            
            # Check for passwords in connection strings
            if 'password=' in conn_str.lower() or 'pwd=' in conn_str.lower():
                # Check if it's using environment variable or Key Vault reference
                if not ('${' in conn_str or '$(' in conn_str or '@Microsoft.KeyVault' in conn_str):
                    issues.append({
                        "type": "connection_string_password",
                        "message": f"Connection string '{name}' contains password (use Managed Identity or Key Vault)",
                        "severity": "high",
                        "filename": filename
                    })
            
            # Check for non-encrypted connections (if not using Managed Identity)
            if 'encrypt=' in conn_str.lower():
                if 'encrypt=false' in conn_str.lower() or 'encrypt=no' in conn_str.lower():
                    issues.append({
                        "type": "unencrypted_connection",
                        "message": f"Connection string '{name}' has encryption disabled",
                        "severity": "high",
                        "filename": filename
                    })
        
        return issues
    
    def _check_config_https(self, config: dict, filename: str) -> List[Dict]:
        """Check HTTPS and HSTS configuration."""
        issues = []
        
        # Check Kestrel HTTPS configuration
        kestrel = config.get('Kestrel', {})
        endpoints = kestrel.get('Endpoints', {})
        
        has_https = False
        for endpoint_name, endpoint_config in endpoints.items():
            if isinstance(endpoint_config, dict):
                url = endpoint_config.get('Url', '')
                if 'https://' in url.lower():
                    has_https = True
        
        if endpoints and not has_https and 'production' in filename.lower():
            issues.append({
                "type": "no_https_endpoint",
                "message": "No HTTPS endpoint configured in production Kestrel settings",
                "severity": "high",
                "filename": filename
            })
        
        # Check HSTS settings
        hsts = config.get('Hsts', {})
        if hsts:
            max_age = hsts.get('MaxAge', 0)
            if isinstance(max_age, (int, float)) and max_age < 31536000:  # 1 year
                issues.append({
                    "type": "short_hsts_maxage",
                    "message": f"HSTS MaxAge is {max_age} seconds (recommended: 31536000+ for 1 year)",
                    "severity": "medium",
                    "filename": filename
                })
        
        return issues
    
    # ========================================================================
    # Data Flow Tracking Infrastructure
    # ========================================================================
    
    def _identify_sensitive_identifiers(self) -> Set[str]:
        """Identify sensitive data patterns in identifiers."""
        sensitive_patterns = {
            'ssn', 'social_security', 'socialsecurity', 'social_security_number',
            'password', 'pwd', 'passwd', 'passphrase',
            'token', 'access_token', 'refresh_token', 'bearer_token', 'jwt',
            'secret', 'api_key', 'apikey', 'api_secret', 'client_secret',
            'credit_card', 'creditcard', 'card_number', 'cvv', 'cvc',
            'pin', 'personal_identification_number',
            'email', 'email_address', 'phone', 'phone_number', 'telephone',
            'address', 'street_address', 'home_address',
            'date_of_birth', 'dateofbirth', 'dob', 'birth_date',
            'license', 'drivers_license', 'passport',
            'credential', 'credentials'
        }
        return sensitive_patterns
    
    def _is_sensitive_identifier(self, name: str) -> Tuple[bool, Optional[str]]:
        """Check if an identifier name suggests sensitive data."""
        if not name:
            return (False, None)
        
        name_lower = name.lower()
        sensitive_patterns = self._identify_sensitive_identifiers()
        
        for pattern in sensitive_patterns:
            if pattern in name_lower:
                # Determine sensitivity type
                if any(p in name_lower for p in ['ssn', 'social_security', 'credit_card', 'dob', 'birth', 'passport']):
                    return (True, 'pii')
                elif any(p in name_lower for p in ['password', 'pwd', 'passwd']):
                    return (True, 'password')
                elif any(p in name_lower for p in ['token', 'jwt', 'bearer']):
                    return (True, 'token')
                elif any(p in name_lower for p in ['secret', 'api_key', 'credential']):
                    return (True, 'secret')
                else:
                    return (True, 'pii')
        
        return (False, None)
    
    def _build_method_call_graph(self, classes: List[Dict]) -> Dict[str, MethodSignature]:
        """Build a call graph of methods for data flow analysis."""
        method_signatures = {}
        
        for class_info in classes:
            class_name = class_info.get('name', 'Unknown')
            
            for method in class_info.get('methods', []):
                method_name = method.get('name')
                if not method_name:
                    continue
                
                # Analyze parameters for sensitive data
                sensitive_params = set()
                for param in method.get('parameters', []):
                    param_name = param.get('name', '')
                    is_sensitive, sensitivity_type = self._is_sensitive_identifier(param_name)
                    if is_sensitive:
                        sensitive_params.add(param_name)
                
                # Check return type and method body for sensitive data
                return_type = method.get('return_type')
                returns_sensitive = False
                
                # Analyze method body for return statements with sensitive data
                if method.get('node'):
                    returns_sensitive = self._method_returns_sensitive_data(method['node'])
                
                signature = MethodSignature(
                    class_name=class_name,
                    method_name=method_name,
                    parameters=method.get('parameters', []),
                    return_type=return_type,
                    has_sensitive_data=len(sensitive_params) > 0 or returns_sensitive,
                    sensitive_params=sensitive_params,
                    returns_sensitive=returns_sensitive
                )
                
                key = f"{class_name}.{method_name}"
                method_signatures[key] = signature
        
        return method_signatures
    
    def _method_returns_sensitive_data(self, method_node: TreeSitterNode) -> bool:
        """Check if a method returns sensitive data by analyzing return statements."""
        if not method_node:
            return False
        
        method_text = self.code_bytes[method_node.start_byte:method_node.end_byte].decode('utf8')
        
        # Look for return statements
        return_matches = re.finditer(r'return\s+([^;]+);', method_text)
        
        for match in return_matches:
            returned_expr = match.group(1).strip()
            
            # Check if returned expression contains sensitive identifiers
            is_sensitive, _ = self._is_sensitive_identifier(returned_expr)
            if is_sensitive:
                return True
            
            # Check for property access like user.Password, customer.SSN
            if '.' in returned_expr:
                parts = returned_expr.split('.')
                for part in parts:
                    is_sensitive, _ = self._is_sensitive_identifier(part)
                    if is_sensitive:
                        return True
        
        return False
    
    def _track_data_flow_in_method(self, method_node: TreeSitterNode, method_name: str) -> List[DataFlowNode]:
        """Track data flow within a method to detect sensitive data propagation."""
        flow_nodes = []
        
        if not method_node:
            return flow_nodes
        
        method_text = self.code_bytes[method_node.start_byte:method_node.end_byte].decode('utf8')
        
        # Track variable assignments
        assignment_pattern = r'(\w+)\s*=\s*([^;]+);'
        for match in re.finditer(assignment_pattern, method_text):
            var_name = match.group(1)
            assigned_value = match.group(2).strip()
            
            # Check if variable itself is sensitive
            is_sensitive_var, sensitivity_type = self._is_sensitive_identifier(var_name)
            
            # Check if assigned value is sensitive
            is_sensitive_val, val_sensitivity_type = self._is_sensitive_identifier(assigned_value)
            
            # Check for method calls that might return sensitive data
            propagated_from = []
            if '(' in assigned_value:  # Likely a method call
                method_call_match = re.search(r'(\w+)\s*\(', assigned_value)
                if method_call_match:
                    called_method = method_call_match.group(1)
                    is_called_sensitive, _ = self._is_sensitive_identifier(called_method)
                    if is_called_sensitive:
                        propagated_from.append(called_method)
            
            # Check for property access
            if '.' in assigned_value:
                for part in assigned_value.split('.'):
                    part_clean = re.sub(r'[^\w]', '', part)
                    is_part_sensitive, _ = self._is_sensitive_identifier(part_clean)
                    if is_part_sensitive:
                        propagated_from.append(part_clean)
            
            if is_sensitive_var or is_sensitive_val or propagated_from:
                line_num = method_text[:match.start()].count('\n') + 1
                flow_node = DataFlowNode(
                    name=var_name,
                    node_type='variable',
                    is_sensitive=is_sensitive_var or is_sensitive_val or bool(propagated_from),
                    sensitivity_type=sensitivity_type or val_sensitivity_type,
                    declared_in=method_name,
                    line_number=line_num,
                    propagated_from=propagated_from
                )
                flow_nodes.append(flow_node)
        
        return flow_nodes
    
    def _check_data_flow_violations(self, code: str, file_path: str, classes: List[Dict]) -> None:
        """Check for data flow violations - sensitive data exposure through indirect paths."""
        # Build method call graph
        method_signatures = self._build_method_call_graph(classes)
        
        for class_info in classes:
            class_name = class_info.get('name', 'Unknown')
            
            for method in class_info.get('methods', []):
                method_name = method.get('name')
                if not method_name:
                    continue
                
                # Track data flow within method
                flow_nodes = self._track_data_flow_in_method(method['node'], method_name)
                
                # Check for sensitive data being logged, returned, or exposed
                for flow_node in flow_nodes:
                    if not flow_node.is_sensitive:
                        continue
                    
                    # Check if sensitive variable is logged
                    if method.get('node'):
                        method_text = self.code_bytes[method['node'].start_byte:method['node'].end_byte].decode('utf8')
                        
                        # Check for logging of sensitive variable
                        log_pattern = rf'(Log\w+|_logger\.\w+)\([^)]*{re.escape(flow_node.name)}[^)]*\)'
                        log_match = re.search(log_pattern, method_text)
                        
                        if log_match:
                            # Check if there's redaction
                            context_start = max(0, log_match.start() - 100)
                            context_end = min(len(method_text), log_match.end() + 100)
                            context = method_text[context_start:context_end]
                            
                            has_redaction = bool(re.search(r'(Redact|Mask|Sanitize|Hash|Encrypt)\s*\(', context))
                            
                            if not has_redaction:
                                line_num = method_text[:log_match.start()].count('\n') + self._get_line_from_node(method['node'])
                                
                                propagation_msg = ""
                                if flow_node.propagated_from:
                                    propagation_msg = f" (propagated from {', '.join(flow_node.propagated_from)})"
                                
                                self.add_finding(Finding(
                                    requirement_id="KSI-PIY-02",
                                    severity=Severity.HIGH,
                                    title=f"Sensitive data logged without redaction",
                                    description=f"Variable '{flow_node.name}' contains {flow_node.sensitivity_type or 'sensitive'} data and is logged without redaction{propagation_msg}. FedRAMP 20x requires PII protection.",
                                    file_path=file_path,
                                    line_number=line_num,
                                    recommendation=f"""Redact sensitive data before logging:
```csharp
// Add redaction helper
public static class SensitiveDataRedactor
{{
    public static string RedactPII(string value)
    {{
        if (string.IsNullOrEmpty(value)) return value;
        return value.Length > 4 ? new string('*', value.Length - 4) + value.Substring(value.Length - 4) : "****";
    }}
}}

// In {class_name}.{method_name}:
_logger.LogInformation("Processing data: {{RedactedValue}}", 
    SensitiveDataRedactor.RedactPII({flow_node.name}));
```
Source: Azure Well-Architected Framework Security (https://learn.microsoft.com/azure/well-architected/security/design-privacy)"""
                                ))
                        
                        # Check if sensitive variable is returned without encryption
                        return_pattern = rf'return\s+[^;]*{re.escape(flow_node.name)}[^;]*;'
                        return_match = re.search(return_pattern, method_text)
                        
                        if return_match:
                            # Check if there's encryption in the return path
                            has_encryption = bool(re.search(r'(Encrypt|Protect|IDataProtector)\s*\(', return_match.group(0)))
                            
                            # Check if this is a public API method (has [HttpGet/Post/etc] or is public)
                            is_public_api = any(attr in method.get('attributes', []) 
                                              for attr in ['HttpGet', 'HttpPost', 'HttpPut', 'HttpDelete', 'HttpPatch'])
                            
                            if not has_encryption and is_public_api:
                                line_num = method_text[:return_match.start()].count('\n') + self._get_line_from_node(method['node'])
                                
                                self.add_finding(Finding(
                                    requirement_id="KSI-PIY-02",
                                    severity=Severity.HIGH,
                                    title=f"Sensitive data returned from API without encryption",
                                    description=f"Method '{method_name}' returns {flow_node.sensitivity_type or 'sensitive'} data ('{flow_node.name}') without encryption. FedRAMP 20x requires PII protection.",
                                    file_path=file_path,
                                    line_number=line_num,
                                    recommendation=f"""Encrypt sensitive data before returning from API:
```csharp
using Microsoft.AspNetCore.DataProtection;

public class {class_name}
{{
    private readonly IDataProtectionProvider _dataProtection;
    
    public {class_name}(IDataProtectionProvider dataProtection)
    {{
        _dataProtection = dataProtection;
    }}
    
    [HttpGet]
    public IActionResult {method_name}()
    {{
        var protector = _dataProtection.CreateProtector("SensitiveDataProtection");
        var encryptedValue = protector.Protect({flow_node.name});
        return Ok(new {{ EncryptedData = encryptedValue }});
    }}
}}
```
Source: ASP.NET Core Data Protection (https://learn.microsoft.com/aspnet/core/security/data-protection/)"""
                                ))
    
    def _extract_usings(self, root_node: TreeSitterNode) -> Set[str]:
        """Extract all using directives from the AST."""
        usings = set()
        
        def visit(node: TreeSitterNode):
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
    
    # ========================================================================
    # Dependency Vulnerability Checking (KSI-SVC-08, TPR-03)
    # ========================================================================
    
    def _find_csproj_files(self, file_path: str) -> List[Path]:
        """Find .csproj files in project directory."""
        try:
            project_dir = Path(file_path).parent
            while project_dir != project_dir.parent:
                csproj_files = list(project_dir.glob("*.csproj"))
                if csproj_files:
                    return csproj_files
                project_dir = project_dir.parent
            return []
        except Exception:
            return []
    
    def _parse_csproj(self, csproj_path: Path) -> List[NuGetPackage]:
        """Parse .csproj file to extract NuGet package references."""
        packages = []
        
        try:
            tree = ET.parse(csproj_path)
            root = tree.getroot()
            
            # Find all PackageReference elements
            for package_ref in root.findall(".//PackageReference"):
                name = package_ref.get("Include")
                version_str = package_ref.get("Version")
                
                if name and version_str:
                    packages.append(NuGetPackage(
                        name=name,
                        version=version_str
                    ))
        except Exception:
            pass
        
        return packages
    
    def _get_cve_fetcher(self) -> CVEFetcher:
        """
        Get CVE fetcher instance.
        
        Queries GitHub Advisory Database for real-time vulnerability data.
        Results are cached for 1 hour to improve performance.
        """
        if not hasattr(self, '_cve_fetcher'):
            self._cve_fetcher = CVEFetcher()
        return self._cve_fetcher
    
    def _check_package_vulnerabilities(self, packages: List[NuGetPackage]) -> None:
        """
        Check packages against live CVE databases (GitHub Advisory, NVD).
        
        Maps to KSI-SVC-08 (Secure Dependencies) and KSI-TPR-03 (Supply Chain Security).
        """
        fetcher = self._get_cve_fetcher()
        
        for package in packages:
            try:
                # Query live CVE data from GitHub Advisory Database
                vulnerabilities = fetcher.get_package_vulnerabilities(
                    package_name=package.name,
                    ecosystem="nuget",
                    version=package.version
                )
                
                if vulnerabilities:
                    package.is_vulnerable = True
                    
                    # Report each vulnerability
                    for vuln in vulnerabilities:
                        severity_map = {
                            "CRITICAL": Severity.HIGH,
                            "HIGH": Severity.HIGH,
                            "MODERATE": Severity.MEDIUM,
                            "MEDIUM": Severity.MEDIUM,
                            "LOW": Severity.LOW
                        }
                        
                        # Format patched versions
                        patched = ", ".join(vuln.patched_versions) if vuln.patched_versions else "See CVE for details"
                        affected = ", ".join(vuln.affected_versions) if vuln.affected_versions else package.version
                        
                        # Format references
                        refs = "\n".join(f"- {ref}" for ref in vuln.references[:3]) if vuln.references else "See GitHub Advisory Database"
                        
                        self.add_finding(Finding(
                            requirement_id="KSI-SVC-08",
                            severity=severity_map.get(vuln.severity, Severity.HIGH),
                            title=f"Vulnerable NuGet package detected: {package.name} ({vuln.cve_id})",
                            description=f"Package {package.name} version {package.version} has known vulnerability:\n\n{vuln.description[:300]}...",
                            file_path="[Project Dependencies]",
                            line_number=None,
                            recommendation=f"""Update to secure version:
```xml
<PackageReference Include="{package.name}" Version="{patched}" />
```

Vulnerability Details:
- CVE: {vuln.cve_id}
- Severity: {vuln.severity} (CVSS: {vuln.cvss_score})
- Affected Versions: {affected}
- Patched Versions: {patched}
- Published: {vuln.published_date}

References:
{refs}

FedRAMP 20x Requirements:
- KSI-SVC-08: Secure Dependencies - Use secure, up-to-date dependencies without known vulnerabilities
- HIGH/CRITICAL vulnerabilities must be remediated within 30 days of disclosure
- Document in POA&M if remediation requires extended timeline

Automated Scanning Tools:
- dotnet list package --vulnerable (built-in .NET CLI)
- GitHub Dependabot (automatic PRs)
- Snyk (https://snyk.io/)
- OWASP Dependency-Check (https://owasp.org/www-project-dependency-check/)

Source: GitHub Advisory Database (https://github.com/advisories), NVD (https://nvd.nist.gov/)"""
                        ))
                        
                        # Store vulnerability in package object
                        if package.vulnerabilities is not None:
                            package.vulnerabilities.append({
                                "cve": vuln.cve_id,
                                "severity": vuln.severity,
                                "description": vuln.description,
                                "affected_versions": vuln.affected_versions,
                                "fixed_in": patched
                            })
            
            except Exception as e:
                # Log error but don't fail analysis
                import sys
                print(f"Warning: Failed to check vulnerabilities for {package.name}: {e}", file=sys.stderr)
    
    def _analyze_project_dependencies(self, file_path: str) -> None:
        """
        Analyze project dependencies for vulnerabilities.
        
        Finds .csproj files, parses NuGet references, and checks for:
        - Known CVEs in package versions
        - Outdated packages with security updates
        """
        csproj_files = self._find_csproj_files(file_path)
        
        if not csproj_files:
            return
        
        all_packages = []
        for csproj_path in csproj_files:
            packages = self._parse_csproj(csproj_path)
            all_packages.extend(packages)
        
        if all_packages:
            self._check_package_vulnerabilities(all_packages)
        else:
            # No packages found - might indicate missing dependency management
            self.add_finding(Finding(
                requirement_id="KSI-TPR-03",
                severity=Severity.INFO,
                title="No NuGet package references detected",
                description="No PackageReference elements found in .csproj file. If this project uses NuGet packages, ensure they're properly referenced.",
                file_path="[Project Dependencies]",
                line_number=None,
                recommendation="""Ensure dependencies are properly managed:
```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.0" />
    <PackageReference Include="Azure.Identity" Version="1.11.0" />
  </ItemGroup>
</Project>
```

Use dotnet CLI to add packages:
```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

Regularly audit dependencies:
```bash
dotnet list package --vulnerable
dotnet list package --outdated
```"""
            ))
    
    def _extract_classes(self, root_node: TreeSitterNode) -> List[Dict]:
        """Extract class definitions with their attributes and methods."""
        classes = []
        
        def visit(node: TreeSitterNode, current_namespace: str = ""):
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
    
    def _extract_attributes(self, attribute_list_node: TreeSitterNode) -> List[str]:
        """Extract attribute names from attribute list."""
        attributes = []
        
        def visit(node: TreeSitterNode):
            if node.type == "attribute":
                for child in node.children:
                    if child.type == "identifier" or child.type == "qualified_name":
                        attr_name = self._get_node_text(child)
                        attributes.append(attr_name)
            
            for child in node.children:
                visit(child)
        
        visit(attribute_list_node)
        return attributes
    
    def _extract_base_classes(self, base_list_node: TreeSitterNode) -> List[str]:
        """Extract base class names."""
        base_classes = []
        for child in base_list_node.children:
            if child.type in ["identifier", "qualified_name", "generic_name"]:
                base_classes.append(self._get_node_text(child))
        return base_classes
    
    def _extract_methods(self, declaration_list_node: TreeSitterNode) -> List[Dict]:
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
    
    def _extract_properties(self, declaration_list_node: TreeSitterNode) -> List[Dict]:
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
    
    def _extract_parameters(self, parameter_list_node: TreeSitterNode) -> List[Dict]:
        """Extract method parameters with attributes and types."""
        parameters = []
        
        for child in parameter_list_node.children:
            if child.type == "parameter":
                param_info = {
                    "name": None,
                    "type": None,
                    "attributes": []
                }
                
                identifiers = []
                for subchild in child.children:
                    if subchild.type == "attribute_list":
                        param_info["attributes"] = self._extract_attributes(subchild)
                    elif subchild.type in ["identifier", "qualified_name", "generic_name", "predefined_type"]:
                        identifiers.append(self._get_node_text(subchild))
                
                # In C# parameters: type name
                # First identifier is type, last is name
                if len(identifiers) >= 2:
                    param_info["type"] = identifiers[0]
                    param_info["name"] = identifiers[-1]
                elif len(identifiers) == 1:
                    param_info["name"] = identifiers[0]
                
                parameters.append(param_info)
        
        return parameters
    
    def _get_node_text(self, node: TreeSitterNode) -> str:
        """Get the text content of a node."""
        if node and self.code_bytes:
            return self.code_bytes[node.start_byte:node.end_byte].decode('utf8')
        return ""
    
    def _find_nodes_by_type(self, root: TreeSitterNode, node_type: str) -> List[TreeSitterNode]:
        """Find all nodes of a specific type in the AST."""
        results = []
        
        def visit(node: TreeSitterNode):
            if node.type == node_type:
                results.append(node)
            for child in node.children:
                visit(child)
        
        visit(root)
        return results
    
    def _is_in_comment(self, node: TreeSitterNode) -> bool:
        """Check if node is inside a comment."""
        current = node
        while current:
            if current.type in ["comment", "block_comment", "line_comment"]:
                return True
            current = current.parent
        return False
    
    def _is_in_string_literal(self, node: TreeSitterNode) -> bool:
        """Check if node is inside a string literal."""
        current = node
        while current:
            if current.type in ["string_literal", "verbatim_string_literal", "interpolated_string_expression"]:
                return True
            current = current.parent
        return False
    
    def _extract_try_catch_blocks(self, root_node: TreeSitterNode) -> List[Dict]:
        """
        Extract all try-catch-finally blocks with structure analysis.
        
        Returns list of dicts with:
        - try_body: try block node
        - catch_clauses: list of catch clause dicts with exception_type, exception_var, body
        - finally_clause: finally block node (if present)
        - has_logging: whether any catch block contains logging calls
        - has_rethrow: whether any catch contains throw/throw ex
        - node: the try_statement node
        """
        try_blocks = []
        
        def visit(node: TreeSitterNode):
            if node.type == "try_statement":
                block_info = {
                    "try_body": None,
                    "catch_clauses": [],
                    "finally_clause": None,
                    "has_logging": False,
                    "has_rethrow": False,
                    "node": node,
                    "line_number": node.start_point[0] + 1
                }
                
                for child in node.children:
                    if child.type == "block" and block_info["try_body"] is None:
                        # First block is the try body
                        block_info["try_body"] = child
                    elif child.type == "catch_clause":
                        catch_info = self._parse_catch_clause(child)
                        block_info["catch_clauses"].append(catch_info)
                        
                        # Check for logging in catch body
                        if catch_info["body"]:
                            catch_text = self._get_node_text(catch_info["body"])
                            if any(log_pattern in catch_text for log_pattern in ["Log", "logger", "_logger", "ILogger"]):
                                block_info["has_logging"] = True
                            if "throw" in catch_text:
                                block_info["has_rethrow"] = True
                    elif child.type == "finally_clause":
                        block_info["finally_clause"] = child
                
                try_blocks.append(block_info)
            
            for child in node.children:
                visit(child)
        
        visit(root_node)
        return try_blocks
    
    def _parse_catch_clause(self, catch_node: TreeSitterNode) -> Dict:
        """Parse a catch clause to extract exception type, variable, and body."""
        catch_info = {
            "exception_type": None,
            "exception_var": None,
            "body": None,
            "is_empty": False,
            "node": catch_node
        }
        
        for child in catch_node.children:
            if child.type == "catch_declaration":
                # Extract exception type and variable name
                # catch_declaration contains: '(' type identifier ')'
                identifiers = []
                for decl_child in child.children:
                    if decl_child.type in ["identifier", "qualified_name", "generic_name"]:
                        identifiers.append(self._get_node_text(decl_child))
                
                # First is the type, second (if present) is the variable name
                if len(identifiers) >= 1:
                    catch_info["exception_type"] = identifiers[0]
                if len(identifiers) >= 2:
                    catch_info["exception_var"] = identifiers[1]
            elif child.type == "block":
                catch_info["body"] = child
                body_text = self._get_node_text(child).strip()
                
                # Check if empty: only braces, whitespace, or comments
                # Remove comments and check if anything substantial remains
                import re
                # Remove single-line comments
                without_line_comments = re.sub(r'//.*?$', '', body_text, flags=re.MULTILINE)
                # Remove multi-line comments
                without_comments = re.sub(r'/\*.*?\*/', '', without_line_comments, flags=re.DOTALL)
                # Remove whitespace
                cleaned = without_comments.strip().replace('\n', '').replace('\r', '').replace(' ', '')
                
                # Empty if only braces remain
                catch_info["is_empty"] = cleaned == "{}" or cleaned == ""
        
        return catch_info
    
    def _contains_method_call(self, node: TreeSitterNode, method_names: List[str]) -> bool:
        """Check if a node contains any method call matching the given names."""
        def visit(n: TreeSitterNode):
            if n.type == "invocation_expression":
                # Get the method name from the invocation
                for child in n.children:
                    if child.type in ["identifier", "member_access_expression"]:
                        method_text = self._get_node_text(child)
                        if any(name in method_text for name in method_names):
                            return True
            
            for child in n.children:
                if visit(child):
                    return True
            return False
        
        return visit(node)
    
    def _extract_controller_methods_with_params(self, classes: List[Dict]) -> List[Dict]:
        """
        Extract controller methods with their parameters and validation attributes.
        
        Returns list of dicts with:
        - class_name: Name of the controller class
        - method_name: Name of the method
        - parameters: List of parameter dicts with name, type, attributes
        - body: Method body node
        - has_model_state_check: Whether method checks ModelState.IsValid
        - line_number: Line number of the method
        """
        controller_methods = []
        
        for class_info in classes:
            # Check if this is a controller
            is_controller = any(
                base in ["Controller", "ControllerBase"]
                for base in class_info["base_classes"]
            )
            
            is_api_controller = "ApiController" in class_info["attributes"]
            
            if not (is_controller or is_api_controller):
                continue
            
            for method in class_info["methods"]:
                # Check for HTTP method attributes
                http_methods = ["HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"]
                has_http_method = any(
                    http_attr in method["attributes"]
                    for http_attr in http_methods
                )
                
                if not has_http_method:
                    continue
                
                # Check if method body contains ModelState.IsValid
                has_model_state_check = False
                if method["node"]:
                    method_text = self._get_node_text(method["node"])
                    has_model_state_check = "ModelState.IsValid" in method_text or "ModelState?.IsValid" in method_text
                
                # Extract parameters with their attributes
                params_with_binding = []
                for param in method["parameters"]:
                    # Check if parameter has FromBody, FromQuery, FromRoute, FromForm
                    binding_attrs = [attr for attr in param["attributes"] 
                                   if attr in ["FromBody", "FromQuery", "FromRoute", "FromForm"]]
                    
                    if binding_attrs:
                        params_with_binding.append({
                            "name": param["name"],
                            "type": param.get("type"),
                            "attributes": param["attributes"],
                            "binding": binding_attrs[0] if binding_attrs else None
                        })
                
                if params_with_binding:
                    controller_methods.append({
                        "class_name": class_info["name"],
                        "method_name": method["name"],
                        "parameters": params_with_binding,
                        "has_model_state_check": has_model_state_check,
                        "line_number": self._get_line_from_node(method["node"])
                    })
        
        return controller_methods
    
    def _check_class_has_validation_attributes(self, class_name: str, classes: List[Dict]) -> bool:
        """Check if a class (model) has validation attributes on its properties."""
        for class_info in classes:
            if class_info["name"] == class_name:
                for prop in class_info["properties"]:
                    validation_attrs = ["Required", "StringLength", "Range", "RegularExpression", 
                                      "MaxLength", "MinLength", "EmailAddress", "Phone", "Url",
                                      "Compare", "CreditCard", "DataType"]
                    if any(attr in prop["attributes"] for attr in validation_attrs):
                        return True
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
    
    def _check_secrets_management_ast(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
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
                    secret_value = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
                    
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
                            description="Method uses [Authorize] attribute for authorization and access control.",
                            file_path=file_path,
                            line_number=line_num,
                            recommendation="Ensure authorization policies are defined in Program.cs with proper role/claims requirements.",
                            good_practice=True
                        ))
    
    def _check_error_handling_ast(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Enhanced error handling check using AST (KSI-SVC-01).
        
        Tier 1.1 Enhancements over regex:
        - Extracts try-catch-finally block structure semantically
        - Analyzes exception types (generic vs specific)
        - Detects empty catch blocks accurately
        - Verifies logging calls within catch blocks
        - Detects rethrow patterns (throw vs throw ex)
        - Understands exception flow context
        """
        try_blocks = self._extract_try_catch_blocks(root_node)
        
        if not try_blocks:
            # No error handling found - this may or may not be an issue depending on context
            return
        
        for block in try_blocks:
            for catch_clause in block["catch_clauses"]:
                # Issue 1: Empty catch blocks (swallow exceptions)
                if catch_clause["is_empty"]:
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-01",
                        severity=Severity.HIGH,
                        title="Empty catch block swallows exceptions",
                        description=f"Empty catch block at line {block['line_number']} silently swallows exceptions without logging or handling. FedRAMP 20x requires error logging for audit trails and incident response.",
                        file_path=file_path,
                        line_number=block['line_number'],
                        code_snippet=self._get_node_text(catch_clause["node"]),
                        recommendation="Add logging and appropriate error handling:\n```csharp\ntry\n{\n    await _service.ProcessDataAsync();\n}\ncatch (Exception ex)\n{\n    _logger.LogError(ex, \"Data processing failed: {{Operation}}\", \"ProcessData\");\n    throw; // or handle gracefully with return\n}\n```\nSource: Azure WAF Operational Excellence (https://learn.microsoft.com/azure/well-architected/operational-excellence/)"
                    ))
                    continue
                
                # Issue 2: Catch block without logging
                if catch_clause["body"] and not self._contains_method_call(catch_clause["body"], ["Log", "logger", "_logger"]):
                    # Check if it at least rethrows
                    has_throw = "throw" in self._get_node_text(catch_clause["body"])
                    
                    severity = Severity.MEDIUM if has_throw else Severity.HIGH
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-01",
                        severity=severity,
                        title="Exception caught without logging",
                        description=f"Catch block at line {block['line_number']} handles exception type '{catch_clause['exception_type']}' without logging. {'Exception is rethrown but audit trail is incomplete.' if has_throw else 'No logging or rethrowing detected.'} FedRAMP 20x requires comprehensive error logging.",
                        file_path=file_path,
                        line_number=block['line_number'],
                        code_snippet=self._get_node_text(catch_clause["node"])[:200],
                        recommendation="Add structured logging before handling:\n```csharp\ncatch (DbUpdateException ex)\n{\n    _logger.LogError(ex, \"Database update failed for {{Entity}}\", entityName);\n    return StatusCode(500, new { error = \"Database error occurred\" });\n}\n```"
                    ))
                
                # Issue 3: Generic Exception catch (too broad)
                if catch_clause["exception_type"] == "Exception":
                    # Check if this is in a top-level handler (acceptable there)
                    node_text = self._get_node_text(block["node"])
                    parent_context = self._get_node_text(block["node"].parent) if block["node"].parent else ""
                    
                    is_global_handler = any(keyword in parent_context for keyword in ["Program", "Startup", "Middleware", "ExceptionHandler"])
                    
                    if not is_global_handler:
                        # Generic exception catch in business logic
                        has_logging = self._contains_method_call(catch_clause["body"], ["Log", "logger"])
                        
                        self.add_finding(Finding(
                            requirement_id="KSI-SVC-01",
                            severity=Severity.LOW,
                            title="Generic exception handler in business logic",
                            description=f"Catch block at line {block['line_number']} catches generic 'Exception' type. While {'it includes logging, ' if has_logging else ''}catching specific exception types improves error handling precision and debugging.",
                            file_path=file_path,
                            line_number=block['line_number'],
                            recommendation="Catch specific exceptions when possible:\n```csharp\ntry\n{\n    await _database.SaveAsync();\n}\ncatch (DbUpdateConcurrencyException ex)\n{\n    _logger.LogWarning(ex, \"Concurrency conflict detected\");\n    return Conflict(\"Resource was modified by another user\");\n}\ncatch (DbUpdateException ex)\n{\n    _logger.LogError(ex, \"Database update failed\");\n    return StatusCode(500, \"Database error\");\n}\n```"
                        ))
                
                # Good Practice: Proper error handling with logging and specific exception
                if (catch_clause["exception_type"] and catch_clause["exception_type"] != "Exception" and
                    self._contains_method_call(catch_clause["body"], ["Log", "logger"])):
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-01",
                        severity=Severity.INFO,
                        title=f"Proper error handling for {catch_clause['exception_type']}",
                        description=f"Catch block at line {block['line_number']} correctly handles specific exception type '{catch_clause['exception_type']}' with logging. Good practice for FedRAMP audit requirements.",
                        file_path=file_path,
                        line_number=block['line_number'],
                        recommendation="Continue following this pattern for all exception handling.",
                        good_practice=True
                    ))
    
    def _check_input_validation_ast(self, code: str, file_path: str, classes: List[Dict]) -> None:
        """
        Enhanced input validation check using AST (KSI-SVC-02).
        
        Tier 1.2 Enhancements over regex:
        - Extracts controller methods with parameters semantically
        - Verifies each parameter with FromBody/FromQuery has validation
        - Tracks whether parameter types have validation attributes
        - Analyzes ModelState.IsValid placement in method body
        - Detects custom validation logic
        - Framework detection: Recognizes Data Annotations and FluentValidation
        - FluentValidation deep support: Detects AbstractValidator<T> classes
        """
        # Framework detection to reduce false positives
        usings = self._extract_usings(self.tree.root_node) if self.tree else set()
        has_data_annotations = self._has_data_annotations(code, usings)
        has_fluent_validation = self._has_fluent_validation(code, usings)
        
        # Extract FluentValidation validators (separate validator classes)
        fluent_validators = self._extract_fluent_validators(self.tree.root_node) if self.tree else {}
        has_fluent_registration = self._check_fluent_validation_registration(code)
        
        controller_methods = self._extract_controller_methods_with_params(classes)
        
        if not controller_methods:
            # No controller methods with input binding found
            return
        
        for method_info in controller_methods:
            unvalidated_params = []
            validated_params = []
            
            for param in method_info["parameters"]:
                # Check if the parameter type itself has validation attributes
                param_type = param.get("type")
                has_type_validation = False
                has_fluent_validator = False
                
                if param_type:
                    # Check if this is a known model class with validation
                    has_type_validation = self._check_class_has_validation_attributes(param_type, classes)
                    
                    # Check if FluentValidation validator exists for this type
                    if param_type in fluent_validators:
                        has_fluent_validator = True
                        has_type_validation = True  # FluentValidation counts as validation
                
                # Check if parameter has validation attributes directly
                validation_attrs = ["Required", "StringLength", "Range", "RegularExpression",
                                  "MaxLength", "MinLength", "EmailAddress", "Phone", "Url"]
                has_param_validation = any(attr in param["attributes"] for attr in validation_attrs)
                
                if has_type_validation or has_param_validation:
                    validated_params.append({
                        "name": param["name"],
                        "type": param_type,
                        "fluent": has_fluent_validator
                    })
                else:
                    unvalidated_params.append({
                        "name": param["name"],
                        "binding": param["binding"],
                        "type": param_type
                    })
            
            # Issue 1: Parameters without validation
            if unvalidated_params and not method_info["has_model_state_check"]:
                # Framework detection: Only reduce severity if framework is present AND used on other params
                # If all params are unvalidated, framework presence alone isn't enough to reduce severity
                framework_in_use = (has_data_annotations or has_fluent_validation) and len(validated_params) > 0
                
                if framework_in_use:
                    # Framework present and used on some params, but not all - lower severity
                    param_names = ", ".join([f"'{p['name']}'" for p in unvalidated_params])
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-02",
                        severity=Severity.MEDIUM,
                        title=f"Input parameters without validation in {method_info['method_name']}",
                        description=f"Method '{method_info['method_name']}' in controller '{method_info['class_name']}' accepts input parameters ({param_names}) without validation attributes. Data Annotations or FluentValidation is being used on other parameters - consider applying to all parameters consistently.",
                        file_path=file_path,
                        line_number=method_info['line_number'],
                        recommendation="Add validation attributes to all input parameters:\n```csharp\npublic class QueryRequest\n{\n    [Required]\n    [StringLength(100)]\n    public string Filter { get; set; }\n    \n    [Range(1, 100)]\n    public int PageSize { get; set; }\n}\n\n[HttpGet]\npublic IActionResult GetData([FromQuery] QueryRequest request)\n{\n    if (!ModelState.IsValid)\n        return BadRequest(ModelState);\n    // Process validated input\n}\n```\n\nOr use FluentValidation:\n```csharp\npublic class QueryRequestValidator : AbstractValidator<QueryRequest>\n{\n    public QueryRequestValidator()\n    {\n        RuleFor(x => x.Filter).NotEmpty().MaximumLength(100);\n        RuleFor(x => x.PageSize).InclusiveBetween(1, 100);\n    }\n}\n```\nSource: ASP.NET Core Model Validation (https://learn.microsoft.com/aspnet/core/mvc/models/validation)"
                    ))
                else:
                    # No validation framework detected or not being used - higher severity
                    param_names = ", ".join([f"'{p['name']}'" for p in unvalidated_params])
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-02",
                        severity=Severity.HIGH,
                        title=f"Input parameters without validation in {method_info['method_name']}",
                        description=f"Method '{method_info['method_name']}' in controller '{method_info['class_name']}' accepts input parameters ({param_names}) without validation attributes and doesn't check ModelState.IsValid. FedRAMP 20x requires input validation to prevent injection attacks and data integrity issues.",
                        file_path=file_path,
                        line_number=method_info['line_number'],
                        recommendation="Add validation attributes to model properties:\n```csharp\npublic class CreateUserRequest\n{\n    [Required(ErrorMessage = \"Username is required\")]\n    [StringLength(50, MinimumLength = 3)]\n    [RegularExpression(@\"^[a-zA-Z0-9_]+$\")]\n    public string Username { get; set; }\n    \n    [Required]\n    [EmailAddress]\n    public string Email { get; set; }\n}\n\n[HttpPost]\npublic IActionResult CreateUser([FromBody] CreateUserRequest request)\n{\n    if (!ModelState.IsValid)\n        return BadRequest(ModelState);\n    // Process validated input\n}\n```\nSource: ASP.NET Core Model Validation (https://learn.microsoft.com/aspnet/core/mvc/models/validation)"
                    ))
            
            # Issue 2: Has validation but missing ModelState check
            elif validated_params and not method_info["has_model_state_check"]:
                # Check if FluentValidation is properly registered
                fluent_params = [p for p in validated_params if p.get("fluent")]
                if fluent_params and has_fluent_registration:
                    # FluentValidation with registration - automatic validation via pipeline
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-02",
                        severity=Severity.INFO,
                        title=f"FluentValidation configured in {method_info['method_name']}",
                        description=f"Method '{method_info['method_name']}' uses FluentValidation with automatic validation pipeline. Validators registered via AddFluentValidation() automatically validate requests before reaching controller action.",
                        file_path=file_path,
                        line_number=method_info['line_number'],
                        recommendation="Good practice: FluentValidation automatically validates and returns 400 Bad Request for invalid models when registered in pipeline.",
                        good_practice=True
                    ))
                else:
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-02",
                        severity=Severity.MEDIUM,
                        title=f"Missing ModelState.IsValid check in {method_info['method_name']}",
                        description=f"Method '{method_info['method_name']}' has validated parameters but doesn't check ModelState.IsValid before processing. Validation attributes are defined but not enforced at runtime.",
                        file_path=file_path,
                        line_number=method_info['line_number'],
                        recommendation="Add ModelState validation check:\n```csharp\n[HttpPost]\npublic IActionResult {method_info['method_name']}([FromBody] Model request)\n{\n    if (!ModelState.IsValid)\n    {\n        _logger.LogWarning(\"Validation failed: {{Errors}}\", ModelState.Values.SelectMany(v => v.Errors));\n        return BadRequest(ModelState);\n    }\n    // Process validated input\n}\n```"
                    ))
            
            # Good Practice: Proper validation with ModelState check
            elif validated_params and method_info["has_model_state_check"]:
                fluent_params = [p for p in validated_params if p.get("fluent")]
                if fluent_params:
                    validator_info = ", ".join([f"{p['type']} (FluentValidation)" for p in fluent_params[:2]])
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-02",
                        severity=Severity.INFO,
                        title=f"Input validation with FluentValidation in {method_info['method_name']}",
                        description=f"Method '{method_info['method_name']}' correctly validates input parameters using FluentValidation validators ({validator_info}) and checks ModelState.IsValid. Excellent practice for complex validation rules with business logic.",
                        file_path=file_path,
                        line_number=method_info['line_number'],
                        recommendation="Continue using FluentValidation for maintainable validation logic separate from models.",
                        good_practice=True
                    ))
                else:
                    self.add_finding(Finding(
                        requirement_id="KSI-SVC-02",
                        severity=Severity.INFO,
                        title=f"Input validation properly configured in {method_info['method_name']}",
                        description=f"Method '{method_info['method_name']}' correctly validates input parameters with data annotations and checks ModelState.IsValid. Good practice for FedRAMP compliance.",
                        file_path=file_path,
                        line_number=method_info['line_number'],
                        recommendation="Consider using FluentValidation for complex validation scenarios requiring business logic.",
                        good_practice=True
                    ))
    
    # ========================================================================
    # Entity Framework Security Checks (Phase A Enhancements)
    # ========================================================================
    
    def _check_entity_framework_security_ast(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        AST-enhanced Entity Framework security checks.
        
        Phase A enhancements:
        1. SQL Injection via ExecuteSqlRaw/FromSqlRaw (KSI-SVC-02)
        2. N+1 Query Detection (KSI-SVC-01 - Performance)
        3. Missing AsNoTracking() in read-only queries (KSI-MLA-06)
        """
        # Phase A.1: SQL Injection Detection
        self._check_ef_sql_injection(code, file_path, root_node)
        
        # Phase A.2: N+1 Query Detection
        self._check_ef_n_plus_one(code, file_path, root_node)
        
        # Phase A.3: Tracking vs No-Tracking
        self._check_ef_tracking_performance(code, file_path, root_node)
    
    def _check_ef_sql_injection(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect SQL injection vulnerabilities in Entity Framework code (KSI-SVC-02).
        
        Dangerous patterns:
        - ExecuteSqlRaw with string interpolation or concatenation
        - FromSqlRaw with string interpolation or concatenation
        - Dynamic LINQ with user input
        """
        def find_ef_sql_calls(node):
            """Find EF raw SQL method calls."""
            if node.type == "invocation_expression":
                # Extract method name
                method_name = None
                for child in node.children:
                    if child.type == "member_access_expression":
                        # Get the last identifier (method name)
                        identifiers = [n for n in child.children if n.type == "identifier"]
                        if identifiers:
                            method_name = self.code_bytes[identifiers[-1].start_byte:identifiers[-1].end_byte].decode('utf8')
                
                # Check if it's a dangerous EF method
                if method_name in ["ExecuteSqlRaw", "FromSqlRaw", "ExecuteSql", "FromSql"]:
                    # Extract arguments
                    args_node = None
                    for child in node.children:
                        if child.type == "argument_list":
                            args_node = child
                            break
                    
                    if args_node:
                        args_text = self.code_bytes[args_node.start_byte:args_node.end_byte].decode('utf8')
                        
                        # Check for string interpolation ($"...") or concatenation (+ with strings)
                        has_interpolation = '$"' in args_text
                        has_concatenation = '" +' in args_text or '+ "' in args_text or '"+"' in args_text
                        has_format_call = '.Format(' in args_text
                        
                        # Check if using parameters (safe pattern)
                        has_parameters = '{0}' in args_text or (', ' in args_text and not has_concatenation)
                        
                        is_dangerous = False
                        if has_interpolation and not method_name.endswith("Interpolated"):
                            is_dangerous = True
                        elif has_concatenation:
                            is_dangerous = True
                        elif has_format_call and not has_parameters:
                            is_dangerous = True
                        
                        if is_dangerous:
                                line_num = node.start_point[0] + 1
                                
                                # Extract full statement for context
                                statement_text = self.code_bytes[node.start_byte:node.end_byte].decode('utf8')
                                if len(statement_text) > 100:
                                    statement_text = statement_text[:97] + "..."
                                
                                self.add_finding(Finding(
                                    requirement_id="KSI-SVC-02",
                                    severity=Severity.HIGH,
                                    title=f"SQL injection vulnerability in {method_name}",
                                    description=f"Entity Framework method '{method_name}' uses string interpolation or concatenation, which can lead to SQL injection attacks. FedRAMP 20x requires parameterized queries to prevent injection vulnerabilities.",
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=statement_text,
                                    recommendation=f"""Use parameterized queries instead:

```csharp
// ❌ DANGEROUS: String interpolation
{statement_text}

// ✅ SAFE: Parameterized query
context.Database.ExecuteSqlRaw("SELECT * FROM Users WHERE Id = {{0}}", userId);

// ✅ SAFE: Interpolated (automatic parameters)
context.Database.ExecuteSqlInterpolated($"SELECT * FROM Users WHERE Id = {{userId}}");

// ✅ BEST: Use LINQ (automatically parameterized)
var user = context.Users.FirstOrDefault(u => u.Id == userId);
```

Source: EF Core Raw SQL Queries (https://learn.microsoft.com/ef/core/querying/raw-sql)"""
                                ))
            
            for child in node.children:
                find_ef_sql_calls(child)
        
        find_ef_sql_calls(root_node)
    
    def _check_ef_n_plus_one(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect N+1 query problems in Entity Framework (KSI-SVC-01).
        
        Pattern: foreach loop accessing navigation properties without Include().
        """
        def find_foreach_loops(node):
            """Find foreach loops and analyze for N+1 issues."""
            # Tree-sitter uses "for_each_statement" or "foreach_statement"
            if node.type in ["for_each_statement", "foreach_statement"]:
                # Extract loop body
                loop_body = None
                for child in node.children:
                    if child.type == "block":
                        loop_body = child
                        break
                
                if loop_body:
                    loop_text = self.code_bytes[loop_body.start_byte:loop_body.end_byte].decode('utf8')
                    
                    # Check for navigation property access (pattern: item.Property.SubProperty)
                    # Common patterns: order.Customer.Name, user.Orders.Count, etc.
                    nav_prop_pattern = r'\w+\.(\w+)\.(\w+)'
                    nav_matches = re.findall(nav_prop_pattern, loop_text)
                    
                    if nav_matches:
                        # Check if Include() is used before the loop
                        # Look backwards from foreach statement
                        context_start = max(0, node.start_byte - 500)
                        context_text = self.code_bytes[context_start:node.start_byte].decode('utf8')
                        
                        has_include = '.Include(' in context_text or '.ThenInclude(' in context_text
                        has_select = '.Select(' in context_text  # Projection avoids N+1
                        
                        if not (has_include or has_select):
                            line_num = node.start_point[0] + 1
                            accessed_props = ', '.join([f"{m[0]}.{m[1]}" for m in nav_matches[:3]])
                            
                            self.add_finding(Finding(
                                requirement_id="KSI-SVC-01",
                                severity=Severity.MEDIUM,
                                title="Potential N+1 query problem detected",
                                description=f"Foreach loop accesses navigation properties ({accessed_props}) without eager loading. This causes separate database queries for each iteration (N+1 problem), impacting performance and potentially causing timeout errors under load.",
                                file_path=file_path,
                                line_number=line_num,
                                recommendation="""Fix N+1 query with eager loading:

```csharp
// ❌ N+1 PROBLEM: Separate query for each order's customer
foreach (var order in context.Orders) {
    Console.WriteLine(order.Customer.Name); // Triggers query
}

// ✅ EAGER LOADING: Single query with Include
var orders = context.Orders.Include(o => o.Customer).ToList();
foreach (var order in orders) {
    Console.WriteLine(order.Customer.Name); // No query
}

// ✅ PROJECTION: Only load needed data
var orders = context.Orders
    .Select(o => new { o.Id, CustomerName = o.Customer.Name })
    .ToList();

// ✅ MULTIPLE LEVELS: ThenInclude for nested properties
var orders = context.Orders
    .Include(o => o.Customer)
    .ThenInclude(c => c.Address)
    .ToList();
```

Source: EF Core Related Data (https://learn.microsoft.com/ef/core/querying/related-data)"""
                            ))
            
            for child in node.children:
                find_foreach_loops(child)
        
        find_foreach_loops(root_node)
    
    def _check_ef_tracking_performance(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect missing AsNoTracking() in read-only queries (KSI-MLA-06).
        
        Pattern: GET endpoints or read-only methods without AsNoTracking().
        """
        def find_http_get_methods(node):
            """Find HTTP GET endpoints and check for AsNoTracking()."""
            if node.type == "method_declaration":
                # Check if method has [HttpGet] attribute
                has_http_get = False
                method_name = None
                
                for child in node.children:
                    if child.type == "attribute_list":
                        attr_text = self.code_bytes[child.start_byte:child.end_byte].decode('utf8')
                        if 'HttpGet' in attr_text or '[Get' in attr_text:
                            has_http_get = True
                    
                    if child.type == "identifier":
                        method_name = self.code_bytes[child.start_byte:child.end_byte].decode('utf8')
                
                if has_http_get or (method_name and method_name.startswith('Get')):
                    # Extract method body
                    method_body = None
                    for child in node.children:
                        if child.type == "block":
                            method_body = child
                            break
                    
                    if method_body:
                        body_text = self.code_bytes[method_body.start_byte:method_body.end_byte].decode('utf8')
                        
                        # Check if method queries a DbContext
                        # Look for _context., context., or DbContext variable with LINQ methods
                        # Allow for method chaining with .Include(), .Where(), etc.
                        has_ef_query = bool(re.search(r'(_context|context|\w+DbContext)\s*\.\s*\w+', body_text)) and \
                                       bool(re.search(r'\.(Where|FirstOrDefault|Find|ToList|Single|Any|Count|First|Include|AsNoTracking)\s*\(', body_text))
                        has_no_tracking = '.AsNoTracking()' in body_text
                        has_tracking_behavior = '.AsNoTrackingWithIdentityResolution()' in body_text
                        
                        if has_ef_query:
                            if not (has_no_tracking or has_tracking_behavior):
                                line_num = node.start_point[0] + 1
                                
                                self.add_finding(Finding(
                                    requirement_id="KSI-MLA-06",
                                    severity=Severity.LOW,
                                    title=f"Read-only query without AsNoTracking() in {method_name or 'GET method'}",
                                    description=f"HTTP GET endpoint queries Entity Framework without AsNoTracking(). For read-only operations, tracking overhead is unnecessary and impacts performance. This can cause memory issues and slower response times under high load.",
                                    file_path=file_path,
                                    line_number=line_num,
                                    recommendation="""Add AsNoTracking() for read-only queries:

```csharp
// ❌ INEFFICIENT: Unnecessary change tracking
[HttpGet]
public IActionResult GetUsers() {
    var users = context.Users.ToList(); // Tracking enabled
    return Ok(users);
}

// ✅ EFFICIENT: No-tracking for read-only
[HttpGet]
public IActionResult GetUsers() {
    var users = context.Users.AsNoTracking().ToList();
    return Ok(users);
}

// ✅ WITH NAVIGATION: Include still works
[HttpGet]
public IActionResult GetOrders() {
    var orders = context.Orders
        .Include(o => o.Customer)
        .AsNoTracking()
        .ToList();
    return Ok(orders);
}

// ℹ️ GLOBAL: Set no-tracking as default
services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString)
           .UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking));
```

Benefits: ~20-30% faster queries, reduced memory usage.
Source: EF Core Tracking (https://learn.microsoft.com/ef/core/querying/tracking)"""
                                ))
                            else:
                                # Good practice detected
                                line_num = node.start_point[0] + 1
                                self.add_finding(Finding(
                                    requirement_id="KSI-MLA-06",
                                    severity=Severity.INFO,
                                    title=f"Optimized read-only query in {method_name or 'GET method'}",
                                    description="Query uses AsNoTracking() for read-only operations, improving performance by disabling change tracking overhead.",
                                    file_path=file_path,
                                    line_number=line_num,
                                    recommendation="Good practice. Consider setting no-tracking as default behavior in DbContext configuration if most queries are read-only.",
                                    good_practice=True
                                ))
            
            for child in node.children:
                find_http_get_methods(child)
        
        find_http_get_methods(root_node)
    
    # ========================================================================
    # ASP.NET Core Middleware Security (Phase B Enhancements)
    # ========================================================================
    
    def _check_aspnet_middleware_security_ast(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        AST-enhanced ASP.NET Core middleware security checks.
        
        Phase B enhancements:
        1. Security Headers Validation (KSI-SVC-07)
        2. Rate Limiting Detection (KSI-SVC-07, AFR-01)
        3. Request Size Limits (KSI-SVC-02, AFR-01)
        """
        # Phase B.1: Security Headers
        self._check_security_headers(code, file_path, root_node)
        
        # Phase B.2: Rate Limiting
        self._check_rate_limiting(code, file_path, root_node)
        
        # Phase B.3: Request Size Limits
        self._check_request_size_limits(code, file_path, root_node)
    
    def _check_security_headers(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect missing security headers in ASP.NET Core middleware (KSI-SVC-07).
        
        Critical headers:
        - X-Content-Type-Options: nosniff
        - X-Frame-Options: DENY/SAMEORIGIN
        - Content-Security-Policy
        - X-XSS-Protection
        - Referrer-Policy
        """
        # Track which headers are configured
        configured_headers = set()
        has_nwebsec = False
        
        def find_security_headers(node):
            nonlocal has_nwebsec
            
            if node.type == "invocation_expression":
                method_name = self._extract_method_name(node)
                
                # Check for NWebsec middleware calls
                if method_name in [
                    "UseXContentTypeOptions",
                    "UseXfo",
                    "UseXXssProtection",
                    "UseReferrerPolicy",
                    "UseCsp",
                    "UseHsts"
                ]:
                    has_nwebsec = True
                    if method_name == "UseXContentTypeOptions":
                        configured_headers.add("X-Content-Type-Options")
                    elif method_name == "UseXfo":
                        configured_headers.add("X-Frame-Options")
                    elif method_name == "UseXXssProtection":
                        configured_headers.add("X-XSS-Protection")
                    elif method_name == "UseReferrerPolicy":
                        configured_headers.add("Referrer-Policy")
                    elif method_name == "UseCsp":
                        configured_headers.add("Content-Security-Policy")
                
                # Check for manual header configuration
                if method_name == "Add" or method_name == "Append":
                    # Check if adding to Response.Headers
                    parent_text = self.code_bytes[node.parent.start_byte:node.parent.end_byte].decode('utf8') if node.parent else ""
                    if "Response.Headers" in parent_text or "Headers.Add" in parent_text:
                        # Extract header name from arguments
                        args_text = self._extract_arguments_text(node)
                        if args_text:
                            if "X-Content-Type-Options" in args_text:
                                configured_headers.add("X-Content-Type-Options")
                            if "X-Frame-Options" in args_text:
                                configured_headers.add("X-Frame-Options")
                            if "Content-Security-Policy" in args_text:
                                configured_headers.add("Content-Security-Policy")
                            if "X-XSS-Protection" in args_text:
                                configured_headers.add("X-XSS-Protection")
                            if "Referrer-Policy" in args_text:
                                configured_headers.add("Referrer-Policy")
            
            for child in node.children:
                find_security_headers(child)
        
        find_security_headers(root_node)
        
        # Check for missing critical headers
        required_headers = {
            "X-Content-Type-Options": "prevents MIME-type sniffing attacks",
            "X-Frame-Options": "prevents clickjacking attacks",
            "Content-Security-Policy": "prevents XSS and data injection attacks"
        }
        
        missing_headers = [h for h in required_headers if h not in configured_headers]
        
        if missing_headers and ("Configure" in code or "UseEndpoints" in code or "app.Use" in code):
            header_list = ", ".join(missing_headers)
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.MEDIUM,
                title=f"Missing critical security headers: {header_list}",
                description=f"Application middleware pipeline is missing {len(missing_headers)} critical security headers: {', '.join([f'{h} ({required_headers[h]})' for h in missing_headers])}. This leaves the application vulnerable to various attacks.",
                file_path=file_path,
                line_number=1,
                recommendation=f"""Add security headers to middleware pipeline:

// Option 1: Use NWebsec middleware package (recommended)
app.UseXContentTypeOptions();
app.UseXfo(options => options.Deny());
app.UseCsp(opts => opts.DefaultSources(s => s.Self()));

// Option 2: Manual header configuration
app.Use(async (context, next) => {{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
}});

Source: OWASP Secure Headers (https://owasp.org/www-project-secure-headers/)
Package: NWebsec (https://docs.nwebsec.com/)"""
            ))
    
    def _check_rate_limiting(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect missing rate limiting on API endpoints (KSI-SVC-07, AFR-01).
        
        Checks for:
        - .NET 7+ built-in rate limiting (AddRateLimiter)
        - AspNetCoreRateLimit package
        - [EnableRateLimiting] attribute on endpoints
        """
        has_rate_limiter_service = "AddRateLimiter" in code
        has_aspnetcore_rate_limit = "AddInMemoryRateLimiting" in code or "IpRateLimitOptions" in code
        has_rate_limit_attribute = "[EnableRateLimiting" in code or "[RateLimit" in code
        
        # Find HTTP POST/PUT/DELETE endpoints without rate limiting
        def find_unprotected_endpoints(node):
            if node.type == "method_declaration":
                method_text = self.code_bytes[node.start_byte:node.end_byte].decode('utf8')
                method_name = self._extract_method_name_from_declaration(node)
                
                # Check for HTTP verb attributes
                has_post = "[HttpPost" in method_text
                has_put = "[HttpPut" in method_text
                has_delete = "[HttpDelete" in method_text
                
                if has_post or has_put or has_delete:
                    # Check if this specific endpoint has rate limiting
                    has_endpoint_rate_limit = "[EnableRateLimiting" in method_text or "[RateLimit" in method_text
                    
                    if not has_endpoint_rate_limit and not has_rate_limiter_service and not has_aspnetcore_rate_limit:
                        verb = "POST" if has_post else ("PUT" if has_put else "DELETE")
                        line_num = node.start_point[0] + 1
                        self.add_finding(Finding(
                            requirement_id="KSI-SVC-07",
                            severity=Severity.MEDIUM,
                            title=f"Missing rate limiting on {verb} endpoint: {method_name or 'endpoint'}",
                            description=f"{verb} endpoint lacks rate limiting protection, making it vulnerable to brute-force attacks, resource exhaustion, and denial-of-service attacks.",
                            file_path=file_path,
                            line_number=line_num,
                            recommendation=f"""Add rate limiting to protect endpoint:

// Option 1: .NET 7+ built-in rate limiting (recommended)
// In Program.cs:
builder.Services.AddRateLimiter(options => {{
    options.AddFixedWindowLimiter("fixed", options => {{
        options.PermitLimit = 100;
        options.Window = TimeSpan.FromMinutes(1);
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        options.QueueLimit = 5;
    }});
}});

// On endpoint:
[EnableRateLimiting("fixed")]
{verb.capitalize()}]
public IActionResult {method_name or 'Method'}(...) {{ }}

// Option 2: AspNetCoreRateLimit package
// Install: dotnet add package AspNetCoreRateLimit
services.AddMemoryCache();
services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));
services.AddInMemoryRateLimiting();

Source: Rate Limiting (https://learn.microsoft.com/aspnet/core/performance/rate-limit)
KSI-AFR-01: Automated remediation for brute-force attacks"""
                        ))
            
            for child in node.children:
                find_unprotected_endpoints(child)
        
        find_unprotected_endpoints(root_node)
    
    def _check_request_size_limits(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect file upload endpoints without request size limits (KSI-SVC-02, AFR-01).
        
        Checks for:
        - [RequestSizeLimit] attribute
        - FormOptions.MultipartBodyLengthLimit configuration
        - IISServerOptions.MaxRequestBodySize configuration
        """
        has_global_size_limit = "MultipartBodyLengthLimit" in code or "MaxRequestBodySize" in code
        
        def find_upload_endpoints(node):
            if node.type == "method_declaration":
                method_text = self.code_bytes[node.start_byte:node.end_byte].decode('utf8')
                method_name = self._extract_method_name_from_declaration(node)
                
                # Check if endpoint handles file uploads
                has_file_param = "IFormFile" in method_text or "IFormFileCollection" in method_text
                has_post = "[HttpPost" in method_text
                
                if has_file_param and has_post:
                    # Check for [RequestSizeLimit] attribute
                    has_size_limit_attr = "[RequestSizeLimit" in method_text
                    
                    if not has_size_limit_attr and not has_global_size_limit:
                        line_num = node.start_point[0] + 1
                        self.add_finding(Finding(
                            requirement_id="KSI-SVC-02",
                            severity=Severity.HIGH,
                            title=f"Missing request size limit on file upload endpoint: {method_name or 'endpoint'}",
                            description="File upload endpoint lacks request size limits, making it vulnerable to denial-of-service attacks through large payload submissions. Attackers could exhaust server resources by uploading extremely large files.",
                            file_path=file_path,
                            line_number=line_num,
                            recommendation=f"""Add request size limits to file upload endpoint:

// Option 1: Per-endpoint attribute (recommended for specific endpoints)
[RequestSizeLimit(10_000_000)] // 10MB limit
[HttpPost]
public IActionResult {method_name or 'Upload'}(IFormFile file) {{ }}

// Option 2: Global configuration (recommended for all uploads)
// In Program.cs:
builder.Services.Configure<FormOptions>(options => {{
    options.MultipartBodyLengthLimit = 10_000_000; // 10MB
}});

builder.Services.Configure<IISServerOptions>(options => {{
    options.MaxRequestBodySize = 10_000_000; // 10MB
}});

// Option 3: Disable limit for specific endpoint (use with caution)
[RequestSizeLimit(long.MaxValue)]
[HttpPost]
public IActionResult {method_name or 'Upload'}(IFormFile file) {{ }}

Recommended limits:
- Small files (images, documents): 5-10 MB
- Large files (videos, backups): 50-100 MB
- Check available disk space and memory before setting limits

Source: Upload Files (https://learn.microsoft.com/aspnet/core/mvc/models/file-uploads#upload-large-files-with-streaming)
KSI-AFR-01: DoS protection through resource limits"""
                        ))
            
            for child in node.children:
                find_upload_endpoints(child)
        
        find_upload_endpoints(root_node)
    
    # ========================================================================
    # Azure Integration Security (Phase C Enhancements)
    # ========================================================================
    
    def _check_azure_integration_security_ast(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        AST-enhanced Azure service integration security checks.
        
        Phase C enhancements:
        1. Cosmos DB Security (KSI-IAM-02, SVC-06)
        2. Service Bus Security (KSI-IAM-02)
        3. Azure Storage Security (KSI-IAM-02, SVC-06)
        4. Key Vault Integration (KSI-SVC-06)
        """
        # Phase C.1: Cosmos DB Security
        self._check_cosmos_db_security(code, file_path, root_node)
        
        # Phase C.2: Service Bus Security
        self._check_service_bus_security(code, file_path, root_node)
        
        # Phase C.3: Azure Storage Security
        self._check_azure_storage_security(code, file_path, root_node)
        
        # Phase C.4: Key Vault Integration
        self._check_key_vault_integration(code, file_path, root_node)
    
    def _check_cosmos_db_security(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect insecure Cosmos DB connection patterns (KSI-IAM-02, SVC-06).
        
        Checks for:
        - Connection strings in code (should use Managed Identity)
        - CosmosClient instantiation patterns
        - DefaultAzureCredential usage (good practice)
        """
        has_managed_identity = "DefaultAzureCredential" in code or "ManagedIdentityCredential" in code
        has_connection_string = False
        connection_string_lines = []
        
        def find_cosmos_patterns(node):
            nonlocal has_connection_string
            
            if node.type == "object_creation_expression":
                # Check for new CosmosClient(connectionString)
                type_node = node.child_by_field_name("type")
                if type_node:
                    type_text = self.code_bytes[type_node.start_byte:type_node.end_byte].decode('utf8')
                    
                    if "CosmosClient" in type_text:
                        # Check arguments
                        args_node = node.child_by_field_name("arguments")
                        if args_node:
                            args_text = self.code_bytes[args_node.start_byte:args_node.end_byte].decode('utf8')
                            
                            # Check if using connection string (string literal or variable)
                            if ('"' in args_text or "connectionString" in args_text.lower() or 
                                "GetConnectionString" in args_text or "_configuration[" in args_text):
                                
                                # Verify it's not using credential parameter
                                if "DefaultAzureCredential" not in args_text and "TokenCredential" not in args_text:
                                    has_connection_string = True
                                    line_num = node.start_point[0] + 1
                                    connection_string_lines.append(line_num)
            
            for child in node.children:
                find_cosmos_patterns(child)
        
        find_cosmos_patterns(root_node)
        
        if has_connection_string and not has_managed_identity:
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.HIGH,
                title="Cosmos DB using connection string instead of Managed Identity",
                description="CosmosClient instantiated with connection string. FedRAMP 20x requires passwordless authentication using Managed Identity for Azure services per Azure Security Benchmark.",
                file_path=file_path,
                line_number=connection_string_lines[0] if connection_string_lines else None,
                recommendation="""Use Managed Identity for Cosmos DB authentication:
```csharp
// ❌ DON'T: Connection string authentication
var client = new CosmosClient(configuration["CosmosDb:ConnectionString"]);

// ✅ DO: Managed Identity authentication
var credential = new DefaultAzureCredential();
var client = new CosmosClient(
    accountEndpoint: "https://your-account.documents.azure.com:443/",
    tokenCredential: credential
);

// Configure in Program.cs
builder.Services.AddSingleton<CosmosClient>(sp =>
{
    var credential = new DefaultAzureCredential();
    return new CosmosClient(
        accountEndpoint: builder.Configuration["CosmosDb:AccountEndpoint"],
        tokenCredential: credential
    );
});
```

**RBAC Assignment Required:**
```bash
# Assign Cosmos DB Built-in Data Contributor role to managed identity
az cosmosdb sql role assignment create \\
  --account-name <cosmos-account> \\
  --resource-group <resource-group> \\
  --role-definition-name "Cosmos DB Built-in Data Contributor" \\
  --principal-id <managed-identity-principal-id> \\
  --scope "/"
```

Source: Azure Cosmos DB Managed Identity (https://learn.microsoft.com/azure/cosmos-db/how-to-setup-rbac), Azure Security Benchmark - IM-1 (https://learn.microsoft.com/security/benchmark/azure/mcsb-identity-management#im-1-use-centralized-identity-and-authentication-system)"""
            ))
        elif has_managed_identity and "CosmosClient" in code:
            # Good practice detected
            line_num = code.find("DefaultAzureCredential")
            if line_num != -1:
                line_num = code[:line_num].count('\n') + 1
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.INFO,
                title="Cosmos DB using Managed Identity authentication",
                description="CosmosClient configured with DefaultAzureCredential for passwordless authentication. Follows FedRAMP 20x identity management requirements.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure the managed identity has least-privilege RBAC roles (Cosmos DB Built-in Data Reader/Contributor) and not account-level keys.",
                good_practice=True
            ))
    
    def _check_service_bus_security(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect insecure Service Bus connection patterns (KSI-IAM-02).
        
        Checks for:
        - Connection strings in code (should use Managed Identity)
        - ServiceBusClient instantiation patterns
        - DefaultAzureCredential usage (good practice)
        """
        has_managed_identity = "DefaultAzureCredential" in code or "ManagedIdentityCredential" in code
        has_connection_string = False
        connection_string_lines = []
        
        def find_service_bus_patterns(node):
            nonlocal has_connection_string
            
            if node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node:
                    type_text = self.code_bytes[type_node.start_byte:type_node.end_byte].decode('utf8')
                    
                    if "ServiceBusClient" in type_text or "ServiceBusSender" in type_text or "ServiceBusReceiver" in type_text:
                        args_node = node.child_by_field_name("arguments")
                        if args_node:
                            args_text = self.code_bytes[args_node.start_byte:args_node.end_byte].decode('utf8')
                            
                            # Check if using connection string
                            if ('"' in args_text or "connectionString" in args_text.lower() or 
                                "GetConnectionString" in args_text or "ServiceBus:ConnectionString" in args_text):
                                
                                if "DefaultAzureCredential" not in args_text and "TokenCredential" not in args_text:
                                    has_connection_string = True
                                    line_num = node.start_point[0] + 1
                                    connection_string_lines.append(line_num)
            
            for child in node.children:
                find_service_bus_patterns(child)
        
        find_service_bus_patterns(root_node)
        
        if has_connection_string and not has_managed_identity:
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.HIGH,
                title="Service Bus using connection string instead of Managed Identity",
                description="ServiceBusClient instantiated with connection string. FedRAMP 20x requires passwordless authentication using Managed Identity per Azure Security Benchmark.",
                file_path=file_path,
                line_number=connection_string_lines[0] if connection_string_lines else None,
                recommendation="""Use Managed Identity for Service Bus authentication:
```csharp
// ❌ DON'T: Connection string authentication
var client = new ServiceBusClient(configuration["ServiceBus:ConnectionString"]);

// ✅ DO: Managed Identity authentication
var credential = new DefaultAzureCredential();
var client = new ServiceBusClient(
    fullyQualifiedNamespace: "your-namespace.servicebus.windows.net",
    credential: credential
);

// Configure in Program.cs
builder.Services.AddSingleton<ServiceBusClient>(sp =>
{
    var credential = new DefaultAzureCredential();
    return new ServiceBusClient(
        fullyQualifiedNamespace: builder.Configuration["ServiceBus:Namespace"],
        credential: credential
    );
});
```

**RBAC Assignment Required:**
```bash
# Assign Azure Service Bus Data Sender/Receiver role
az role assignment create \\
  --role "Azure Service Bus Data Sender" \\
  --assignee <managed-identity-principal-id> \\
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ServiceBus/namespaces/<namespace>
```

Source: Service Bus Managed Identity (https://learn.microsoft.com/azure/service-bus-messaging/service-bus-managed-service-identity), Azure Security Benchmark - IM-1"""
            ))
        elif has_managed_identity and "ServiceBusClient" in code:
            line_num = code.find("DefaultAzureCredential")
            if line_num != -1:
                line_num = code[:line_num].count('\n') + 1
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.INFO,
                title="Service Bus using Managed Identity authentication",
                description="ServiceBusClient configured with DefaultAzureCredential. Follows FedRAMP 20x passwordless authentication requirements.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure RBAC roles are scoped to specific queues/topics (not namespace-wide) for least privilege.",
                good_practice=True
            ))
    
    def _check_azure_storage_security(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Detect insecure Azure Storage access patterns (KSI-IAM-02, SVC-06).
        
        Checks for:
        - Account keys in code (should use Managed Identity)
        - SAS tokens without user delegation
        - BlobServiceClient instantiation patterns
        """
        has_managed_identity = "DefaultAzureCredential" in code or "ManagedIdentityCredential" in code
        has_account_key = False
        has_sas_token = False
        account_key_lines = []
        sas_token_lines = []
        
        def find_storage_patterns(node):
            nonlocal has_account_key, has_sas_token
            
            if node.type == "object_creation_expression":
                type_node = node.child_by_field_name("type")
                if type_node:
                    type_text = self.code_bytes[type_node.start_byte:type_node.end_byte].decode('utf8')
                    
                    if "BlobServiceClient" in type_text or "BlobContainerClient" in type_text or "BlobClient" in type_text:
                        args_node = node.child_by_field_name("arguments")
                        if args_node:
                            args_text = self.code_bytes[args_node.start_byte:args_node.end_byte].decode('utf8')
                            
                            # Check for account key usage
                            if ("AccountKey" in args_text or "connectionString" in args_text.lower() or 
                                "GetConnectionString" in args_text or "Storage:ConnectionString" in args_text):
                                
                                if "DefaultAzureCredential" not in args_text and "TokenCredential" not in args_text:
                                    has_account_key = True
                                    line_num = node.start_point[0] + 1
                                    account_key_lines.append(line_num)
                            
                            # Check for SAS token usage
                            if ("sasToken" in args_text or "SharedAccessSignature" in args_text or 
                                "?sv=" in args_text or "sig=" in args_text):
                                
                                # Check if it's user delegation SAS (good) vs account SAS (bad)
                                if "UserDelegationKey" not in code:
                                    has_sas_token = True
                                    line_num = node.start_point[0] + 1
                                    sas_token_lines.append(line_num)
            
            for child in node.children:
                find_storage_patterns(child)
        
        find_storage_patterns(root_node)
        
        if has_account_key and not has_managed_identity:
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.HIGH,
                title="Azure Storage using account key instead of Managed Identity",
                description="BlobServiceClient instantiated with connection string or account key. FedRAMP 20x requires passwordless authentication using Managed Identity per Azure Security Benchmark.",
                file_path=file_path,
                line_number=account_key_lines[0] if account_key_lines else None,
                recommendation="""Use Managed Identity for Azure Storage authentication:
```csharp
// ❌ DON'T: Account key authentication
var client = new BlobServiceClient(configuration["Storage:ConnectionString"]);

// ✅ DO: Managed Identity authentication
var credential = new DefaultAzureCredential();
var client = new BlobServiceClient(
    new Uri("https://youraccount.blob.core.windows.net"),
    credential
);

// Configure in Program.cs
builder.Services.AddSingleton<BlobServiceClient>(sp =>
{
    var credential = new DefaultAzureCredential();
    return new BlobServiceClient(
        new Uri(builder.Configuration["Storage:BlobEndpoint"]),
        credential
    );
});
```

**RBAC Assignment Required:**
```bash
# Assign Storage Blob Data Contributor role
az role assignment create \\
  --role "Storage Blob Data Contributor" \\
  --assignee <managed-identity-principal-id> \\
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>
```

**Rotate account keys immediately** and disable Shared Key authorization:
```bash
az storage account update \\
  --name <account> \\
  --resource-group <rg> \\
  --allow-shared-key-access false
```

Source: Azure Storage Managed Identity (https://learn.microsoft.com/azure/storage/blobs/authorize-access-azure-active-directory), Azure Security Benchmark - IM-1"""
            ))
        
        if has_sas_token:
            self.add_finding(Finding(
                requirement_id="KSI-SVC-06",
                severity=Severity.MEDIUM,
                title="Azure Storage using account SAS token (consider user delegation SAS)",
                description="Detected account-based SAS token usage. FedRAMP 20x recommends user delegation SAS (backed by Entra ID) over account keys per Azure Security Benchmark.",
                file_path=file_path,
                line_number=sas_token_lines[0] if sas_token_lines else None,
                recommendation="""Use user delegation SAS tokens for temporary access:
```csharp
// Generate user delegation SAS (secured by Entra ID, not account key)
var credential = new DefaultAzureCredential();
var blobServiceClient = new BlobServiceClient(
    new Uri("https://youraccount.blob.core.windows.net"),
    credential
);

// Get user delegation key (valid for up to 7 days)
UserDelegationKey userDelegationKey = await blobServiceClient
    .GetUserDelegationKeyAsync(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1));

// Create user delegation SAS
BlobSasBuilder sasBuilder = new BlobSasBuilder()
{
    BlobContainerName = "container-name",
    BlobName = "blob-name",
    Resource = "b", // "b" for blob, "c" for container
    StartsOn = DateTimeOffset.UtcNow,
    ExpiresOn = DateTimeOffset.UtcNow.AddHours(1),
    Protocol = SasProtocol.Https // HTTPS only
};

sasBuilder.SetPermissions(BlobSasPermissions.Read);

BlobUriBuilder blobUriBuilder = new BlobUriBuilder(blobClient.Uri)
{
    Sas = sasBuilder.ToSasQueryParameters(userDelegationKey, blobServiceClient.AccountName)
};

string sasUrl = blobUriBuilder.ToUri().ToString();
```

**Benefits of user delegation SAS:**
- No account key exposure
- Revocable via Entra ID (disable service principal)
- Auditable in Entra ID logs
- Supports ABAC/RBAC conditions

Source: User Delegation SAS (https://learn.microsoft.com/azure/storage/blobs/storage-blob-user-delegation-sas-create-dotnet), Azure WAF Security pillar"""
            ))
        
        if has_managed_identity and ("BlobServiceClient" in code or "BlobContainerClient" in code):
            line_num = code.find("DefaultAzureCredential")
            if line_num != -1:
                line_num = code[:line_num].count('\n') + 1
            
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.INFO,
                title="Azure Storage using Managed Identity authentication",
                description="BlobServiceClient configured with DefaultAzureCredential. Follows FedRAMP 20x passwordless authentication requirements.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Consider disabling Shared Key access at storage account level for additional security: az storage account update --allow-shared-key-access false",
                good_practice=True
            ))
    
    def _check_key_vault_integration(self, code: str, file_path: str, root_node: TreeSitterNode) -> None:
        """
        Check Key Vault integration patterns (KSI-SVC-06).
        
        Checks for:
        - SecretClient with Managed Identity (good practice)
        - Direct secret access patterns
        - Configuration integration
        """
        has_key_vault = "SecretClient" in code or "KeyClient" in code or "CertificateClient" in code
        has_managed_identity = "DefaultAzureCredential" in code or "ManagedIdentityCredential" in code
        has_config_integration = "AddAzureKeyVault" in code or "ConfigureKeyVault" in code
        
        if has_key_vault and not has_managed_identity:
            self.add_finding(Finding(
                requirement_id="KSI-SVC-06",
                severity=Severity.HIGH,
                title="Key Vault client without Managed Identity",
                description="SecretClient instantiated without DefaultAzureCredential. FedRAMP 20x requires Managed Identity for Key Vault access per Azure Security Benchmark.",
                file_path=file_path,
                line_number=None,
                recommendation="""Use Managed Identity for Key Vault access:
```csharp
// ❌ DON'T: Client secret credential
var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);

// ✅ DO: Managed Identity
var credential = new DefaultAzureCredential();
var client = new SecretClient(
    new Uri("https://your-vault.vault.azure.net"),
    credential
);

// ✅ BETTER: Integrate with configuration system
builder.Configuration.AddAzureKeyVault(
    new Uri("https://your-vault.vault.azure.net"),
    new DefaultAzureCredential()
);

// Access secrets through IConfiguration
var connectionString = builder.Configuration["CosmosDb--ConnectionString"]; // Note: -- not :
```

**RBAC Assignment Required:**
```bash
# Assign Key Vault Secrets User role (read-only)
az role assignment create \\
  --role "Key Vault Secrets User" \\
  --assignee <managed-identity-principal-id> \\
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>
```

Source: Key Vault Managed Identity (https://learn.microsoft.com/azure/key-vault/general/authentication), Azure Security Benchmark - IM-1"""
            ))
        elif has_config_integration and has_managed_identity:
            line_num = code.find("AddAzureKeyVault")
            if line_num != -1:
                line_num = code[:line_num].count('\n') + 1
            
            self.add_finding(Finding(
                requirement_id="KSI-SVC-06",
                severity=Severity.INFO,
                title="Key Vault integrated with configuration system",
                description="AddAzureKeyVault with DefaultAzureCredential detected. Follows FedRAMP 20x secrets management best practices.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use Key Vault Secrets User role (not Key Vault Administrator) for least privilege. Enable soft delete and purge protection on vault.",
                good_practice=True
            ))
        elif has_key_vault and has_managed_identity and not has_config_integration:
            # Using SecretClient directly (less ideal but acceptable)
            line_num = code.find("SecretClient")
            if line_num != -1:
                line_num = code[:line_num].count('\n') + 1
            
            self.add_finding(Finding(
                requirement_id="KSI-SVC-06",
                severity=Severity.INFO,
                title="Key Vault using Managed Identity (consider configuration integration)",
                description="SecretClient configured with DefaultAzureCredential. Consider using AddAzureKeyVault for seamless IConfiguration integration.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Integrate Key Vault with configuration system using AddAzureKeyVault() for automatic secret updates and simplified access pattern.",
                good_practice=True
            ))
    
    def _extract_middleware_pipeline(self, tree_node) -> List[Dict]:
        """
        Extract middleware configuration from Configure or Program.cs startup code.
        Returns list of middleware call info: {name, line_number, arguments}
        """
        middleware_calls = []
        
        def visit(node):
            # Look for invocation_expression nodes like app.UseHttpsRedirection()
            if node.type == "invocation_expression":
                # Check if it's a member access (app.Use...)
                for child in node.children:
                    if child.type == "member_access_expression":
                        # Get the method name
                        method_name = None
                        for member_child in child.children:
                            if member_child.type == "identifier":
                                method_name = self.code_bytes[member_child.start_byte:member_child.end_byte].decode('utf8')
                        
                        if method_name and method_name.startswith("Use"):
                            line_number = self.get_line_number(self.code_bytes.decode('utf8'), method_name)
                            
                            # Extract arguments if present
                            arguments = []
                            arg_list_node = next((c for c in node.children if c.type == "argument_list"), None)
                            if arg_list_node:
                                for arg in arg_list_node.children:
                                    if arg.type == "argument":
                                        arg_text = self.code_bytes[arg.start_byte:arg.end_byte].decode('utf8')
                                        arguments.append(arg_text)
                            
                            middleware_calls.append({
                                "name": method_name,
                                "line_number": line_number,
                                "arguments": arguments
                            })
            
            # Recursively visit children
            for child in node.children:
                visit(child)
        
        visit(tree_node)
        return middleware_calls
    
    def _check_middleware_ordering(self, middleware_calls: List[Dict]) -> List[str]:
        """
        Check if middleware is in correct security order.
        Returns list of ordering issues found.
        """
        issues = []
        
        # Build middleware sequence
        middleware_sequence = [m["name"] for m in middleware_calls]
        
        # Security-critical ordering rules
        # 1. UseAuthentication must come before UseAuthorization
        auth_index = next((i for i, m in enumerate(middleware_sequence) if m == "UseAuthentication"), -1)
        authz_index = next((i for i, m in enumerate(middleware_sequence) if m == "UseAuthorization"), -1)
        
        if authz_index != -1 and auth_index == -1:
            issues.append("UseAuthorization present but UseAuthentication is missing")
        elif auth_index != -1 and authz_index != -1 and auth_index > authz_index:
            issues.append("UseAuthentication must be called before UseAuthorization")
        
        # 2. UseHttpsRedirection should come early
        https_index = next((i for i, m in enumerate(middleware_sequence) if m == "UseHttpsRedirection"), -1)
        if https_index == -1:
            issues.append("UseHttpsRedirection is missing")
        elif https_index > 5:  # Should be in first few middleware
            issues.append("UseHttpsRedirection should be called earlier in the pipeline")
        
        # 3. UseHsts should be present for production
        hsts_index = next((i for i, m in enumerate(middleware_sequence) if m == "UseHsts"), -1)
        if hsts_index == -1:
            issues.append("UseHsts is missing (should be conditional on !Development)")
        
        return issues
    
    def _analyze_cors_policy(self, code: str, middleware_calls: List[Dict]) -> Dict:
        """
        Analyze CORS configuration for security issues.
        Returns dict with {has_cors, is_permissive, policy_name, line_number}
        """
        cors_info = {
            "has_cors": False,
            "is_permissive": False,
            "policy_name": None,
            "line_number": None
        }
        
        # Check for UseCors calls
        cors_calls = [m for m in middleware_calls if m["name"] == "UseCors"]
        if cors_calls:
            cors_info["has_cors"] = True
            cors_call = cors_calls[0]
            cors_info["line_number"] = cors_call["line_number"]
            
            if cors_call["arguments"]:
                policy_arg = cors_call["arguments"][0]
                cors_info["policy_name"] = policy_arg.strip('"')
        
        # Check for permissive CORS patterns in code
        # AllowAnyOrigin, WithOrigins("*"), etc.
        if re.search(r"AllowAnyOrigin\(\)", code):
            cors_info["is_permissive"] = True
        elif re.search(r'WithOrigins\s*\(\s*["\']?\*["\']?\s*\)', code):
            cors_info["is_permissive"] = True
        elif re.search(r"UseCors\s*\(\s*[\"']?\*[\"']?", code):
            cors_info["is_permissive"] = True
        
        return cors_info
    
    def _check_secure_coding_practices_ast(self, code: str, file_path: str, tree_node) -> None:
        """
        AST-enhanced check for secure coding practices (KSI-SVC-07).
        
        Tier 1.3 enhancements:
        - Semantic middleware pipeline extraction and ordering validation
        - CORS policy configuration analysis
        - Security header detection with configuration details
        - Middleware argument parsing for policy validation
        """
        # Extract middleware pipeline
        middleware_calls = self._extract_middleware_pipeline(tree_node)
        
        if not middleware_calls:
            # No middleware configuration found - might be in a different file
            # Don't report as error since this could be a model/service file
            return
        
        # Check middleware ordering
        ordering_issues = self._check_middleware_ordering(middleware_calls)
        
        if ordering_issues:
            # Report ordering issues as HIGH severity
            line_num = middleware_calls[0]["line_number"] if middleware_calls else 1
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.HIGH,
                title="Incorrect security middleware ordering",
                description=f"Security middleware configuration issues detected: {'; '.join(ordering_issues)}. FedRAMP 20x requires proper security middleware ordering per Azure WAF Security pillar.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Configure middleware in correct security order:\n```csharp\nvar app = builder.Build();\n\n// 1. HTTPS redirection (early in pipeline)\nif (!app.Environment.IsDevelopment())\n{\n    app.UseHsts();  // HTTP Strict Transport Security\n}\napp.UseHttpsRedirection();\n\n// 2. Static files (if needed)\napp.UseStaticFiles();\n\n// 3. Routing\napp.UseRouting();\n\n// 4. CORS (before auth)\napp.UseCors(\"AllowedOrigins\");\n\n// 5. Authentication (MUST come before Authorization)\napp.UseAuthentication();\n\n// 6. Authorization\napp.UseAuthorization();\n\n// 7. Endpoints\napp.MapControllers();\n```\nSource: Azure WAF Security - ASP.NET Core Security (https://learn.microsoft.com/aspnet/core/security/)"
            ))
        
        # Analyze CORS configuration
        cors_info = self._analyze_cors_policy(code, middleware_calls)
        
        if cors_info["is_permissive"]:
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.MEDIUM,
                title="Overly permissive CORS policy",
                description="CORS configuration allows any origin (*) or uses AllowAnyOrigin(). FedRAMP 20x requires restricted cross-origin access per Azure Security Benchmark.",
                file_path=file_path,
                line_number=cors_info["line_number"],
                recommendation="Restrict CORS to specific trusted origins:\n```csharp\nbuilder.Services.AddCors(options =>\n{\n    options.AddPolicy(\"AllowedOrigins\", policy =>\n    {\n        policy.WithOrigins(\n                \"https://yourdomain.com\",\n                \"https://app.yourdomain.com\"\n            )\n            .AllowAnyHeader()\n            .AllowAnyMethod()\n            .AllowCredentials();  // Required for auth cookies\n    });\n});\n\napp.UseCors(\"AllowedOrigins\");\n```\nSource: Azure Security Benchmark - CORS Configuration (https://learn.microsoft.com/azure/security/fundamentals/network-best-practices)"
            ))
        
        # Check for proper HTTPS enforcement (good practice)
        has_https_redirect = any(m["name"] == "UseHttpsRedirection" for m in middleware_calls)
        has_hsts = any(m["name"] == "UseHsts" for m in middleware_calls)
        has_auth = any(m["name"] == "UseAuthentication" for m in middleware_calls)
        has_authz = any(m["name"] == "UseAuthorization" for m in middleware_calls)
        
        if has_https_redirect and has_hsts and has_auth and has_authz and not ordering_issues:
            line_num = middleware_calls[0]["line_number"]
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.INFO,
                title="Security middleware properly configured",
                description="Application has proper HTTPS enforcement, HSTS, authentication, and authorization middleware in correct order.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure HSTS max-age is set to at least 1 year (31536000 seconds) per Azure WAF recommendations.",
                good_practice=True
            ))
    
    def _extract_sensitive_operations(self, method_node) -> List[Dict]:
        """
        Extract sensitive database/data operations from method body.
        Returns list of {operation_type, line_number, method_call}
        """
        sensitive_ops = []
        
        def visit(node):
            if node.type == "invocation_expression":
                # Get the method being called
                method_text = self.code_bytes[node.start_byte:node.end_byte].decode('utf8')
                
                # Database operations
                if any(keyword in method_text for keyword in ["SaveChanges", "ExecuteSql", "FromSql", "Delete", "Remove", "Update"]):
                    line_num = self.get_line_number(self.code_bytes.decode('utf8'), method_text[:50])
                    sensitive_ops.append({
                        "operation_type": "database_write",
                        "line_number": line_num,
                        "method_call": method_text[:100]
                    })
                
                # File operations
                elif any(keyword in method_text for keyword in ["File.Delete", "File.Write", "Directory.Delete"]):
                    line_num = self.get_line_number(self.code_bytes.decode('utf8'), method_text[:50])
                    sensitive_ops.append({
                        "operation_type": "file_operation",
                        "line_number": line_num,
                        "method_call": method_text[:100]
                    })
                
                # HTTP calls to external services
                elif any(keyword in method_text for keyword in ["HttpClient", "SendAsync", "PostAsync", "PutAsync", "DeleteAsync"]):
                    line_num = self.get_line_number(self.code_bytes.decode('utf8'), method_text[:50])
                    sensitive_ops.append({
                        "operation_type": "http_call",
                        "line_number": line_num,
                        "method_call": method_text[:100]
                    })
            
            for child in node.children:
                visit(child)
        
        visit(method_node)
        return sensitive_ops
    
    def _has_inline_authorization_check(self, method_node) -> bool:
        """
        Check if method body contains inline authorization checks.
        Looks for User.IsInRole(), User.HasClaim(), etc.
        """
        method_text = self.code_bytes[method_node.start_byte:method_node.end_byte].decode('utf8')
        
        # Check for inline authorization patterns
        auth_patterns = [
            r"User\.IsInRole\(",
            r"User\.HasClaim\(",
            r"User\.Identity\.Name",
            r"HttpContext\.User",
            r"_authorizationService\.AuthorizeAsync\(",
            r"if\s*\(\s*!User\.",
            r"return\s+Unauthorized\(",
            r"return\s+Forbid\("
        ]
        
        return any(re.search(pattern, method_text) for pattern in auth_patterns)
    
    def _check_least_privilege_authorization_ast(self, code: str, file_path: str, classes: List[Dict]) -> None:
        """
        AST-enhanced check for least privilege authorization (KSI-IAM-04).
        
        Tier 2.1 enhancements:
        - Identifies sensitive operations (database writes, file ops, HTTP calls)
        - Verifies authorization checks before sensitive operations
        - Detects [Authorize] without Roles or Policy (overly broad)
        - Tracks inline authorization checks (User.IsInRole, etc.)
        - Control flow analysis for authorization enforcement
        """
        for class_info in classes:
            # Only analyze controllers
            if not any(base in class_info["base_classes"] for base in ["Controller", "ControllerBase"]):
                continue
            
            class_has_auth = any("Authorize" in attr for attr in class_info["attributes"])
            
            for method in class_info["methods"]:
                # Check if method has HTTP attributes (GET, POST, etc.)
                is_endpoint = any(attr in ["HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch"]
                                 for attr in method["attributes"])
                
                if not is_endpoint:
                    continue
                
                # Extract authorization attributes
                method_authorize_attrs = [attr for attr in method["attributes"] if "Authorize" in attr]
                has_method_auth = len(method_authorize_attrs) > 0
                has_any_auth = class_has_auth or has_method_auth
                
                # Check for [AllowAnonymous]
                has_allow_anon = any("AllowAnonymous" in attr for attr in method["attributes"])
                
                # Extract sensitive operations from method body
                sensitive_ops = self._extract_sensitive_operations(method["node"])
                
                # Check for inline authorization
                has_inline_auth = self._has_inline_authorization_check(method["node"])
                
                # Issue 1: Sensitive operations without ANY authorization (HIGH)
                if sensitive_ops and not has_any_auth and not has_inline_auth and not has_allow_anon:
                    line_num = self._get_line_from_node(method["node"])
                    ops_summary = f"{len(sensitive_ops)} sensitive operation(s): " + ", ".join(set([op['operation_type'] for op in sensitive_ops]))
                    
                    self.add_finding(Finding(
                        requirement_id="KSI-IAM-04",
                        severity=Severity.HIGH,
                        title=f"Sensitive operations in {method['name']} without authorization",
                        description=f"Controller method performs {ops_summary} without [Authorize] attribute or inline authorization checks. FedRAMP 20x requires least privilege access control per Azure Security Benchmark.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Add authorization to method or class:\n```csharp\n// Option 1: Method-level with policy\n[HttpPost]\n[Authorize(Policy = \"RequireAdminRole\")]\npublic async Task<IActionResult> DeleteUser(int id)\n{\n    await _db.Users.Remove(user);\n    await _db.SaveChangesAsync();\n    return Ok();\n}\n\n// Option 2: Inline authorization check\n[HttpPost]\n[Authorize]\npublic async Task<IActionResult> DeleteUser(int id)\n{\n    if (!User.IsInRole(\"Admin\"))\n        return Forbid();\n    \n    await _db.Users.Remove(user);\n    await _db.SaveChangesAsync();\n    return Ok();\n}\n```\nSource: Azure Security Benchmark - Identity and Access Control (https://learn.microsoft.com/security/benchmark/azure/mcsb-identity-management)"
                    ))
                
                # Issue 2: [Authorize] without Roles or Policy (MEDIUM) - but skip if inline auth present
                elif has_method_auth and sensitive_ops:
                    # Check if authorize attribute has roles or policy
                    has_roles_or_policy = any(
                        "Roles" in attr or "Policy" in attr 
                        for attr in method_authorize_attrs
                    )
                    
                    # If inline auth is present, this is good practice, not an issue
                    if not has_roles_or_policy and not has_inline_auth:
                        line_num = self._get_line_from_node(method["node"])
                        ops_summary = ", ".join(set([op['operation_type'] for op in sensitive_ops]))
                        
                        self.add_finding(Finding(
                            requirement_id="KSI-IAM-04",
                            severity=Severity.MEDIUM,
                            title=f"Overly permissive [Authorize] on {method['name']}",
                            description=f"Method performing {ops_summary} uses [Authorize] without Roles or Policy restrictions. Any authenticated user can access. FedRAMP 20x requires least privilege principle.",
                            file_path=file_path,
                            line_number=line_num,
                            recommendation="Add role-based or policy-based authorization:\n```csharp\n// Option 1: Role-based\n[HttpDelete(\"{id}\")]\n[Authorize(Roles = \"Admin,SuperUser\")]\npublic async Task<IActionResult> DeleteResource(int id)\n{\n    // Only Admin or SuperUser can delete\n}\n\n// Option 2: Policy-based (recommended)\n[HttpPost]\n[Authorize(Policy = \"RequireWritePermission\")]\npublic async Task<IActionResult> CreateResource(ResourceModel model)\n{\n    // Policy defined in Program.cs:\n    // options.AddPolicy(\"RequireWritePermission\", policy =>\n    //     policy.RequireClaim(\"permission\", \"write\"));\n}\n```\nSource: ASP.NET Core Authorization (https://learn.microsoft.com/aspnet/core/security/authorization/roles)"
                        ))
                    elif has_inline_auth:
                        # Inline auth makes this good practice
                        line_num = self._get_line_from_node(method["node"])
                        
                        self.add_finding(Finding(
                            requirement_id="KSI-IAM-04",
                            severity=Severity.INFO,
                            title=f"Proper least privilege authorization on {method['name']}",
                            description=f"Method with sensitive operations correctly implements inline authorization checks. Follows FedRAMP 20x least privilege principle.",
                            file_path=file_path,
                            line_number=line_num,
                            recommendation="Consider using policy-based authorization for complex scenarios: https://learn.microsoft.com/aspnet/core/security/authorization/policies",
                            good_practice=True
                        ))
                
                # Issue 3: AllowAnonymous on sensitive operations (HIGH)
                elif has_allow_anon and sensitive_ops:
                    line_num = self._get_line_from_node(method["node"])
                    ops_summary = ", ".join(set([op['operation_type'] for op in sensitive_ops]))
                    
                    self.add_finding(Finding(
                        requirement_id="KSI-IAM-04",
                        severity=Severity.HIGH,
                        title=f"[AllowAnonymous] on sensitive method {method['name']}",
                        description=f"Method performing {ops_summary} allows anonymous access via [AllowAnonymous]. This bypasses authorization entirely. FedRAMP 20x prohibits unauthenticated access to sensitive operations.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Remove [AllowAnonymous] and add proper authorization:\n```csharp\n// REMOVE:\n// [AllowAnonymous]\n\n// ADD:\n[HttpPost]\n[Authorize(Policy = \"RequireAdminRole\")]\npublic async Task<IActionResult> DeleteUser(int id)\n{\n    // Sensitive operation now requires authorization\n}\n```"
                    ))
                
                # Good Practice: Proper authorization with roles/policy
                elif has_any_auth and sensitive_ops:
                    has_specific_auth = any(
                        "Roles" in attr or "Policy" in attr 
                        for attr in method_authorize_attrs
                    ) or has_inline_auth
                    
                    if has_specific_auth:
                        line_num = self._get_line_from_node(method["node"])
                        auth_type = "inline authorization checks" if has_inline_auth else "role/policy-based authorization"
                        
                        self.add_finding(Finding(
                            requirement_id="KSI-IAM-04",
                            severity=Severity.INFO,
                            title=f"Proper least privilege authorization on {method['name']}",
                            description=f"Method with sensitive operations correctly implements {auth_type}. Follows FedRAMP 20x least privilege principle.",
                            file_path=file_path,
                            line_number=line_num,
                            recommendation="Consider using policy-based authorization for complex scenarios: https://learn.microsoft.com/aspnet/core/security/authorization/policies",
                            good_practice=True
                        ))
    
    # ========================================================================
    # Tier 2.2: Session Management (KSI-IAM-07) - AST-enhanced
    # ========================================================================
    
    def _extract_cookie_options(self, node) -> Dict[str, Any]:
        """Extract cookie configuration options from AST node.
        
        Parses lambda expressions like:
        options => { options.Cookie.HttpOnly = true; ... }
        
        And object initializers like:
        new CookieOptions { HttpOnly = true, ... }
        """
        cookie_config: Dict[str, Any] = {
            "HttpOnly": None,
            "Secure": None,
            "SecurePolicy": None,
            "SameSite": None,
            "IdleTimeout": None,
            "ExpireTimeSpan": None,
        }
        
        def visit(n):
            # Look for assignment expressions
            if n.type == "assignment_expression":
                # Extract left side (property name)
                left_node = n.child_by_field_name("left")
                right_node = n.child_by_field_name("right")
                
                if left_node and right_node:
                    left_text = self.code_bytes[left_node.start_byte:left_node.end_byte].decode('utf8')
                    right_text = self.code_bytes[right_node.start_byte:right_node.end_byte].decode('utf8')
                    
                    # Check for Cookie properties - order matters! Check specific properties before general ones
                    if "SecurePolicy" in left_text:  # Check SecurePolicy BEFORE Secure
                        cookie_config["SecurePolicy"] = right_text
                    elif "SameSite" in left_text:
                        cookie_config["SameSite"] = right_text
                    elif "HttpOnly" in left_text:
                        cookie_config["HttpOnly"] = "true" in right_text.lower()
                    elif "Secure" in left_text and "SecurePolicy" not in left_text:  # Only match plain Secure, not SecurePolicy
                        cookie_config["Secure"] = "true" in right_text.lower()
                    elif "IdleTimeout" in left_text:
                        cookie_config["IdleTimeout"] = right_text
                    elif "ExpireTimeSpan" in left_text:
                        cookie_config["ExpireTimeSpan"] = right_text
            
            for child in n.children:
                visit(child)
        
        visit(node)
        return cookie_config
    
    def _check_session_management_ast(self, code: str, file_path: str, root_node) -> None:
        """AST-enhanced session management check (KSI-IAM-07).
        
        Analyzes cookie configuration objects for:
        - AddSession() with lambda configuration
        - ConfigureApplicationCookie() with lambda configuration
        - Cookie security flags: HttpOnly, Secure/SecurePolicy, SameSite
        - Session timeout configuration
        """
        session_configs = []
        
        def find_session_methods(node):
            """Find AddSession and ConfigureApplicationCookie invocations."""
            if node.type == "invocation_expression":
                # Get the method being called
                method_node = node.child_by_field_name("function")
                if method_node:
                    method_text = self.code_bytes[method_node.start_byte:method_node.end_byte].decode('utf8')
                    
                    if "AddSession" in method_text or "ConfigureApplicationCookie" in method_text:
                        # Found session configuration - extract arguments
                        args_node = node.child_by_field_name("arguments")
                        if args_node:
                            session_configs.append({
                                "method": method_text,
                                "line": node.start_point[0] + 1,  # tree-sitter uses 0-based indexing
                                "args_node": args_node
                            })
            
            for child in node.children:
                find_session_methods(child)
        
        find_session_methods(root_node)
        
        # Analyze each session configuration
        for config in session_configs:
            cookie_options = self._extract_cookie_options(config["args_node"])
            
            # Check for security issues
            issues = []
            
            # Issue 1: HttpOnly not set to true
            if cookie_options["HttpOnly"] is False:
                issues.append("HttpOnly is set to false (should be true)")
            elif cookie_options["HttpOnly"] is None:
                issues.append("HttpOnly flag not explicitly configured")
            
            # Issue 2: Secure/SecurePolicy not properly configured
            # Check if this is in a development environment context
            in_dev_context = self._is_development_environment_check(code)
            
            if cookie_options["Secure"] is False:
                if in_dev_context:
                    issues.append("Secure is set to false (acceptable in development - ensure production override exists)")
                else:
                    issues.append("Secure is set to false (should be true)")
            elif cookie_options["SecurePolicy"]:
                if "None" in cookie_options["SecurePolicy"]:
                    if in_dev_context:
                        issues.append("SecurePolicy is set to None (acceptable in development - ensure production override exists)")
                    else:
                        issues.append("SecurePolicy is set to None (should be Always)")
                elif "Always" not in cookie_options["SecurePolicy"] and "Required" not in cookie_options["SecurePolicy"]:
                    issues.append("SecurePolicy not set to Always or Required")
            elif cookie_options["Secure"] is None and cookie_options["SecurePolicy"] is None:
                issues.append("Secure/SecurePolicy flag not explicitly configured")
            
            # Issue 3: SameSite not configured or set incorrectly
            if cookie_options["SameSite"]:
                if "None" in cookie_options["SameSite"]:
                    issues.append("SameSite is set to None (should be Strict or Lax)")
            else:
                issues.append("SameSite flag not explicitly configured")
            
            # Issue 4: No timeout configuration
            if cookie_options["IdleTimeout"] is None and cookie_options["ExpireTimeSpan"] is None:
                issues.append("Session timeout not configured")
            
            if issues:
                # Report security issue
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.HIGH,
                    title="Insecure session cookie configuration",
                    description=f"Session configuration in {config['method']} has security issues: {'; '.join(issues)}. FedRAMP 20x requires secure session handling with HttpOnly, Secure, SameSite flags and appropriate timeout.",
                    file_path=file_path,
                    line_number=config["line"],
                    recommendation="""Configure secure session cookies per FedRAMP 20x requirements:
```csharp
// For session cookies
builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.IdleTimeout = TimeSpan.FromMinutes(20);
});

// For authentication cookies
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    options.SlidingExpiration = true;
});
```
Source: ASP.NET Core Security (https://learn.microsoft.com/aspnet/core/security/), Azure WAF Security pillar (https://learn.microsoft.com/azure/well-architected/security/)"""
                ))
            else:
                # All security flags properly configured - good practice
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.INFO,
                    title="Secure session management configured",
                    description=f"Session configuration in {config['method']} properly implements security flags (HttpOnly, Secure/SecurePolicy, SameSite) and timeout. Follows FedRAMP 20x session management requirements.",
                    file_path=file_path,
                    line_number=config["line"],
                    recommendation="Verify session timeout aligns with organizational security policy (typically 15-30 minutes for idle timeout).",
                    good_practice=True
                ))
    
    # ========================================================================
    # Tier 2.3: Logging Implementation (KSI-MLA-05) - AST-enhanced
    # ========================================================================
    
    def _extract_log_arguments(self, node) -> list:
        """Extract arguments from logging invocation.
        
        Returns list of argument texts being logged.
        """
        arguments = []
        
        def visit(n):
            if n.type == "argument":
                arg_text = self.code_bytes[n.start_byte:n.end_byte].decode('utf8')
                arguments.append(arg_text.strip())
            
            for child in n.children:
                visit(child)
        
        visit(node)
        return arguments
    
    def _contains_sensitive_data(self, text: str) -> tuple:
        """Check if text contains sensitive data patterns.
        
        Returns: (has_sensitive, sensitive_type)
        """
        sensitive_patterns = {
            "password": r'\b(password|pwd|passwd)\b',
            "token": r'\b(token|bearer|jwt)\b',
            "secret": r'\b(secret|apikey|api_key)\b',
            "credential": r'\b(credential|cred)\b',
            "ssn": r'\b(ssn|social.?security)\b',
            "credit_card": r'\b(card|credit.?card|cc)\b',
        }
        
        for sensitive_type, pattern in sensitive_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                return (True, sensitive_type)
        
        return (False, None)
    
    def _has_redaction_function(self, text: str) -> bool:
        """Check if text uses redaction/masking function."""
        redaction_patterns = [
            r'Redact\s*\(',
            r'Mask\s*\(',
            r'Sanitize\s*\(',
            r'Hash\s*\(',
            r'Encrypt\s*\(',
            r'\.Substring\(',  # Common redaction pattern
        ]
        
        for pattern in redaction_patterns:
            if re.search(pattern, text):
                return True
        
        return False
    
    def _check_logging_implementation_ast(self, code: str, file_path: str, root_node) -> None:
        """AST-enhanced logging implementation check (KSI-MLA-05).
        
        Analyzes:
        - Logging invocations and their arguments
        - Sensitive data in log statements
        - Redaction function usage
        - Structured logging patterns
        """
        log_invocations = []
        has_logger_field = False
        has_app_insights = False
        
        def find_logging(node):
            """Find logging invocations and logger fields."""
            nonlocal has_logger_field, has_app_insights
            
            if node.type == "field_declaration":
                field_text = self.code_bytes[node.start_byte:node.end_byte].decode('utf8')
                if "ILogger<" in field_text or "_logger" in field_text:
                    has_logger_field = True
                if "TelemetryClient" in field_text or "ApplicationInsights" in field_text:
                    has_app_insights = True
            
            if node.type == "invocation_expression":
                method_node = node.child_by_field_name("function")
                if method_node:
                    method_text = self.code_bytes[method_node.start_byte:method_node.end_byte].decode('utf8')
                    
                    # Check for logging methods
                    logging_methods = [
                        "LogInformation", "LogWarning", "LogError", "LogCritical", "LogDebug", "LogTrace",
                        "TrackEvent", "TrackException", "TrackTrace"
                    ]
                    
                    if any(method in method_text for method in logging_methods):
                        args_node = node.child_by_field_name("arguments")
                        arguments = self._extract_log_arguments(args_node) if args_node else []
                        
                        log_invocations.append({
                            "method": method_text,
                            "line": node.start_point[0] + 1,
                            "arguments": arguments,
                            "node": node
                        })
            
            for child in node.children:
                find_logging(child)
        
        find_logging(root_node)
        
        # Analyze logging invocations for sensitive data
        for log_call in log_invocations:
            # Combine all arguments for analysis
            all_args_text = " ".join(log_call["arguments"])
            
            has_sensitive, sensitive_type = self._contains_sensitive_data(all_args_text)
            has_redaction = self._has_redaction_function(all_args_text)
            
            if has_sensitive and not has_redaction:
                # HIGH severity: Logging sensitive data without redaction
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.HIGH,
                    title=f"Sensitive data ({sensitive_type}) in logs without redaction",
                    description=f"Logging statement contains {sensitive_type} without redaction. FedRAMP 20x requires audit logs without exposing sensitive information (PII, credentials, secrets).",
                    file_path=file_path,
                    line_number=log_call["line"],
                    recommendation="""Redact sensitive data before logging:
```csharp
// Redaction helper
public static class LogRedaction
{
    public static string RedactEmail(string email) =>
        string.IsNullOrEmpty(email) ? "***" : $"{email[..2]}***@{email.Split('@')[1]}";
    
    public static string RedactSensitive(string value) =>
        string.IsNullOrEmpty(value) || value.Length < 4 ? "***" : $"{value[..2]}***{value[^2..]}";
}

// Use structured logging with redaction
_logger.LogInformation("User action: {{Email}}, Result: {{Status}}", 
    LogRedaction.RedactEmail(user.Email), result.Status);
```
Source: Azure Monitor best practices (https://learn.microsoft.com/azure/azure-monitor/best-practices-logs), Azure WAF Security pillar (https://learn.microsoft.com/azure/well-architected/security/)"""
                ))
            elif has_sensitive and has_redaction:
                # Good practice: Sensitive data with redaction
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-05",
                    severity=Severity.INFO,
                    title="Proper sensitive data redaction in logs",
                    description=f"Logging statement properly redacts {sensitive_type}. Follows FedRAMP 20x secure logging requirements.",
                    file_path=file_path,
                    line_number=log_call["line"],
                    recommendation="Continue using redaction for all sensitive data in logs.",
                    good_practice=True
                ))
        
        # Check if logging is implemented at all
        if not has_logger_field and not log_invocations:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.MEDIUM,
                title="No logging implementation detected",
                description="No ILogger usage found in class. FedRAMP 20x requires comprehensive audit logging for security events, access attempts, and system changes.",
                file_path=file_path,
                line_number=1,
                recommendation="""Implement structured logging with dependency injection:
```csharp
using Microsoft.Extensions.Logging;

public class MyController : ControllerBase
{
    private readonly ILogger<MyController> _logger;
    
    public MyController(ILogger<MyController> logger)
    {
        _logger = logger;
    }
    
    [HttpPost]
    public IActionResult CreateResource(Resource resource)
    {
        _logger.LogInformation("Resource creation attempt: {{User}}, {{ResourceType}}", 
            User.Identity?.Name, resource.Type);
        
        try
        {
            var result = _service.Create(resource);
            _logger.LogInformation("Resource created: {{Id}}", result.Id);
            return Ok(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Resource creation failed: {{ResourceType}}", resource.Type);
            throw;
        }
    }
}
```
Source: ASP.NET Core Logging (https://learn.microsoft.com/aspnet/core/fundamentals/logging), Azure Application Insights (https://learn.microsoft.com/azure/azure-monitor/app/asp-net-core)"""
            ))
        elif has_app_insights:
            # Good practice: Application Insights configured
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.INFO,
                title="Application Insights telemetry configured",
                description="Application Insights integration detected. Provides centralized logging to Azure Monitor. Follows FedRAMP 20x centralized logging requirements.",
                file_path=file_path,
                line_number=1,
                recommendation="Ensure Application Insights is connected to Log Analytics workspace and integrated with Microsoft Sentinel for SIEM compliance.",
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
    
    def _get_line_from_node(self, node: TreeSitterNode) -> Optional[int]:
        """Get line number from AST node."""
        if node:
            return node.start_point[0] + 1  # tree-sitter uses 0-based indexing
        return None
    
    # ========================================================================
    # AST Helper Methods for Phase B
    # ========================================================================
    
    def _extract_method_name(self, invocation_node: TreeSitterNode) -> Optional[str]:
        """Extract method name from an invocation_expression node."""
        for child in invocation_node.children:
            if child.type == "member_access_expression":
                # Get the last identifier (method name)
                identifiers = [n for n in child.children if n.type == "identifier"]
                if identifiers:
                    return self.code_bytes[identifiers[-1].start_byte:identifiers[-1].end_byte].decode('utf8')
            elif child.type == "identifier":
                # Direct method call without member access
                return self.code_bytes[child.start_byte:child.end_byte].decode('utf8')
        return None
    
    def _extract_method_name_from_declaration(self, method_node: TreeSitterNode) -> Optional[str]:
        """Extract method name from a method_declaration node."""
        for child in method_node.children:
            if child.type == "identifier":
                return self.code_bytes[child.start_byte:child.end_byte].decode('utf8')
        return None
    
    def _extract_arguments_text(self, invocation_node: TreeSitterNode) -> Optional[str]:
        """Extract argument list text from an invocation_expression node."""
        for child in invocation_node.children:
            if child.type == "argument_list":
                return self.code_bytes[child.start_byte:child.end_byte].decode('utf8')
        return None
    
    # ========================================================================
    # Legacy Methods (keep for compatibility, can be enhanced)
    # ========================================================================
    
    def get_line_number(self, code: str, search_text: str) -> Optional[int]:
        """Get line number for search text (used by legacy methods)."""
        try:
            index = code.index(search_text)
            return code[:index].count('\n') + 1
        except ValueError:
            return None
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
        """Check for PII handling with framework detection."""
        # Check for Data Protection API usage
        usings = self._extract_usings(self.tree.root_node) if self.tree else set()
        has_data_protection = self._has_data_protection_api(code, usings)
        
        if re.search(r"(Ssn|SocialSecurityNumber)", code, re.IGNORECASE):
            if not re.search(r"(Encrypt|Protect|IDataProtector)", code, re.IGNORECASE):
                # Check if Data Protection API is configured elsewhere
                if has_data_protection:
                    self.add_finding(Finding(
                        requirement_id="KSI-PIY-02",
                        severity=Severity.LOW,
                        title="PII field detected - verify encryption",
                        description="Found PII field (SSN). Data Protection API is configured - verify it's used for this field.",
                        file_path=file_path,
                        line_number=None,
                        recommendation="Ensure IDataProtector is used to encrypt/decrypt this PII field before storage."
                    ))
                else:
                    self.add_finding(Finding(
                        requirement_id="KSI-PIY-02",
                        severity=Severity.MEDIUM,
                        title="Potential unprotected PII",
                        description="Found PII field without encryption. Data Protection API not detected.",
                        file_path=file_path,
                        line_number=None,
                        recommendation="Use ASP.NET Core Data Protection API for PII encryption:\n```csharp\nservices.AddDataProtection();\n\npublic class UserService\n{\n    private readonly IDataProtector _protector;\n    \n    public UserService(IDataProtectionProvider provider)\n    {\n        _protector = provider.CreateProtector(\"UserService.SSN\");\n    }\n    \n    public void SaveUser(User user)\n    {\n        user.EncryptedSsn = _protector.Protect(user.Ssn);\n    }\n}\n```"
                    ))
            else:
                # Good practice detected
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-02",
                    severity=Severity.INFO,
                    title="PII encryption detected",
                    description="PII field with encryption/protection mechanism.",
                    file_path=file_path,
                    line_number=None,
                    recommendation="Continue protecting PII with Data Protection API.",
                    good_practice=True
                ))

    def _check_logging(self, code: str, file_path: str) -> None:
        """Check for proper logging implementation with framework detection (KSI-MLA-05)."""
        # Check for logging usage
        has_logging = bool(re.search(r"(ILogger<|_logger\.|LogInformation|LogError|LogWarning)", code))
        
        # Framework detection: Check for Application Insights
        usings = self._extract_usings(self.tree.root_node) if self.tree else set()
        has_app_insights = self._has_application_insights(code, usings)
        
        # Check for potentially sensitive data in logs
        if has_logging:
            sensitive_in_logs = re.search(
                r'(LogInformation|LogError|LogWarning).*\(.*\{.*\}.*\)',
                code
            )
            
            if sensitive_in_logs:
                # Check if nearby code handles passwords, tokens, etc.
                context_start = max(0, sensitive_in_logs.start() - 200)
                context_end = min(len(code), sensitive_in_logs.end() + 200)
                context = code[context_start:context_end]
                
                if re.search(r"(password|token|secret|apikey)", context, re.IGNORECASE):
                    line_num = self.get_line_number(code, sensitive_in_logs.group(0))
                    self.add_finding(Finding(
                        requirement_id="KSI-MLA-05",
                        severity=Severity.MEDIUM,
                        title="Potential sensitive data in logs",
                        description="Logging statement near sensitive data. Ensure secrets are not logged. FedRAMP 20x requires audit logs without exposing sensitive information.",
                        file_path=file_path,
                        line_number=line_num,
                        recommendation="Redact sensitive data before logging:\n```csharp\npublic static string Redact(string sensitive)\n{\n    if (string.IsNullOrEmpty(sensitive) || sensitive.Length < 4)\n        return \"***\";\n    return $\"{sensitive.Substring(0, 2)}***{sensitive.Substring(sensitive.Length - 2)}\";\n}\n\n// Use structured logging with redaction\n_logger.LogInformation(\"User login: {{Email}}\", Redact(userEmail));\n```"
                    ))
        
        if not has_logging:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.MEDIUM,
                title="No logging implementation detected",
                description="No ILogger usage found. FedRAMP 20x requires comprehensive audit logging for security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement structured logging with Application Insights:\n```csharp\n// Program.cs\nbuilder.Logging.AddApplicationInsights();\nbuilder.Services.AddApplicationInsightsTelemetry();\n\n// Controller\npublic class ApiController : ControllerBase\n{\n    private readonly ILogger<ApiController> _logger;\n    \n    public ApiController(ILogger<ApiController> logger)\n    {\n        _logger = logger;\n    }\n    \n    [HttpGet]\n    public IActionResult GetData()\n    {\n        _logger.LogInformation(\"Data access request from {{User}}\", User.Identity?.Name);\n        return Ok();\n    }\n}\n```\nSource: Azure Application Insights for .NET (https://learn.microsoft.com/azure/azure-monitor/app/asp-net-core)"
            ))
        elif has_app_insights:
            line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "TelemetryClient")
            self.add_finding(Finding(
                requirement_id="KSI-MLA-05",
                severity=Severity.INFO,
                title="Application Insights logging configured",
                description="Application Insights telemetry enabled for centralized logging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure logs are sent to Log Analytics workspace and connected to Sentinel SIEM.",
                good_practice=True
            ))
    
    def _check_service_account_management(self, code: str, file_path: str) -> None:
        """Check for proper service account management (KSI-IAM-02)."""
        # Check for service principal or managed identity usage
        has_managed_identity = bool(re.search(r"DefaultAzureCredential|ManagedIdentityCredential|ChainedTokenCredential", code))
        
        # Check for hardcoded credentials (anti-pattern)
        has_hardcoded_creds = bool(re.search(r'ClientSecretCredential.*"[a-zA-Z0-9]{30,}"', code))
        
        if has_hardcoded_creds:
            line_num = self.get_line_number(code, "ClientSecretCredential")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.HIGH,
                title="Hardcoded service principal credentials detected",
                description="Client secret appears to be hardcoded. FedRAMP 20x requires managed identities for service authentication.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use managed identities instead of service principals:\n```csharp\n// Remove ClientSecretCredential with hardcoded secret\n// Use DefaultAzureCredential which automatically uses managed identity in Azure\nvar credential = new DefaultAzureCredential();\n\n// Or explicitly use managed identity\nvar credential = new ManagedIdentityCredential();\n\n// Works in Azure App Service, Azure Functions, AKS, VMs with system-assigned identity\n```\nSource: Azure Managed Identities (https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview)"
            ))
        elif has_managed_identity:
            line_num = self.get_line_number(code, "DefaultAzureCredential") or self.get_line_number(code, "ManagedIdentityCredential")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-02",
                severity=Severity.INFO,
                title="Managed identity authentication configured",
                description="Service uses DefaultAzureCredential or ManagedIdentityCredential for passwordless authentication.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure the managed identity has least-privilege RBAC assignments.",
                good_practice=True
            ))
    
    def _check_microservices_security(self, code: str, file_path: str) -> None:
        """Check for microservices security patterns (KSI-CNA-07)."""
        # Check for service-to-service authentication
        has_dapr = bool(re.search(r"Dapr\.|DaprClient|AddDapr", code))
        has_http_client = bool(re.search(r"HttpClient|IHttpClientFactory", code))
        
        if has_http_client and not has_dapr:
            # Check if DefaultAzureCredential is used for service calls
            has_auth_handler = bool(re.search(r"(AddHttpMessageHandler|DelegatingHandler|Bearer.*token)", code, re.IGNORECASE))
            
            if not has_auth_handler:
                line_num = self.get_line_number(code, "HttpClient")
                self.add_finding(Finding(
                    requirement_id="KSI-CNA-07",
                    severity=Severity.MEDIUM,
                    title="HttpClient without authentication handler",
                    description="Service-to-service calls should use managed identity and bearer tokens. FedRAMP 20x requires authenticated service communication.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add authentication to HttpClient:\n```csharp\n// Add Azure AD authentication to HttpClient\nservices.AddHttpClient<IMyService, MyService>(client =>\n{\n    client.BaseAddress = new Uri(\"https://api.example.com\");\n})\n.AddHttpMessageHandler<AuthenticationDelegatingHandler>();\n\n// Implement delegating handler\npublic class AuthenticationDelegatingHandler : DelegatingHandler\n{\n    private readonly TokenCredential _credential;\n    \n    protected override async Task<HttpResponseMessage> SendAsync(\n        HttpRequestMessage request, CancellationToken cancellationToken)\n    {\n        var token = await _credential.GetTokenAsync(\n            new TokenRequestContext(new[] { \"api://your-api/.default\" }));\n        request.Headers.Authorization = \n            new AuthenticationHeaderValue(\"Bearer\", token.Token);\n        return await base.SendAsync(request, cancellationToken);\n    }\n}\n```"
                ))
        elif has_dapr:
            line_num = self.get_line_number(code, "Dapr")
            self.add_finding(Finding(
                requirement_id="KSI-CNA-07",
                severity=Severity.INFO,
                title="Dapr service mesh configured",
                description="Using Dapr for service-to-service communication with built-in security.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure Dapr mTLS is enabled and service invocation uses access control policies.",
                good_practice=True
            ))
    
    def _check_error_handling(self, code: str, file_path: str) -> None:
        """Check for proper error handling (KSI-SVC-01)."""
        # Check for empty catch blocks
        empty_catch = re.search(r"catch\s*\([^)]*\)\s*\{\s*\}", code)
        
        if empty_catch:
            line_num = self.get_line_number(code, empty_catch.group(0))
            self.add_finding(Finding(
                requirement_id="KSI-SVC-01",
                severity=Severity.MEDIUM,
                title="Empty catch block detected",
                description="Empty catch block swallows exceptions without logging. FedRAMP 20x requires error logging for audit trails.",
                file_path=file_path,
                line_number=line_num,
                code_snippet=empty_catch.group(0),
                recommendation="Log exceptions and handle appropriately:\n```csharp\ntry\n{\n    // operation\n}\ncatch (Exception ex)\n{\n    _logger.LogError(ex, \"Operation failed: {{Operation}}\", \"operationName\");\n    throw; // or handle gracefully\n}\n```"
            ))
        
        # Check for generic exception catching
        generic_catch = re.search(r"catch\s*\(\s*Exception\s+\w+\s*\)", code)
        
        if generic_catch:
            # Check if it's near the top-level (acceptable for global error handling)
            context_before = code[:generic_catch.start()]
            if "Program" not in context_before and "Startup" not in context_before and "Middleware" not in context_before:
                line_num = self.get_line_number(code, generic_catch.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-SVC-01",
                    severity=Severity.LOW,
                    title="Generic exception handler detected",
                    description="Catching generic Exception hides specific error types. Consider catching specific exceptions.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Catch specific exceptions when possible:\n```csharp\ntry\n{\n    await database.SaveAsync();\n}\ncatch (DbUpdateException ex)\n{\n    _logger.LogError(ex, \"Database update failed\");\n    return StatusCode(500, \"Database error\");\n}\ncatch (ValidationException ex)\n{\n    _logger.LogWarning(ex, \"Validation failed\");\n    return BadRequest(ex.Message);\n}\n```"
                ))
    
    def _check_input_validation(self, code: str, file_path: str) -> None:
        """Check for input validation (KSI-SVC-02)."""
        # Check for data annotations
        has_validation = bool(re.search(r"\[(Required|StringLength|Range|RegularExpression|MaxLength|MinLength)\]", code))
        
        # Check for model binding in controllers
        has_model_binding = bool(re.search(r"\[FromBody\]|\[FromQuery\]|\[FromRoute\]", code))
        
        # Check for model state validation
        has_model_state_check = bool(re.search(r"ModelState\.IsValid", code))
        
        if has_model_binding and not (has_validation or has_model_state_check):
            line_num = self.get_line_number(code, "[FromBody]") or self.get_line_number(code, "[FromQuery]")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.MEDIUM,
                title="Model binding without validation",
                description="Controller accepts input without validation attributes or ModelState check. FedRAMP 20x requires input validation to prevent injection attacks.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add data annotations and validate ModelState:\n```csharp\npublic class CreateUserRequest\n{\n    [Required(ErrorMessage = \"Username is required\")]\n    [StringLength(50, MinimumLength = 3)]\n    [RegularExpression(@\"^[a-zA-Z0-9_]+$\", ErrorMessage = \"Invalid characters\")]\n    public string Username { get; set; }\n    \n    [Required]\n    [EmailAddress]\n    public string Email { get; set; }\n}\n\n[HttpPost]\npublic IActionResult CreateUser([FromBody] CreateUserRequest request)\n{\n    if (!ModelState.IsValid)\n    {\n        return BadRequest(ModelState);\n    }\n    // Process validated input\n}\n```\nSource: ASP.NET Core Model Validation (https://learn.microsoft.com/aspnet/core/mvc/models/validation)"
            ))
        elif has_validation and has_model_state_check:
            line_num = self.get_line_number(code, "[Required]") or self.get_line_number(code, "ModelState.IsValid")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-02",
                severity=Severity.INFO,
                title="Input validation properly configured",
                description="Models use data annotations and controllers validate ModelState.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Consider using FluentValidation for complex validation scenarios.",
                good_practice=True
            ))
    
    def _check_secure_coding(self, code: str, file_path: str) -> None:
        """Check for secure coding practices (KSI-SVC-07)."""
        issues = []
        
        # Check for HTTPS redirection
        if re.search(r"(UseHsts|UseHttpsRedirection)", code):
            line_num = self.get_line_number(code, "UseHttpsRedirection") or self.get_line_number(code, "UseHsts")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.INFO,
                title="HTTPS enforcement configured",
                description="Application enforces HTTPS with HSTS.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure HSTS max-age is set to at least 1 year (31536000 seconds).",
                good_practice=True
            ))
        elif re.search(r"(WebApplication\.Create|CreateBuilder)", code):
            line_num = self.get_line_number(code, "WebApplication")
            issues.append("Missing app.UseHttpsRedirection() and app.UseHsts()")
        
        # Check for CORS configuration
        if re.search(r"UseCors\(.*\*", code):
            line_num = self.get_line_number(code, "UseCors")
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.MEDIUM,
                title="Overly permissive CORS policy",
                description="CORS allows all origins (*). FedRAMP 20x requires restricted cross-origin access.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Restrict CORS to specific origins:\n```csharp\nbuilder.Services.AddCors(options =>\n{\n    options.AddPolicy(\"AllowedOrigins\", policy =>\n    {\n        policy.WithOrigins(\"https://yourdomain.com\")\n              .AllowAnyHeader()\n              .AllowAnyMethod()\n              .AllowCredentials();\n    });\n});\n\napp.UseCors(\"AllowedOrigins\");\n```"
            ))
        
        if issues:
            line_num = 1
            self.add_finding(Finding(
                requirement_id="KSI-SVC-07",
                severity=Severity.HIGH,
                title="Missing security configurations",
                description=f"Security issues detected: {'; '.join(issues)}",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add security middleware in Program.cs:\n```csharp\nvar app = builder.Build();\n\nif (!app.Environment.IsDevelopment())\n{\n    app.UseHsts();\n}\n\napp.UseHttpsRedirection();\napp.UseAuthentication();\napp.UseAuthorization();\n```"
            ))
    
    def _check_data_classification(self, code: str, file_path: str) -> None:
        """Check for data classification attributes (KSI-PIY-01)."""
        # Check for custom data classification attributes
        has_classification = bool(re.search(r"\[(Sensitive|Confidential|Internal|Public)Data\]", code))
        
        # Check for PII-related properties
        has_pii_properties = bool(re.search(r"(Email|Phone|SSN|DateOfBirth|Address)", code))
        
        if has_pii_properties and not has_classification:
            line_num = self.get_line_number(code, "Email") or self.get_line_number(code, "Phone")
            self.add_finding(Finding(
                requirement_id="KSI-PIY-01",
                severity=Severity.LOW,
                title="PII properties without data classification attributes",
                description="Properties containing PII should be marked with data classification attributes for tracking and compliance.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Create and use data classification attributes:\n```csharp\n[AttributeUsage(AttributeTargets.Property)]\npublic class SensitiveDataAttribute : Attribute\n{\n    public DataClassification Classification { get; set; }\n}\n\npublic enum DataClassification\n{\n    Public,\n    Internal,\n    Confidential,\n    Restricted\n}\n\npublic class User\n{\n    [SensitiveData(Classification = DataClassification.Restricted)]\n    public string SSN { get; set; }\n    \n    [SensitiveData(Classification = DataClassification.Confidential)]\n    public string Email { get; set; }\n}\n```"
            ))
    
    def _check_privacy_controls(self, code: str, file_path: str) -> None:
        """Check for privacy control implementation (KSI-PIY-03)."""
        # Check for data anonymization/pseudonymization
        has_anonymization = bool(re.search(r"(Anonymize|Pseudonymize|Hash|Redact)", code))
        
        # Check for consent tracking
        has_consent = bool(re.search(r"(Consent|UserConsent|PrivacyAgreement)", code))
        
        if not has_consent and re.search(r"(User|Customer|Person)", code):
            line_num = self.get_line_number(code, "class.*User") or self.get_line_number(code, "class.*Customer")
            if line_num:
                self.add_finding(Finding(
                    requirement_id="KSI-PIY-03",
                    severity=Severity.LOW,
                    title="User data without consent tracking",
                    description="User/customer entities should track privacy consent for FedRAMP 20x compliance.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Add consent tracking properties:\n```csharp\npublic class User\n{\n    public bool MarketingConsentGiven { get; set; }\n    public DateTime? ConsentDate { get; set; }\n    public string ConsentVersion { get; set; }\n    public bool DataSharingConsent { get; set; }\n}\n```"
                ))
    
    def _check_service_mesh(self, code: str, file_path: str) -> None:
        """Check for service mesh security (KSI-CNA-07)."""
        # Already covered in _check_microservices_security
        pass
    
    def _check_least_privilege(self, code: str, file_path: str) -> None:
        """Check for least privilege implementation (KSI-IAM-04)."""
        # Check for role-based authorization
        has_role_auth = bool(re.search(r'\[Authorize\(Roles\s*=|Policy\s*=', code))
        
        # Check for resource-based authorization
        has_resource_auth = bool(re.search(r"IAuthorizationService|AuthorizeAsync", code))
        
        if re.search(r"\[Authorize\]", code) and not (has_role_auth or has_resource_auth):
            line_num = self.get_line_number(code, "[Authorize]")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.MEDIUM,
                title="Authorization without role or policy checks",
                description="Using [Authorize] without Roles or Policy allows any authenticated user. FedRAMP 20x requires least-privilege access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Implement role-based or policy-based authorization:\n```csharp\n// Role-based\n[Authorize(Roles = \"Admin,Manager\")]\npublic IActionResult DeleteUser(int id) { }\n\n// Policy-based (recommended)\nservices.AddAuthorization(options =>\n{\n    options.AddPolicy(\"CanDeleteUser\", policy =>\n        policy.RequireClaim(\"permission\", \"user.delete\"));\n});\n\n[Authorize(Policy = \"CanDeleteUser\")]\npublic IActionResult DeleteUser(int id) { }\n\n// Resource-based (most granular)\npublic async Task<IActionResult> Edit(int id)\n{\n    var resource = await _repository.GetAsync(id);\n    var authResult = await _authService.AuthorizeAsync(\n        User, resource, \"CanEdit\");\n    if (!authResult.Succeeded)\n        return Forbid();\n}\n```\nSource: ASP.NET Core Authorization (https://learn.microsoft.com/aspnet/core/security/authorization/)"
            ))
        elif has_role_auth or has_resource_auth:
            line_num = self.get_line_number(code, "Policy =") or self.get_line_number(code, "Roles =") or self.get_line_number(code, "AuthorizeAsync")
            self.add_finding(Finding(
                requirement_id="KSI-IAM-04",
                severity=Severity.INFO,
                title="Least privilege authorization implemented",
                description="Application uses role-based or policy-based authorization for access control.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Regularly review authorization policies and ensure they follow least privilege principle.",
                good_practice=True
            ))
    
    def _check_session_management(self, code: str, file_path: str) -> None:
        """Check for secure session management (KSI-IAM-07)."""
        # Check for session configuration
        has_session_config = bool(re.search(r"AddSession|UseSession", code))
        
        if has_session_config:
            # Check for secure cookie settings
            has_secure_cookies = bool(re.search(r"Cookie\s*=\s*new.*HttpOnly\s*=\s*true.*Secure\s*=\s*true", code, re.DOTALL))
            
            if not has_secure_cookies:
                line_num = self.get_line_number(code, "AddSession") or self.get_line_number(code, "UseSession")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.MEDIUM,
                    title="Session cookies without security flags",
                    description="Session management should use HttpOnly and Secure flags. FedRAMP 20x requires secure session handling.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Configure secure session cookies:\n```csharp\nbuilder.Services.AddSession(options =>\n{\n    options.Cookie.HttpOnly = true;\n    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n    options.Cookie.SameSite = SameSiteMode.Strict;\n    options.IdleTimeout = TimeSpan.FromMinutes(20);\n});\n\n// For authentication cookies\nbuilder.Services.ConfigureApplicationCookie(options =>\n{\n    options.Cookie.HttpOnly = true;\n    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n    options.Cookie.SameSite = SameSiteMode.Strict;\n    options.ExpireTimeSpan = TimeSpan.FromHours(1);\n    options.SlidingExpiration = true;\n});\n```\nSource: ASP.NET Core Security best practices (https://learn.microsoft.com/aspnet/core/security/)"
                ))
            else:
                line_num = self.get_line_number(code, "HttpOnly")
                self.add_finding(Finding(
                    requirement_id="KSI-IAM-07",
                    severity=Severity.INFO,
                    title="Secure session management configured",
                    description="Session cookies use HttpOnly, Secure, and SameSite flags.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure session timeout is configured appropriately (e.g., 20 minutes idle timeout).",
                    good_practice=True
                ))
    
    def _check_security_monitoring(self, code: str, file_path: str) -> None:
        """Check for security event monitoring (KSI-MLA-03)."""
        # Check for Application Insights telemetry
        has_app_insights = bool(re.search(r"(Microsoft\.ApplicationInsights|TelemetryClient|ILogger)", code))
        
        if has_app_insights:
            # Check for security event tracking
            has_security_tracking = bool(re.search(
                r"(TrackEvent|TrackException|TrackTrace|LogWarning|LogError|LogCritical)",
                code
            ))
            
            if not has_security_tracking:
                line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "ILogger")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.MEDIUM,
                    title="Limited security event tracking",
                    description="Application Insights or ILogger is configured but not actively tracking security events. FedRAMP 20x requires comprehensive security monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track security-relevant events:\n```csharp\nusing Microsoft.ApplicationInsights;\nusing Microsoft.Extensions.Logging;\n\npublic class SecurityMonitor\n{\n    private readonly TelemetryClient _telemetry;\n    private readonly ILogger<SecurityMonitor> _logger;\n    \n    public void TrackAuthenticationEvent(string username, bool success, string ipAddress)\n    {\n        var properties = new Dictionary<string, string>\n        {\n            { \"Username\", username },\n            { \"Success\", success.ToString() },\n            { \"IPAddress\", ipAddress },\n            { \"EventType\", \"Authentication\" }\n        };\n        \n        _telemetry.TrackEvent(\"SecurityEvent\", properties);\n        _logger.LogWarning(\"Authentication attempt: {Username} from {IP} - {Result}\",\n            username, ipAddress, success ? \"Success\" : \"Failed\");\n    }\n    \n    public void TrackAuthorizationFailure(string username, string resource)\n    {\n        _telemetry.TrackEvent(\"AuthorizationDenied\", new Dictionary<string, string>\n        {\n            { \"Username\", username },\n            { \"Resource\", resource }\n        });\n        _logger.LogWarning(\"Authorization denied: {Username} attempted to access {Resource}\",\n            username, resource);\n    }\n}\n```\nSource: Azure Monitor Application Insights (https://learn.microsoft.com/azure/azure-monitor/app/api-custom-events-metrics)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackEvent") or self.get_line_number(code, "LogWarning")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-03",
                    severity=Severity.INFO,
                    title="Security monitoring implemented",
                    description="Application tracks security events using Application Insights or ILogger.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure all authentication, authorization, and data access events are logged.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-03",
                severity=Severity.HIGH,
                title="No security monitoring framework detected",
                description="Application does not appear to use Application Insights or structured logging. FedRAMP 20x requires comprehensive security event monitoring.",
                file_path=file_path,
                recommendation="Implement Application Insights:\n```csharp\n// Program.cs\nbuilder.Services.AddApplicationInsightsTelemetry(options =>\n{\n    options.ConnectionString = builder.Configuration[\"ApplicationInsights:ConnectionString\"];\n});\n\n// Add structured logging\nbuilder.Logging.AddApplicationInsights();\nbuilder.Logging.AddConsole();\nbuilder.Logging.AddAzureWebAppDiagnostics();\n```\nSource: Azure Monitor overview (https://learn.microsoft.com/azure/azure-monitor/overview)"
            ))
    
    def _check_anomaly_detection(self, code: str, file_path: str) -> None:
        """Check for anomaly detection configuration (KSI-MLA-04)."""
        # Check for Application Insights smart detection
        has_app_insights = bool(re.search(r"Microsoft\.ApplicationInsights", code))
        
        if has_app_insights:
            # Check for metrics tracking
            has_metrics = bool(re.search(r"(TrackMetric|GetMetric|TelemetryClient)", code))
            
            if not has_metrics:
                line_num = self.get_line_number(code, "ApplicationInsights")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-04",
                    severity=Severity.MEDIUM,
                    title="No custom metrics for anomaly detection",
                    description="Application Insights is configured but not tracking custom metrics for anomaly detection. FedRAMP 20x requires baseline-based anomaly detection.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track custom metrics for anomaly detection:\n```csharp\npublic class MetricsTracker\n{\n    private readonly TelemetryClient _telemetry;\n    \n    public void TrackLoginAttempts(int count, string ipAddress)\n    {\n        _telemetry.GetMetric(\"LoginAttempts\", \"IPAddress\").TrackValue(count, ipAddress);\n    }\n    \n    public void TrackApiCallRate(int count, string endpoint)\n    {\n        _telemetry.GetMetric(\"APICallRate\", \"Endpoint\").TrackValue(count, endpoint);\n    }\n    \n    public void TrackDataAccessVolume(long bytes, string username)\n    {\n        _telemetry.GetMetric(\"DataAccessVolume\", \"User\").TrackValue(bytes, username);\n    }\n}\n```\nEnable Smart Detection in Azure Portal:\n1. Navigate to Application Insights resource\n2. Go to Smart Detection settings\n3. Enable anomaly detection alerts\n\nSource: Application Insights Smart Detection (https://learn.microsoft.com/azure/azure-monitor/alerts/proactive-diagnostics)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackMetric") or self.get_line_number(code, "GetMetric")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-04",
                    severity=Severity.INFO,
                    title="Metrics tracking configured",
                    description="Application tracks custom metrics that can be used for anomaly detection.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure Smart Detection is enabled in Azure Application Insights for automated anomaly detection.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-04",
                severity=Severity.HIGH,
                title="No anomaly detection framework",
                description="Application does not use Application Insights for anomaly detection. FedRAMP 20x requires baseline-based anomaly detection.",
                file_path=file_path,
                recommendation="Implement Application Insights with Smart Detection (see KSI-MLA-03 recommendation)."
            ))
    
    def _check_performance_monitoring(self, code: str, file_path: str) -> None:
        """Check for performance monitoring (KSI-MLA-06)."""
        # Check for performance tracking
        has_perf_monitoring = bool(re.search(
            r"(ApplicationInsights|ILogger|TrackDependency|TrackRequest|Stopwatch)",
            code
        ))
        
        if has_perf_monitoring:
            # Check for dependency tracking
            has_dependency_tracking = bool(re.search(r"TrackDependency", code))
            
            if not has_dependency_tracking:
                line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "Stopwatch")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.MEDIUM,
                    title="Limited performance monitoring",
                    description="Application has monitoring but doesn't track dependencies (database calls, external APIs). FedRAMP 20x requires comprehensive performance monitoring.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Track dependencies for performance monitoring:\n```csharp\npublic class PerformanceMonitor\n{\n    private readonly TelemetryClient _telemetry;\n    \n    public async Task<T> TrackDependencyAsync<T>(string dependencyName, string target, Func<Task<T>> operation)\n    {\n        var startTime = DateTime.UtcNow;\n        var timer = Stopwatch.StartNew();\n        bool success = false;\n        \n        try\n        {\n            var result = await operation();\n            success = true;\n            return result;\n        }\n        finally\n        {\n            timer.Stop();\n            _telemetry.TrackDependency(\n                dependencyTypeName: dependencyName,\n                target: target,\n                dependencyName: dependencyName,\n                data: target,\n                startTime: startTime,\n                duration: timer.Elapsed,\n                resultCode: success ? \"200\" : \"500\",\n                success: success\n            );\n        }\n    }\n}\n\n// Usage\nawait _monitor.TrackDependencyAsync(\"SQL\", \"UserDatabase\",\n    async () => await _dbContext.Users.ToListAsync());\n```\nSource: Application Insights dependency tracking (https://learn.microsoft.com/azure/azure-monitor/app/asp-net-dependencies)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackDependency")
                self.add_finding(Finding(
                    requirement_id="KSI-MLA-06",
                    severity=Severity.INFO,
                    title="Comprehensive performance monitoring",
                    description="Application tracks dependencies and performance metrics.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure monitoring covers all critical dependencies and set up alerts for performance degradation.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-MLA-06",
                severity=Severity.HIGH,
                title="No performance monitoring detected",
                description="Application does not implement performance monitoring. FedRAMP 20x requires tracking of request rates, response times, and resource utilization.",
                file_path=file_path,
                recommendation="Implement Application Insights for performance monitoring (see KSI-MLA-03 recommendation)."
            ))
    
    def _check_incident_response(self, code: str, file_path: str) -> None:
        """Check for automated incident response integration (KSI-INR-01)."""
        # Check for incident response integrations
        has_incident_integration = bool(re.search(
            r"(PagerDuty|ServiceNow|Opsgenie|webhook|Alert|Notification|SendGrid|Twilio)",
            code,
            re.IGNORECASE
        ))
        
        if has_incident_integration:
            # Check for error handling with alerting
            has_alert_on_error = bool(re.search(
                r"(TrackException|LogError|LogCritical).*(?:.*\n.*){0,5}.*(?:SendAsync|PostAsync|Alert|Notify)",
                code,
                re.DOTALL
            ))
            
            if not has_alert_on_error:
                line_num = self.get_line_number(code, "PagerDuty") or self.get_line_number(code, "webhook")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.MEDIUM,
                    title="Incident response integration not connected to errors",
                    description="Incident response tools are referenced but not integrated with error handling. FedRAMP 20x requires automated incident response.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Integrate incident response with error handling:\n```csharp\npublic class IncidentResponseService\n{\n    private readonly HttpClient _client;\n    private readonly ILogger<IncidentResponseService> _logger;\n    private readonly string _webhookUrl;\n    \n    public async Task TriggerIncidentAsync(Exception ex, string severity, Dictionary<string, string> context)\n    {\n        var incident = new\n        {\n            routing_key = _webhookUrl,\n            event_action = \"trigger\",\n            payload = new\n            {\n                summary = ex.Message,\n                severity = severity,\n                source = Environment.MachineName,\n                timestamp = DateTime.UtcNow,\n                custom_details = context\n            }\n        };\n        \n        try\n        {\n            var response = await _client.PostAsJsonAsync(\n                \"https://events.pagerduty.com/v2/enqueue\",\n                incident\n            );\n            response.EnsureSuccessStatusCode();\n            _logger.LogInformation(\"Incident triggered: {ExceptionType}\", ex.GetType().Name);\n        }\n        catch (Exception alertEx)\n        {\n            _logger.LogError(alertEx, \"Failed to trigger incident\");\n        }\n    }\n}\n\n// Usage in exception handler\ncatch (SecurityException ex)\n{\n    _logger.LogCritical(ex, \"Security breach detected\");\n    await _incidentResponse.TriggerIncidentAsync(ex, \"critical\", new Dictionary<string, string>\n    {\n        { \"user\", User.Identity.Name },\n        { \"ip\", HttpContext.Connection.RemoteIpAddress.ToString() }\n    });\n}\n```\nSource: Azure Monitor Action Groups (https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups)"
                ))
            else:
                line_num = self.get_line_number(code, "TrackException") or self.get_line_number(code, "PostAsync")
                self.add_finding(Finding(
                    requirement_id="KSI-INR-01",
                    severity=Severity.INFO,
                    title="Automated incident response configured",
                    description="Application integrates incident response tools with error handling.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure incident response covers all critical errors and security events.",
                    good_practice=True
                ))
        else:
            self.add_finding(Finding(
                requirement_id="KSI-INR-01",
                severity=Severity.HIGH,
                title="No incident response integration",
                description="Application does not integrate with incident response tools. FedRAMP 20x requires automated incident response for security events.",
                file_path=file_path,
                recommendation="Integrate with incident response system:\n1. Use Azure Monitor Action Groups for alerts\n2. Configure webhooks to PagerDuty, ServiceNow, or similar\n3. Implement automated alerting for critical errors\n\nSource: Azure Monitor alerting (https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-overview)"
            ))
    
    # Phase 5: DevSecOps Automation Methods
    
    def _check_configuration_management(self, code: str, file_path: str) -> None:
        """Check for secure configuration management (KSI-CMT-01)."""
        # Check for hardcoded configuration values
        config_patterns = [
            (r'(ApiUrl|BaseUrl|Endpoint)\s*=\s*"https?://[^"]+";', "API endpoint"),
            (r'(ConnectionString|DbConnection)\s*=\s*"[^"]+";', "Connection string"),
            (r'(Port|DbPort)\s*=\s*\d+;', "Port number"),
        ]
        
        hardcoded_configs = []
        for pattern, config_type in config_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            if matches:
                for match in matches:
                    context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                    if not re.search(r'(Configuration\[|GetValue<|GetSection|IConfiguration|Environment\.GetEnvironmentVariable)', context):
                        hardcoded_configs.append((match, config_type))
        
        # Check for Azure App Configuration integration
        has_app_config = bool(re.search(r'(Azure\.AppConfiguration|ConfigurationClient|AzureAppConfigurationOptions)', code))
        has_key_vault = bool(re.search(r'(Azure\.KeyVault|SecretClient)', code))
        has_iconfiguration = bool(re.search(r'IConfiguration', code))
        
        if hardcoded_configs:
            for match, config_type in hardcoded_configs[:3]:
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-01",
                    severity=Severity.HIGH,
                    title=f"Hardcoded {config_type} configuration",
                    description=f"Configuration value hardcoded in source. FedRAMP 20x requires externalized configuration.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation=f"Use Azure App Configuration:\n```csharp\n// Program.cs\nvar builder = WebApplication.CreateBuilder(args);\n\n// Add Azure App Configuration\nbuilder.Configuration.AddAzureAppConfiguration(options =>\n{{\n    options.Connect(\n        new Uri(builder.Configuration[\"AppConfig:Endpoint\"]),\n        new DefaultAzureCredential()\n    )\n    .ConfigureKeyVault(kv =>\n    {{\n        kv.SetCredential(new DefaultAzureCredential());\n    }});\n}});\n\n// Service configuration\npublic class MyService\n{{\n    private readonly IConfiguration _configuration;\n    \n    public MyService(IConfiguration configuration)\n    {{\n        _configuration = configuration;\n    }}\n    \n    public string Get{config_type.replace(' ', '')}()\n    {{\n        return _configuration[\"{config_type.replace(' ', '')}\"];\n    }}\n}}\n```\nSource: Azure App Configuration (https://learn.microsoft.com/azure/azure-app-configuration/quickstart-dotnet-core-app)"
                ))
        
        if has_app_config or has_key_vault:
            line_num = self.get_line_number(code, "AppConfiguration") or self.get_line_number(code, "KeyVault")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.INFO,
                title="Azure App Configuration or Key Vault integration",
                description="Application uses centralized configuration management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure all environment-specific values are externalized.",
                good_practice=True
            ))
        elif not hardcoded_configs and has_iconfiguration:
            line_num = self.get_line_number(code, "IConfiguration")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-01",
                severity=Severity.LOW,
                title="Configuration uses IConfiguration",
                description="Environment variables/appsettings.json used. Consider Azure App Configuration for centralized management.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Migrate to Azure App Configuration for FedRAMP audit trails.",
                good_practice=True
            ))
    
    def _analyze_project_configuration(self, file_path: str) -> None:
        """Analyze appsettings.json files for security misconfigurations."""
        # Find configuration files in project
        config_files = self._find_appsettings_files(file_path)
        
        if not config_files:
            return
        
        # Analyze each configuration file
        severity_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
        
        for config_file in config_files:
            issues = self._analyze_configuration_file(config_file)
            
            for issue in issues:
                severity = severity_map.get(issue.get("severity", "medium"), Severity.MEDIUM)
                issue_type = issue.get("type", "unknown")
                
                # Map issue types to KSI requirements
                ksi_mapping = {
                    "hardcoded_secret": ("KSI-SVC-06", "Hardcoded secrets in configuration"),
                    "connection_string_password": ("KSI-SVC-06", "Connection string contains password"),
                    "unencrypted_connection": ("KSI-CNA-01", "Database connection encryption disabled"),
                    "verbose_logging": ("KSI-MLA-05", "Overly verbose logging in production"),
                    "missing_logging": ("KSI-MLA-05", "Logging configuration missing"),
                    "missing_app_insights": ("KSI-MLA-03", "Application Insights not configured"),
                    "no_https_endpoint": ("KSI-SVC-07", "No HTTPS endpoint in production"),
                    "short_hsts_maxage": ("KSI-SVC-07", "HSTS MaxAge too short"),
                    "parse_error": ("KSI-CMT-01", "Invalid configuration file"),
                }
                
                ksi_id, title = ksi_mapping.get(issue_type, ("KSI-CMT-01", "Configuration security issue"))
                
                # Build recommendation based on issue type
                recommendations = {
                    "hardcoded_secret": f"""Remove hardcoded secret from {config_file.name}. Use Azure Key Vault:
```csharp
// Program.cs
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{{vaultName}}.vault.azure.net/"),
    new DefaultAzureCredential()
);

// Access secrets via IConfiguration
var secret = configuration["{issue.get('path', 'SecretName')}"];
```
Source: Azure Key Vault configuration provider (https://learn.microsoft.com/azure/key-vault/general/tutorial-net-create-vault-azure-web-app)""",
                    
                    "connection_string_password": f"""Use Managed Identity for database authentication:
```csharp
// Remove password from connection string in {config_file.name}:
"ConnectionStrings": {{
    "Database": "Server=myserver.database.windows.net;Database=mydb;Authentication=Active Directory Default;"
}}

// Or use Key Vault reference:
"ConnectionStrings": {{
    "Database": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-connection-string)"
}}
```
Source: Azure SQL Managed Identity authentication (https://learn.microsoft.com/azure/azure-sql/database/authentication-aad-configure)""",
                    
                    "unencrypted_connection": """Enable SQL connection encryption:
```json
"ConnectionStrings": {
    "Database": "Server=myserver.database.windows.net;Database=mydb;Encrypt=true;TrustServerCertificate=false;"
}
```""",
                    
                    "verbose_logging": f"""Set appropriate log level in {config_file.name}:
```json
"Logging": {{
    "LogLevel": {{
        "Default": "Information",
        "Microsoft.AspNetCore": "Warning"
    }}
}}
```""",
                    
                    "no_https_endpoint": """Configure HTTPS endpoint in production:
```json
"Kestrel": {
    "Endpoints": {
        "Https": {
            "Url": "https://*:443",
            "Certificate": {
                "Source": "AzureKeyVault",
                "StoreLocation": "https://myvault.vault.azure.net/secrets/ssl-cert"
            }
        }
    }
}
```""",
                }
                
                recommendation = recommendations.get(issue_type, issue.get("message", "Review configuration security"))
                
                self.add_finding(Finding(
                    requirement_id=ksi_id,
                    severity=severity,
                    title=title,
                    description=f"{issue.get('message', 'Configuration issue detected')} in {config_file.name}",
                    file_path=str(config_file),
                    line_number=None,  # JSON files don't have meaningful line numbers without JSON parser
                    recommendation=recommendation or "Review security configuration"
                ))
    
    def _check_version_control(self, code: str, file_path: str) -> None:
        """Check for version control enforcement (KSI-CMT-02)."""
        # Check for direct production deployment (anti-pattern)
        direct_deploy_patterns = [
            r'Process\.Start\s*\(\s*["\']git["\'].*production',
            r'ProcessStartInfo.*deploy.*production',
        ]
        
        has_direct_deploy = False
        for pattern in direct_deploy_patterns:
            match = re.search(pattern, code, re.IGNORECASE)
            if match:
                has_direct_deploy = True
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-02",
                    severity=Severity.HIGH,
                    title="Direct production deployment without approval",
                    description="Code performs direct production deployment. FedRAMP 20x requires approval workflows.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=match.group(0),
                    recommendation="Use Azure DevOps pipelines with approval gates or GitHub Actions with environment protection rules."
                ))
                break
        
        has_cicd_config = bool(re.search(r'(azure-pipelines|\.github/workflows)', code, re.IGNORECASE))
        if has_cicd_config:
            line_num = self.get_line_number(code, "pipeline")
            self.add_finding(Finding(
                requirement_id="KSI-CMT-02",
                severity=Severity.INFO,
                title="CI/CD configuration referenced",
                description="Code references CI/CD pipelines.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Verify branch protection and approval requirements.",
                good_practice=True
            ))
    
    def _check_automated_testing(self, code: str, file_path: str) -> None:
        """Check for automated security testing (KSI-CMT-03)."""
        # Check for test frameworks
        test_frameworks = [
            r'using\s+Xunit',
            r'using\s+NUnit',
            r'using\s+Microsoft\.VisualStudio\.TestTools',
        ]
        
        has_test_framework = False
        for pattern in test_frameworks:
            if re.search(pattern, code):
                has_test_framework = True
                break
        
        # Check for security tests
        has_security_tests = bool(re.search(
            r'(Test.*Security|Test.*Auth|Test.*Sql.*Injection|Test.*Xss)',
            code,
            re.IGNORECASE
        ))
        
        is_test_file = bool(re.search(r'Tests?\.cs$', file_path))
        
        if not is_test_file and not has_test_framework:
            if re.search(r'(Controllers|Services|Repositories)', file_path, re.IGNORECASE) or re.search(r'(class\s+\w+Service|public\s+class\s+\w+Service)', code):
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.MEDIUM,
                    title="No automated tests found",
                    description="Application code without tests. FedRAMP 20x requires automated security testing.",
                    file_path=file_path,
                    line_number=1,
                    recommendation="Create test project with security tests:\n```csharp\nusing Xunit;\nusing Microsoft.AspNetCore.Mvc.Testing;\n\npublic class SecurityTests : IClassFixture<WebApplicationFactory<Program>>\n{\n    private readonly HttpClient _client;\n    \n    [Fact]\n    public async Task ProtectedEndpoint_RequiresAuthentication()\n    {\n        var response = await _client.GetAsync(\"/api/protected\");\n        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);\n    }\n    \n    [Theory]\n    [InlineData(\"'; DROP TABLE Users; --\")]\n    [InlineData(\"<script>alert('XSS')</script>\")]\n    public async Task InputValidation_BlocksMaliciousInput(string maliciousInput)\n    {\n        var response = await _client.PostAsJsonAsync(\"/api/search\",\n            new { query = maliciousInput });\n        \n        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);\n    }\n    \n    [Fact]\n    public async Task Authorization_EnforcesAccessControl()\n    {\n        var token = GetTokenForUser(\"user1\");\n        _client.DefaultRequestHeaders.Authorization =\n            new AuthenticationHeaderValue(\"Bearer\", token);\n        \n        var response = await _client.GetAsync(\"/api/users/user2/data\");\n        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);\n    }\n}\n```"
                ))
        elif is_test_file and has_test_framework:
            if has_security_tests:
                line_num = self.get_line_number(code, "Security") or self.get_line_number(code, "Auth")
                self.add_finding(Finding(
                    requirement_id="KSI-CMT-03",
                    severity=Severity.INFO,
                    title="Security tests implemented",
                    description="Test file includes security-focused tests.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation="Ensure coverage: authentication, authorization, input validation, XSS, SQL injection.",
                    good_practice=True
                ))
    
    def _check_audit_logging(self, code: str, file_path: str) -> None:
        """Check for audit logging of security events (KSI-AFR-01)."""
        # Check for actual authentication logic (not just [Authorize] attributes)
        has_auth_code = bool(re.search(
            r'(Authenticate\s*\(|Login\s*\(|SignIn\s*\(|ClaimsPrincipal\s+\w+)',
            code,
            re.IGNORECASE
        ))
        
        has_data_access = bool(re.search(
            r'(DbContext|IQueryable|FromSql|ExecuteSql)',
            code,
            re.IGNORECASE
        ))
        
        has_logging = bool(re.search(r'(ILogger|Log\.|TrackEvent|TelemetryClient)', code))
        
        if has_auth_code and not has_logging:
            line_num = self.get_line_number(code, "Authenticate") or self.get_line_number(code, "Login")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.HIGH,
                title="Authentication without audit logging",
                description="Authentication code missing audit logs. FedRAMP 20x requires logging of all security events.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Add audit logging:\n```csharp\npublic class SecurityAuditLogger\n{\n    private readonly ILogger<SecurityAuditLogger> _logger;\n    private readonly TelemetryClient _telemetry;\n    \n    public void LogAuthenticationAttempt(\n        string userId,\n        string ipAddress,\n        bool success,\n        string method = \"password\")\n    {\n        var properties = new Dictionary<string, string>\n        {\n            [\"UserId\"] = userId,\n            [\"IpAddress\"] = ipAddress,\n            [\"Success\"] = success.ToString(),\n            [\"Method\"] = method,\n            [\"Timestamp\"] = DateTime.UtcNow.ToString(\"O\")\n        };\n        \n        _telemetry.TrackEvent(\"AuthenticationAttempt\", properties);\n        _logger.Log(\n            success ? LogLevel.Information : LogLevel.Warning,\n            \"Authentication {Result} for user {UserId} from {IpAddress}\",\n            success ? \"success\" : \"failed\",\n            userId,\n            ipAddress\n        );\n    }\n    \n    public void LogAuthorizationCheck(\n        string userId,\n        string resource,\n        string action,\n        bool allowed)\n    {\n        _logger.Log(\n            allowed ? LogLevel.Information : LogLevel.Warning,\n            \"Authorization {Result}: {UserId} attempted {Action} on {Resource}\",\n            allowed ? \"granted\" : \"denied\",\n            userId,\n            action,\n            resource\n        );\n    }\n}\n```"
            ))
        
        if has_data_access and not has_logging:
            line_num = self.get_line_number(code, "DbContext")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.MEDIUM,
                title="Data access without audit logging",
                description="Database operations missing audit trails.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Log sensitive data access operations."
            ))
        
        if (has_auth_code or has_data_access) and has_logging:
            line_num = self.get_line_number(code, "ILogger") or self.get_line_number(code, "TrackEvent")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-01",
                severity=Severity.INFO,
                title="Audit logging implemented",
                description="Security operations include audit logging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure logs include: user ID, timestamp, action, result, IP, resource.",
                good_practice=True
            ))
    
    def _check_log_integrity(self, code: str, file_path: str) -> None:
        """Check for log integrity and protection (KSI-AFR-02)."""
        # Check for local file logging
        local_logging = bool(re.search(
            r'(FileAppender|File.*Logger|StreamWriter.*\.log)',
            code,
            re.IGNORECASE
        ))
        
        if local_logging:
            line_num = self.get_line_number(code, "File")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.HIGH,
                title="Logs written to local files (insecure)",
                description="Application writes logs locally. FedRAMP 20x requires centralized, immutable logging.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Stream logs to Azure Monitor:\n```csharp\nusing Microsoft.ApplicationInsights;\nusing Azure.Messaging.EventHubs;\n\n// Configure Application Insights\nservices.AddApplicationInsightsTelemetry(\n    builder.Configuration[\"ApplicationInsights:ConnectionString\"]\n);\n\n// For immutable audit logs, use Event Hubs\npublic class ImmutableAuditLogger\n{\n    private readonly EventHubProducerClient _producer;\n    \n    public async Task LogAuditEventAsync(object auditEvent)\n    {\n        var eventData = new EventData(\n            JsonSerializer.SerializeToUtf8Bytes(auditEvent)\n        );\n        await _producer.SendAsync(new[] { eventData });\n    }\n}\n```"
            ))
        
        has_app_insights = bool(re.search(r'(ApplicationInsights|TelemetryClient)', code))
        has_event_hub = bool(re.search(r'EventHub', code))
        
        if not local_logging and (has_app_insights or has_event_hub):
            line_num = self.get_line_number(code, "ApplicationInsights") or self.get_line_number(code, "EventHub")
            self.add_finding(Finding(
                requirement_id="KSI-AFR-02",
                severity=Severity.INFO,
                title="Logs streamed to centralized SIEM",
                description="Application sends logs to Azure Monitor or Event Hubs.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Verify log retention meets FedRAMP requirements (90+ days).",
                good_practice=True
            ))
    
    def _check_key_management(self, code: str, file_path: str) -> None:
        """Check for cryptographic key management (KSI-CED-01)."""
        # Check for hardcoded keys
        key_patterns = [
            (r'(privateKey|secretKey|encryptionKey)\s*=\s*"[^"]{20,}";', "encryption key"),
            (r'-----BEGIN\s+(PRIVATE|RSA)\s+KEY-----', "private key"),
            (r'new\s+AesManaged\(\).*Key\s*=\s*', "AES key"),
        ]
        
        hardcoded_keys = []
        for pattern, key_type in key_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE | re.DOTALL))
            for match in matches:
                context = code[max(0, match.start()-100):min(len(code), match.end()+100)]
                if not re.search(r'(SecretClient|GetSecretAsync|KeyVaultSecret)', context):
                    hardcoded_keys.append((match, key_type))
        
        # Check for local key generation
        key_generation = bool(re.search(
            r'(Aes\.Create|AesManaged|RSA\.Create|RNGCryptoServiceProvider|GenerateKey\s*\()',
            code
        ))
        
        if key_generation:
            line_num = self.get_line_number(code, "Aes.Create") or self.get_line_number(code, "RSA.Create")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.HIGH,
                title="Local cryptographic key generation",
                description="Application generates keys locally. FedRAMP 20x requires Azure Key Vault with HSM.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Use Azure Key Vault:\n```csharp\nusing Azure.Security.KeyVault.Keys;\nusing Azure.Security.KeyVault.Keys.Cryptography;\n\nvar keyClient = new KeyClient(\n    new Uri(configuration[\"KeyVault:Url\"]),\n    new DefaultAzureCredential()\n);\n\n// Generate key in Key Vault\nvar key = await keyClient.CreateRsaKeyAsync(\n    new CreateRsaKeyOptions(\"data-encryption-key\")\n    {\n        KeySize = 2048,\n        HardwareProtected = true  // Use HSM\n    }\n);\n\n// Use for encryption\nvar cryptoClient = new CryptographyClient(key.Value.Id, new DefaultAzureCredential());\nvar result = await cryptoClient.EncryptAsync(\n    EncryptionAlgorithm.RsaOaep,\n    plaintext\n);\n```"
            ))
        
        if hardcoded_keys:
            for match, key_type in hardcoded_keys[:2]:
                line_num = self.get_line_number(code, match.group(0))
                self.add_finding(Finding(
                    requirement_id="KSI-CED-01",
                    severity=Severity.HIGH,
                    title=f"Hardcoded {key_type} in source",
                    description=f"Cryptographic {key_type} hardcoded. FedRAMP 20x prohibits keys in source.",
                    file_path=file_path,
                    line_number=line_num,
                    recommendation=f"Store {key_type} in Azure Key Vault and retrieve at runtime."
                ))
        
        has_key_vault = bool(re.search(r'(KeyClient|SecretClient|KeyVault)', code))
        has_managed_identity = bool(re.search(r'DefaultAzureCredential|ManagedIdentityCredential', code))
        
        if has_key_vault and has_managed_identity:
            line_num = self.get_line_number(code, "KeyClient") or self.get_line_number(code, "SecretClient")
            self.add_finding(Finding(
                requirement_id="KSI-CED-01",
                severity=Severity.INFO,
                title="Azure Key Vault integration with Managed Identity",
                description="Application retrieves keys from Key Vault using Managed Identity.",
                file_path=file_path,
                line_number=line_num,
                recommendation="Ensure HSM-backed keys and key rotation policies configured.",
                good_practice=True
            ))


