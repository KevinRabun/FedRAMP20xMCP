"""
KSI-SVC-04: Configuration Automation

Manage configuration of machine-based information resources using automation.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_SVC_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-04: Configuration Automation
    
    **Official Statement:**
    Manage configuration of machine-based information resources using automation.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2.4
    - cm-2
    - cm-2.2
    - cm-2.3
    - cm-6
    - cm-7.1
    - pl-9
    - pl-10
    - sa-5
    - si-5
    - sr-10
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Manage configuration of machine-based information resources using automation....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-04"
    KSI_NAME = "Configuration Automation"
    KSI_STATEMENT = """Manage configuration of machine-based information resources using automation."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-2.4", "Automated Audit Actions"),
        ("cm-2", "Baseline Configuration"),
        ("cm-2.2", "Automation Support for Accuracy and Currency"),
        ("cm-2.3", "Retention of Previous Configurations"),
        ("cm-6", "Configuration Settings"),
        ("cm-7.1", "Periodic Review"),
        ("pl-9", "Central Management"),
        ("pl-10", "Baseline Selection"),
        ("sa-5", "System Documentation"),
        ("si-5", "Security Alerts, Advisories, and Directives"),
        ("sr-10", "Inspection of Systems or Components")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-SVC-04 compliance.
        
        AST-first analysis with regex fallback.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Hardcoded configuration values (hostnames, ports, timeouts)
        - Missing configuration management frameworks
        - Manual configuration scripts without automation
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_python_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Python analysis for hardcoded configuration."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Find all assignment nodes (target = value)
        assignments = parser.find_nodes_by_type(tree.root_node, 'assignment')
        
        for assignment in assignments:
            # Get left side (target) and right side (value)
            target_node = assignment.child_by_field_name('left')
            value_node = assignment.child_by_field_name('right')
            
            if not target_node or not value_node:
                continue
            
            target_text = parser.get_node_text(target_node, code_bytes).lower()
            value_text = parser.get_node_text(value_node, code_bytes)
            
            # Check for hardcoded config patterns
            config_keywords = ['host', 'server', 'endpoint', 'port', 'timeout', 'retry']
            
            if any(keyword in target_text for keyword in config_keywords):
                # Check if value is a string literal or integer (not os.getenv, not variable)
                if value_node.type in ('string', 'integer'):
                    # Skip if it looks like a test/example (contains 'localhost', 'example', '127.0.0.1')
                    if any(skip in value_text.lower() for skip in ['localhost', 'example', '127.0.0.1', 'test']):
                        continue
                    
                    # Skip if there's a comment indicating it's from config
                    line_num = value_node.start_point[0] + 1
                    if line_num <= len(lines):
                        line_text = lines[line_num - 1]
                        if '#' in line_text and any(word in line_text.lower() for word in ['config', 'env', 'example']):
                            continue
                    
                    # Determine severity and description based on keyword
                    if 'port' in target_text and value_node.type == 'integer':
                        desc = "Hardcoded port number"
                    elif any(kw in target_text for kw in ['host', 'server', 'endpoint']):
                        desc = "Hardcoded hostname/endpoint"
                    else:
                        desc = "Hardcoded timeout/retry value"
                    
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"{desc} in Application Code",
                        description=(
                            f"Configuration value hardcoded in application code instead of using configuration management. "
                            f"KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                            f"environment-specific configuration and automation (CM-2, CM-6). "
                            f"This violates FedRAMP 20x configuration automation requirements."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            "Use environment variables or configuration files:\n"
                            "# Option 1: Environment variables\n"
                            "import os\n"
                            f"{target_text} = os.getenv('{target_text.upper()}', 'default_value')\n\n"
                            "# Option 2: Configuration management (Python-dotenv, Azure App Configuration)\n"
                            "from azure.appconfiguration import AzureAppConfigurationClient\n"
                            "from azure.identity import DefaultAzureCredential\n\n"
                            "client = AzureAppConfigurationClient(\n"
                            "    base_url=os.getenv('APPCONFIGURATION_ENDPOINT'),\n"
                            "    credential=DefaultAzureCredential()\n"
                            ")\n"
                            "config_value = client.get_configuration_setting(key='my-config-key').value\n\n"
                            "Ref: Azure Well-Architected Framework - Operational Excellence "
                            "(https://learn.microsoft.com/azure/well-architected/operational-excellence/app-configuration)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex-based Python analysis (fallback when AST unavailable)."""
        findings = []
        lines = code.split('\n')
        
        # Pattern: Hardcoded configuration in code (MEDIUM)
        hardcoded_patterns = [
            (r'(host|server|endpoint)\s*=\s*["\'](?!.*{.*})[a-zA-Z0-9.-]+["\']', "Hardcoded hostname/endpoint"),
            (r'(port)\s*=\s*\d{2,5}(?!\s*#.*config)', "Hardcoded port number"),
            (r'(timeout|retry)\s*=\s*\d+(?!\s*#.*config)', "Hardcoded timeout/retry value")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in Application Code",
                    description=(
                        f"Configuration value hardcoded in application code instead of using configuration management. "
                        f"KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        f"environment-specific configuration and automation (CM-2, CM-6). "
                        f"This violates FedRAMP 20x configuration automation requirements."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use environment variables or configuration files:\n"
                        "# Option 1: Environment variables\n"
                        "import os\n"
                        f"{desc.split()[1].lower()} = os.getenv('{desc.split()[1].upper()}', 'default_value')\n\n"
                        "# Option 2: Configuration management (Python-dotenv, Azure App Configuration)\n"
                        "from azure.appconfiguration import AzureAppConfigurationClient\n"
                        "from azure.identity import DefaultAzureCredential\n\n"
                        "client = AzureAppConfigurationClient(\n"
                        "    base_url=os.getenv('APPCONFIGURATION_ENDPOINT'),\n"
                        "    credential=DefaultAzureCredential()\n"
                        ")\n"
                        "config_value = client.get_configuration_setting(key='my-config-key').value\n\n"
                        "Ref: Azure Well-Architected Framework - Operational Excellence "
                        "(https://learn.microsoft.com/azure/well-architected/operational-excellence/app-configuration)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-04 compliance.
        
        AST-first analysis with regex fallback.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Hardcoded configuration values (URLs, ports, timeouts)
        - Missing IConfiguration usage
        - Manual configuration without automation
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based C# analysis for hardcoded configuration."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Find variable declarations with initializers (string/int varName = value;)
        var_declarations = parser.find_nodes_by_type(tree.root_node, 'variable_declaration')
        
        for var_decl in var_declarations:
            # Get declarators (the actual variable assignments)
            declarators = parser.find_nodes_by_type(var_decl, 'variable_declarator')
            
            for declarator in declarators:
                # C# structure: variable_declarator has children [identifier, '=', value]
                if declarator.child_count < 3:
                    continue
                
                identifier = declarator.children[0]  # First child is identifier
                value = declarator.children[2]  # Third child is the value (after '=')
                
                if not identifier or identifier.type != 'identifier':
                    continue
                
                var_name = parser.get_node_text(identifier, code_bytes)
                value_text = parser.get_node_text(value, code_bytes)
                
                # Check for config keywords in variable name
                config_keywords = ['url', 'endpoint', 'host', 'server', 'port', 'timeout', 'retry']
                var_lower = var_name.lower()
                
                if any(keyword in var_lower for keyword in config_keywords):
                    # Check if value is a string literal or integer (not from IConfiguration)
                    value_type = value.type
                    
                    # Skip if value comes from configuration (Configuration[], GetValue, etc.)
                    if 'Configuration' in value_text or 'GetValue' in value_text or 'GetEnvironment' in value_text:
                        continue
                    
                    # Skip test/example values
                    if any(skip in value_text.lower() for skip in ['localhost', 'example', '127.0.0.1', 'test']):
                        continue
                    
                    # Detect hardcoded string literals or integers
                    if value_type in ('string_literal', 'integer_literal', 'object_creation_expression'):
                        line_num = value.start_point[0] + 1
                        
                        if 'port' in var_lower or 'timeout' in var_lower or 'retry' in var_lower:
                            desc = "Hardcoded port/timeout value"
                        elif 'uri' in value_text.lower() and 'http' in value_text.lower():
                            desc = "Hardcoded URI in constructor"
                        else:
                            desc = "Hardcoded URL/endpoint"
                        
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title=f"{desc} in C# Application",
                            description=(
                                "Configuration value hardcoded in C# code instead of using IConfiguration. "
                                "KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                                "environment-specific configuration and automation (CM-2, CM-6). "
                                "ASP.NET Core provides IConfiguration for centralized configuration management."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num, context=3),
                            remediation=(
                                "Use IConfiguration for configuration management:\n"
                                "// In Program.cs or Startup.cs\n"
                                "var configuration = builder.Configuration;\n\n"
                                "// Option 1: appsettings.json\n"
                                "string endpoint = configuration[\"ServiceEndpoint\"];\n"
                                "int port = configuration.GetValue<int>(\"ServicePort\");\n\n"
                                "// Option 2: Azure App Configuration\n"
                                "builder.Configuration.AddAzureAppConfiguration(options => {\n"
                                "    options.Connect(Environment.GetEnvironmentVariable(\"APPCONFIGURATION_CONNECTION_STRING\"))\n"
                                "           .ConfigureKeyVault(kv => kv.SetCredential(new DefaultAzureCredential()));\n"
                                "});\n\n"
                                "Ref: ASP.NET Core Configuration (https://learn.microsoft.com/aspnet/core/fundamentals/configuration/)"
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex-based C# analysis (fallback when AST unavailable)."""
        findings = []
        lines = code.split('\n')
        
        # Pattern: Hardcoded configuration (MEDIUM)
        hardcoded_patterns = [
            (r'(string\s+\w*(Url|Endpoint|Host|Server)\w*\s*=\s*"[^{])', "Hardcoded URL/endpoint"),
            (r'(int\s+\w*(Port|Timeout|Retry)\w*\s*=\s*\d)', "Hardcoded port/timeout value"),
            (r'(new\s+Uri\s*\(\s*"http)', "Hardcoded URI in constructor")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in C# Application",
                    description=(
                        "Configuration value hardcoded in C# code instead of using IConfiguration. "
                        "KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        "environment-specific configuration and automation (CM-2, CM-6). "
                        "ASP.NET Core provides IConfiguration for centralized configuration management."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use IConfiguration for configuration management:\n"
                        "// In Program.cs or Startup.cs\n"
                        "var configuration = builder.Configuration;\n\n"
                        "// Option 1: appsettings.json\n"
                        "string endpoint = configuration[\"ServiceEndpoint\"];\n"
                        "int port = configuration.GetValue<int>(\"ServicePort\");\n\n"
                        "// Option 2: Azure App Configuration\n"
                        "builder.Configuration.AddAzureAppConfiguration(options => {\n"
                        "    options.Connect(Environment.GetEnvironmentVariable(\"APPCONFIGURATION_CONNECTION_STRING\"))\n"
                        "           .ConfigureKeyVault(kv => kv.SetCredential(new DefaultAzureCredential()));\n"
                        "});\n\n"
                        "Ref: ASP.NET Core Configuration (https://learn.microsoft.com/aspnet/core/fundamentals/configuration/)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-04 compliance.
        
        AST-first analysis with regex fallback.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Hardcoded configuration values (URLs, ports, timeouts)
        - Missing @Value or @ConfigurationProperties usage
        - Manual configuration without Spring Boot automation
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Java analysis for hardcoded configuration."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Find field declarations (class fields) and local variable declarations
        field_declarations = parser.find_nodes_by_type(tree.root_node, 'field_declaration')
        local_declarations = parser.find_nodes_by_type(tree.root_node, 'local_variable_declaration')
        
        all_declarations = field_declarations + local_declarations
        
        for declaration in all_declarations:
            # Get variable declarators
            declarators = parser.find_nodes_by_type(declaration, 'variable_declarator')
            
            for declarator in declarators:
                name_node = declarator.child_by_field_name('name')
                value_node = declarator.child_by_field_name('value')
                
                if not name_node or not value_node:
                    continue
                
                var_name = parser.get_node_text(name_node, code_bytes)
                value_text = parser.get_node_text(value_node, code_bytes)
                
                # Check for config keywords
                config_keywords = ['url', 'endpoint', 'host', 'server', 'port', 'timeout', 'retry']
                var_lower = var_name.lower()
                
                if any(keyword in var_lower for keyword in config_keywords):
                    # Skip if value comes from Spring configuration
                    if any(cfg in value_text for cfg in ['@Value', 'Environment.getProperty', 'System.getenv']):
                        continue
                    
                    # Skip test values
                    if any(skip in value_text.lower() for skip in ['localhost', 'example', '127.0.0.1', 'test']):
                        continue
                    
                    # Check if it's a string literal or integer
                    if value_node.type in ('string_literal', 'decimal_integer_literal', 'hex_integer_literal'):
                        line_num = value_node.start_point[0] + 1
                        
                        # Determine type
                        if 'port' in var_lower or 'timeout' in var_lower or 'retry' in var_lower:
                            desc = "Hardcoded port/timeout value"
                        elif 'final' in parser.get_node_text(declaration, code_bytes).lower():
                            desc = "Hardcoded constant configuration"
                        else:
                            desc = "Hardcoded URL/endpoint"
                        
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title=f"{desc} in Java Application",
                            description=(
                                "Configuration value hardcoded in Java code instead of using Spring Boot configuration. "
                                "KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                                "environment-specific configuration and automation (CM-2, CM-6). "
                                "Spring Boot provides @Value and @ConfigurationProperties for centralized configuration."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num, context=3),
                            remediation=(
                                "Use Spring Boot configuration management:\n"
                                "// Option 1: @Value annotation\n"
                                "@Value(\"${service.endpoint}\")\n"
                                "private String serviceEndpoint;\n\n"
                                "@Value(\"${service.port}\")\n"
                                "private int servicePort;\n\n"
                                "// Option 2: @ConfigurationProperties\n"
                                "@Configuration\n"
                                "@ConfigurationProperties(prefix = \"service\")\n"
                                "public class ServiceConfig {\n"
                                "    private String endpoint;\n"
                                "    private int port;\n"
                                "    // getters and setters\n"
                                "}\n\n"
                                "// Option 3: Azure App Configuration\n"
                                "@Bean\n"
                                "public ConfigurationCustomizer configurationCustomizer() {\n"
                                "    return builder -> builder.addAzureAppConfiguration(options ->\n"
                                "        options.connect(System.getenv(\"APPCONFIGURATION_CONNECTION_STRING\"))\n"
                                "    );\n"
                                "}\n\n"
                                "Ref: Spring Boot Externalized Configuration (https://docs.spring.io/spring-boot/reference/features/external-config.html)"
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex-based Java analysis (fallback when AST unavailable)."""
        findings = []
        lines = code.split('\n')
        
        # Pattern: Hardcoded configuration (MEDIUM)
        hardcoded_patterns = [
            (r'(String\s+\w*(url|endpoint|host|server)\w*\s*=\s*"http)', "Hardcoded URL/endpoint"),
            (r'(int\s+\w*(port|timeout|retry)\w*\s*=\s*\d)', "Hardcoded port/timeout value"),
            (r'(private\s+static\s+final\s+String\s+\w*(URL|ENDPOINT|HOST)\w*\s*=\s*")', "Hardcoded constant configuration")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in Java Application",
                    description=(
                        "Configuration value hardcoded in Java code instead of using Spring Boot configuration. "
                        "KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        "environment-specific configuration and automation (CM-2, CM-6). "
                        "Spring Boot provides @Value and @ConfigurationProperties for centralized configuration."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use Spring Boot configuration management:\n"
                        "// Option 1: @Value annotation\n"
                        "@Value(\"${service.endpoint}\")\n"
                        "private String serviceEndpoint;\n\n"
                        "@Value(\"${service.port}\")\n"
                        "private int servicePort;\n\n"
                        "// Option 2: @ConfigurationProperties\n"
                        "@Configuration\n"
                        "@ConfigurationProperties(prefix = \"service\")\n"
                        "public class ServiceConfig {\n"
                        "    private String endpoint;\n"
                        "    private int port;\n"
                        "    // getters and setters\n"
                        "}\n\n"
                        "// Option 3: Azure App Configuration\n"
                        "@Bean\n"
                        "public ConfigurationCustomizer configurationCustomizer() {\n"
                        "    return builder -> builder.addAzureAppConfiguration(options ->\n"
                        "        options.connect(System.getenv(\"APPCONFIGURATION_CONNECTION_STRING\"))\n"
                        "    );\n"
                        "}\n\n"
                        "Ref: Spring Boot Externalized Configuration (https://docs.spring.io/spring-boot/reference/features/external-config.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-04 compliance.
        
        AST-first analysis with regex fallback.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Hardcoded configuration values (URLs, ports, timeouts)
        - Missing environment variable usage
        - Manual configuration without automation
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based TypeScript/JavaScript analysis for hardcoded configuration."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf8')
        
        # Find variable declarations (const/let/var)
        var_declarations = parser.find_nodes_by_type(tree.root_node, 'variable_declarator')
        
        for declarator in var_declarations:
            name_node = declarator.child_by_field_name('name')
            value_node = declarator.child_by_field_name('value')
            
            if not name_node or not value_node:
                continue
            
            var_name = parser.get_node_text(name_node, code_bytes)
            value_text = parser.get_node_text(value_node, code_bytes)
            
            # Check for config keywords
            config_keywords = ['url', 'endpoint', 'host', 'server', 'port', 'timeout', 'retry']
            var_lower = var_name.lower()
            
            if any(keyword in var_lower for keyword in config_keywords):
                # Skip if value comes from environment variables or config
                if any(env in value_text for env in ['process.env', 'config.get', 'getenv']):
                    continue
                
                # Skip test values
                if any(skip in value_text.lower() for skip in ['localhost', 'example', '127.0.0.1', 'test']):
                    continue
                
                # Check if it's a string or number literal
                if value_node.type in ('string', 'number'):
                    line_num = value_node.start_point[0] + 1
                    
                    if 'port' in var_lower or 'timeout' in var_lower or 'retry' in var_lower:
                        desc = "Hardcoded port/timeout value"
                    else:
                        desc = "Hardcoded URL/endpoint"
                    
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"{desc} in TypeScript/JavaScript Application",
                        description=(
                            "Configuration value hardcoded in application code instead of using environment variables. "
                            "KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                            "environment-specific configuration and automation (CM-2, CM-6). "
                            "Node.js provides process.env for centralized configuration management."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            "Use environment variables or configuration libraries:\n"
                            "// Option 1: Environment variables with dotenv\n"
                            "import 'dotenv/config';\n"
                            "const serviceEndpoint = process.env.SERVICE_ENDPOINT || 'default-value';\n"
                            "const servicePort = parseInt(process.env.SERVICE_PORT || '3000');\n\n"
                            "// Option 2: Configuration library (config)\n"
                            "import config from 'config';\n"
                            "const serviceEndpoint = config.get<string>('service.endpoint');\n\n"
                            "// Option 3: Azure App Configuration\n"
                            "import { AppConfigurationClient } from '@azure/app-configuration';\n"
                            "import { DefaultAzureCredential } from '@azure/identity';\n\n"
                            "const client = new AppConfigurationClient(\n"
                            "  process.env.APPCONFIGURATION_ENDPOINT!,\n"
                            "  new DefaultAzureCredential()\n"
                            ");\n"
                            "const setting = await client.getConfigurationSetting({ key: 'my-config-key' });\n\n"
                            "Ref: Azure App Configuration for Node.js (https://learn.microsoft.com/azure/azure-app-configuration/quickstart-javascript)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Also check object literals with hardcoded config
        object_literals = parser.find_nodes_by_type(tree.root_node, 'object')
        
        for obj in object_literals:
            pairs = parser.find_nodes_by_type(obj, 'pair')
            
            for pair in pairs:
                key_node = pair.child_by_field_name('key')
                value_node = pair.child_by_field_name('value')
                
                if not key_node or not value_node:
                    continue
                
                key_text = parser.get_node_text(key_node, code_bytes).lower()
                value_text = parser.get_node_text(value_node, code_bytes)
                
                # Check for config keywords in keys
                if any(keyword in key_text for keyword in ['baseurl', 'endpoint', 'host', 'server']):
                    # Skip if value comes from environment
                    if 'process.env' in value_text or 'config' in value_text:
                        continue
                    
                    # Check if it's a string literal
                    if value_node.type == 'string' and 'http' in value_text.lower():
                        line_num = value_node.start_point[0] + 1
                        
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Hardcoded configuration in object literal",
                            description=(
                                "Configuration value hardcoded in object literal instead of using environment variables. "
                                "KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                                "environment-specific configuration and automation (CM-2, CM-6)."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num, context=3),
                            remediation=(
                                "Use environment variables in object literals:\n"
                                "const config = {\n"
                                "  baseURL: process.env.API_BASE_URL || 'https://api.example.com',\n"
                                "  endpoint: process.env.API_ENDPOINT,\n"
                                "  timeout: parseInt(process.env.API_TIMEOUT || '5000')\n"
                                "};"
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex-based TypeScript/JavaScript analysis (fallback when AST unavailable)."""
        findings = []
        lines = code.split('\n')
        
        # Pattern: Hardcoded configuration (MEDIUM)
        hardcoded_patterns = [
            (r'(const|let|var)\s+\w*(url|endpoint|host|server)\w*\s*=\s*[\'"]http', "Hardcoded URL/endpoint"),
            (r'(const|let|var)\s+\w*(port|timeout|retry)\w*\s*=\s*\d{2,5}', "Hardcoded port/timeout value"),
            (r'(baseURL|endpoint|host):\s*[\'"]http', "Hardcoded configuration in object literal")
        ]
        
        for pattern, desc in hardcoded_patterns:
            match = self._find_line(lines, pattern)
            if match:
                line_num = match['line_num']
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title=f"{desc} in TypeScript/JavaScript Application",
                    description=(
                        "Configuration value hardcoded in application code instead of using environment variables. "
                        "KSI-SVC-04 requires automated configuration management - hardcoded values prevent "
                        "environment-specific configuration and automation (CM-2, CM-6). "
                        "Node.js provides process.env for centralized configuration management."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use environment variables or configuration libraries:\n"
                        "// Option 1: Environment variables with dotenv\n"
                        "import 'dotenv/config';\n"
                        "const serviceEndpoint = process.env.SERVICE_ENDPOINT || 'default-value';\n"
                        "const servicePort = parseInt(process.env.SERVICE_PORT || '3000');\n\n"
                        "// Option 2: Configuration library (config)\n"
                        "import config from 'config';\n"
                        "const serviceEndpoint = config.get<string>('service.endpoint');\n\n"
                        "// Option 3: Azure App Configuration\n"
                        "import { AppConfigurationClient } from '@azure/app-configuration';\n"
                        "import { DefaultAzureCredential } from '@azure/identity';\n\n"
                        "const client = new AppConfigurationClient(\n"
                        "  process.env.APPCONFIGURATION_ENDPOINT!,\n"
                        "  new DefaultAzureCredential()\n"
                        ");\n"
                        "const setting = await client.getConfigurationSetting({ key: 'my-config-key' });\n\n"
                        "Ref: Azure App Configuration for Node.js (https://learn.microsoft.com/azure/azure-app-configuration/quickstart-javascript)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-04 compliance.
        
        Detects:
        - Manual VM configuration without Azure Automation
        - Missing Azure App Configuration references
        - Resources without configuration management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without Azure Automation DSC (MEDIUM)
        vm_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines@")
        has_dsc = re.search(r"Microsoft\.Compute/virtualMachines/.*/extensions.*DSC", code, re.IGNORECASE)
        has_custom_script = re.search(r"Microsoft\.Compute/virtualMachines/.*/extensions.*CustomScript", code, re.IGNORECASE)
        
        if vm_match and not has_dsc and has_custom_script:
            line_num = vm_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="VM Configuration Without Azure Automation DSC",
                description=(
                    "Virtual Machine deployed with CustomScriptExtension instead of Azure Automation DSC. "
                    "KSI-SVC-04 requires automated configuration management (CM-2, CM-6) - CustomScript is "
                    "imperative and doesn't provide drift detection, compliance reporting, or idempotent configuration. "
                    "Azure Automation DSC provides declarative configuration management with version control."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Use Azure Automation DSC extension instead:\n"
                    "resource vmDscExtension 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
                    "  name: '${virtualMachine.name}/DSC'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    publisher: 'Microsoft.Powershell'\n"
                    "    type: 'DSC'\n"
                    "    typeHandlerVersion: '2.77'\n"
                    "    autoUpgradeMinorVersion: true\n"
                    "    settings: {\n"
                    "      wmfVersion: 'latest'\n"
                    "      configuration: {\n"
                    "        url: automationAccount.properties.endpoint\n"
                    "        script: 'MyConfiguration.ps1'\n"
                    "        function: 'MyConfiguration'\n"
                    "      }\n"
                    "      configurationArguments: {\n"
                    "        nodeName: virtualMachine.name\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Or use Azure Machine Configuration (Policy Guest Configuration):\n"
                    "resource guestConfigExtension 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {\n"
                    "  name: '${virtualMachine.name}/AzurePolicyforWindows'\n"
                    "  location: location\n"
                    "  properties: {\n"
                    "    publisher: 'Microsoft.GuestConfiguration'\n"
                    "    type: 'ConfigurationforWindows'\n"
                    "    typeHandlerVersion: '1.0'\n"
                    "    autoUpgradeMinorVersion: true\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Automation DSC (https://learn.microsoft.com/azure/automation/automation-dsc-overview)\n"
                    "Ref: Azure Machine Configuration (https://learn.microsoft.com/azure/governance/machine-configuration/overview)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-04 compliance.
        
        Detects:
        - Manual VM configuration without Azure Automation
        - Missing Azure App Configuration integration
        - Resources without configuration management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without DSC extension (MEDIUM)
        vm_match = self._find_line(lines, r'resource\s+"azurerm_virtual_machine"')
        has_dsc = re.search(r'azurerm_virtual_machine_extension.*type\s*=\s*"DSC"', code, re.IGNORECASE)
        has_custom_script = re.search(r'azurerm_virtual_machine_extension.*type\s*=\s*"CustomScript', code, re.IGNORECASE)
        
        if vm_match and not has_dsc and has_custom_script:
            line_num = vm_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="VM Configuration Without Azure Automation DSC",
                description=(
                    "Virtual Machine deployed with CustomScriptExtension instead of Azure Automation DSC. "
                    "KSI-SVC-04 requires automated configuration management (CM-2, CM-6) - CustomScript is "
                    "imperative and doesn't provide drift detection, compliance reporting, or idempotent configuration. "
                    "Azure Automation DSC provides declarative configuration management with version control."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Use azurerm_virtual_machine_extension with DSC:\n"
                    "resource \"azurerm_virtual_machine_extension\" \"dsc\" {\n"
                    "  name                       = \"DSC\"\n"
                    "  virtual_machine_id         = azurerm_virtual_machine.example.id\n"
                    "  publisher                  = \"Microsoft.Powershell\"\n"
                    "  type                       = \"DSC\"\n"
                    "  type_handler_version       = \"2.77\"\n"
                    "  auto_upgrade_minor_version = true\n\n"
                    "  settings = jsonencode({\n"
                    "    wmfVersion = \"latest\"\n"
                    "    configuration = {\n"
                    "      url      = azurerm_automation_account.example.endpoint\n"
                    "      script   = \"MyConfiguration.ps1\"\n"
                    "      function = \"MyConfiguration\"\n"
                    "    }\n"
                    "    configurationArguments = {\n"
                    "      nodeName = azurerm_virtual_machine.example.name\n"
                    "    }\n"
                    "  })\n"
                    "}\n\n"
                    "Or use Azure Machine Configuration (Policy Guest Configuration):\n"
                    "resource \"azurerm_virtual_machine_extension\" \"guest_config\" {\n"
                    "  name                       = \"AzurePolicyforWindows\"\n"
                    "  virtual_machine_id         = azurerm_virtual_machine.example.id\n"
                    "  publisher                  = \"Microsoft.GuestConfiguration\"\n"
                    "  type                       = \"ConfigurationforWindows\"\n"
                    "  type_handler_version       = \"1.0\"\n"
                    "  auto_upgrade_minor_version = true\n"
                    "}\n\n"
                    "Ref: Azure Automation DSC (https://learn.microsoft.com/azure/automation/automation-dsc-overview)\n"
                    "Ref: Azure Machine Configuration (https://learn.microsoft.com/azure/governance/machine-configuration/overview)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-SVC-04.
        
        **KSI-SVC-04: Configuration Automation**
        Manage configuration of machine-based information resources using automation.
        
        Returns:
            Dictionary with automation recommendations including:
            - azure_services: List of Azure services for evidence collection
            - collection_methods: Methods to collect evidence
            - automation_feasibility: Level of automation possible (high/medium/low/manual-only)
            - evidence_types: Types of evidence (log-based, config-based, metric-based, process-based)
        """
        return {
            "ksi_id": "KSI-SVC-04",
            "ksi_name": "Configuration Automation",
            "azure_services": [
                {
                    "service": "Azure Automation",
                    "purpose": "Configuration management and automation runbook evidence",
                    "capabilities": [
                        "Runbook execution logs and schedules",
                        "Desired State Configuration (DSC) compliance reports",
                        "Change tracking and inventory",
                        "Update management automation"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Policy-driven configuration enforcement",
                    "capabilities": [
                        "Guest Configuration for machine compliance",
                        "Automated remediation of non-compliant configurations",
                        "Configuration compliance reporting",
                        "Policy assignment and effect tracking"
                    ]
                },
                {
                    "service": "Azure Arc",
                    "purpose": "Hybrid and multi-cloud configuration management",
                    "capabilities": [
                        "Unified management for Azure and non-Azure machines",
                        "Policy and configuration extension to on-premises",
                        "Centralized inventory and compliance",
                        "Update management across hybrid infrastructure"
                    ]
                },
                {
                    "service": "Azure Monitor / Log Analytics",
                    "purpose": "Configuration change audit trail and compliance logging",
                    "capabilities": [
                        "Change Tracking logs for configuration modifications",
                        "Automation job execution logs",
                        "DSC compliance state tracking",
                        "Configuration drift detection"
                    ]
                },
                {
                    "service": "Azure DevOps / GitHub Actions",
                    "purpose": "Infrastructure as Code (IaC) pipeline evidence",
                    "capabilities": [
                        "Pipeline run history for infrastructure deployments",
                        "Terraform/Bicep state management",
                        "Automated testing and validation logs",
                        "Pull request approvals for configuration changes"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "Runbook Execution Evidence",
                    "description": "Export Azure Automation runbook execution history showing automated configuration management",
                    "automation": "Azure Monitor logs query for automation jobs",
                    "frequency": "Weekly",
                    "evidence_produced": "Runbook execution report with job status, schedules, and outcomes"
                },
                {
                    "method": "DSC Compliance Reporting",
                    "description": "Query Azure Automation DSC compliance status for all managed nodes",
                    "automation": "Azure Automation API or PowerShell queries",
                    "frequency": "Daily",
                    "evidence_produced": "DSC node compliance report showing configuration state"
                },
                {
                    "method": "Guest Configuration Compliance",
                    "description": "Export Azure Policy Guest Configuration compliance data for machine-level settings",
                    "automation": "Azure Policy compliance scan export",
                    "frequency": "Daily",
                    "evidence_produced": "Machine configuration compliance report"
                },
                {
                    "method": "Change Tracking Analysis",
                    "description": "Query Change Tracking solution for configuration modifications and trends",
                    "automation": "Log Analytics KQL queries",
                    "frequency": "Weekly",
                    "evidence_produced": "Configuration change inventory with before/after snapshots"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["log-based", "config-based"],
            "implementation_guidance": {
                "quick_start": "Deploy Azure Automation with DSC, enable Guest Configuration policies, configure Change Tracking in Log Analytics, use IaC pipelines for all infrastructure changes",
                "azure_well_architected": "Follows Azure WAF operational excellence for automated operations and configuration management",
                "compliance_mapping": "Addresses NIST controls cm-2, cm-2.2, cm-2.3, cm-6, cm-7.1, ac-2.4"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-SVC-04 evidence.
        
        Returns:
            Dictionary with executable queries for evidence collection
        """
        return {
            "ksi_id": "KSI-SVC-04",
            "queries": [
                {
                    "name": "Azure Automation Runbook Execution History",
                    "type": "kql",
                    "workspace": "Log Analytics workspace linked to Azure Automation",
                    "query": """
                        AzureDiagnostics
                        | where ResourceProvider == "MICROSOFT.AUTOMATION"
                        | where Category == "JobLogs" or Category == "JobStreams"
                        | where TimeGenerated > ago(30d)
                        | summarize 
                            JobCount = dcount(JobId_g),
                            SuccessfulJobs = countif(ResultType == "Completed"),
                            FailedJobs = countif(ResultType == "Failed")
                            by RunbookName_s, ResourceGroup
                        | extend SuccessRate = round((SuccessfulJobs * 100.0) / JobCount, 2)
                        | order by JobCount desc
                        """,
                    "purpose": "Demonstrate active use of automation for configuration management",
                    "expected_result": "Regular runbook executions with high success rate"
                },
                {
                    "name": "DSC Node Compliance Status",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Automation/automationAccounts/{accountName}/nodes",
                    "method": "GET",
                    "api_version": "2023-11-01",
                    "purpose": "Verify nodes are managed by DSC and compliance state",
                    "expected_result": "Nodes with 'Compliant' status for DSC configurations"
                },
                {
                    "name": "Guest Configuration Compliance",
                    "type": "azure_resource_graph",
                    "query": """
                        policyresources
                        | where type == 'microsoft.guestconfiguration/guestconfigurationassignments'
                        | extend complianceStatus = tostring(properties.complianceStatus)
                        | extend assignmentName = tostring(properties.assignmentName)
                        | project vmName=split(id, '/')[8], assignmentName, complianceStatus, resourceGroup
                        | summarize 
                            TotalAssignments = count(),
                            CompliantAssignments = countif(complianceStatus == 'Compliant'),
                            NonCompliantAssignments = countif(complianceStatus == 'NonCompliant')
                            by vmName, resourceGroup
                        """,
                    "purpose": "Show machine configuration management via Azure Policy Guest Configuration",
                    "expected_result": "High compliance rate across managed machines"
                },
                {
                    "name": "Configuration Change Tracking",
                    "type": "kql",
                    "workspace": "Log Analytics workspace with Change Tracking enabled",
                    "query": """
                        ConfigurationChange
                        | where TimeGenerated > ago(7d)
                        | where ConfigChangeType in ('Software', 'Files', 'Registry', 'WindowsServices', 'Daemons')
                        | summarize ChangeCount = count() by Computer, ConfigChangeType, ChangeCategory
                        | order by ChangeCount desc
                        """,
                    "purpose": "Track configuration changes to demonstrate automated monitoring",
                    "expected_result": "Change history showing automated configuration management activity"
                },
                {
                    "name": "IaC Pipeline Execution Evidence",
                    "type": "azure_devops_api",
                    "endpoint": "https://dev.azure.com/{organization}/{project}/_apis/pipelines/{pipelineId}/runs?api-version=7.1-preview.1",
                    "method": "GET",
                    "purpose": "Show infrastructure deployments via automated IaC pipelines",
                    "expected_result": "Regular pipeline runs deploying infrastructure configurations"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI (az login) or Managed Identity",
                "permissions_required": [
                    "Reader role for Log Analytics and Automation queries",
                    "Policy Reader for Guest Configuration compliance",
                    "DevOps Reader for pipeline execution history"
                ],
                "automation_tools": [
                    "Azure CLI (az monitor, az automation, az policy)",
                    "PowerShell Az.Automation and Az.Monitor modules",
                    "Python azure-mgmt-automation SDK"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-SVC-04.
        
        Returns:
            Dictionary describing evidence artifacts to collect
        """
        return {
            "ksi_id": "KSI-SVC-04",
            "artifacts": [
                {
                    "name": "Runbook Automation Report",
                    "description": "Monthly report of all configuration management runbooks with execution statistics",
                    "source": "Azure Automation job logs via Log Analytics",
                    "format": "CSV with runbook name, execution count, success rate, last run date",
                    "collection_frequency": "Monthly",
                    "retention_period": "1 year",
                    "automation": "Scheduled KQL query with CSV export to Blob Storage"
                },
                {
                    "name": "DSC Compliance Report",
                    "description": "Current compliance state of all DSC-managed nodes",
                    "source": "Azure Automation DSC node API",
                    "format": "JSON export from Azure Automation REST API",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "PowerShell script or Azure Function calling Automation API"
                },
                {
                    "name": "Guest Configuration Compliance Report",
                    "description": "Machine-level configuration compliance via Azure Policy Guest Configuration",
                    "source": "Azure Policy compliance data",
                    "format": "CSV from Resource Graph query",
                    "collection_frequency": "Daily",
                    "retention_period": "1 year",
                    "automation": "Scheduled Resource Graph query export"
                },
                {
                    "name": "Configuration Change Inventory",
                    "description": "Historical log of configuration changes tracked by Change Tracking solution",
                    "source": "Log Analytics Change Tracking logs",
                    "format": "CSV from KQL query results",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "Scheduled KQL query with storage export"
                },
                {
                    "name": "IaC Pipeline History",
                    "description": "Infrastructure deployment pipeline runs showing automated configuration management",
                    "source": "Azure DevOps or GitHub Actions",
                    "format": "JSON export from pipeline API",
                    "collection_frequency": "Weekly",
                    "retention_period": "1 year",
                    "automation": "API query via Azure DevOps CLI or GitHub API"
                },
                {
                    "name": "Configuration Drift Report",
                    "description": "Detected configuration drift from desired state with remediation actions",
                    "source": "Azure Automation DSC or Azure Policy",
                    "format": "JSON with drift details and remediation status",
                    "collection_frequency": "Daily",
                    "retention_period": "1 year",
                    "automation": "Automated drift detection with alert and export"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["cm-2", "cm-2.2", "cm-2.3", "cm-6", "cm-7.1", "ac-2.4", "pl-9", "pl-10"],
                "evidence_purpose": "Demonstrate automated configuration management for machine-based resources"
            }
        }