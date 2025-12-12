#!/usr/bin/env python3
"""
Improved Pattern Test Generator

Generates more accurate test code by analyzing pattern detection logic:
- Extracts targets from AST queries
- Analyzes regex patterns for specific keywords
- Uses positive_indicators where available
- Creates realistic code that matches pattern expectations
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any

class ImprovedPatternTestGenerator:
    """Generates improved pattern-specific test cases"""
    
    def __init__(self, patterns_dir: str, output_dir: str):
        self.patterns_dir = Path(patterns_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_all_tests(self):
        """Generate test files for all pattern families"""
        pattern_files = sorted(self.patterns_dir.glob("*_patterns.yaml"))
        
        total_patterns = 0
        for pattern_file in pattern_files:
            family = pattern_file.stem.replace('_patterns', '')
            if family == 'common':
                continue  # Skip common patterns for now
            
            patterns = self.load_patterns(pattern_file)
            if patterns:
                test_file = self.output_dir / f"test_{family}_patterns.py"
                self.generate_test_file(family, patterns, test_file)
                total_patterns += len(patterns)
                print(f"Updated {test_file.name}: {len(patterns)} patterns")
        
        print(f"\n✓ Total: {total_patterns} patterns updated")
    
    def load_patterns(self, pattern_file: Path) -> List[Dict]:
        """Load all patterns from a YAML file"""
        patterns = []
        try:
            with open(pattern_file, 'r', encoding='utf-8') as f:
                for doc in yaml.safe_load_all(f):
                    if doc and 'pattern_id' in doc:
                        patterns.append(doc)
        except Exception as e:
            print(f"Error loading {pattern_file}: {e}")
        return patterns
    
    def generate_test_file(self, family: str, patterns: List[Dict], output_file: Path):
        """Generate or update a test file with improved positive tests"""
        
        # Read existing test file
        if not output_file.exists():
            print(f"Test file {output_file} not found, skipping")
            return
        
        with open(output_file, 'r', encoding='utf-8') as f:
            existing_content = f.read()
        
        # Update each positive test
        new_content = existing_content
        for pattern in patterns:
            pattern_id = pattern['pattern_id']
            test_method_name = f"test_{pattern_id.replace('.', '_').replace('-', '_')}_positive"
            
            # Generate improved positive test code
            improved_code = self._generate_improved_positive_code(pattern)
            
            if improved_code and test_method_name in new_content:
                # Find and replace the code in the positive test
                start_marker = f'code = """'
                end_marker = '"""'
                
                # Find the test method
                method_start = new_content.find(f"def {test_method_name}(")
                if method_start != -1:
                    # Find the code assignment within the method
                    code_start = new_content.find(start_marker, method_start)
                    if code_start != -1:
                        code_end = new_content.find(end_marker, code_start + len(start_marker))
                        if code_end != -1:
                            # Replace the code
                            old_code_block = new_content[code_start + len(start_marker):code_end]
                            new_content = new_content[:code_start + len(start_marker)] + improved_code + new_content[code_end:]
        
        # Write updated content
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
    
    def _generate_improved_positive_code(self, pattern: Dict) -> str:
        """Generate improved positive test code based on pattern analysis"""
        pattern_id = pattern.get('pattern_id', '')
        pattern_type = pattern.get('pattern_type', '')
        languages = pattern.get('languages', {})
        
        # Try Python first
        if 'python' in languages:
            return self._generate_python_positive(pattern, languages['python'])
        elif 'csharp' in languages:
            return self._generate_csharp_positive(pattern, languages['csharp'])
        elif 'bicep' in languages:
            return self._generate_bicep_positive(pattern, languages['bicep'])
        elif 'terraform' in languages:
            return self._generate_terraform_positive(pattern, languages['terraform'])
        elif 'github_actions' in languages or 'azure_pipelines' in languages or 'gitlab_ci' in languages:
            return self._generate_cicd_positive(pattern, languages)
        
        return None
    
    def _generate_python_positive(self, pattern: Dict, lang_config: Dict) -> str:
        """Generate improved Python positive test code"""
        ast_queries = lang_config.get('ast_queries', [])
        regex = lang_config.get('regex_fallback', '')
        positive_indicators = lang_config.get('positive_indicators', [])
        pattern_type = pattern.get('pattern_type', '')
        
        # For import patterns, use actual target from AST or indicators
        if pattern_type == 'import' or 'import' in pattern.get('pattern_id', ''):
            if ast_queries:
                query = ast_queries[0]
                target = query.get('target', '')
                query_type = query.get('query_type', '')
                
                if target:
                    # Handle from X import Y vs import X
                    if '.' in target or '@' in target:
                        return f"from {target} import *\n\ndef main():\n    pass"
                    else:
                        return f"import {target}\n\ndef main():\n    pass"
            
            # Use positive indicators
            if positive_indicators:
                indicator = positive_indicators[0]
                return f"import {indicator}\n\ndef main():\n    pass"
        
        # For security patterns, generate specific vulnerable code
        if regex:
            # Debug mode patterns
            if 'DEBUG' in regex and 'True' in regex:
                return "DEBUG = True\napp.debug = True"
            
            # Hardcoded secrets
            if 'password' in regex.lower() or 'secret' in regex.lower():
                return 'password = "hardcoded123"\napi_key = "secret-key-here"'
            
            # Weak crypto
            if 'md5' in regex.lower() or 'sha1' in regex.lower():
                return "import hashlib\nhash = hashlib.md5(data.encode())"
            
            # Code injection
            if 'eval' in regex or 'exec' in regex:
                return "user_input = request.args.get('code')\nresult = eval(user_input)"
            
            # Logging
            if 'logging' in regex.lower() or 'logger' in regex.lower():
                return "import logging\nlogging.basicConfig(level=logging.INFO)\nlogger = logging.getLogger(__name__)"
        
        return None
    
    def _generate_csharp_positive(self, pattern: Dict, lang_config: Dict) -> str:
        """Generate improved C# positive test code"""
        ast_queries = lang_config.get('ast_queries', [])
        regex = lang_config.get('regex_fallback', '')
        positive_indicators = lang_config.get('positive_indicators', [])
        pattern_type = pattern.get('pattern_type', '')
        
        # For import/using patterns
        if pattern_type == 'import' or 'using' in str(ast_queries):
            if ast_queries:
                query = ast_queries[0]
                target = query.get('target', '')
                if target:
                    return f"using {target};\n\nnamespace TestApp\n{{\n    class Program\n    {{\n        static void Main(string[] args)\n        {{\n        }}\n    }}\n}}"
            
            if positive_indicators:
                indicator = positive_indicators[0]
                return f"using {indicator};\n\nnamespace TestApp\n{{\n    class Program\n    {{\n        static void Main(string[] args)\n        {{\n        }}\n    }}\n}}"
        
        # Specific security patterns
        if regex:
            if 'UseHsts' in regex:
                return "using Microsoft.AspNetCore.Builder;\n\npublic void Configure(IApplicationBuilder app)\n{\n    app.UseHsts();\n}"
            
            if 'RequireHttpsMetadata.*false' in regex:
                return "options.RequireHttpsMetadata = false;"
            
            if 'MD5' in regex or 'SHA1' in regex:
                return "using System.Security.Cryptography;\nvar hash = MD5.Create();"
        
        return None
    
    def _generate_bicep_positive(self, pattern: Dict, lang_config: Dict) -> str:
        """Generate improved Bicep positive test code"""
        ast_queries = lang_config.get('ast_queries', [])
        regex = lang_config.get('regex_fallback', '')
        
        # Extract resource type and properties from AST queries
        if ast_queries:
            query = ast_queries[0]
            target = query.get('target', '')
            property_name = query.get('property', query.get('attribute', ''))
            expected_value = query.get('expected_value', query.get('value', ''))
            
            if target and 'Microsoft.' in target:
                props = ""
                if property_name and expected_value:
                    # Format the value correctly
                    if isinstance(expected_value, bool):
                        value_str = 'true' if expected_value else 'false'
                    elif isinstance(expected_value, str):
                        value_str = f"'{expected_value}'"
                    else:
                        value_str = str(expected_value)
                    props = f"    {property_name}: {value_str}\n  "
                
                return f"resource example '{target}@2023-01-01' = {{\n  name: 'example'\n  location: resourceGroup().location\n  properties: {{\n  {props}}}\n}}"
        
        # Use regex to infer the vulnerability
        if regex:
            if 'supportsHttpsTrafficOnly.*false' in regex:
                return "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'examplestorage'\n  location: resourceGroup().location\n  properties: {\n    supportsHttpsTrafficOnly: false\n  }\n}"
            
            if 'publicNetworkAccess.*Enabled' in regex:
                return "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'examplestorage'\n  location: resourceGroup().location\n  properties: {\n    publicNetworkAccess: 'Enabled'\n  }\n}"
            
            if 'minimalTlsVersion' in regex and ('1.0' in regex or '1.1' in regex):
                return "resource sqlServer 'Microsoft.Sql/servers@2023-01-01' = {\n  name: 'examplesql'\n  location: resourceGroup().location\n  properties: {\n    minimalTlsVersion: '1.0'\n  }\n}"
            
            if 'retentionInDays' in regex and ('365' in regex or '730' in regex):
                return "resource workspace 'Microsoft.OperationalInsights/workspaces@2023-01-01' = {\n  name: 'exampleworkspace'\n  location: resourceGroup().location\n  properties: {\n    retentionInDays: 365\n  }\n}"
        
        return None
    
    def _generate_terraform_positive(self, pattern: Dict, lang_config: Dict) -> str:
        """Generate improved Terraform positive test code"""
        ast_queries = lang_config.get('ast_queries', [])
        regex = lang_config.get('regex_fallback', '')
        
        # Extract resource type and attributes
        if ast_queries:
            query = ast_queries[0]
            target = query.get('target', '')
            attribute = query.get('attribute', query.get('property', ''))
            expected_value = query.get('expected_value', query.get('value', ''))
            
            if target and 'azurerm_' in target:
                attrs = ""
                if attribute and expected_value is not None:
                    # Format value
                    if isinstance(expected_value, bool):
                        value_str = 'true' if expected_value else 'false'
                    elif isinstance(expected_value, str):
                        value_str = f'"{expected_value}"'
                    else:
                        value_str = str(expected_value)
                    attrs = f"\n  {attribute} = {value_str}"
                
                return f'resource "{target}" "example" {{\n  name     = "example"\n  location = "eastus"{attrs}\n}}'
        
        # Use regex to infer configuration
        if regex:
            if 'enable_https_traffic_only.*false' in regex:
                return 'resource "azurerm_storage_account" "example" {\n  name                     = "examplestorage"\n  resource_group_name      = azurerm_resource_group.example.name\n  location                 = "eastus"\n  enable_https_traffic_only = false\n}'
            
            if 'public_network_access_enabled.*true' in regex:
                return 'resource "azurerm_storage_account" "example" {\n  name                     = "examplestorage"\n  resource_group_name      = azurerm_resource_group.example.name\n  location                 = "eastus"\n  public_network_access_enabled = true\n}'
            
            if 'minimum_tls_version.*1.0' in regex or 'minimum_tls_version.*1.1' in regex:
                return 'resource "azurerm_sql_server" "example" {\n  name                         = "examplesqlserver"\n  resource_group_name          = azurerm_resource_group.example.name\n  location                     = "eastus"\n  version                      = "12.0"\n  minimum_tls_version          = "1.0"\n}'
        
        return None
    
    def _generate_cicd_positive(self, pattern: Dict, languages: Dict) -> str:
        """Generate improved CI/CD pipeline code"""
        
        # Check GitHub Actions
        if 'github_actions' in languages:
            config = languages['github_actions']
            regex = config.get('regex_fallback', '')
            positive_indicators = config.get('positive_indicators', [])
            
            if positive_indicators:
                indicator = positive_indicators[0]
                return f"name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n      - name: Security Scan\n        uses: {indicator}\n"
            
            if regex:
                if 'trivy' in regex.lower():
                    return "name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n      - name: Run Trivy\n        run: trivy scan .\n"
                
                if 'snyk' in regex.lower():
                    return "name: CI\n\non: [push]\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n      - name: Run Snyk\n        run: snyk test\n"
        
        # Check Azure Pipelines
        if 'azure_pipelines' in languages:
            config = languages['azure_pipelines']
            regex = config.get('regex_fallback', '')
            
            if regex and 'trivy' in regex.lower():
                return "trigger:\n  - main\n\npool:\n  vmImage: 'ubuntu-latest'\n\nsteps:\n  - task: UsePythonVersion@0\n  - script: trivy scan .\n    displayName: 'Security Scan'\n"
        
        return None

def main():
    """Main entry point"""
    script_dir = Path(__file__).parent
    patterns_dir = script_dir.parent / "data" / "patterns"
    output_dir = script_dir / "generated_pattern_tests"
    
    generator = ImprovedPatternTestGenerator(patterns_dir, output_dir)
    generator.generate_all_tests()

if __name__ == "__main__":
    main()
