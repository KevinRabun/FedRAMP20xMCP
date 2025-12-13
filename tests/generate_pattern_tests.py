#!/usr/bin/env python3
"""
Pattern Test Generator

Automatically generates comprehensive test suites for all pattern YAML files.
Creates positive and negative test cases for each pattern with realistic code examples.
"""
import yaml
import os
from pathlib import Path
from typing import Dict, List, Any


class PatternTestGenerator:
    """Generates pytest test files for pattern detection"""
    
    def __init__(self, pattern_dir: str, output_dir: str):
        self.pattern_dir = Path(pattern_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def generate_all_tests(self):
        """Generate test files for all pattern families"""
        pattern_files = list(self.pattern_dir.glob("*_patterns.yaml"))
        
        print(f"Generating tests for {len(pattern_files)} pattern files...")
        
        for pattern_file in pattern_files:
            if pattern_file.stem == "pattern_schema":
                continue
                
            family = pattern_file.stem.replace("_patterns", "")
            print(f"  Processing {family}...")
            
            patterns = self.load_patterns(pattern_file)
            test_code = self.generate_test_file(family, patterns)
            
            output_file = self.output_dir / f"test_{family}_patterns.py"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(test_code)
            
            print(f"    Generated {output_file.name} with {len(patterns)} pattern tests")
        
        print(f"\nGenerated {len(pattern_files)} test files in {self.output_dir}")
    
    def load_patterns(self, pattern_file: Path) -> List[Dict[str, Any]]:
        """Load all patterns from a YAML file"""
        with open(pattern_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Parse all YAML documents
        patterns = list(yaml.safe_load_all(content))
        # Filter out None values
        return [p for p in patterns if p is not None]
    
    def generate_test_file(self, family: str, patterns: List[Dict[str, Any]]) -> str:
        """Generate complete test file for a pattern family"""
        
        family_upper = family.upper()
        test_imports = self._generate_imports()
        test_class = self._generate_test_class(family, family_upper, patterns)
        
        return f'''{test_imports}

{test_class}

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
'''
    
    def _generate_imports(self) -> str:
        """Generate import statements"""
        return '''"""
Auto-generated tests for pattern detection.
Tests both positive cases (pattern should detect) and negative cases (should not detect).
"""
import pytest
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.generic_analyzer import GenericPatternAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity'''
    
    def _generate_test_class(self, family: str, family_upper: str, patterns: List[Dict[str, Any]]) -> str:
        """Generate test class for a family"""
        
        class_header = f'''class Test{family_upper.title()}Patterns:
    """Test {family_upper} pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer
'''
        
        # Generate tests for each pattern
        test_methods = []
        for i, pattern in enumerate(patterns):
            if not pattern or 'pattern_id' not in pattern:
                continue
            
            test_methods.append(self._generate_pattern_test(pattern))
        
        return class_header + "\n".join(test_methods)
    
    def _generate_pattern_test(self, pattern: Dict[str, Any]) -> str:
        """Generate positive and negative test for a single pattern"""
        
        pattern_id = pattern.get('pattern_id', 'unknown')
        name = pattern.get('name', 'Unknown Pattern')
        description = pattern.get('description', '').split('\n')[0][:80]
        languages = pattern.get('languages', {})
        
        # Get first supported language for testing
        lang = self._get_primary_language(languages)
        
        # Generate test code examples
        positive_code = self._generate_positive_example(pattern, lang)
        negative_code = self._generate_negative_example(pattern, lang)
        
        # Create test method
        safe_method_name = pattern_id.replace('.', '_').replace('-', '_')
        
        return f'''
    def test_{safe_method_name}_positive(self, analyzer):
        """Test {pattern_id}: {name} - Should detect"""
        code = """{positive_code}"""
        
        result = analyzer.analyze(code, "{lang}")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "{pattern_id}" == f.pattern_id]
        assert len(findings) > 0, f"Pattern {pattern_id} should detect this code"
    
    def test_{safe_method_name}_negative(self, analyzer):
        """Test {pattern_id}: {name} - Should NOT detect"""
        code = """{negative_code}"""
        
        result = analyzer.analyze(code, "{lang}")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "{pattern_id}" == f.pattern_id]
        assert len(findings) == 0, f"Pattern {pattern_id} should NOT detect compliant code"
'''
    
    def _get_primary_language(self, languages: Dict) -> str:
        """Get primary language for testing"""
        # Priority order
        priority = ['python', 'csharp', 'bicep', 'terraform', 'typescript', 
                   'java', 'javascript', 'github-actions', 'azure-pipelines']
        
        for lang in priority:
            if lang in languages:
                return lang
        
        # Return first available
        if languages:
            return list(languages.keys())[0]
        
        return "python"  # Default fallback
    
    def _generate_positive_example(self, pattern: Dict[str, Any], lang: str) -> str:
        """Generate code that SHOULD trigger the pattern"""
        
        pattern_id = pattern.get('pattern_id', '')
        pattern_type = pattern.get('pattern_type', 'function_call')
        languages = pattern.get('languages', {})
        
        # Get language-specific queries
        lang_config = languages.get(lang, {})
        ast_queries = lang_config.get('ast_queries', [])
        regex_patterns = lang_config.get('regex_patterns', [])
        
        # Generate based on pattern type and queries
        if lang == 'python':
            return self._generate_python_positive(pattern_id, pattern_type, ast_queries, regex_patterns)
        elif lang == 'csharp':
            return self._generate_csharp_positive(pattern_id, pattern_type, ast_queries, regex_patterns)
        elif lang == 'bicep':
            return self._generate_bicep_positive(pattern_id, pattern_type, ast_queries, regex_patterns)
        elif lang == 'terraform':
            return self._generate_terraform_positive(pattern_id, pattern_type, ast_queries, regex_patterns)
        elif lang in ['github-actions', 'azure-pipelines', 'gitlab-ci']:
            return self._generate_cicd_positive(pattern_id, pattern_type, ast_queries, regex_patterns)
        else:
            return self._generate_generic_positive(pattern_id, pattern_type)
    
    def _generate_negative_example(self, pattern: Dict[str, Any], lang: str) -> str:
        """Generate code that should NOT trigger the pattern"""
        
        pattern_id = pattern.get('pattern_id', '')
        
        # Generate compliant/unrelated code
        if lang == 'python':
            return self._generate_python_negative(pattern_id)
        elif lang == 'csharp':
            return self._generate_csharp_negative(pattern_id)
        elif lang == 'bicep':
            return self._generate_bicep_negative(pattern_id)
        elif lang == 'terraform':
            return self._generate_terraform_negative(pattern_id)
        else:
            return self._generate_generic_negative(pattern_id)
    
    # Language-specific positive example generators
    
    def _generate_python_positive(self, pattern_id: str, pattern_type: str, 
                                  ast_queries: List, regex_patterns: List) -> str:
        """Generate Python code that triggers pattern"""
        
        # Extract target from AST queries
        if ast_queries:
            query = ast_queries[0]
            target = query.get('target', '')
            query_type = query.get('query_type', '')
            
            # Handle import patterns with actual library names
            if ('import' in pattern_type or 'import' in pattern_id or 'import' in query_type.lower()) and target:
                # Handle different import formats
                if '.' in target or '@' in target:
                    return f"from {target} import *\n\ndef main():\n    pass"
                else:
                    return f"import {target}\n\ndef main():\n    pass"
            
            # Handle decorator patterns
            elif query_type == 'decorator' or 'decorator' in pattern_type:
                return f"@{target}\ndef protected_view():\n    return 'Protected content'"
            
            # Handle function call patterns
            elif 'function_call' in query_type or 'function_call' in pattern_type:
                if 'login' in target.lower() or 'auth' in target.lower():
                    return f"def authenticate_user(username, password):\n    return {target}(username, password)"
                return f"result = {target}(data)\nprint(result)"
            
            # Handle class patterns
            elif 'class' in pattern_type:
                return f"class MyClass({target}):\n    pass"
        
        # Fallback: analyze regex patterns for specific vulnerability types
        if regex_patterns:
            pattern = regex_patterns[0] if isinstance(regex_patterns, list) else regex_patterns
            
            # Debug mode patterns
            if 'DEBUG' in pattern and 'True' in pattern:
                return "DEBUG = True\napp.debug = True"
            
            # Hardcoded secrets
            if 'password' in pattern.lower() or 'secret' in pattern.lower():
                return 'password = "hardcoded123"\napi_key = "secret"'
            
            # Weak crypto
            if 'md5' in pattern.lower() or 'sha1' in pattern.lower():
                return "import hashlib\nhash = hashlib.md5(data.encode())"
            
            # Code injection
            if 'eval' in pattern or 'exec' in pattern:
                return "user_input = request.args.get('code')\nresult = eval(user_input)"
            
            # Logging patterns
            if 'logging' in pattern.lower() or 'logger' in pattern.lower():
                return "import logging\nlogging.basicConfig(level=logging.INFO)"
            
            return f"# Pattern: {pattern}\ncode_with_pattern = True"
        
        # Pattern-ID based generation (last resort)
        if 'login_without_mfa' in pattern_id or 'login_required' in pattern_id:
            return "def login(username, password):\n    # Login without MFA\n    return authenticate(username, password)"
        elif 'timeout' in pattern_id:
            return "from datetime import timedelta\napp.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)  # Exceeds 30 min"
        elif 'managed_identity' in pattern_id:
            return "# Using connection string instead of managed identity\nconnection = client.connect(connection_string='...')"
        
        # Generic fallback
        return f"# Code that triggers {pattern_id}\ntrigger_pattern = True"
    
    def _generate_csharp_positive(self, pattern_id: str, pattern_type: str,
                                  ast_queries: List, regex_patterns: List) -> str:
        """Generate C# code that triggers pattern"""
        
        if ast_queries:
            query = ast_queries[0]
            target = query.get('target', '')
            
            if 'using' in pattern_type or 'import' in pattern_id:
                return f"using {target};\n\npublic class MyClass\n{{\n}}"
            elif 'attribute' in pattern_type:
                return f"[{target}]\npublic void MyMethod() {{ }}"
        
        return f"// Code that triggers {pattern_id}\npublic class MyClass {{ }}"
    
    def _generate_bicep_positive(self, pattern_id: str, pattern_type: str,
                                 ast_queries: List, regex_patterns: List) -> str:
        """Generate Bicep code that triggers pattern"""
        
        # Extract resource type from AST queries
        if ast_queries:
            query = ast_queries[0]
            target = query.get('target', '')
            
            # Wildcard permissions (check BEFORE rbac since it contains "rbac" too)
            if 'wildcard' in pattern_id.lower() and 'permission' in pattern_id.lower():
                return """resource roleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'CustomRole')
  properties: {
    roleName: 'Custom Admin Role'
    description: 'Role with wildcard permissions'
    permissions: [
      {
        actions: ['*']  // Wildcard - non-compliant
        notActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}"""
            
            # RBAC assignment patterns
            elif 'rbac' in pattern_id.lower() or 'roleAssignment' in target:
                return """resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, 'Contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalId: 'user-principal-id'
    principalType: 'User'
  }
}"""
        
        # Pattern-specific generation
        if 'nsg' in pattern_id.lower():
            return """resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'myNSG'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAll'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}"""
        elif 'keyvault' in pattern_id.lower() or 'vault' in pattern_id.lower():
            if 'soft_delete' in pattern_id:
                return """resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    sku: { name: 'standard' }
    tenantId: tenant().tenantId
    enableSoftDelete: false  // Non-compliant
  }
}"""
            else:
                return """resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    sku: { name: 'standard' }
    tenantId: tenant().tenantId
  }
}"""
        elif 'storage' in pattern_id.lower():
            return """resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true  // Potential issue
  }
}"""
        elif 'log_analytics' in pattern_id.lower() or 'workspace' in pattern_id.lower():
            return """resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'myWorkspace'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}"""
        elif 'monitor' in pattern_id.lower() or 'diagnostic' in pattern_id.lower():
            return """resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diagnostics'
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: []
    metrics: []
  }
}"""
        
        return f"// Bicep code for {pattern_id}\nresource example 'Microsoft.Resources/tags@2022-09-01' = {{}}"
    
    def _generate_terraform_positive(self, pattern_id: str, pattern_type: str,
                                     ast_queries: List, regex_patterns: List) -> str:
        """Generate Terraform code that triggers pattern"""
        
        return f'''resource "azurerm_resource_group" "example" {{
  name     = "example-resources"
  location = "East US"
}}'''
    
    def _generate_cicd_positive(self, pattern_id: str, pattern_type: str,
                               ast_queries: List, regex_patterns: List) -> str:
        """Generate CI/CD YAML that triggers pattern"""
        
        # SAST/scanning patterns
        if 'sast' in pattern_id.lower() or 'scan' in pattern_id.lower():
            return """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run SAST scan
        run: semgrep --config=auto ."""
        
        # Dependency scanning
        elif 'dependency' in pattern_id.lower() or 'sca' in pattern_id.lower():
            return """name: Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Dependency scan
        uses: github/dependency-review-action@v3"""
        
        # Container scanning
        elif 'container' in pattern_id.lower() and 'scan' in pattern_id.lower():
            return """name: Container Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build image
        run: docker build -t myapp:latest .
      - name: Scan image
        run: trivy image myapp:latest"""
        
        # Backup/export patterns
        elif 'backup' in pattern_id.lower() or 'export' in pattern_id.lower():
            return """name: Configuration Backup
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - name: Export configuration
        run: az export --output backup.json"""
        
        # Generic CI/CD
        return """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: echo "Building..." """
    
    def _generate_generic_positive(self, pattern_id: str, pattern_type: str) -> str:
        """Generic positive example"""
        return f"# Code that triggers {pattern_id}"
    
    # Language-specific negative example generators
    
    def _generate_python_negative(self, pattern_id: str) -> str:
        """Generate Python code that does NOT trigger pattern"""
        return """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
    
    def _generate_csharp_negative(self, pattern_id: str) -> str:
        """Generate C# code that does NOT trigger pattern"""
        return """public class CompliantClass
{
    public void CompliantMethod()
    {
        // This is compliant code
    }
}"""
    
    def _generate_bicep_negative(self, pattern_id: str) -> str:
        """Generate Bicep code that does NOT trigger pattern"""
        return """param location string = resourceGroup().location

output resourceLocation string = location
"""
    
    def _generate_terraform_negative(self, pattern_id: str) -> str:
        """Generate Terraform code that does NOT trigger pattern"""
        return """variable "location" {
  type    = string
  default = "East US"
}"""
    
    def _generate_generic_negative(self, pattern_id: str) -> str:
        """Generic negative example"""
        return "# Compliant code that should not trigger detection"


def main():
    """Generate all pattern tests"""
    script_dir = Path(__file__).parent
    pattern_dir = script_dir.parent / "data" / "patterns"
    output_dir = script_dir / "generated_pattern_tests"
    
    generator = PatternTestGenerator(str(pattern_dir), str(output_dir))
    generator.generate_all_tests()
    
    print("\n" + "=" * 70)
    print("Test generation complete!")
    print(f"Generated tests are in: {output_dir}")
    print("=" * 70)


if __name__ == "__main__":
    main()
