"""
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
from fedramp_20x_mcp.analyzers.base import Severity

class TestAdsPatterns:
    """Test ADS pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_ads_machine_readable_json_export_positive(self, analyzer):
        """Test ads.machine_readable.json_export: JSON Export for Audit Data - Should detect"""
        code = """result = json.dumps(data)
print(result)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.machine_readable.json_export" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.machine_readable.json_export should detect this code"
    
    def test_ads_machine_readable_json_export_negative(self, analyzer):
        """Test ads.machine_readable.json_export: JSON Export for Audit Data - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.machine_readable.json_export" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.machine_readable.json_export should NOT detect compliant code"


    def test_ads_machine_readable_xml_export_positive(self, analyzer):
        """Test ads.machine_readable.xml_export: XML Export for Audit Data - Should detect"""
        code = """result = xml.etree.ElementTree(data)
print(result)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.machine_readable.xml_export" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.machine_readable.xml_export should detect this code"
    
    def test_ads_machine_readable_xml_export_negative(self, analyzer):
        """Test ads.machine_readable.xml_export: XML Export for Audit Data - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.machine_readable.xml_export" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.machine_readable.xml_export should NOT detect compliant code"


    def test_ads_api_endpoint_rest_positive(self, analyzer):
        """Test ads.api_endpoint.rest: REST API for Audit Data Access - Should detect"""
        code = """@app.route('/api/audit')
def protected_view():
    return 'Protected content'"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.api_endpoint.rest" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.api_endpoint.rest should detect this code"
    
    def test_ads_api_endpoint_rest_negative(self, analyzer):
        """Test ads.api_endpoint.rest: REST API for Audit Data Access - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.api_endpoint.rest" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.api_endpoint.rest should NOT detect compliant code"


    def test_ads_structured_logging_structured_format_positive(self, analyzer):
        """Test ads.structured_logging.structured_format: Structured Logging Format - Should detect"""
        code = """import structlog

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.structured_logging.structured_format" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.structured_logging.structured_format should detect this code"
    
    def test_ads_structured_logging_structured_format_negative(self, analyzer):
        """Test ads.structured_logging.structured_format: Structured Logging Format - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.structured_logging.structured_format" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.structured_logging.structured_format should NOT detect compliant code"


    def test_ads_audit_fields_required_fields_positive(self, analyzer):
        """Test ads.audit_fields.required_fields: Required Audit Fields - Should detect"""
        code = """audit_record = {
    "timestamp": datetime.now(),
    "userId": current_user.id,
    "action": "data_access",
    "resourceId": resource.id
}"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.audit_fields.required_fields" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.audit_fields.required_fields should detect this code"
    
    def test_ads_audit_fields_required_fields_negative(self, analyzer):
        """Test ads.audit_fields.required_fields: Required Audit Fields - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.audit_fields.required_fields" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.audit_fields.required_fields should NOT detect compliant code"


    def test_ads_query_api_filtering_positive(self, analyzer):
        """Test ads.query_api.filtering: Audit Data Query API - Should detect"""
        code = """def query_audit_logs(start_date, end_date, user_id=None):
    filters = {'timestamp': {'gte': start_date, 'lte': end_date}}
    if user_id:
        filters['user'] = user_id
    return audit_logs.find(filters)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.query_api.filtering" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.query_api.filtering should detect this code"
    
    def test_ads_query_api_filtering_negative(self, analyzer):
        """Test ads.query_api.filtering: Audit Data Query API - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.query_api.filtering" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.query_api.filtering should NOT detect compliant code"


    def test_ads_missing_machine_readable_positive(self, analyzer):
        """Test ads.missing_machine_readable: Missing Machine-Readable Format - Should detect"""
        code = """def export_audit_data():
    # No JSON or XML export
    print('Audit data exported')
    return True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.missing_machine_readable" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.missing_machine_readable should detect this code"
    
    def test_ads_missing_machine_readable_negative(self, analyzer):
        """Test ads.missing_machine_readable: Missing Machine-Readable Format - Should NOT detect"""
        code = """import json

def export_audit_data(data):
    # Has JSON export - compliant
    return json.dumps(data)
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.missing_machine_readable" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.missing_machine_readable should NOT detect compliant code"


    def test_ads_iac_azure_monitor_export_positive(self, analyzer):
        """Test ads.iac.azure_monitor_export: Azure Monitor Data Export - Should detect"""
        code = """resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: 'auditDataCollection'
  location: location
  properties: {
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspace.id
          name: 'auditWorkspace'
        }
      ]
    }
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.iac.azure_monitor_export" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.iac.azure_monitor_export should detect this code"
    
    def test_ads_iac_azure_monitor_export_negative(self, analyzer):
        """Test ads.iac.azure_monitor_export: Azure Monitor Data Export - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.iac.azure_monitor_export" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.iac.azure_monitor_export should NOT detect compliant code"


    def test_ads_iac_log_analytics_workspace_positive(self, analyzer):
        """Test ads.iac.log_analytics_workspace: Log Analytics Workspace for Audit Data - Should detect"""
        code = """resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'myWorkspace'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.iac.log_analytics_workspace" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.iac.log_analytics_workspace should detect this code"
    
    def test_ads_iac_log_analytics_workspace_negative(self, analyzer):
        """Test ads.iac.log_analytics_workspace: Log Analytics Workspace for Audit Data - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.iac.log_analytics_workspace" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.iac.log_analytics_workspace should NOT detect compliant code"


    def test_ads_cicd_audit_export_step_positive(self, analyzer):
        """Test ads.cicd.audit_export_step: CI/CD Audit Data Export Step - Should detect"""
        code = """name: Export Audit Data
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - name: Export audit logs
        run: python scripts/export_audit.py"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.cicd.audit_export_step" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ads.cicd.audit_export_step should detect this code"
    
    def test_ads_cicd_audit_export_step_negative(self, analyzer):
        """Test ads.cicd.audit_export_step: CI/CD Audit Data Export Step - Should NOT detect"""
        code = """name: Simple Pipeline
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: npm test"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ads.cicd.audit_export_step" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ads.cicd.audit_export_step should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
