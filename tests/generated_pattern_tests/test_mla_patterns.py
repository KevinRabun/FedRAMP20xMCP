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

class TestMlaPatterns:
    """Test MLA pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_mla_logging_local_file_positive(self, analyzer):
        """Test mla.logging.local_file: Local File Logging - Should detect"""
        code = """result = FileHandler(data)
print(result)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.logging.local_file" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.logging.local_file should detect this code"
    
    def test_mla_logging_local_file_negative(self, analyzer):
        """Test mla.logging.local_file: Local File Logging - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.logging.local_file" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.logging.local_file should NOT detect compliant code"


    def test_mla_logging_azure_monitor_positive(self, analyzer):
        """Test mla.logging.azure_monitor: Azure Monitor Integration - Should detect"""
        code = """import opencensus.ext.azure

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.logging.azure_monitor" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.logging.azure_monitor should detect this code"
    
    def test_mla_logging_azure_monitor_negative(self, analyzer):
        """Test mla.logging.azure_monitor: Azure Monitor Integration - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.logging.azure_monitor" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.logging.azure_monitor should NOT detect compliant code"


    def test_mla_logging_siem_integration_positive(self, analyzer):
        """Test mla.logging.siem_integration: SIEM Integration - Should detect"""
        code = """import splunk

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.logging.siem_integration" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.logging.siem_integration should detect this code"
    
    def test_mla_logging_siem_integration_negative(self, analyzer):
        """Test mla.logging.siem_integration: SIEM Integration - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.logging.siem_integration" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.logging.siem_integration should NOT detect compliant code"


    def test_mla_retention_log_analytics_workspace_positive(self, analyzer):
        """Test mla.retention.log_analytics_workspace: Log Analytics Workspace Retention - Should detect"""
        code = """// Bicep code for mla.retention.log_analytics_workspace
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.retention.log_analytics_workspace" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.retention.log_analytics_workspace should detect this code"
    
    def test_mla_retention_log_analytics_workspace_negative(self, analyzer):
        """Test mla.retention.log_analytics_workspace: Log Analytics Workspace Retention - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.retention.log_analytics_workspace" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.retention.log_analytics_workspace should NOT detect compliant code"


    def test_mla_monitoring_failed_login_tracking_positive(self, analyzer):
        """Test mla.monitoring.failed_login_tracking: Failed Login Monitoring - Should detect"""
        code = """result = log(data)
print(result)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.monitoring.failed_login_tracking" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.monitoring.failed_login_tracking should detect this code"
    
    def test_mla_monitoring_failed_login_tracking_negative(self, analyzer):
        """Test mla.monitoring.failed_login_tracking: Failed Login Monitoring - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.monitoring.failed_login_tracking" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.monitoring.failed_login_tracking should NOT detect compliant code"


    def test_mla_monitoring_azure_sentinel_analytics_positive(self, analyzer):
        """Test mla.monitoring.azure_sentinel_analytics: Azure Sentinel Analytics Rule - Should detect"""
        code = """// Bicep code for mla.monitoring.azure_sentinel_analytics
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.monitoring.azure_sentinel_analytics" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.monitoring.azure_sentinel_analytics should detect this code"
    
    def test_mla_monitoring_azure_sentinel_analytics_negative(self, analyzer):
        """Test mla.monitoring.azure_sentinel_analytics: Azure Sentinel Analytics Rule - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.monitoring.azure_sentinel_analytics" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.monitoring.azure_sentinel_analytics should NOT detect compliant code"


    def test_mla_alerting_action_group_positive(self, analyzer):
        """Test mla.alerting.action_group: Azure Monitor Action Group - Should detect"""
        code = """// Bicep code for mla.alerting.action_group
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.alerting.action_group" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.alerting.action_group should detect this code"
    
    def test_mla_alerting_action_group_negative(self, analyzer):
        """Test mla.alerting.action_group: Azure Monitor Action Group - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.alerting.action_group" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.alerting.action_group should NOT detect compliant code"


    def test_mla_alerting_metric_alert_positive(self, analyzer):
        """Test mla.alerting.metric_alert: Azure Monitor Metric Alert - Should detect"""
        code = """// Bicep code for mla.alerting.metric_alert
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.alerting.metric_alert" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.alerting.metric_alert should detect this code"
    
    def test_mla_alerting_metric_alert_negative(self, analyzer):
        """Test mla.alerting.metric_alert: Azure Monitor Metric Alert - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.alerting.metric_alert" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.alerting.metric_alert should NOT detect compliant code"


    def test_mla_apm_application_insights_positive(self, analyzer):
        """Test mla.apm.application_insights: Application Insights SDK - Should detect"""
        code = """import applicationinsights

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.apm.application_insights" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.apm.application_insights should detect this code"
    
    def test_mla_apm_application_insights_negative(self, analyzer):
        """Test mla.apm.application_insights: Application Insights SDK - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.apm.application_insights" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.apm.application_insights should NOT detect compliant code"


    def test_mla_audit_activity_log_positive(self, analyzer):
        """Test mla.audit.activity_log: Azure Activity Log Export - Should detect"""
        code = """// Bicep code for mla.audit.activity_log
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.audit.activity_log" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.audit.activity_log should detect this code"
    
    def test_mla_audit_activity_log_negative(self, analyzer):
        """Test mla.audit.activity_log: Azure Activity Log Export - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.audit.activity_log" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.audit.activity_log should NOT detect compliant code"


    def test_mla_audit_resource_logs_missing_positive(self, analyzer):
        """Test mla.audit.resource_logs_missing: Missing Resource Diagnostic Logs - Should detect"""
        code = """// Bicep code for mla.audit.resource_logs_missing
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "mla.audit.resource_logs_missing" in f.requirement_id]
        assert len(findings) > 0, f"Pattern mla.audit.resource_logs_missing should detect this code"
    
    def test_mla_audit_resource_logs_missing_negative(self, analyzer):
        """Test mla.audit.resource_logs_missing: Missing Resource Diagnostic Logs - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "mla.audit.resource_logs_missing" in f.requirement_id]
        assert len(findings) == 0, f"Pattern mla.audit.resource_logs_missing should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
