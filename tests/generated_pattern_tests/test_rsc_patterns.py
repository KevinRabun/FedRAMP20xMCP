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

class TestRscPatterns:
    """Test RSC pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_rsc_allocation_resource_limits_positive(self, analyzer):
        """Test rsc.allocation.resource_limits: Resource Limits Configuration - Should detect"""
        code = """# Code that triggers rsc.allocation.resource_limits
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.allocation.resource_limits" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.allocation.resource_limits should detect this code"
    
    def test_rsc_allocation_resource_limits_negative(self, analyzer):
        """Test rsc.allocation.resource_limits: Resource Limits Configuration - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.allocation.resource_limits" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.allocation.resource_limits should NOT detect compliant code"


    def test_rsc_monitoring_resource_metrics_positive(self, analyzer):
        """Test rsc.monitoring.resource_metrics: Resource Metrics Monitoring - Should detect"""
        code = """# Code that triggers rsc.monitoring.resource_metrics
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.monitoring.resource_metrics" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.monitoring.resource_metrics should detect this code"
    
    def test_rsc_monitoring_resource_metrics_negative(self, analyzer):
        """Test rsc.monitoring.resource_metrics: Resource Metrics Monitoring - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.monitoring.resource_metrics" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.monitoring.resource_metrics should NOT detect compliant code"


    def test_rsc_scaling_autoscaling_positive(self, analyzer):
        """Test rsc.scaling.autoscaling: Autoscaling Configuration - Should detect"""
        code = """# Code that triggers rsc.scaling.autoscaling"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.scaling.autoscaling" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.scaling.autoscaling should detect this code"
    
    def test_rsc_scaling_autoscaling_negative(self, analyzer):
        """Test rsc.scaling.autoscaling: Autoscaling Configuration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.scaling.autoscaling" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.scaling.autoscaling should NOT detect compliant code"


    def test_rsc_quota_namespace_quota_positive(self, analyzer):
        """Test rsc.quota.namespace_quota: Namespace Resource Quota - Should detect"""
        code = """# Code that triggers rsc.quota.namespace_quota"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.quota.namespace_quota" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.quota.namespace_quota should detect this code"
    
    def test_rsc_quota_namespace_quota_negative(self, analyzer):
        """Test rsc.quota.namespace_quota: Namespace Resource Quota - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.quota.namespace_quota" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.quota.namespace_quota should NOT detect compliant code"


    def test_rsc_allocation_priority_class_positive(self, analyzer):
        """Test rsc.allocation.priority_class: Priority Class for Resource Allocation - Should detect"""
        code = """# Code that triggers rsc.allocation.priority_class"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.allocation.priority_class" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.allocation.priority_class should detect this code"
    
    def test_rsc_allocation_priority_class_negative(self, analyzer):
        """Test rsc.allocation.priority_class: Priority Class for Resource Allocation - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.allocation.priority_class" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.allocation.priority_class should NOT detect compliant code"


    def test_rsc_cost_budget_alert_positive(self, analyzer):
        """Test rsc.cost.budget_alert: Cost Budget Alerts - Should detect"""
        code = """// Bicep code for rsc.cost.budget_alert
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.cost.budget_alert" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.cost.budget_alert should detect this code"
    
    def test_rsc_cost_budget_alert_negative(self, analyzer):
        """Test rsc.cost.budget_alert: Cost Budget Alerts - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.cost.budget_alert" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.cost.budget_alert should NOT detect compliant code"


    def test_rsc_iac_app_service_plan_positive(self, analyzer):
        """Test rsc.iac.app_service_plan: Azure App Service Plan Configuration - Should detect"""
        code = """// Bicep code for rsc.iac.app_service_plan
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.iac.app_service_plan" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.iac.app_service_plan should detect this code"
    
    def test_rsc_iac_app_service_plan_negative(self, analyzer):
        """Test rsc.iac.app_service_plan: Azure App Service Plan Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.iac.app_service_plan" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.iac.app_service_plan should NOT detect compliant code"


    def test_rsc_iac_vm_size_positive(self, analyzer):
        """Test rsc.iac.vm_size: Virtual Machine Size Configuration - Should detect"""
        code = """// Bicep code for rsc.iac.vm_size
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.iac.vm_size" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.iac.vm_size should detect this code"
    
    def test_rsc_iac_vm_size_negative(self, analyzer):
        """Test rsc.iac.vm_size: Virtual Machine Size Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.iac.vm_size" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.iac.vm_size should NOT detect compliant code"


    def test_rsc_iac_reserved_instances_positive(self, analyzer):
        """Test rsc.iac.reserved_instances: Reserved Instance Usage - Should detect"""
        code = """// Bicep code for rsc.iac.reserved_instances
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.iac.reserved_instances" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.iac.reserved_instances should detect this code"
    
    def test_rsc_iac_reserved_instances_negative(self, analyzer):
        """Test rsc.iac.reserved_instances: Reserved Instance Usage - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.iac.reserved_instances" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.iac.reserved_instances should NOT detect compliant code"


    def test_rsc_cicd_resource_validation_positive(self, analyzer):
        """Test rsc.cicd.resource_validation: Resource Configuration Validation - Should detect"""
        code = """# Code that triggers rsc.cicd.resource_validation"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.cicd.resource_validation" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.cicd.resource_validation should detect this code"
    
    def test_rsc_cicd_resource_validation_negative(self, analyzer):
        """Test rsc.cicd.resource_validation: Resource Configuration Validation - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.cicd.resource_validation" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.cicd.resource_validation should NOT detect compliant code"


    def test_rsc_missing_resource_limits_positive(self, analyzer):
        """Test rsc.missing_resource_limits: Missing Resource Limits - Should detect"""
        code = """# Code that triggers rsc.missing_resource_limits"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "rsc.missing_resource_limits" in f.requirement_id]
        assert len(findings) > 0, f"Pattern rsc.missing_resource_limits should detect this code"
    
    def test_rsc_missing_resource_limits_negative(self, analyzer):
        """Test rsc.missing_resource_limits: Missing Resource Limits - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "rsc.missing_resource_limits" in f.requirement_id]
        assert len(findings) == 0, f"Pattern rsc.missing_resource_limits should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
