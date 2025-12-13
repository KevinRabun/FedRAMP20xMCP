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
        code = """apiVersion: v1
kind: Pod
metadata:
  name: resource-demo
spec:
  containers:
  - name: demo
    image: nginx
    resources:
      limits: {cpu: "1", memory: "1Gi"}
      requests: {cpu: "500m", memory: "512Mi"}"""

        result = analyzer.analyze(code, "yaml")
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.allocation.resource_limits" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.allocation.resource_limits" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.allocation.resource_limits should NOT detect compliant code"


    def test_rsc_monitoring_resource_metrics_positive(self, analyzer):
        """Test rsc.monitoring.resource_metrics: Resource Metrics Monitoring - Should detect"""
        code = """import psutil

def monitor_resources():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    return {'cpu': cpu_usage, 'memory': memory_usage, 'disk': disk_usage}"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.monitoring.resource_metrics" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.monitoring.resource_metrics" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.monitoring.resource_metrics should NOT detect compliant code"


    def test_rsc_scaling_autoscaling_positive(self, analyzer):
        """Test rsc.scaling.autoscaling: Autoscaling Configuration - Should detect"""
        code = """# Code that triggers rsc.scaling.autoscaling"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.scaling.autoscaling" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.scaling.autoscaling should detect this code"
    
    def test_rsc_scaling_autoscaling_negative(self, analyzer):
        """Test rsc.scaling.autoscaling: Autoscaling Configuration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.scaling.autoscaling" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.scaling.autoscaling should NOT detect compliant code"


    def test_rsc_quota_namespace_quota_positive(self, analyzer):
        """Test rsc.quota.namespace_quota: Namespace Resource Quota - Should detect"""
        code = """apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-quota
  namespace: development
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.quota.namespace_quota" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.quota.namespace_quota should detect this code"
    
    def test_rsc_quota_namespace_quota_negative(self, analyzer):
        """Test rsc.quota.namespace_quota: Namespace Resource Quota - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.quota.namespace_quota" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.quota.namespace_quota should NOT detect compliant code"


    def test_rsc_allocation_priority_class_positive(self, analyzer):
        """Test rsc.allocation.priority_class: Priority Class for Resource Allocation - Should detect"""
        code = """apiVersion: v1
kind: Pod
metadata:
  name: critical-app
spec:
  priorityClassName: high-priority
  containers:
  - name: app
    image: nginx"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.allocation.priority_class" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.allocation.priority_class should detect this code"
    
    def test_rsc_allocation_priority_class_negative(self, analyzer):
        """Test rsc.allocation.priority_class: Priority Class for Resource Allocation - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.allocation.priority_class" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.allocation.priority_class should NOT detect compliant code"


    def test_rsc_cost_budget_alert_positive(self, analyzer):
        """Test rsc.cost.budget_alert: Cost Budget Alerts - Should detect"""
        code = """// Bicep code for rsc.cost.budget_alert
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.cost.budget_alert" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.cost.budget_alert should detect this code"
    
    def test_rsc_cost_budget_alert_negative(self, analyzer):
        """Test rsc.cost.budget_alert: Cost Budget Alerts - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.cost.budget_alert" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.cost.budget_alert should NOT detect compliant code"


    def test_rsc_iac_app_service_plan_positive(self, analyzer):
        """Test rsc.iac.app_service_plan: Azure App Service Plan Configuration - Should detect"""
        code = """resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: 'production-plan'
  location: resourceGroup().location
  sku: {
    name: 'P1V3'
    tier: 'PremiumV3'
    capacity: 2
  }
  kind: 'linux'
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.iac.app_service_plan" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.iac.app_service_plan should detect this code"
    
    def test_rsc_iac_app_service_plan_negative(self, analyzer):
        """Test rsc.iac.app_service_plan: Azure App Service Plan Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.iac.app_service_plan" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.iac.app_service_plan should NOT detect compliant code"


    def test_rsc_iac_vm_size_positive(self, analyzer):
        """Test rsc.iac.vm_size: Virtual Machine Size Configuration - Should detect"""
        code = """// Bicep code for rsc.iac.vm_size
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.iac.vm_size" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.iac.vm_size should detect this code"
    
    def test_rsc_iac_vm_size_negative(self, analyzer):
        """Test rsc.iac.vm_size: Virtual Machine Size Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.iac.vm_size" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.iac.vm_size should NOT detect compliant code"


    def test_rsc_iac_reserved_instances_positive(self, analyzer):
        """Test rsc.iac.reserved_instances: Reserved Instance Usage - Should detect"""
        code = """// Bicep code for rsc.iac.reserved_instances
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.iac.reserved_instances" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.iac.reserved_instances should detect this code"
    
    def test_rsc_iac_reserved_instances_negative(self, analyzer):
        """Test rsc.iac.reserved_instances: Reserved Instance Usage - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.iac.reserved_instances" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.iac.reserved_instances should NOT detect compliant code"


    def test_rsc_cicd_resource_validation_positive(self, analyzer):
        """Test rsc.cicd.resource_validation: Resource Configuration Validation - Should detect"""
        code = """name: Validate Resources
on: [push]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate K8s resources
        run: kubectl apply --dry-run=client -f kubernetes/
      - name: Check resource limits
        run: python scripts/validate_resources.py"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.cicd.resource_validation" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.cicd.resource_validation should detect this code"
    
    def test_rsc_cicd_resource_validation_negative(self, analyzer):
        """Test rsc.cicd.resource_validation: Resource Configuration Validation - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.cicd.resource_validation" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rsc.cicd.resource_validation should NOT detect compliant code"


    def test_rsc_missing_resource_limits_positive(self, analyzer):
        """Test rsc.missing_resource_limits: Missing Resource Limits - Should detect"""
        code = """apiVersion: v1
kind: Pod
metadata:
  name: no-limits
spec:
  containers:
  - name: app
    image: nginx
    ports:
    - containerPort: 80"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rsc.missing_resource_limits" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rsc.missing_resource_limits should detect this code"
    
    def test_rsc_missing_resource_limits_negative(self, analyzer):
        """Test rsc.missing_resource_limits: Missing Resource Limits - Should NOT detect"""
        code = """apiVersion: v1
kind: Pod
metadata:
  name: with-limits
spec:
  containers:
  - name: app
    image: nginx
    resources:
      limits: {cpu: "1", memory: "1Gi"}
      requests: {cpu: "500m", memory: "512Mi"}"""
