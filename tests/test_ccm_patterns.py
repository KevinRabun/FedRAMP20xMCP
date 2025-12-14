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

class TestCcmPatterns:
    """Test CCM pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_ccm_version_control_git_usage_positive(self, analyzer):
        """Test ccm.version_control.git_usage: Git Version Control Usage - Should detect"""
        code = """# Git configuration
# .gitignore file present
# git commit changes
files = ['.git/', '.gitignore']"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.version_control.git_usage" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.version_control.git_usage should detect this code"
    
    def test_ccm_version_control_git_usage_negative(self, analyzer):
        """Test ccm.version_control.git_usage: Git Version Control Usage - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.version_control.git_usage" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.version_control.git_usage should NOT detect compliant code"


    def test_ccm_change_logging_audit_log_positive(self, analyzer):
        """Test ccm.change_logging.audit_log: Change Audit Logging - Should detect"""
        code = """import logging
logger = logging.getLogger(__name__)
logger.info('Configuration change: updated database connection')"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.change_logging.audit_log" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.change_logging.audit_log should detect this code"
    
    def test_ccm_change_logging_audit_log_negative(self, analyzer):
        """Test ccm.change_logging.audit_log: Change Audit Logging - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.change_logging.audit_log" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.change_logging.audit_log should NOT detect compliant code"


    def test_ccm_approval_workflow_pull_request_positive(self, analyzer):
        """Test ccm.approval_workflow.pull_request: Pull Request Approval Workflow - Should detect"""
        code = """# Code that triggers ccm.approval_workflow.pull_request"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.approval_workflow.pull_request" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.approval_workflow.pull_request should detect this code"
    
    def test_ccm_approval_workflow_pull_request_negative(self, analyzer):
        """Test ccm.approval_workflow.pull_request: Pull Request Approval Workflow - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.approval_workflow.pull_request" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.approval_workflow.pull_request should NOT detect compliant code"


    def test_ccm_automated_testing_pre_deploy_positive(self, analyzer):
        """Test ccm.automated_testing.pre_deploy: Automated Testing Before Deployment - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: pytest tests/"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.automated_testing.pre_deploy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.automated_testing.pre_deploy should detect this code"
    
    def test_ccm_automated_testing_pre_deploy_negative(self, analyzer):
        """Test ccm.automated_testing.pre_deploy: Automated Testing Before Deployment - Should NOT detect"""
        code = """name: Build Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build application
        run: npm run build"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.automated_testing.pre_deploy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.automated_testing.pre_deploy should NOT detect compliant code"


    def test_ccm_rollback_capability_positive(self, analyzer):
        """Test ccm.rollback.capability: Rollback Capability - Should detect"""
        code = """def rollback_deployment(version):
    previous_version = get_previous_version()
    deploy(previous_version)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.rollback.capability" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.rollback.capability should detect this code"
    
    def test_ccm_rollback_capability_negative(self, analyzer):
        """Test ccm.rollback.capability: Rollback Capability - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.rollback.capability" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.rollback.capability should NOT detect compliant code"


    def test_ccm_baseline_configuration_positive(self, analyzer):
        """Test ccm.baseline.configuration: Baseline Configuration Management - Should detect"""
        code = """# Code that triggers ccm.baseline.configuration"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.baseline.configuration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.baseline.configuration should detect this code"
    
    def test_ccm_baseline_configuration_negative(self, analyzer):
        """Test ccm.baseline.configuration: Baseline Configuration Management - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.baseline.configuration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.baseline.configuration should NOT detect compliant code"


    def test_ccm_change_approval_explicit_positive(self, analyzer):
        """Test ccm.change_approval.explicit: Explicit Change Approval Check - Should detect"""
        code = """def deploy_changes(change_request):
    if not change_request.is_approved():
        raise ValueError('Change requires approval')
    apply_changes(change_request)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.change_approval.explicit" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.change_approval.explicit should detect this code"
    
    def test_ccm_change_approval_explicit_negative(self, analyzer):
        """Test ccm.change_approval.explicit: Explicit Change Approval Check - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.change_approval.explicit" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.change_approval.explicit should NOT detect compliant code"


    def test_ccm_iac_arm_template_validation_positive(self, analyzer):
        """Test ccm.iac.arm_template_validation: ARM Template Validation - Should detect"""
        code = """name: IaC Validation
on: [push]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate ARM templates
        run: az deployment group validate --template-file main.bicep"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.iac.arm_template_validation" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.iac.arm_template_validation should detect this code"
    
    def test_ccm_iac_arm_template_validation_negative(self, analyzer):
        """Test ccm.iac.arm_template_validation: ARM Template Validation - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.iac.arm_template_validation" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.iac.arm_template_validation should NOT detect compliant code"


    def test_ccm_iac_terraform_plan_positive(self, analyzer):
        """Test ccm.iac.terraform_plan: Terraform Plan for Change Preview - Should detect"""
        code = """name: Terraform
on: [pull_request]
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Terraform plan
        run: terraform plan -out=tfplan"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.iac.terraform_plan" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.iac.terraform_plan should detect this code"
    
    def test_ccm_iac_terraform_plan_negative(self, analyzer):
        """Test ccm.iac.terraform_plan: Terraform Plan for Change Preview - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.iac.terraform_plan" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.iac.terraform_plan should NOT detect compliant code"


    def test_ccm_cicd_deployment_gate_positive(self, analyzer):
        """Test ccm.cicd.deployment_gate: Deployment Gate/Approval - Should detect"""
        code = """name: Deploy to Production
on: workflow_dispatch
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://example.com
    steps:
      - uses: actions/checkout@v2
      - name: Deploy
        run: deploy.sh"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.cicd.deployment_gate" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.cicd.deployment_gate should detect this code"
    
    def test_ccm_cicd_deployment_gate_negative(self, analyzer):
        """Test ccm.cicd.deployment_gate: Deployment Gate/Approval - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.cicd.deployment_gate" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.cicd.deployment_gate should NOT detect compliant code"


    def test_ccm_cicd_configuration_backup_positive(self, analyzer):
        """Test ccm.cicd.configuration_backup: Configuration Backup Before Change - Should detect"""
        code = """name: Configuration Backup
on:
  schedule:
    - cron: '0 0 * * *'
jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - name: Export configuration
        run: az export --output backup.json"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.cicd.configuration_backup" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.cicd.configuration_backup should detect this code"
    
    def test_ccm_cicd_configuration_backup_negative(self, analyzer):
        """Test ccm.cicd.configuration_backup: Configuration Backup Before Change - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.cicd.configuration_backup" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.cicd.configuration_backup should NOT detect compliant code"


    def test_ccm_missing_version_control_positive(self, analyzer):
        """Test ccm.missing_version_control: Missing Version Control Evidence - Should detect"""
        code = """# Code that triggers ccm.missing_version_control
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.missing_version_control" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ccm.missing_version_control should detect this code"
    
    def test_ccm_missing_version_control_negative(self, analyzer):
        """Test ccm.missing_version_control: Missing Version Control Evidence - Should NOT detect"""
        code = """.gitignore
*.pyc
__pycache__/
.env"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ccm.missing_version_control" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ccm.missing_version_control should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
