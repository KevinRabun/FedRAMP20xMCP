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

class TestPiyPatterns:
    """Test PIY pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_piy_pii_logging_detection_positive(self, analyzer):
        """Test piy.pii.logging_detection: PII in Logging Statements - Should detect"""
        code = """import logging
logger = logging.getLogger(__name__)

logger.info(f"User email: {user.email}")
logger.debug(f"SSN: {user.social_security}")
print(f"Phone: {customer.phone}")"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.pii.logging_detection" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.pii.logging_detection should detect this code"
    
    def test_piy_pii_logging_detection_negative(self, analyzer):
        """Test piy.pii.logging_detection: PII in Logging Statements - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.pii.logging_detection" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.pii.logging_detection should NOT detect compliant code"


    def test_piy_retention_missing_policy_positive(self, analyzer):
        """Test piy.retention.missing_policy: Missing Data Retention Policy - Should detect"""
        # Bicep blob service without deleteRetentionPolicy
        code = """resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
      name: 'default'
      properties: {
        containerRetention: {
          enabled: true
        }
      }
    }"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.retention.missing_policy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.retention.missing_policy should detect this code"
    
    def test_piy_retention_missing_policy_negative(self, analyzer):
        """Test piy.retention.missing_policy: Missing Data Retention Policy - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.retention.missing_policy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.retention.missing_policy should NOT detect compliant code"


    def test_piy_vdp_missing_program_positive(self, analyzer):
        """Test piy.vdp.missing_program: Missing Vulnerability Disclosure Program - Should detect"""
        code = """# Security
We take security seriously.
# SECURITY.md
This file exists but has no contact info."""
        
        result = analyzer.analyze(code, "markdown")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.vdp.missing_program" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.vdp.missing_program should detect this code"
    
    def test_piy_vdp_missing_program_negative(self, analyzer):
        """Test piy.vdp.missing_program: Missing Vulnerability Disclosure Program - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.vdp.missing_program" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.vdp.missing_program should NOT detect compliant code"


    def test_piy_secure_by_design_missing_practices_positive(self, analyzer):
        """Test piy.secure_by_design.missing_practices: Missing CISA Secure By Design Practices - Should detect"""
        code = """password = 'hardcoded123'
api_key = 'sk-1234567890abcdef'
secret = 'my-secret-key'"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.secure_by_design.missing_practices" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.secure_by_design.missing_practices should detect this code"
    
    def test_piy_secure_by_design_missing_practices_negative(self, analyzer):
        """Test piy.secure_by_design.missing_practices: Missing CISA Secure By Design Practices - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.secure_by_design.missing_practices" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.secure_by_design.missing_practices should NOT detect compliant code"


    def test_piy_evaluation_missing_validation_positive(self, analyzer):
        """Test piy.evaluation.missing_validation: Missing Implementation Validation - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: echo "Building..." """
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.evaluation.missing_validation" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.evaluation.missing_validation should detect this code"
    
    def test_piy_evaluation_missing_validation_negative(self, analyzer):
        """Test piy.evaluation.missing_validation: Missing Implementation Validation - Should NOT detect"""
        # Pipeline with security testing (has negative indicators)
        code = """name: Security CI
    on: [push]
    jobs:
      security-scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v2
          - name: OWASP ZAP Security Scan
            run: zap-baseline.py -t https://example.com
          - name: Penetration Testing
            run: burp-scan"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.evaluation.missing_validation" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.evaluation.missing_validation should NOT detect compliant code"


    def test_piy_investment_missing_metrics_positive(self, analyzer):
        """Test piy.investment.missing_metrics: Missing Security Investment Metrics - Should detect"""
        # Documentation that mentions security metrics but lacks specific measurements
        code = """# Security Metrics
        
        We track security effectiveness through various KPIs and performance measurements.
        Our security program ROI is important to demonstrate value.
        
        ## Measurement Approach
        We measure security effectiveness regularly."""
        
        result = analyzer.analyze(code, "markdown")
        
        # Should detect the pattern (has positive indicators but lacks negative indicators like MTTR, MTTD)
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.investment.missing_metrics" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.investment.missing_metrics should detect this code"
    
    def test_piy_investment_missing_metrics_negative(self, analyzer):
        """Test piy.investment.missing_metrics: Missing Security Investment Metrics - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "markdown")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.investment.missing_metrics" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.investment.missing_metrics should NOT detect compliant code"


    def test_piy_supply_chain_unvetted_dependencies_positive(self, analyzer):
        """Test piy.supply_chain.unvetted_dependencies: Unvetted Supply Chain Dependencies - Should detect"""
        code = """# requirements.txt
django==4.2.0
requests==2.31.0
celery==5.3.0"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.supply_chain.unvetted_dependencies" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.supply_chain.unvetted_dependencies should detect this code"
    
    def test_piy_supply_chain_unvetted_dependencies_negative(self, analyzer):
        """Test piy.supply_chain.unvetted_dependencies: Unvetted Supply Chain Dependencies - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.supply_chain.unvetted_dependencies" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.supply_chain.unvetted_dependencies should NOT detect compliant code"


    def test_piy_executive_missing_governance_positive(self, analyzer):
        """Test piy.executive.missing_governance: Missing Executive Security Governance - Should detect"""
        code = """# Code that triggers piy.executive.missing_governance"""
        
        result = analyzer.analyze(code, "markdown")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.executive.missing_governance" == f.pattern_id]
        assert len(findings) > 0, f"Pattern piy.executive.missing_governance should detect this code"
    
    def test_piy_executive_missing_governance_negative(self, analyzer):
        """Test piy.executive.missing_governance: Missing Executive Security Governance - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "markdown")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "piy.executive.missing_governance" == f.pattern_id]
        assert len(findings) == 0, f"Pattern piy.executive.missing_governance should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
