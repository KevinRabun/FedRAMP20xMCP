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

class TestCedPatterns:
    """Test CED pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_ced_training_missing_documentation_positive(self, analyzer):
        """Test ced.training.missing_documentation: Missing Security Training Documentation - Should detect"""
        # Code mentions training but lacks verification/tracking (has positive, lacks negative indicators)
        code = """class EmployeeTrainingSystem:
    def __init__(self):
        self.training_courses = []
        self.certification_programs = {}
        
    def enroll_training(self, employee_id, course_name):
        self.training_courses.append({'employee': employee_id, 'course': course_name})
        # Missing verification and completion tracking
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.missing_documentation" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ced.training.missing_documentation should detect this code"
    
    def test_ced_training_missing_documentation_negative(self, analyzer):
        """Test ced.training.missing_documentation: Missing Security Training Documentation - Should NOT detect"""
        code = """class EmployeeManager:
    def __init__(self):
        self.completed_tasks = []
        self.verified_users = {}
        self.tracked_activities = set()
        self.documented_processes = []
    
    def process_employee_data(self, emp_id):
        return self.verified_users.get(emp_id, None)
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.missing_documentation" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ced.training.missing_documentation should NOT detect compliant code"


    def test_ced_training_role_based_missing_positive(self, analyzer):
        """Test ced.training.role_based_missing: Insufficient Role-Based Security Training - Should detect"""
        # Code with role/privilege assignments but no training verification
        code = """class UserRoleManager:
    def assign_admin_role(self, user_id):
        # Grant admin privileges without training verification
        self.admin_roles[user_id] = {'role': 'administrator', 'permissions': ['all']}
        
    def grant_privileged_access(self, user_id, resource):
        # Missing training requirement check
        self.privileged_users.add(user_id)
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.role_based_missing" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ced.training.role_based_missing should detect this code"
    
    def test_ced_training_role_based_missing_negative(self, analyzer):
        """Test ced.training.role_based_missing: Insufficient Role-Based Security Training - Should NOT detect"""
        code = """class DataProcessor:
    def __init__(self):
        self.authorized_users = []
        self.certified_operations = True
        self.training_completed = False
    
    def process_data(self, data):
        return data.upper()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.role_based_missing" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ced.training.role_based_missing should NOT detect compliant code"


    def test_ced_training_developer_gaps_positive(self, analyzer):
        """Test ced.training.developer_gaps: Inadequate Developer Security Training - Should detect"""
        code = """user_input = request.args.get('code')
result = eval(user_input)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.developer_gaps" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ced.training.developer_gaps should detect this code"
    
    def test_ced_training_developer_gaps_negative(self, analyzer):
        """Test ced.training.developer_gaps: Inadequate Developer Security Training - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.developer_gaps" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ced.training.developer_gaps should NOT detect compliant code"


    def test_ced_training_incident_response_missing_positive(self, analyzer):
        """Test ced.training.incident_response_missing: Missing Incident Response Training - Should detect"""
        # Code with incident/response mentions but no training/planning
        code = """class IncidentHandler:
    def handle_security_incident(self, incident_id):
        # Respond to incident without trained procedures
        self.incidents[incident_id] = {'status': 'new', 'severity': 'high'}
        
    def disaster_recovery_process(self):
        # Missing recovery plan and trained personnel
        pass
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.incident_response_missing" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ced.training.incident_response_missing should detect this code"
    
    def test_ced_training_incident_response_missing_negative(self, analyzer):
        """Test ced.training.incident_response_missing: Missing Incident Response Training - Should NOT detect"""
        code = """class DataValidator:
    def __init__(self):
        self.plan_documented = True
        self.training_provided = True
        self.drilled_procedures = []
        self.tested_systems = True
    
    def validate_input(self, value):
        if not value:
            return None
        return value.strip()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ced.training.incident_response_missing" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ced.training.incident_response_missing should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
