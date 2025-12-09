"""
Test suite for KSI-CMT-04 Enhanced: Change Management Procedure
Tests AST-based Python analyzer and CI/CD pipeline analyzers
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cmt_04 import KSI_CMT_04_Analyzer


def test_python_execute_without_approval():
    """Test Python AST detection of .execute() without approval"""
    code = """
import psycopg2

def apply_production_change():
    '''Apply database change in production'''
    connection = psycopg2.connect("dbname=production")
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET role='admin' WHERE id=1")
    connection.commit()
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'db_change.py')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected findings for .execute() without approval, got {len(findings)}"
    exec_findings = [f for f in findings if "execute" in f.description.lower() or "commit" in f.description.lower()]
    assert len(exec_findings) >= 1, "Should detect .execute() or .commit() without approval"
    print("[PASS] Python: Detects .execute() without approval check")


def test_python_with_approval_parameter():
    """Test Python AST accepts database change with approval parameter"""
    code = """
import psycopg2

def apply_change_with_approval(change_ticket: str, approved_by: str):
    '''Apply database change with change management'''
    if not change_ticket or not approved_by:
        raise ValueError("Approval required")
    
    connection = psycopg2.connect("dbname=production")
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET role='user' WHERE id=1")
    connection.commit()
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'approved_change.py')
    findings = result.findings
    
    # Should not find issues if approval parameter exists
    exec_findings = [f for f in findings if "execute" in f.description.lower()]
    assert len(exec_findings) == 0, "Should not flag .execute() with approval parameter"
    print("[PASS] Python: Accepts database change with approval parameter")


def test_python_ddl_without_approval():
    """Test Python AST detection of DDL statements without approval"""
    code = """
def drop_table_production():
    '''Drop table in production'''
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("DROP TABLE old_data")
    connection.commit()
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'ddl.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect DDL statement without approval"
    ddl_findings = [f for f in findings if "DDL" in f.title]
    assert len(ddl_findings) >= 1, "Should detect DROP statement"
    print("[PASS] Python: Detects DDL statement without approval")


def test_csharp_executesql_without_approval():
    """Test C# detection of ExecuteSqlRaw without approval"""
    code = """
public class ProductionMigration
{
    public void ApplyChange()
    {
        // Production environment
        var context = new ProductionDbContext();
        context.Database.ExecuteSqlRaw("UPDATE Users SET Role='Admin'");
        context.SaveChanges();
    }
}
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'Migration.cs')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect ExecuteSqlRaw without approval"
    assert any("production" in f.description.lower() for f in findings)
    print("[PASS] C#: Detects ExecuteSqlRaw without approval check")


def test_github_actions_prod_without_approval():
    """Test GitHub Actions detection of production deployment without approval gate"""
    code = """
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy
        run: ./deploy.sh
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'github-actions', '.github/workflows/deploy.yml')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect production deployment without approval"
    approval_findings = [f for f in findings if "approval" in f.title.lower()]
    assert len(approval_findings) >= 1, "Should detect missing approval gate"
    assert any(f.severity.value == "high" for f in findings), "Should be HIGH severity"
    print("[PASS] GitHub Actions: Detects production deployment without approval gate")


def test_github_actions_with_approval():
    """Test GitHub Actions accepts workflow with approval gate"""
    code = """
name: Deploy to Production

on:
  workflow_dispatch:
    inputs:
      change_ticket:
        required: true
      approver:
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      # Protected environment with required reviewers configured
    steps:
      - name: Deploy
        run: ./deploy.sh
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'github-actions', '.github/workflows/deploy.yml')
    findings = result.findings
    
    # Should not flag as missing approval (has workflow_dispatch and change_ticket)
    approval_findings = [f for f in findings if "approval gate" in f.title.lower()]
    assert len(approval_findings) == 0, "Should not flag workflow with manual trigger and change tracking"
    print("[PASS] GitHub Actions: Accepts workflow with approval gate")


def test_github_actions_missing_change_tracking():
    """Test GitHub Actions detection of missing change tracking"""
    code = """
name: Deploy Application

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to staging
        run: ./deploy.sh
      - name: Release to production
        run: ./release.sh
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'github-actions', '.github/workflows/app.yml')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect missing change tracking"
    tracking_findings = [f for f in findings if "change tracking" in f.title.lower()]
    assert len(tracking_findings) >= 1, "Should detect missing change/ticket tracking"
    print("[PASS] GitHub Actions: Detects missing change tracking")


def test_github_actions_auto_prod_deploy():
    """Test GitHub Actions detection of automatic production deployment on push"""
    code = """
name: Auto Deploy

on:
  push:

jobs:
  deploy-production:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        run: ./deploy-prod.sh
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'github-actions', '.github/workflows/auto.yml')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect automatic production deployment"
    auto_findings = [f for f in findings if "automated" in f.title.lower() or "push" in f.description.lower()]
    assert len(auto_findings) >= 1, "Should detect push-triggered production deploy"
    print("[PASS] GitHub Actions: Detects automated production deployment on push")


def test_azure_pipelines_prod_without_approval():
    """Test Azure Pipelines detection of production deployment without approval"""
    code = """
trigger:
- main

stages:
- stage: Deploy
  jobs:
  - deployment: ProductionDeploy
    environment: production
    strategy:
      runOnce:
        deploy:
          steps:
          - script: ./deploy.sh
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'azure-pipelines', 'azure-pipelines.yml')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect production deployment without approval"
    approval_findings = [f for f in findings if "approval" in f.title.lower()]
    assert len(approval_findings) >= 1, "Should detect missing approval step"
    print("[PASS] Azure Pipelines: Detects production deployment without approval")


def test_python_regex_fallback():
    """Test Python regex fallback on syntax error"""
    code = """
# Invalid syntax to trigger fallback
def apply_change(
    connection = get_production_connection()
    cursor.execute("UPDATE data")
    connection.commit()
"""
    analyzer = KSI_CMT_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'invalid.py')
    findings = result.findings
    
    # Should use regex fallback and still detect issue
    assert len(findings) >= 1, "Regex fallback should detect patterns"
    fallback_findings = [f for f in findings if "Regex Fallback" in f.title]
    assert len(fallback_findings) >= 1, "Should use regex fallback on syntax error"
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all CMT-04 tests"""
    tests = [
        test_python_execute_without_approval,
        test_python_with_approval_parameter,
        test_python_ddl_without_approval,
        test_csharp_executesql_without_approval,
        test_github_actions_prod_without_approval,
        test_github_actions_with_approval,
        test_github_actions_missing_change_tracking,
        test_github_actions_auto_prod_deploy,
        test_azure_pipelines_prod_without_approval,
        test_python_regex_fallback,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"CMT-04 Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} test(s) failed")
    print(f"{'='*60}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
