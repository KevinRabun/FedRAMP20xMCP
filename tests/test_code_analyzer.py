"""
Comprehensive tests for code analyzers.

Tests validate actual detection capabilities, not just existence.
Includes both positive (should detect) and negative (should not detect) test cases.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers import (
    BicepAnalyzer,
    TerraformAnalyzer,
    PythonAnalyzer,
    CICDAnalyzer,
    Severity,
)


def test_bicep_missing_diagnostic_settings():
    """Test detection of missing diagnostic settings in Bicep."""
    print("\n=== Testing Bicep: Missing Diagnostic Settings ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorageaccount'
      location: location
      sku: {
        name: 'Standard_LRS'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    # Should find missing diagnostic settings
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-05" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing diagnostic settings"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing diagnostic settings: {findings[0].title}")
    print(f"   Recommendation: {findings[0].recommendation[:100]}...")


def test_bicep_with_diagnostic_settings():
    """Test that diagnostic settings are recognized as good practice."""
    print("\n=== Testing Bicep: With Diagnostic Settings ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorageaccount'
      location: location
    }
    
    resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
      name: 'logs'
      scope: storageAccount
      properties: {
        logs: [{ category: 'StorageWrite', enabled: true }]
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    # Should find good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-MLA-05" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize diagnostic settings as good practice"
    print(f"✅ Recognized good practice: {good_practices[0].title}")


def test_bicep_hardcoded_password():
    """Test detection of hardcoded passwords in Bicep."""
    print("\n=== Testing Bicep: Hardcoded Password ===")
    
    code = """
    resource sqlServer 'Microsoft.Sql/servers@2023-02-01' = {
      name: 'myserver'
      properties: {
        administratorLogin: 'admin'
        administratorLoginPassword: 'P@ssw0rd123!'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "sql.bicep")
    
    # Should detect hardcoded password
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-06" and not f.good_practice]
    assert len(findings) > 0, "Should detect hardcoded password"
    assert findings[0].severity == Severity.HIGH
    assert "Key Vault" in findings[0].recommendation
    print(f"✅ Detected hardcoded secret: {findings[0].title}")
    print(f"   Code snippet: {findings[0].code_snippet}")


def test_bicep_missing_nsg():
    """Test detection of VNet without NSG."""
    print("\n=== Testing Bicep: Missing Network Security Group ===")
    
    code = """
    resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
      name: 'myvnet'
      location: location
      properties: {
        addressSpace: {
          addressPrefixes: ['10.0.0.0/16']
        }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "network.bicep")
    
    # Should detect missing NSG
    findings = [f for f in result.findings if f.requirement_id == "KSI-CNA-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing NSG"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected network security issue: {findings[0].title}")


def test_terraform_missing_diagnostic_settings():
    """Test detection of missing diagnostic settings in Terraform."""
    print("\n=== Testing Terraform: Missing Diagnostic Settings ===")
    
    code = """
    resource "azurerm_storage_account" "example" {
      name                     = "mystorageaccount"
      resource_group_name      = azurerm_resource_group.example.name
      location                 = azurerm_resource_group.example.location
      account_tier             = "Standard"
      account_replication_type = "LRS"
    }
    """
    
    analyzer = TerraformAnalyzer()
    result = analyzer.analyze(code, "storage.tf")
    
    # Should find missing diagnostic settings
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-05" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing diagnostic settings"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing diagnostic settings: {findings[0].title}")


def test_terraform_hardcoded_connection_string():
    """Test detection of hardcoded connection strings."""
    print("\n=== Testing Terraform: Hardcoded Connection String ===")
    
    code = """
    resource "azurerm_app_service" "example" {
      name                = "myapp"
      resource_group_name = azurerm_resource_group.example.name
      
      connection_string {
        name  = "Database"
        type  = "SQLAzure"
        value = "Server=tcp:myserver.database.windows.net;Database=mydb;User ID=admin;Password=P@ssw0rd!"
      }
    }
    """
    
    analyzer = TerraformAnalyzer()
    result = analyzer.analyze(code, "app.tf")
    
    # Should detect hardcoded connection string
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-06" and not f.good_practice]
    assert len(findings) > 0, "Should detect hardcoded connection string"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected hardcoded secret: {findings[0].title}")


def test_python_missing_authentication():
    """Test detection of unprotected API endpoints."""
    print("\n=== Testing Python: Missing Authentication ===")
    
    code = """
    from flask import Flask, request
    
    app = Flask(__name__)
    
    @app.route('/api/users', methods=['GET'])
    def get_users():
        return {'users': ['alice', 'bob']}
    
    @app.route('/api/admin', methods=['POST'])
    def admin_action():
        return {'status': 'completed'}
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "app.py")
    
    # Should detect missing authentication
    findings = [f for f in result.findings if f.requirement_id == "KSI-IAM-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect endpoints without authentication"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected authentication issue: {findings[0].title}")


def test_python_with_authentication():
    """Test recognition of properly authenticated endpoints."""
    print("\n=== Testing Python: With Authentication ===")
    
    code = """
    from flask import Flask
    from azure.identity import DefaultAzureCredential
    from functools import wraps
    
    app = Flask(__name__)
    
    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Auth logic
            return f(*args, **kwargs)
        return decorated
    
    @app.route('/api/data')
    @require_auth
    def get_data():
        return {'data': 'secure'}
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "app.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-IAM-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize authentication as good practice"
    print(f"✅ Recognized good practice: {good_practices[0].title}")


def test_python_hardcoded_api_key():
    """Test detection of hardcoded API keys."""
    print("\n=== Testing Python: Hardcoded API Key ===")
    
    code = """
    import requests
    
    API_KEY = "sk-1234567890abcdef1234567890abcdef"
    
    def call_external_api():
        headers = {'Authorization': f'Bearer {API_KEY}'}
        response = requests.get('https://api.example.com/data', headers=headers)
        return response.json()
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "api_client.py")
    
    # Should detect hardcoded API key
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-06" and not f.good_practice]
    assert len(findings) > 0, "Should detect hardcoded API key"
    assert findings[0].severity == Severity.HIGH
    assert "Key Vault" in findings[0].recommendation
    print(f"✅ Detected hardcoded secret: {findings[0].title}")


def test_python_key_vault_usage():
    """Test recognition of Key Vault usage."""
    print("\n=== Testing Python: Key Vault Usage ===")
    
    code = """
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url="https://myvault.vault.azure.net", credential=credential)
    api_key = client.get_secret("api-key").value
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "config.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-SVC-06" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize Key Vault usage as good practice"
    print(f"✅ Recognized good practice: {good_practices[0].title}")


def test_python_unsafe_pickle():
    """Test detection of unsafe pickle usage."""
    print("\n=== Testing Python: Unsafe pickle Usage ===")
    
    code = """
    import pickle
    
    def load_data(filename):
        with open(filename, 'rb') as f:
            data = pickle.load(f)
        return data
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "data_loader.py")
    
    # Should detect unsafe pickle
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-08" and not f.good_practice]
    assert len(findings) > 0, "Should detect unsafe pickle usage"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected unsafe library: {findings[0].title}")


def test_python_pii_handling():
    """Test detection of unencrypted PII."""
    print("\n=== Testing Python: Unencrypted PII ===")
    
    code = """
    class User:
        def __init__(self, name, ssn, email):
            self.name = name
            self.social_security_number = ssn
            self.email = email
        
        def save_to_db(self):
            db.insert({'ssn': self.social_security_number, 'email': self.email})
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "models.py")
    
    # Should detect unencrypted PII
    findings = [f for f in result.findings if f.requirement_id == "KSI-PIY-02"]
    assert len(findings) > 0, "Should detect unencrypted PII"
    assert any("Social Security Number" in f.description for f in findings)
    print(f"✅ Detected PII handling issue: {findings[0].title}")


def test_python_pinned_dependencies():
    """Test recognition of pinned dependencies."""
    print("\n=== Testing Python: Pinned Dependencies ===")
    
    code = """
    flask==2.3.0
    requests==2.31.0
    azure-identity==1.14.0
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "requirements.txt")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-SVC-08" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize pinned dependencies as good practice"
    print(f"✅ Recognized good practice: {good_practices[0].title}")


def test_analysis_result_summary():
    """Test analysis result summary calculations."""
    print("\n=== Testing Analysis Result Summary ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      properties: {
        password: 'hardcoded123'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "test.bicep")
    
    # Verify summary counts
    summary = result.to_dict()['summary']
    assert summary['high_priority'] >= 0
    assert summary['medium_priority'] >= 0
    assert summary['low_priority'] >= 0
    assert summary['good_practices'] >= 0
    
    total_issues = summary['high_priority'] + summary['medium_priority'] + summary['low_priority']
    print(f"✅ Summary calculated: {total_issues} issues, {summary['good_practices']} good practices")


def test_python_bare_except():
    """Test detection of bare except clauses (KSI-SVC-01)."""
    print("\n=== Testing Python: Bare Except Detection ===")
    
    code = """
    def process_data(data):
        try:
            result = risky_operation(data)
            return result
        except:
            print("Error occurred")
            return None
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "app.py")
    
    # Should detect bare except
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-01" and "bare except" in f.title.lower()]
    assert len(findings) > 0, "Should detect bare except clause"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected bare except: {findings[0].title}")


def test_python_proper_error_handling():
    """Test recognition of proper error handling with logging (KSI-SVC-01)."""
    print("\n=== Testing Python: Proper Error Handling ===")
    
    code = """
    import logging
    
    def process_data(data):
        try:
            result = risky_operation(data)
            return result
        except ValueError as e:
            logging.error(f"Validation error: {e}")
            raise
        except Exception as e:
            logging.exception("Unexpected error in process_data")
            raise
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "app.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-SVC-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize proper error handling"
    print(f"✅ Recognized good practice: {good_practices[0].title}")


def test_python_sql_injection():
    """Test detection of SQL injection vulnerabilities (KSI-SVC-02)."""
    print("\n=== Testing Python: SQL Injection Detection ===")
    
    code = """
    import sqlite3
    
    def get_user(username):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        return cursor.fetchone()
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "db.py")
    
    # Should detect SQL injection
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "SQL injection" in f.title]
    assert len(findings) > 0, "Should detect SQL injection vulnerability"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected SQL injection: {findings[0].title}")


def test_python_parameterized_query():
    """Test recognition of parameterized queries (KSI-SVC-02)."""
    print("\n=== Testing Python: Parameterized Queries ===")
    
    code = """
    import sqlite3
    
    def get_user(username):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "db.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize parameterized queries"
    print(f"✅ Recognized parameterized query: {good_practices[0].title}")


def test_python_command_injection():
    """Test detection of command injection vulnerabilities (KSI-SVC-02)."""
    print("\n=== Testing Python: Command Injection Detection ===")
    
    code = """
    import subprocess
    
    def process_file(filename):
        subprocess.run(f"cat {filename}", shell=True)
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "utils.py")
    
    # Should detect command injection
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "command injection" in f.title.lower()]
    assert len(findings) > 0, "Should detect command injection vulnerability"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected command injection: {findings[0].title}")


def test_python_eval_usage():
    """Test detection of eval/exec usage (KSI-SVC-07)."""
    print("\n=== Testing Python: Eval/Exec Detection ===")
    
    code = """
    def calculate(expression):
        result = eval(expression)
        return result
    
    def run_code(code_string):
        exec(code_string)
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "calculator.py")
    
    # Should detect eval and exec
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and not f.good_practice]
    assert len(findings) >= 2, "Should detect both eval and exec usage"
    assert all(f.severity == Severity.HIGH for f in findings)
    print(f"✅ Detected unsafe functions: {len(findings)} findings")


def test_python_insecure_random():
    """Test detection of insecure random usage (KSI-SVC-07)."""
    print("\n=== Testing Python: Insecure Random Detection ===")
    
    code = """
    import random
    
    def generate_token():
        return ''.join(random.choices('0123456789abcdef', k=32))
    
    def generate_password():
        return random.randint(1000, 9999)
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "auth.py")
    
    # Should detect insecure random
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "random" in f.title.lower()]
    assert len(findings) > 0, "Should detect insecure random usage"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected insecure random: {findings[0].title}")


def test_python_secure_random():
    """Test recognition of secure random (KSI-SVC-07)."""
    print("\n=== Testing Python: Secure Random Usage ===")
    
    code = """
    import secrets
    
    def generate_token():
        return secrets.token_hex(32)
    
    def generate_password():
        return secrets.randbelow(10000)
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "auth.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize secure random usage"
    print(f"✅ Recognized secure random: {good_practices[0].title}")


def test_python_missing_data_classification():
    """Test detection of PII without classification (KSI-PIY-01)."""
    print("\n=== Testing Python: Missing Data Classification ===")
    
    code = """
    class User:
        def __init__(self, name, email, ssn):
            self.name = name
            self.email = email
            self.ssn = ssn
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "models.py")
    
    # Should detect missing classification
    findings = [f for f in result.findings if f.requirement_id == "KSI-PIY-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect PII without classification"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing data classification: {findings[0].title}")


def test_python_with_data_classification():
    """Test recognition of data classification (KSI-PIY-01)."""
    print("\n=== Testing Python: With Data Classification ===")
    
    code = """
    from dataclasses import dataclass
    
    @dataclass
    class User:
        name: str  # PII
        email: str  # PII
        ssn: str  # Sensitive PII
        classification: str = "confidential"
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "models.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-PIY-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize data classification"
    print(f"✅ Recognized data classification: {good_practices[0].title}")


def test_python_missing_retention_policy():
    """Test detection of missing data retention policies (KSI-PIY-03)."""
    print("\n=== Testing Python: Missing Retention Policy ===")
    
    code = """
    class UserData(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(120))
        personal_info = db.Column(db.Text)
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "models.py")
    
    # Should detect missing retention policy
    findings = [f for f in result.findings if f.requirement_id == "KSI-PIY-03" and "retention" in f.title.lower()]
    assert len(findings) > 0, "Should detect missing retention policy"
    assert findings[0].severity == Severity.LOW
    print(f"✅ Detected missing retention policy: {findings[0].title}")


def test_python_missing_deletion_capability():
    """Test detection of missing secure deletion (KSI-PIY-03)."""
    print("\n=== Testing Python: Missing Deletion Capability ===")
    
    code = """
    class UserService:
        def get_user(self, user_id):
            return db.query(User).filter_by(id=user_id).first()
        
        def update_user(self, user_id, data):
            user = self.get_user(user_id)
            user.update(data)
            db.commit()
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "services.py")
    
    # Should detect missing deletion
    findings = [f for f in result.findings if f.requirement_id == "KSI-PIY-03" and "deletion" in f.title.lower()]
    assert len(findings) > 0, "Should detect missing deletion capability"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing deletion: {findings[0].title}")


def test_python_service_mesh_missing_mtls():
    """Test detection of missing mTLS in service mesh (KSI-CNA-07)."""
    print("\n=== Testing Python: Missing Service Mesh mTLS ===")
    
    code = """
    apiVersion: networking.istio.io/v1beta1
    kind: PeerAuthentication
    metadata:
      name: default
    spec:
      mtls:
        mode: PERMISSIVE
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "istio-config.py")
    
    # Should detect permissive mTLS
    findings = [f for f in result.findings if f.requirement_id == "KSI-CNA-07" and not f.good_practice]
    assert len(findings) > 0, "Should detect permissive mTLS mode"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected service mesh issue: {findings[0].title}")


def test_python_wildcard_permissions():
    """Test detection of wildcard permissions (KSI-IAM-04)."""
    print("\n=== Testing Python: Wildcard Permissions Detection ===")
    
    code = """
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    
    def assign_role(principal_id):
        role_assignment = client.role_assignments.create(
            scope='*',
            role_assignment_name='admin-role',
            parameters={
                'principal_id': principal_id,
                'role_definition_id': contributor_role
            }
        )
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "iam.py")
    
    # Should detect wildcard scope
    findings = [f for f in result.findings if f.requirement_id == "KSI-IAM-04" and not f.good_practice]
    assert len(findings) > 0, "Should detect wildcard permissions"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected wildcard permissions: {findings[0].title}")


def test_python_scoped_permissions():
    """Test recognition of scoped permissions (KSI-IAM-04)."""
    print("\n=== Testing Python: Scoped Permissions ===")
    
    code = """
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    
    def assign_role(principal_id, resource_group):
        scope = f'/subscriptions/{subscription_id}/resourceGroups/{resource_group}'
        role_assignment = client.role_assignments.create(
            scope=scope,
            role_assignment_name='reader-role',
            parameters={
                'principal_id': principal_id,
                'role_definition_id': reader_role
            }
        )
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "iam.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-IAM-04" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize scoped permissions"
    print(f"✅ Recognized scoped permissions: {good_practices[0].title}")


def test_python_insecure_session():
    """Test detection of insecure session configuration (KSI-IAM-07)."""
    print("\n=== Testing Python: Insecure Session Configuration ===")
    
    code = """
    from flask import Flask, session
    
    app = Flask(__name__)
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['SESSION_COOKIE_HTTPONLY'] = False
    
    @app.route('/login')
    def login():
        session['user_id'] = 123
        return 'Logged in'
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "app.py")
    
    # Should detect insecure cookies
    findings = [f for f in result.findings if f.requirement_id == "KSI-IAM-07" and not f.good_practice]
    assert len(findings) > 0, "Should detect insecure session configuration"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected insecure session: {findings[0].title}")


def test_python_secure_session():
    """Test recognition of secure session configuration (KSI-IAM-07)."""
    print("\n=== Testing Python: Secure Session Configuration ===")
    
    code = """
    from flask import Flask, session
    
    app = Flask(__name__)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800
    
    @app.route('/login')
    def login():
        session.permanent = True
        session['user_id'] = 123
        return 'Logged in'
    """
    
    analyzer = PythonAnalyzer()
    result = analyzer.analyze(code, "app.py")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-IAM-07" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize secure session configuration"
    print(f"✅ Recognized secure session: {good_practices[0].title}")


# ==============================================================================
# Phase 4: CI/CD Pipeline Analysis Tests (KSI-CMT-01, CMT-02, CMT-03, AFR-01, AFR-02, CED-01)
# ==============================================================================

def test_github_missing_pr_triggers():
    """Test detection of missing PR triggers in GitHub Actions (KSI-CMT-01)."""
    print("\n=== Testing GitHub Actions: Missing PR Triggers ===")
    
    code = """
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: ./deploy.sh
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/deploy.yml")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CMT-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing PR triggers"
    assert any("pull request" in f.description.lower() for f in findings)
    print(f"✅ Detected missing PR triggers: {findings[0].title}")


def test_github_with_pr_triggers():
    """Test recognition of PR triggers in GitHub Actions (KSI-CMT-01)."""
    print("\n=== Testing GitHub Actions: With PR Triggers ===")
    
    code = """
name: CI
on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm test
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/ci.yml")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CMT-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize PR trigger as good practice"
    print(f"✅ Recognized PR triggers: {good_practices[0].title}")


def test_azure_missing_approval_gates():
    """Test detection of missing approval gates in Azure Pipelines (KSI-CMT-02)."""
    print("\n=== Testing Azure Pipelines: Missing Approval Gates ===")
    
    code = """
trigger:
  - main

stages:
  - stage: Production
    jobs:
      - job: Deploy
        steps:
          - script: az webapp deploy
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, "azure-pipelines.yml")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CMT-02" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing approval gates"
    assert any("approval" in f.description.lower() for f in findings)
    print(f"✅ Detected missing approval gates: {findings[0].title}")


def test_github_with_environment_protection():
    """Test recognition of environment protection rules (KSI-CMT-02)."""
    print("\n=== Testing GitHub Actions: With Environment Protection ===")
    
    code = """
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy-production:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://prod.example.com
    steps:
      - uses: actions/checkout@v3
      - run: ./deploy.sh
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/deploy.yml")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CMT-02" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize environment protection"
    print(f"✅ Recognized environment protection: {good_practices[0].title}")


def test_github_missing_tests():
    """Test detection of missing test execution in pipeline (KSI-CMT-03)."""
    print("\n=== Testing GitHub Actions: Missing Tests ===")
    
    code = """
name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm run build
      - run: docker build -t myapp .
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/build.yml")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CMT-03" and not f.good_practice]
    assert len(findings) >= 2, "Should detect missing unit tests and security scans"
    print(f"✅ Detected missing tests: {len(findings)} findings")


def test_azure_with_tests():
    """Test recognition of test execution in pipeline (KSI-CMT-03)."""
    print("\n=== Testing Azure Pipelines: With Tests ===")
    
    code = """
trigger:
  - main

stages:
  - stage: Test
    jobs:
      - job: UnitTests
        steps:
          - script: pytest tests/ --cov=src
          - task: PublishTestResults@2
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, "azure-pipelines.yml")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CMT-03" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize test execution"
    print(f"✅ Recognized test execution: {good_practices[0].title}")


def test_github_missing_vulnerability_scan():
    """Test detection of missing vulnerability scanning (KSI-AFR-01)."""
    print("\n=== Testing GitHub Actions: Missing Vulnerability Scan ===")
    
    code = """
name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: docker build -t myapp:${{ github.sha }} .
      - run: docker push myapp:${{ github.sha }}
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/build.yml")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-AFR-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing vulnerability scanning"
    assert any("scan" in f.description.lower() for f in findings)
    print(f"✅ Detected missing vulnerability scan: {findings[0].title}")


def test_github_with_trivy_scan():
    """Test recognition of Trivy vulnerability scanning (KSI-AFR-01)."""
    print("\n=== Testing GitHub Actions: With Trivy Scan ===")
    
    code = """
name: Security
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/security.yml")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-AFR-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize vulnerability scanning"
    print(f"✅ Recognized Trivy scanning: {good_practices[0].title}")


def test_azure_vulnerabilities_not_blocking():
    """Test detection of non-blocking vulnerability findings (KSI-AFR-02)."""
    print("\n=== Testing Azure Pipelines: Vulnerabilities Not Blocking ===")
    
    code = """
trigger:
  - main

stages:
  - stage: Security
    jobs:
      - job: Scan
        steps:
          - script: |
              trivy image myapp:latest
              echo "Scan complete"
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, "azure-pipelines.yml")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-AFR-02" and not f.good_practice]
    assert len(findings) > 0, "Should detect non-blocking vulnerabilities"
    assert any("block" in f.description.lower() or "fail" in f.description.lower() for f in findings)
    print(f"✅ Detected non-blocking vulnerabilities: {findings[0].title}")


def test_github_vulnerability_blocking():
    """Test recognition of blocking on critical vulnerabilities (KSI-AFR-02)."""
    print("\n=== Testing GitHub Actions: Vulnerability Blocking ===")
    
    code = """
name: Security
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan
        run: |
          trivy image myapp:latest --severity CRITICAL,HIGH --exit-code 1
      - name: Create issue
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Security vulnerabilities found',
              labels: ['security', 'priority-high']
            })
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/security.yml")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-AFR-02" and f.good_practice]
    # Should have at least one good practice (either blocking or issue creation)
    assert len(good_practices) > 0, "Should recognize security remediation measures"
    print(f"✅ Recognized vulnerability blocking/tracking: {len(good_practices)} good practices")


def test_azure_missing_evidence_collection():
    """Test detection of missing evidence collection (KSI-CED-01)."""
    print("\n=== Testing Azure Pipelines: Missing Evidence Collection ===")
    
    code = """
trigger:
  - main

stages:
  - stage: Test
    jobs:
      - job: UnitTests
        steps:
          - script: pytest tests/
          - script: npm test
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, "azure-pipelines.yml")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CED-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing evidence collection"
    assert any("artifact" in f.description.lower() or "evidence" in f.description.lower() for f in findings)
    print(f"✅ Detected missing evidence collection: {findings[0].title}")


def test_github_with_artifact_upload():
    """Test recognition of artifact upload for evidence (KSI-CED-01)."""
    print("\n=== Testing GitHub Actions: With Artifact Upload ===")
    
    code = """
name: CI
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pytest tests/ --cov=src --junit-xml=test-results.xml
      - uses: actions/upload-artifact@v3
        with:
          name: test-results-${{ github.sha }}
          path: |
            **/test-results/**
            **/coverage/**
          retention-days: 365
"""
    
    analyzer = CICDAnalyzer()
    result = analyzer.analyze(code, ".github/workflows/ci.yml")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CED-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize evidence collection"
    print(f"✅ Recognized artifact upload: {good_practices[0].title}")


# =============================================================================
# PHASE 5: Runtime Security & Monitoring Tests (KSI-MLA-03, MLA-04, MLA-06, INR-01, INR-02, AFR-03)
# =============================================================================

def test_bicep_missing_security_monitoring():
    """Test detection of missing security monitoring infrastructure."""
    print("\n=== Testing Bicep: Missing Security Monitoring (KSI-MLA-03) ===")
    
    code = """
    resource appService 'Microsoft.Web/sites@2022-03-01' = {
      name: 'my-app-service'
      location: location
      properties: {
        serverFarmId: appServicePlan.id
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "app.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-03" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing monitoring infrastructure"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing monitoring: {findings[0].title}")


def test_bicep_with_security_monitoring():
    """Test that complete monitoring setup is recognized."""
    print("\n=== Testing Bicep: With Security Monitoring (KSI-MLA-03) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
      name: 'law-security'
      location: location
    }
    
    resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
      name: 'appi-main'
      kind: 'web'
      properties: {
        WorkspaceResourceId: logAnalytics.id
      }
    }
    
    resource alertRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
      name: 'alert-security'
      properties: {
        enabled: true
        severity: 1
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "monitoring.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-MLA-03" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize monitoring setup"
    print(f"✅ Recognized monitoring: {good_practices[0].title}")


def test_bicep_missing_performance_monitoring():
    """Test detection of scalable resources without performance monitoring."""
    print("\n=== Testing Bicep: Missing Performance Monitoring (KSI-MLA-04) ===")
    
    code = """
    resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
      name: 'asp-main'
      location: location
      sku: {
        name: 'P1v2'
        capacity: 3
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "app-plan.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-04" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing performance monitoring"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing App Insights: {findings[0].title}")


def test_bicep_with_performance_monitoring():
    """Test that Application Insights is recognized."""
    print("\n=== Testing Bicep: With Performance Monitoring (KSI-MLA-04) ===")
    
    code = """
    resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
      name: 'asp-main'
      location: location
      sku: { name: 'P1v2' }
    }
    
    resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
      name: 'appi-main'
      kind: 'web'
      properties: {
        Application_Type: 'web'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "monitoring.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-MLA-04" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize App Insights"
    print(f"✅ Recognized App Insights: {good_practices[0].title}")


def test_bicep_missing_log_analysis():
    """Test detection of missing log analysis infrastructure."""
    print("\n=== Testing Bicep: Missing Log Analysis (KSI-MLA-06) ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorage'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-06" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing log analysis"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing log analysis: {findings[0].title}")


def test_bicep_with_log_analysis():
    """Test that Sentinel analytics rules are recognized."""
    print("\n=== Testing Bicep: With Log Analysis (KSI-MLA-06) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
      name: 'law-security'
      location: location
    }
    
    resource analyticsRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
      scope: logAnalytics
      kind: 'Scheduled'
      properties: {
        displayName: 'Failed Login Detection'
        enabled: true
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "sentinel.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-MLA-06" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize analytics rules"
    print(f"✅ Recognized log analysis: {good_practices[0].title}")


def test_bicep_missing_incident_detection():
    """Test detection of missing incident detection system."""
    print("\n=== Testing Bicep: Missing Incident Detection (KSI-INR-01) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
      name: 'law-security'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "monitoring.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-INR-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing Sentinel"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing Sentinel: {findings[0].title}")


def test_bicep_with_incident_detection():
    """Test that Sentinel with automation rules is recognized."""
    print("\n=== Testing Bicep: With Incident Detection (KSI-INR-01) ===")
    
    code = """
    resource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
      name: 'SecurityInsights'
      properties: {
        workspaceResourceId: logAnalytics.id
      }
    }
    
    resource automationRule 'Microsoft.SecurityInsights/automationRules@2023-02-01' = {
      scope: logAnalytics
      properties: {
        displayName: 'Auto-classify incidents'
        order: 1
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "sentinel.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-INR-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize incident detection"
    print(f"✅ Recognized incident detection: {good_practices[0].title}")


def test_bicep_missing_incident_logging():
    """Test detection of missing incident response logging."""
    print("\n=== Testing Bicep: Missing Incident Response Logging (KSI-INR-02) ===")
    
    code = """
    resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
      name: 'incident-response'
      location: location
      properties: {
        definition: {
          triggers: { }
        }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "response.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-INR-02" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing diagnostic logging"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing response logging: {findings[0].title}")


def test_bicep_with_incident_logging():
    """Test that diagnostic logging on Logic Apps is recognized."""
    print("\n=== Testing Bicep: With Incident Response Logging (KSI-INR-02) ===")
    
    code = """
    resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
      name: 'incident-response'
      location: location
    }
    
    resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
      scope: logicApp
      name: 'diag-incident-response'
      properties: {
        logs: [ { category: 'WorkflowRuntime' } ]
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "response.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-INR-02" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize response logging"
    print(f"✅ Recognized response logging: {good_practices[0].title}")


def test_bicep_missing_threat_intelligence():
    """Test detection of missing threat intelligence integration."""
    print("\n=== Testing Bicep: Missing Threat Intelligence (KSI-AFR-03) ===")
    
    code = """
    resource appService 'Microsoft.Web/sites@2022-03-01' = {
      name: 'my-app'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "app.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-AFR-03" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing threat intelligence"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing threat intel: {findings[0].title}")


def test_bicep_with_threat_intelligence():
    """Test that threat intelligence connectors are recognized."""
    print("\n=== Testing Bicep: With Threat Intelligence (KSI-AFR-03) ===")
    
    code = """
    resource defenderPricing 'Microsoft.Security/pricings@2023-01-01' = {
      name: 'VirtualMachines'
      properties: { pricingTier: 'Standard' }
    }
    
    resource tiConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01' = {
      kind: 'ThreatIntelligence'
      properties: {
        dataTypes: { indicators: { state: 'Enabled' } }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "threat-intel.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-AFR-03" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize threat intelligence"
    print(f"✅ Recognized threat intelligence: {good_practices[0].title}")


# Phase 6A Tests: Recovery & Infrastructure

def test_bicep_missing_recovery_objectives():
    """Test detection of missing recovery objectives."""
    print("\n=== Testing Bicep: Missing Recovery Objectives (KSI-RPL-01) ===")
    
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
      name: 'criticalVM'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "vm.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-RPL-01" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing recovery objectives"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing recovery objectives: {findings[0].title}")


def test_bicep_with_recovery_objectives():
    """Test that recovery objectives are recognized."""
    print("\n=== Testing Bicep: With Recovery Objectives (KSI-RPL-01) ===")
    
    code = """
    resource recoveryVault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'recovery-vault'
      location: location
      sku: { name: 'Standard' }
      tags: {
        rto: '4hours'
        rpo: '1hour'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "recovery.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-RPL-01" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize recovery objectives"
    print(f"✅ Recognized recovery objectives: {good_practices[0].title}")


def test_bicep_missing_recovery_plan():
    """Test detection of missing recovery plan."""
    print("\n=== Testing Bicep: Missing Recovery Plan (KSI-RPL-02) ===")
    
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
      name: 'criticalVM'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "vm.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-RPL-02" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing recovery plan"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing recovery plan: {findings[0].title}")


def test_bicep_with_recovery_plan():
    """Test that recovery plan is recognized."""
    print("\n=== Testing Bicep: With Recovery Plan (KSI-RPL-02) ===")
    
    code = """
    resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'vault'
      location: location
    }
    
    resource recoveryPlan 'Microsoft.RecoveryServices/vaults/replicationRecoveryPlans@2023-01-01' = {
      parent: vault
      name: 'dr-plan'
      properties: {
        primaryFabricId: 'fabric1'
        recoveryFabricId: 'fabric2'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "recovery-plan.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-RPL-02" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize recovery plan"
    print(f"✅ Recognized recovery plan: {good_practices[0].title}")


def test_bicep_missing_system_backups():
    """Test detection of missing system backups."""
    print("\n=== Testing Bicep: Missing System Backups (KSI-RPL-03) ===")
    
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
      name: 'criticalVM'
      location: location
    }
    
    resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
      name: 'sqlserver'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "resources.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-RPL-03" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing system backups"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing system backups: {findings[0].title}")


def test_bicep_with_system_backups():
    """Test that system backups are recognized."""
    print("\n=== Testing Bicep: With System Backups (KSI-RPL-03) ===")
    
    code = """
    resource backupVault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'backup-vault'
      location: location
    }
    
    resource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {
      parent: backupVault
      name: 'VMBackupPolicy'
      properties: {
        backupManagementType: 'AzureIaasVM'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "backup.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-RPL-03" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize system backups"
    print(f"✅ Recognized system backups: {good_practices[0].title}")


def test_bicep_missing_recovery_testing():
    """Test detection of missing recovery testing."""
    print("\n=== Testing Bicep: Missing Recovery Testing (KSI-RPL-04) ===")
    
    code = """
    resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'vault'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "vault.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-RPL-04" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing recovery testing"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing recovery testing: {findings[0].title}")


def test_bicep_with_recovery_testing():
    """Test that recovery testing automation is recognized."""
    print("\n=== Testing Bicep: With Recovery Testing (KSI-RPL-04) ===")
    
    code = """
    resource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' = {
      name: 'automation'
      location: location
    }
    
    resource testRunbook 'Microsoft.Automation/automationAccounts/runbooks@2023-11-01' = {
      parent: automationAccount
      name: 'Test-Recovery'
      properties: {
        runbookType: 'PowerShell'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "recovery-test.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-RPL-04" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize recovery testing"
    print(f"✅ Recognized recovery testing: {good_practices[0].title}")


def test_bicep_missing_traffic_flow():
    """Test detection of missing traffic flow controls."""
    print("\n=== Testing Bicep: Missing Traffic Flow (KSI-CNA-03) ===")
    
    code = """
    resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
      name: 'vnet'
      location: location
      properties: {
        addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "vnet.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CNA-03" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing traffic flow controls"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing traffic flow: {findings[0].title}")


def test_bicep_with_traffic_flow():
    """Test that traffic flow controls are recognized."""
    print("\n=== Testing Bicep: With Traffic Flow (KSI-CNA-03) ===")
    
    code = """
    resource firewall 'Microsoft.Network/azureFirewalls@2023-05-01' = {
      name: 'firewall'
      location: location
    }
    
    resource networkWatcher 'Microsoft.Network/networkWatchers@2023-05-01' = {
      name: 'networkWatcher'
      location: location
    }
    
    resource flowLog 'Microsoft.Network/networkWatchers/flowLogs@2023-05-01' = {
      parent: networkWatcher
      name: 'nsg-flow-log'
      properties: {
        enabled: true
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "firewall.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CNA-03" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize traffic flow controls"
    print(f"✅ Recognized traffic flow: {good_practices[0].title}")


def test_bicep_missing_ddos_protection():
    """Test detection of missing DDoS protection."""
    print("\n=== Testing Bicep: Missing DDoS Protection (KSI-CNA-05) ===")
    
    code = """
    resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
      name: 'vnet'
      location: location
      properties: {
        addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "vnet.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CNA-05" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing DDoS protection"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing DDoS protection: {findings[0].title}")


def test_bicep_with_ddos_protection():
    """Test that DDoS protection is recognized."""
    print("\n=== Testing Bicep: With DDoS Protection (KSI-CNA-05) ===")
    
    code = """
    resource ddosProtectionPlan 'Microsoft.Network/ddosProtectionPlans@2023-05-01' = {
      name: 'ddos-plan'
      location: location
    }
    
    resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
      name: 'vnet'
      location: location
      properties: {
        enableDdosProtection: true
        ddosProtectionPlan: { id: ddosProtectionPlan.id }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "ddos.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CNA-05" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize DDoS protection"
    print(f"✅ Recognized DDoS protection: {good_practices[0].title}")


def test_bicep_missing_least_privilege():
    """Test detection of missing least privilege."""
    print("\n=== Testing Bicep: Missing Least Privilege (KSI-IAM-05) ===")
    
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
      name: 'vm'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "vm.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-IAM-05" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing RBAC"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing least privilege: {findings[0].title}")


def test_bicep_with_least_privilege():
    """Test that least privilege RBAC is recognized."""
    print("\n=== Testing Bicep: With Least Privilege (KSI-IAM-05) ===")
    
    code = """
    resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
      name: guid(resourceGroup().id)
      properties: {
        roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
        principalId: principalId
      }
    }
    
    resource jitPolicy 'Microsoft.Security/jitNetworkAccessPolicies@2020-01-01' = {
      name: 'jit-policy'
      location: location
      properties: {
        virtualMachines: []
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "rbac.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-IAM-05" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize least privilege"
    print(f"✅ Recognized least privilege: {good_practices[0].title}")


def test_bicep_missing_cryptographic_modules():
    """Test detection of missing cryptographic modules."""
    print("\n=== Testing Bicep: Missing Cryptographic Modules (KSI-AFR-11) ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      location: location
      properties: {
        minimumTlsVersion: 'TLS1_0'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-AFR-11" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing FIPS crypto"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing cryptographic modules: {findings[0].title}")


def test_bicep_with_cryptographic_modules():
    """Test that FIPS-validated crypto is recognized."""
    print("\n=== Testing Bicep: With Cryptographic Modules (KSI-AFR-11) ===")
    
    code = """
    resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
      name: 'keyvault'
      location: location
      properties: {
        sku: {
          family: 'A'
          name: 'premium'
        }
      }
    }
    
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      location: location
      properties: {
        minimumTlsVersion: 'TLS1_2'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "crypto.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-AFR-11" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize FIPS crypto"
    print(f"✅ Recognized cryptographic modules: {good_practices[0].title}")


# ============================================================================
# Phase 6B Tests: Service Management, Advanced Monitoring, Secure Config
# ============================================================================

def test_bicep_missing_communication_integrity():
    """Test detection of missing mTLS/certificate authentication."""
    print("\n=== Testing Bicep: Missing Communication Integrity (KSI-SVC-09) ===")
    
    code = """
    resource appService 'Microsoft.Web/sites@2022-03-01' = {
      name: 'app-name'
      location: location
      properties: {
        httpsOnly: true
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "app.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-09" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing mTLS"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing communication integrity: {findings[0].title}")


def test_bicep_with_communication_integrity():
    """Test that mTLS configuration is recognized."""
    print("\n=== Testing Bicep: With Communication Integrity (KSI-SVC-09) ===")
    
    code = """
    resource appService 'Microsoft.Web/sites@2022-03-01' = {
      name: 'app-name'
      location: location
      properties: {
        clientCertEnabled: true
        clientCertMode: 'Required'
        httpsOnly: true
      }
    }
    
    resource apim 'Microsoft.ApiManagement/service@2022-08-01' = {
      name: 'apim-name'
      properties: {
        clientCertificateEnabled: true
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "mtls.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-SVC-09" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize mTLS"
    print(f"✅ Recognized communication integrity: {good_practices[0].title}")


def test_bicep_missing_data_destruction():
    """Test detection of missing soft delete capabilities."""
    print("\n=== Testing Bicep: Missing Data Destruction (KSI-SVC-10) ===")
    
    code = """
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-10" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing soft delete"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing data destruction: {findings[0].title}")


def test_bicep_with_data_destruction():
    """Test that soft delete is recognized."""
    print("\n=== Testing Bicep: With Data Destruction (KSI-SVC-10) ===")
    
    code = """
    resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
      name: 'kv-name'
      properties: {
        enableSoftDelete: true
        enablePurgeProtection: true
        softDeleteRetentionInDays: 90
      }
    }
    
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      properties: {
        deleteRetentionPolicy: {
          enabled: true
          days: 30
        }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "soft-delete.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-SVC-10" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize soft delete"
    print(f"✅ Recognized data destruction capabilities: {good_practices[0].title}")


def test_bicep_missing_event_types():
    """Test detection of missing event type documentation."""
    print("\n=== Testing Bicep: Missing Event Types (KSI-MLA-07) ===")
    
    code = """
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-07" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing event types"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing event types: {findings[0].title}")


def test_bicep_with_event_types():
    """Test that data collection rules are recognized."""
    print("\n=== Testing Bicep: With Event Types (KSI-MLA-07) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
      name: 'law-name'
      properties: {
        retentionInDays: 365
      }
    }
    
    resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
      name: 'dcr-security'
      properties: {
        description: 'Security event types for monitoring'
        dataSources: {
          windowsEventLogs: [{
            name: 'SecurityEvents'
            streams: ['Microsoft-SecurityEvent']
          }]
        }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "event-types.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-MLA-07" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize event types"
    print(f"✅ Recognized event types monitoring: {good_practices[0].title}")


def test_bicep_missing_log_access_control():
    """Test detection of missing log RBAC."""
    print("\n=== Testing Bicep: Missing Log Access Control (KSI-MLA-08) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
      name: 'law-name'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "logs.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-08" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing log RBAC"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected missing log access control: {findings[0].title}")


def test_bicep_with_log_access_control():
    """Test that log RBAC is recognized."""
    print("\n=== Testing Bicep: With Log Access Control (KSI-MLA-08) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
      name: 'law-name'
      properties: {
        publicNetworkAccessForQuery: 'Disabled'
        features: {
          enableLogAccessUsingOnlyResourcePermissions: true
        }
      }
    }
    
    resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
      scope: logAnalytics
      name: guid(logAnalytics.id, 'LogReader')
      properties: {
        principalId: principalId
        roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '73c42c96-874c-492b-b04d-ab87d138a893')
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "log-rbac.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-MLA-08" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize log RBAC"
    print(f"✅ Recognized log access control: {good_practices[0].title}")


def test_bicep_insecure_configuration():
    """Test detection of insecure default configurations."""
    print("\n=== Testing Bicep: Insecure Configuration (KSI-AFR-07) ===")
    
    code = """
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      properties: {
        allowBlobPublicAccess: true
        publicNetworkAccess: 'Enabled'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-AFR-07" and not f.good_practice]
    assert len(findings) > 0, "Should detect insecure config"
    assert findings[0].severity == Severity.HIGH
    print(f"✅ Detected insecure configuration: {findings[0].title}")


def test_bicep_with_secure_configuration():
    """Test that secure defaults are recognized."""
    print("\n=== Testing Bicep: With Secure Configuration (KSI-AFR-07) ===")
    
    code = """
    resource appService 'Microsoft.Web/sites@2022-03-01' = {
      name: 'app-name'
      properties: {
        httpsOnly: true
        siteConfig: {
          minTlsVersion: '1.2'
          ftpsState: 'Disabled'
        }
      }
    }
    
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      properties: {
        allowBlobPublicAccess: false
        publicNetworkAccess: 'Disabled'
        minimumTlsVersion: 'TLS1_2'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "secure-defaults.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-AFR-07" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize secure config"
    print(f"✅ Recognized secure configuration: {good_practices[0].title}")


def test_bicep_missing_microservices_security():
    """Test detection of missing service mesh/API security."""
    print("\n=== Testing Bicep: Missing Microservices Security (KSI-CNA-08) ===")
    
    code = """
    resource aks 'Microsoft.ContainerService/managedClusters@2023-07-01' = {
      name: 'aks-name'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "aks.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CNA-08" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing service mesh"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing microservices security: {findings[0].title}")


def test_bicep_with_microservices_security():
    """Test that service mesh is recognized."""
    print("\n=== Testing Bicep: With Microservices Security (KSI-CNA-08) ===")
    
    code = """
    resource aks 'Microsoft.ContainerService/managedClusters@2023-07-01' = {
      name: 'aks-name'
      properties: {
        serviceMeshProfile: {
          mode: 'Istio'
          istio: {
            components: {
              ingressGateways: [{ enabled: true }]
            }
          }
        }
      }
    }
    
    resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
      name: 'app-name'
      properties: {
        configuration: {
          dapr: {
            enabled: true
            appId: 'myapp'
          }
        }
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "service-mesh.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CNA-08" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize service mesh"
    print(f"✅ Recognized microservices security: {good_practices[0].title}")


def test_bicep_missing_incident_after_action():
    """Test detection of missing incident automation."""
    print("\n=== Testing Bicep: Missing Incident After-Action (KSI-INR-03) ===")
    
    code = """
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "storage.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-INR-03" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing incident automation"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing incident after-action: {findings[0].title}")


def test_bicep_with_incident_after_action():
    """Test that incident automation is recognized."""
    print("\n=== Testing Bicep: With Incident After-Action (KSI-INR-03) ===")
    
    code = """
    resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
      name: 'incident-after-action'
      properties: {
        state: 'Enabled'
        definition: {
          triggers: {
            'When_an_incident_is_closed': {
              type: 'ApiConnectionWebhook'
            }
          }
        }
      }
    }
    
    resource automation 'Microsoft.Automation/automationAccounts@2022-08-08' = {
      name: 'auto-incident-review'
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "incident-automation.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-INR-03" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize incident automation"
    print(f"✅ Recognized incident after-action: {good_practices[0].title}")


def test_bicep_missing_change_management():
    """Test detection of missing change tracking."""
    print("\n=== Testing Bicep: Missing Change Management (KSI-CMT-04) ===")
    
    code = """
    resource appService 'Microsoft.Web/sites@2022-03-01' = {
      name: 'app-name'
      location: location
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "app.bicep")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-CMT-04" and not f.good_practice]
    assert len(findings) > 0, "Should detect missing change management"
    assert findings[0].severity == Severity.MEDIUM
    print(f"✅ Detected missing change management: {findings[0].title}")


def test_bicep_with_change_management():
    """Test that change tracking is recognized."""
    print("\n=== Testing Bicep: With Change Management (KSI-CMT-04) ===")
    
    code = """
    var changeTags = {
      changeTicket: 'CHG-12345'
      deploymentId: deployment().name
      version: 'v1.2.3'
    }
    
    resource appService 'Microsoft.Web/sites@2022-03-01' = {
      name: 'app-name'
      tags: changeTags
      properties: {}
    }
    
    resource stagingSlot 'Microsoft.Web/sites/slots@2022-03-01' = {
      parent: appService
      name: 'staging'
      tags: changeTags
    }
    
    resource trafficManager 'Microsoft.Network/trafficManagerProfiles@2022-04-01' = {
      name: 'tm-name'
      properties: {
        trafficRoutingMethod: 'Weighted'
      }
    }
    """
    
    analyzer = BicepAnalyzer()
    result = analyzer.analyze(code, "change-tracking.bicep")
    
    good_practices = [f for f in result.findings if f.requirement_id == "KSI-CMT-04" and f.good_practice]
    assert len(good_practices) > 0, "Should recognize change management"
    print(f"✅ Recognized change management: {good_practices[0].title}")


def run_all_tests():
    """Run all analyzer tests."""
    print("\n" + "="*70)
    print("RUNNING CODE ANALYZER TESTS")
    print("="*70)
    
    tests = [
        # Bicep tests
        test_bicep_missing_diagnostic_settings,
        test_bicep_with_diagnostic_settings,
        test_bicep_hardcoded_password,
        test_bicep_missing_nsg,
        
        # Terraform tests
        test_terraform_missing_diagnostic_settings,
        test_terraform_hardcoded_connection_string,
        
        # Python tests - Phase 1
        test_python_missing_authentication,
        test_python_with_authentication,
        test_python_hardcoded_api_key,
        test_python_key_vault_usage,
        test_python_unsafe_pickle,
        test_python_pii_handling,
        test_python_pinned_dependencies,
        
        # Python tests - Phase 3: Error Handling (KSI-SVC-01)
        test_python_bare_except,
        test_python_proper_error_handling,
        
        # Python tests - Phase 3: Input Validation (KSI-SVC-02)
        test_python_sql_injection,
        test_python_parameterized_query,
        test_python_command_injection,
        
        # Python tests - Phase 3: Secure Coding (KSI-SVC-07)
        test_python_eval_usage,
        test_python_insecure_random,
        test_python_secure_random,
        
        # Python tests - Phase 3: Data Classification (KSI-PIY-01)
        test_python_missing_data_classification,
        test_python_with_data_classification,
        
        # Python tests - Phase 3: Privacy Controls (KSI-PIY-03)
        test_python_missing_retention_policy,
        test_python_missing_deletion_capability,
        
        # Python tests - Phase 3: Service Mesh (KSI-CNA-07)
        test_python_service_mesh_missing_mtls,
        
        # Python tests - Phase 3: Least Privilege (KSI-IAM-04)
        test_python_wildcard_permissions,
        test_python_scoped_permissions,
        
        # Python tests - Phase 3: Session Management (KSI-IAM-07)
        test_python_insecure_session,
        test_python_secure_session,
        
        # Summary tests
        test_analysis_result_summary,
        
        # CI/CD tests - Phase 4: Change Management (KSI-CMT-01)
        test_github_missing_pr_triggers,
        test_github_with_pr_triggers,
        
        # CI/CD tests - Phase 4: Deployment Procedures (KSI-CMT-02)
        test_azure_missing_approval_gates,
        test_github_with_environment_protection,
        
        # CI/CD tests - Phase 4: Automated Testing (KSI-CMT-03)
        test_github_missing_tests,
        test_azure_with_tests,
        
        # CI/CD tests - Phase 4: Vulnerability Scanning (KSI-AFR-01)
        test_github_missing_vulnerability_scan,
        test_github_with_trivy_scan,
        
        # CI/CD tests - Phase 4: Security Remediation (KSI-AFR-02)
        test_azure_vulnerabilities_not_blocking,
        test_github_vulnerability_blocking,
        
        # CI/CD tests - Phase 4: Evidence Collection (KSI-CED-01)
        test_azure_missing_evidence_collection,
        test_github_with_artifact_upload,
        
        # Bicep tests - Phase 5: Security Monitoring (KSI-MLA-03)
        test_bicep_missing_security_monitoring,
        test_bicep_with_security_monitoring,
        
        # Bicep tests - Phase 5: Performance Monitoring (KSI-MLA-04)
        test_bicep_missing_performance_monitoring,
        test_bicep_with_performance_monitoring,
        
        # Bicep tests - Phase 5: Log Analysis (KSI-MLA-06)
        test_bicep_missing_log_analysis,
        test_bicep_with_log_analysis,
        
        # Bicep tests - Phase 5: Incident Detection (KSI-INR-01)
        test_bicep_missing_incident_detection,
        test_bicep_with_incident_detection,
        
        # Bicep tests - Phase 5: Incident Response Logging (KSI-INR-02)
        test_bicep_missing_incident_logging,
        test_bicep_with_incident_logging,
        
        # Bicep tests - Phase 5: Threat Intelligence (KSI-AFR-03)
        test_bicep_missing_threat_intelligence,
        test_bicep_with_threat_intelligence,
        
        # Bicep tests - Phase 6A: Recovery Objectives (KSI-RPL-01)
        test_bicep_missing_recovery_objectives,
        test_bicep_with_recovery_objectives,
        
        # Bicep tests - Phase 6A: Recovery Plan (KSI-RPL-02)
        test_bicep_missing_recovery_plan,
        test_bicep_with_recovery_plan,
        
        # Bicep tests - Phase 6A: System Backups (KSI-RPL-03)
        test_bicep_missing_system_backups,
        test_bicep_with_system_backups,
        
        # Bicep tests - Phase 6A: Recovery Testing (KSI-RPL-04)
        test_bicep_missing_recovery_testing,
        test_bicep_with_recovery_testing,
        
        # Bicep tests - Phase 6A: Traffic Flow (KSI-CNA-03)
        test_bicep_missing_traffic_flow,
        test_bicep_with_traffic_flow,
        
        # Bicep tests - Phase 6A: DDoS Protection (KSI-CNA-05)
        test_bicep_missing_ddos_protection,
        test_bicep_with_ddos_protection,
        
        # Bicep tests - Phase 6A: Least Privilege (KSI-IAM-05)
        test_bicep_missing_least_privilege,
        test_bicep_with_least_privilege,
        
        # Bicep tests - Phase 6A: Cryptographic Modules (KSI-AFR-11)
        test_bicep_missing_cryptographic_modules,
        test_bicep_with_cryptographic_modules,
        
        # Bicep tests - Phase 6B: Communication Integrity (KSI-SVC-09)
        test_bicep_missing_communication_integrity,
        test_bicep_with_communication_integrity,
        
        # Bicep tests - Phase 6B: Data Destruction (KSI-SVC-10)
        test_bicep_missing_data_destruction,
        test_bicep_with_data_destruction,
        
        # Bicep tests - Phase 6B: Event Types (KSI-MLA-07)
        test_bicep_missing_event_types,
        test_bicep_with_event_types,
        
        # Bicep tests - Phase 6B: Log Access Control (KSI-MLA-08)
        test_bicep_missing_log_access_control,
        test_bicep_with_log_access_control,
        
        # Bicep tests - Phase 6B: Secure Configuration (KSI-AFR-07)
        test_bicep_insecure_configuration,
        test_bicep_with_secure_configuration,
        
        # Bicep tests - Phase 6B: Microservices Security (KSI-CNA-08)
        test_bicep_missing_microservices_security,
        test_bicep_with_microservices_security,
        
        # Bicep tests - Phase 6B: Incident After-Action (KSI-INR-03)
        test_bicep_missing_incident_after_action,
        test_bicep_with_incident_after_action,
        
        # Bicep tests - Phase 6B: Change Management (KSI-CMT-04)
        test_bicep_missing_change_management,
        test_bicep_with_change_management,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"❌ FAILED: {test.__name__}")
            print(f"   Error: {e}")
            failed += 1
        except Exception as e:
            print(f"❌ ERROR in {test.__name__}: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("="*70)
    
    if failed > 0:
        print("\n❌ Some tests failed!")
        return False
    else:
        print("\n✅ All tests passed!")
        return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
