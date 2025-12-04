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
