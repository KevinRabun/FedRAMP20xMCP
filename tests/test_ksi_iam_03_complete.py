"""
Comprehensive test suite for KSI-IAM-03 AST conversion.
Tests all 4 languages: Python, C#, Java, TypeScript.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity

def test_python_hardcoded_credentials():
    """Test Python detection of hardcoded service account credentials."""
    code = '''
import requests

# Hardcoded credentials (CRITICAL)
service_account_password = "hardcoded-password-123"
client_secret = "my-secret-value"

def authenticate_service():
    return service_account_password
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'python', 'test.py')
    
    hardcoded_findings = [f for f in result.findings if 'hardcoded' in f.title.lower()]
    assert len(hardcoded_findings) >= 1, f"Expected hardcoded credential findings, got {len(hardcoded_findings)}"
    print(f"[PASS] Python hardcoded credentials: {len(hardcoded_findings)} findings")

def test_python_weak_credential_type():
    """Test Python detection of weak credential types."""
    code = '''
from azure.identity import ClientSecretCredential

# Using weak credential type without DefaultAzureCredential (HIGH)
credential = ClientSecretCredential(
    tenant_id="tenant",
    client_id="client",
    client_secret="secret"
)
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'python', 'test.py')
    
    # Debug: print all findings
    print(f"  DEBUG: Got {len(result.findings)} total findings")
    for f in result.findings:
        print(f"    - {f.title}: {f.severity.value}")
    
    weak_cred_findings = [f for f in result.findings if 'weak' in f.title.lower() or 'credential' in f.title.lower()]
    assert len(weak_cred_findings) >= 1, f"Expected weak credential finding, got {len(weak_cred_findings)}"
    print(f"[PASS] Python weak credential type: {len(weak_cred_findings)} findings")

def test_python_safe_env_vars():
    """Test Python correctly excludes environment variables."""
    code = '''
import os
from azure.identity import DefaultAzureCredential

# Safe: Using environment variables
service_account_password = os.environ.get('SERVICE_PASSWORD')
client_secret = os.getenv('CLIENT_SECRET')

# Safe: Using config
app_password = config['service_password']

# Safe: Using DefaultAzureCredential
credential = DefaultAzureCredential()
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'python', 'test.py')
    
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0, f"Expected 0 CRITICAL findings for safe code, got {len(critical_findings)}"
    print(f"[PASS] Python safe environment variables: {len(result.findings)} findings (expected 0)")

def test_csharp_hardcoded_client_secret():
    """Test C# detection of hardcoded ClientSecretCredential."""
    code = '''
using Azure.Identity;
using Azure.Storage.Blobs;

// Hardcoded service principal secret (CRITICAL)
var credential = new ClientSecretCredential("tenant-id", "client-id", "hardcoded-secret-value");

var client = new BlobServiceClient(new Uri(blobUri), credential);
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'csharp', 'test.cs')
    
    # Debug output
    print(f"  DEBUG: Got {len(result.findings)} total findings")
    for f in result.findings:
        print(f"    - {f.title}: {f.severity.value}")
    
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL or f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1, f"Expected CRITICAL finding for hardcoded secret, got {len(critical_findings)}"
    print(f"[PASS] C# hardcoded ClientSecretCredential: {len(critical_findings)} findings")

def test_csharp_missing_managed_identity():
    """Test C# detection of missing DefaultAzureCredential."""
    code = '''
using Azure.Storage.Blobs;
using Azure.Core;

// Missing DefaultAzureCredential (HIGH)
var client = new BlobServiceClient(new Uri(blobUri), credential);
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'csharp', 'test.cs')
    
    # Debug output
    print(f"  DEBUG: Got {len(result.findings)} total findings")
    for f in result.findings:
        print(f"    - {f.title}: {f.severity.value}")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH or f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, f"Expected HIGH finding for missing managed identity, got {len(high_findings)}"
    print(f"[PASS] C# missing DefaultAzureCredential: {len(high_findings)} findings")

def test_csharp_use_password():
    """Test C# detection of UsePassword authentication."""
    code = '''
using Microsoft.AspNetCore.Authentication;

public void ConfigureServices(IServiceCollection services)
{
    // Password-based service account auth (CRITICAL)
    services.AddAuthentication()
        .UsePassword(options => {
            options.ServiceAccountId = "service-account";
        });
}
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'csharp', 'test.cs')
    
    password_findings = [f for f in result.findings if 'password' in f.title.lower()]
    assert len(password_findings) >= 1, f"Expected password authentication finding, got {len(password_findings)}"
    print(f"[PASS] C# UsePassword authentication: {len(password_findings)} findings")

def test_csharp_safe_configuration():
    """Test C# correctly excludes Configuration[] usage."""
    code = '''
using Azure.Identity;
using Microsoft.Extensions.Configuration;

// Safe: Using Configuration
var tenantId = Configuration["Azure:TenantId"];
var clientId = Configuration["Azure:ClientId"];
var clientSecret = Configuration["Azure:ClientSecret"];

// Safe: Using DefaultAzureCredential
var credential = new DefaultAzureCredential();
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'csharp', 'test.cs')
    
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0, f"Expected 0 CRITICAL findings for safe code, got {len(critical_findings)}"
    print(f"[PASS] C# safe Configuration usage: {len(result.findings)} findings (expected 0)")

def test_java_hardcoded_client_secret():
    """Test Java detection of hardcoded setClientSecret."""
    code = '''
import com.azure.identity.ClientSecretCredentialBuilder;

public class AzureClient {
    public void connect() {
        // Hardcoded client secret (CRITICAL)
        var credential = new ClientSecretCredentialBuilder().tenantId("tenant-id").clientId("client-id").clientSecret("hardcoded-secret-123").build();
    }
}
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'java', 'AzureClient.java')
    
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL or f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1, f"Expected CRITICAL finding for hardcoded secret, got {len(critical_findings)}"
    print(f"[PASS] Java hardcoded setClientSecret: {len(critical_findings)} findings")

def test_java_missing_default_credential():
    """Test Java detection of missing DefaultAzureCredentialBuilder."""
    code = '''
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;

public class BlobHandler {
    public void initialize() {
        // Missing DefaultAzureCredentialBuilder (HIGH)
        BlobServiceClient client = new BlobServiceClientBuilder()
            .endpoint(blobEndpoint)
            .buildClient();
    }
}
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'java', 'BlobHandler.java')
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, f"Expected HIGH finding for missing managed identity, got {len(high_findings)}"
    print(f"[PASS] Java missing DefaultAzureCredentialBuilder: {len(high_findings)} findings")

def test_java_basic_authentication():
    """Test Java detection of basic authentication."""
    code = '''
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

@Configuration
public class SecurityConfig {
    @Bean
    public BasicAuthenticationEntryPoint authEntryPoint() {
        // Basic auth for service account (CRITICAL)
        BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
        entryPoint.setRealmName("Service Realm");
        return entryPoint;
    }
}
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'java', 'SecurityConfig.java')
    
    basic_auth_findings = [f for f in result.findings if 'basic' in f.title.lower()]
    assert len(basic_auth_findings) >= 1, f"Expected basic authentication finding, got {len(basic_auth_findings)}"
    print(f"[PASS] Java basic authentication: {len(basic_auth_findings)} findings")

def test_typescript_hardcoded_tokens():
    """Test TypeScript detection of hardcoded service account tokens."""
    code = '''
// Hardcoded service account tokens (CRITICAL)
const serviceAccountToken = "sk-hardcoded-token-123";
const clientSecret = "hardcoded-secret";
const apiKey = "api-key-12345";

async function authenticate() {
    return serviceAccountToken;
}
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'typescript', 'auth.ts')
    
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1, f"Expected CRITICAL finding for hardcoded tokens, got {len(critical_findings)}"
    print(f"[PASS] TypeScript hardcoded tokens: {len(critical_findings)} findings")

def test_typescript_missing_default_credential():
    """Test TypeScript detection of missing DefaultAzureCredential."""
    code = '''
import { BlobServiceClient } from '@azure/storage-blob';
import { ClientSecretCredential } from '@azure/identity';

// Missing DefaultAzureCredential (HIGH)
const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
const client = new BlobServiceClient(blobUrl, credential);
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'typescript', 'blob-client.ts')
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, f"Expected HIGH finding for missing DefaultAzureCredential, got {len(high_findings)}"
    print(f"[PASS] TypeScript missing DefaultAzureCredential: {len(high_findings)} findings")

def test_typescript_basic_auth():
    """Test TypeScript detection of basic authentication."""
    code = '''
import passport from 'passport';
import { BasicStrategy } from 'passport-http';

// Basic auth for service account (HIGH)
passport.use(new BasicStrategy(
    function(username, password, done) {
        // Service account authentication
        return done(null, user);
    }
));
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'typescript', 'auth.ts')
    
    basic_findings = [f for f in result.findings if 'basic' in f.title.lower()]
    assert len(basic_findings) >= 1, f"Expected basic authentication finding, got {len(basic_findings)}"
    print(f"[PASS] TypeScript basic authentication: {len(basic_findings)} findings")

def test_typescript_safe_env_vars():
    """Test TypeScript correctly excludes environment variables."""
    code = '''
import { DefaultAzureCredential } from '@azure/identity';

// Safe: Using environment variables
const serviceAccountToken = process.env.SERVICE_TOKEN;
const clientSecret = process.env.CLIENT_SECRET;
const apiKey = config.get('API_KEY');

// Safe: Using DefaultAzureCredential
const credential = new DefaultAzureCredential();
'''
    factory = get_factory()
    result = factory.analyze('KSI-IAM-03', code, 'typescript', 'auth.ts')
    
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0, f"Expected 0 CRITICAL findings for safe code, got {len(critical_findings)}"
    print(f"[PASS] TypeScript safe environment variables: {len(result.findings)} findings (expected 0)")

if __name__ == '__main__':
    print("=" * 70)
    print("KSI-IAM-03 Comprehensive AST Conversion Tests")
    print("=" * 70)
    print()
    
    # Python tests
    print("Python Tests:")
    test_python_hardcoded_credentials()
    test_python_weak_credential_type()
    test_python_safe_env_vars()
    print()
    
    # C# tests
    print("C# Tests:")
    test_csharp_hardcoded_client_secret()
    test_csharp_missing_managed_identity()
    test_csharp_use_password()
    test_csharp_safe_configuration()
    print()
    
    # Java tests
    print("Java Tests:")
    test_java_hardcoded_client_secret()
    test_java_missing_default_credential()
    test_java_basic_authentication()
    print()
    
    # TypeScript tests
    print("TypeScript Tests:")
    test_typescript_hardcoded_tokens()
    test_typescript_missing_default_credential()
    test_typescript_basic_auth()
    test_typescript_safe_env_vars()
    print()
    
    print("=" * 70)
    print("All KSI-IAM-03 tests passed!")
    print("=" * 70)
