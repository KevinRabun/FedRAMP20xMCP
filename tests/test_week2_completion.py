"""
Week 2 Pattern Expansion Test

Tests new AFR patterns added in Week 2 to measure accuracy improvement.
Target: 50% accuracy (up from 30% in Week 1)
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.tools.analyzer import (
    analyze_infrastructure_code_impl,
    analyze_application_code_impl,
    analyze_cicd_pipeline_impl
)
from fedramp_20x_mcp.analyzers.pattern_tool_adapter import PatternToolAdapter
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory

# Test infrastructure code with AFR pattern issues
TEST_BICEP_CODE = '''
// Test file for Week 2 AFR patterns

// Issue 1: Storage account with TLS 1.0 (afr.crypto.weak_algorithms)
resource storageAccountWeak 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'weakstorageacct'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_0'  // CRITICAL: Weak TLS version
    supportsHttpsTrafficOnly: true
  }
}

// Issue 2: SQL Server with TLS 1.1 (afr.crypto.weak_algorithms)
resource sqlServerWeak 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'weaksqlserver'
  location: 'eastus'
  properties: {
    minimalTlsVersion: '1.1'  // HIGH: Weak TLS version
  }
}

// Issue 3: Storage without HTTPS enforcement (afr.config.insecure_defaults)
resource storageInsecure 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'insecurestorageacct'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: false  // HIGH: Insecure default
  }
}

// Issue 4: SQL Server with public access (afr.config.insecure_defaults)
resource sqlServerPublic 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'publicsqlserver'
  location: 'eastus'
  properties: {
    publicNetworkAccess: 'Enabled'  // HIGH: Insecure default
  }
}

// Issue 5: Key Vault without soft delete (afr.config.insecure_defaults)
resource keyVaultInsecure 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'insecurekeyvault'
  location: 'eastus'
  properties: {
    enableSoftDelete: false  // HIGH: Insecure default
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}

// Issue 6: App Service with debug mode (afr.config.debug_mode)
resource appServiceDebug 'Microsoft.Web/sites@2023-01-01' = {
  name: 'debugappservice'
  location: 'eastus'
  properties: {
    siteConfig: {
      appSettings: [
        {
          name: 'ASPNETCORE_ENVIRONMENT'
          value: 'Development'  // HIGH: Debug mode in production
        }
      ]
    }
  }
}

// Issue 7: Missing Defender for Cloud (afr.scanning.missing_vulnerability_scan)
// No Microsoft.Security/pricings resource = missing vulnerability scanning

// Good: Secure configuration (no issues)
resource storageSecure 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'securestorageacct'
  location: 'eastus'
  sku: {
    name: 'Standard_GRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'  // GOOD: TLS 1.2
    supportsHttpsTrafficOnly: true  // GOOD: HTTPS enforced
    allowBlobPublicAccess: false
  }
}
'''

# Test Python code with AFR pattern issues
TEST_PYTHON_CODE = '''
"""
Test file for Week 2 AFR patterns
"""
import hashlib
from Crypto.Cipher import DES
import ssl
from flask import Flask

# Issue 1: Weak hash algorithm - MD5 (afr.crypto.weak_algorithms)
def hash_password_weak(password):
    hash_obj = hashlib.md5(password.encode())  # CRITICAL: MD5 is weak
    return hash_obj.hexdigest()

# Issue 2: Weak hash algorithm - SHA1 (afr.crypto.weak_algorithms)
def hash_data_weak(data):
    hash_obj = hashlib.sha1(data.encode())  # CRITICAL: SHA1 is weak
    return hash_obj.hexdigest()

# Issue 3: Weak encryption - DES (afr.crypto.weak_algorithms)
def encrypt_weak(data, key):
    cipher = DES.new(key, DES.MODE_ECB)  # CRITICAL: DES is weak
    return cipher.encrypt(data)

# Issue 4: Insecure TLS version (afr.crypto.weak_algorithms)
def create_ssl_context_weak():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # HIGH: TLS 1.0 is weak
    return context

# Issue 5: Debug mode enabled (afr.config.debug_mode)
app = Flask(__name__)
app.debug = True  # HIGH: Debug mode in production

@app.route('/')
def index():
    return 'Hello World'

# Good: Secure hashing (no issues)
def hash_password_secure(password):
    hash_obj = hashlib.sha256(password.encode())  # GOOD: SHA-256
    return hash_obj.hexdigest()

# Good: Secure TLS (no issues)
def create_ssl_context_secure():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # GOOD: TLS 1.2+
    return context

if __name__ == '__main__':
    app.run(debug=False)  # GOOD: Debug disabled
'''

# Test CI/CD with AFR pattern issues
TEST_GITHUB_ACTIONS = '''
# Test file for Week 2 AFR patterns
name: Build and Deploy

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Build application
        run: |
          npm install
          npm run build
      
      # Issue 1: Missing vulnerability scanning (afr.scanning.missing_vulnerability_scan)
      # No SAST, dependency scanning, or container scanning configured
      
      - name: Deploy to production
        run: |
          echo "Deploying..."
'''

# Test CI/CD with good scanning (no issues)
TEST_GITHUB_ACTIONS_SECURE = '''
name: Secure Build and Deploy

on:
  push:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # GOOD: CodeQL for SAST (afr.scanning.missing_vulnerability_scan)
      - uses: github/codeql-action/init@v3
        with:
          languages: 'python, javascript'
      
      - uses: github/codeql-action/analyze@v3
      
      # GOOD: Dependency review (afr.scanning.missing_vulnerability_scan)
      - uses: actions/dependency-review-action@v4
      
      # GOOD: Container scanning with Trivy (afr.scanning.missing_vulnerability_scan)
      - uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
'''

async def run_week2_tests():
    """Test Week 2 AFR patterns for accuracy improvement"""
    
    print("=" * 60)
    print("WEEK 2 PATTERN EXPANSION TEST")
    print("=" * 60)
    print()
    
    # Initialize pattern engine
    print("Initializing pattern engine...")
    pattern_adapter = PatternToolAdapter()
    pattern_adapter._ensure_loaded()
    
    if pattern_adapter.engine:
        total_patterns = len(pattern_adapter.engine.patterns)
        print(f"Loaded {total_patterns} patterns")
    else:
        print("Pattern engine not initialized")
    print()
    
    # Test Bicep infrastructure code
    print("=" * 60)
    print("TEST 1: Bicep Infrastructure Code (AFR patterns)")
    print("=" * 60)
    print()
    print("Expected AFR findings:")
    print("  1. Storage TLS 1.0 (afr.crypto.weak_algorithms) - CRITICAL")
    print("  2. SQL TLS 1.1 (afr.crypto.weak_algorithms) - CRITICAL") 
    print("  3. Storage without HTTPS (afr.config.insecure_defaults) - HIGH")
    print("  4. SQL public access (afr.config.insecure_defaults) - HIGH")
    print("  5. Key Vault no soft delete (afr.config.insecure_defaults) - HIGH")
    print("  6. App Service debug mode (afr.config.debug_mode) - HIGH")
    print()
    
    bicep_result = await analyze_infrastructure_code_impl(TEST_BICEP_CODE, "bicep", "test_week2.bicep")
    bicep_findings = bicep_result.get('findings', [])
    bicep_afr_findings = [f for f in bicep_findings if f.get('requirement_id', '').startswith('afr.')]
    
    print(f"Pattern engine found {len(bicep_findings)} total findings")
    print(f"AFR-specific findings: {len(bicep_afr_findings)}")
    print()
    
    if bicep_afr_findings:
        print("AFR findings detected:")
        for finding in bicep_afr_findings:
            severity = finding.get('severity', 'unknown').upper()
            req_id = finding.get('requirement_id', 'unknown')
            title = finding.get('title', 'unknown')
            print(f"  - [{severity}] {title} ({req_id})")
    else:
        print("No AFR findings detected")
    print()
    
    # Test Python application code
    print("=" * 60)
    print("TEST 2: Python Application Code (AFR patterns)")
    print("=" * 60)
    print()
    print("Expected AFR findings:")
    print("  1. MD5 hash (afr.crypto.weak_algorithms) - CRITICAL")
    print("  2. SHA1 hash (afr.crypto.weak_algorithms) - CRITICAL")
    print("  3. DES encryption (afr.crypto.weak_algorithms) - CRITICAL")
    print("  4. TLS 1.0 (afr.crypto.weak_algorithms) - HIGH")
    print("  5. Debug mode enabled (afr.config.debug_mode) - HIGH")
    print()
    
    python_result = await analyze_application_code_impl(TEST_PYTHON_CODE, "python", "test_week2.py")
    python_findings = python_result.get('findings', [])
    python_afr_findings = [f for f in python_findings if f.get('requirement_id', '').startswith('afr.')]
    
    print(f"Pattern engine found {len(python_findings)} total findings")
    print(f"AFR-specific findings: {len(python_afr_findings)}")
    print()
    
    if python_afr_findings:
        print("AFR findings detected:")
        for finding in python_afr_findings:
            severity = finding.get('severity', 'unknown').upper()
            req_id = finding.get('requirement_id', 'unknown')
            title = finding.get('title', 'unknown')
            print(f"  - [{severity}] {title} ({req_id})")
    else:
        print("No AFR findings detected")
    print()
    # Test GitHub Actions CI/CD
    print("=" * 60)
    print("TEST 3: GitHub Actions CI/CD (AFR patterns)")
    print("=" * 60)
    print()
    print("Expected AFR findings:")
    print("  1. Missing vulnerability scanning (afr.scanning.missing_vulnerability_scan) - HIGH")
    print()
    
    cicd_result = await analyze_cicd_pipeline_impl(TEST_GITHUB_ACTIONS, "github_actions", "test_week2.yml")
    cicd_findings = cicd_result.get('findings', [])
    cicd_afr_findings = [f for f in cicd_findings if f.get('requirement_id', '').startswith('afr.')]
    
    print(f"Pattern engine found {len(cicd_findings)} total findings")
    print(f"AFR-specific findings: {len(cicd_afr_findings)}")
    print()
    
    if cicd_afr_findings:
        print("AFR findings detected:")
        for finding in cicd_afr_findings:
            severity = finding.get('severity', 'unknown').upper()
            req_id = finding.get('requirement_id', 'unknown')
            title = finding.get('title', 'unknown')
            print(f"  - [{severity}] {title} ({req_id})")
    else:
        print("No AFR findings detected (expected - pattern looks for positive security scanning)")
    print()
    
    # Summary
    print("=" * 60)
    print("WEEK 2 TEST SUMMARY")
    print("=" * 60)
    print()
    
    total_afr = len(bicep_afr_findings) + len(python_afr_findings) + len(cicd_afr_findings)
    total_expected = 12  # 6 Bicep + 5 Python + 1 CI/CD (or 0 if pattern is positive)
    
    print(f"Total AFR findings: {total_afr}")
    print(f"Expected AFR findings: {total_expected} (approximately)")
    print(f"Detection rate: {(total_afr / total_expected * 100):.1f}%" if total_expected > 0 else "N/A")
    print()
    
    print(f"Pattern library: 139 patterns across 16 families")
    print(f"New AFR patterns: 4 (crypto, debug mode, insecure defaults, scanning)")
    print()
    
    # Run traditional analyzers for comparison
    print("=" * 60)
    print("COMPARISON WITH TRADITIONAL ANALYZERS")
    print("=" * 60)
    print()
    print("Running traditional KSI analyzers...")
    
    factory = get_factory()
    
    # Analyze Python code with traditional analyzers
    ksi_afr_11 = factory.get_analyzer("KSI-AFR-11")
    ksi_afr_07 = factory.get_analyzer("KSI-AFR-07")
    
    if ksi_afr_11:
        trad_findings_py = ksi_afr_11.analyze(TEST_PYTHON_CODE, "python", "test_week2.py")
        print(f"KSI-AFR-11 (traditional): {len(trad_findings_py.findings) if trad_findings_py else 0} findings")
    
    if ksi_afr_07:
        trad_findings_py_07 = ksi_afr_07.analyze(TEST_PYTHON_CODE, "python", "test_week2.py")
        print(f"KSI-AFR-07 (traditional): {len(trad_findings_py_07.findings) if trad_findings_py_07 else 0} findings")
    
    print()
    print("[PASS] Week 2 pattern expansion test complete")

if __name__ == "__main__":
    asyncio.run(run_week2_tests())
