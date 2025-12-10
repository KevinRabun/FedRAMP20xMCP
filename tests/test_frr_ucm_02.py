"""
Tests for FRR-UCM-02: Use of Validated Cryptographic Modules

Tests comprehensive detection of non-FIPS cryptographic modules across
Python, C#, Java, TypeScript, and Azure IaC (Bicep/Terraform).
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.frr.frr_ucm_02 import FRR_UCM_02_Analyzer
from src.fedramp_20x_mcp.analyzers.base import Severity


def test_python_md5_detected():
    """Test detection of MD5 hash in Python code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import hashlib

def hash_password(password):
    # Weak crypto - MD5 is not FIPS approved
    return hashlib.md5(password.encode()).hexdigest()
"""
    findings = analyzer.analyze_python(code)
    assert len(findings) >= 1, "Should detect MD5 usage"
    assert any('MD5' in f.title for f in findings), "Should flag MD5"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_python_md5_detected PASSED")


def test_python_sha1_detected():
    """Test detection of SHA1 hash in Python code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import hashlib

def create_signature(data):
    # SHA1 is deprecated and not FIPS compliant
    return hashlib.sha1(data.encode()).digest()
"""
    findings = analyzer.analyze_python(code)
    assert len(findings) >= 1, "Should detect SHA1 usage"
    assert any('SHA1' in f.title for f in findings), "Should flag SHA1"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_python_sha1_detected PASSED")


def test_python_des_cipher_detected():
    """Test detection of DES cipher in Python code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def encrypt_data(data, key):
    # DES is not FIPS 140-2 validated
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
"""
    findings = analyzer.analyze_python(code)
    assert len(findings) >= 1, "Should detect DES cipher"
    assert any('DES' in f.title for f in findings), "Should flag DES"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_python_des_cipher_detected PASSED")


def test_python_fips_compliant_passes():
    """Test that FIPS-compliant Python code passes."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def secure_hash(data):
    # SHA-256 is FIPS approved
    return hashlib.sha256(data.encode()).hexdigest()

def secure_encrypt(data, key, iv):
    # AES-256 is FIPS 140-2 validated
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()
"""
    findings = analyzer.analyze_python(code)
    assert len(findings) == 0, f"FIPS-compliant code should pass, but got {len(findings)} findings"
    print("✓ test_python_fips_compliant_passes PASSED")


def test_python_custom_crypto_detected():
    """Test detection of custom cryptography implementation."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
class CustomCryptoEngine:
    def encrypt(self, data, key):
        # Custom crypto implementation - NOT FIPS validated!
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)
    
    def decrypt(self, data, key):
        return self.encrypt(data, key)  # XOR is symmetric
"""
    findings = analyzer.analyze_python(code)
    assert len(findings) >= 1, "Should detect custom crypto implementation"
    assert any('custom' in f.title.lower() for f in findings), "Should flag custom crypto"
    assert any(f.severity == Severity.CRITICAL for f in findings), "Should be CRITICAL severity"
    print("✓ test_python_custom_crypto_detected PASSED")


def test_csharp_md5_provider_detected():
    """Test detection of MD5CryptoServiceProvider in C# code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
using System.Security.Cryptography;

public class HashUtil
{
    public static byte[] ComputeHash(string input)
    {
        // MD5 is not FIPS compliant
        using (var hasher = MD5.Create())
        {
            return hasher.ComputeHash(Encoding.UTF8.GetBytes(input));
        }
    }
}
"""
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1, "Should detect MD5 usage"
    assert any('MD5' in f.title for f in findings), "Should flag MD5"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_csharp_md5_provider_detected PASSED")


def test_csharp_des_provider_detected():
    """Test detection of DESCryptoServiceProvider in C# code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
using System.Security.Cryptography;

public class EncryptionUtil
{
    public static byte[] Encrypt(byte[] data, byte[] key)
    {
        // DES is not FIPS 140-2 validated
        using (var des = DES.Create())
        {
            des.Key = key;
            return des.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }
    }
}
"""
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1, "Should detect DES usage"
    assert any('DES' in f.title for f in findings), "Should flag DES"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_csharp_des_provider_detected PASSED")


def test_csharp_fips_policy_disabled():
    """Test detection of FIPS policy enforcement disabled."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <!-- FIPS policy disabled - non-compliant! -->
    <enforceFIPSPolicy enabled="false"/>
  </runtime>
</configuration>
"""
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1, "Should detect FIPS policy disabled"
    assert any('FIPS policy' in f.title for f in findings), "Should flag FIPS policy"
    assert any(f.severity == Severity.CRITICAL for f in findings), "Should be CRITICAL severity"
    print("✓ test_csharp_fips_policy_disabled PASSED")


def test_java_md5_digest_detected():
    """Test detection of MD5 MessageDigest in Java code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import java.security.MessageDigest;

public class HashUtil {
    public static byte[] hashData(byte[] data) throws Exception {
        // MD5 is not FIPS 140-2 approved
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(data);
    }
}
"""
    findings = analyzer.analyze_java(code)
    assert len(findings) >= 1, "Should detect MD5 MessageDigest"
    assert any('MD5' in f.title for f in findings), "Should flag MD5"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_java_md5_digest_detected PASSED")


def test_java_des_cipher_detected():
    """Test detection of DES Cipher in Java code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CryptoUtil {
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        // DES is not FIPS validated
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
"""
    findings = analyzer.analyze_java(code)
    assert len(findings) >= 1, "Should detect DES cipher"
    assert any('DES' in f.title for f in findings), "Should flag DES"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_java_des_cipher_detected PASSED")


def test_typescript_md5_hash_detected():
    """Test detection of MD5 hash in TypeScript code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import * as crypto from 'crypto';

export function hashPassword(password: string): string {
    // MD5 is not FIPS approved
    return crypto.createHash('md5').update(password).digest('hex');
}
"""
    findings = analyzer.analyze_typescript(code)
    assert len(findings) >= 1, "Should detect MD5 usage"
    assert any('MD5' in f.title for f in findings), "Should flag MD5"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_typescript_md5_hash_detected PASSED")


def test_typescript_des_cipher_detected():
    """Test detection of DES cipher in TypeScript code."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import * as crypto from 'crypto';

export function encryptData(data: string, key: Buffer): Buffer {
    // DES is not FIPS 140-2 validated
    const cipher = crypto.createCipher('des', key);
    return Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
}
"""
    findings = analyzer.analyze_typescript(code)
    assert len(findings) >= 1, "Should detect DES cipher"
    assert any('DES' in f.title for f in findings), "Should flag DES"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_typescript_des_cipher_detected PASSED")


def test_typescript_non_fips_library():
    """Test detection of non-FIPS crypto library."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
import * as CryptoJS from 'crypto-js';

export function hashData(data: string): string {
    // crypto-js is not FIPS validated
    return CryptoJS.SHA256(data).toString();
}
"""
    findings = analyzer.analyze_typescript(code)
    assert len(findings) >= 1, "Should detect non-FIPS library"
    assert any('crypto-js' in f.title for f in findings), "Should flag crypto-js"
    assert any(f.severity == Severity.MEDIUM for f in findings), "Should be MEDIUM severity"
    print("✓ test_typescript_non_fips_library PASSED")


def test_bicep_storage_no_infra_encryption():
    """Test detection of Storage Account without infrastructure encryption."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: 'mystorageaccount'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    encryption: {
      keySource: 'Microsoft.Storage'
      services: {
        blob: {
          enabled: true
        }
      }
      // Missing requireInfrastructureEncryption: true
    }
  }
}
"""
    findings = analyzer.analyze_bicep(code)
    assert len(findings) >= 1, "Should detect missing infrastructure encryption"
    assert any('infrastructure encryption' in f.title.lower() for f in findings), "Should flag infrastructure encryption"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_bicep_storage_no_infra_encryption PASSED")


def test_bicep_keyvault_standard_sku():
    """Test detection of Key Vault with Standard SKU (no HSM support)."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: 'myvault'
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'  // Standard SKU doesn't support HSM-backed keys
    }
    enabledForDeployment: false
    enabledForTemplateDeployment: false
  }
}
"""
    findings = analyzer.analyze_bicep(code)
    assert len(findings) >= 1, "Should detect Standard SKU"
    assert any('standard' in f.title.lower() or 'sku' in f.title.lower() for f in findings), "Should flag Standard SKU"
    assert any(f.severity == Severity.MEDIUM for f in findings), "Should be MEDIUM severity"
    print("✓ test_bicep_keyvault_standard_sku PASSED")


def test_terraform_storage_no_infra_encryption():
    """Test detection of Terraform Storage Account without infrastructure encryption."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  # Missing infrastructure_encryption_enabled = true
}
"""
    findings = analyzer.analyze_terraform(code)
    assert len(findings) >= 1, "Should detect missing infrastructure encryption"
    assert any('infrastructure encryption' in f.title.lower() for f in findings), "Should flag infrastructure encryption"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("✓ test_terraform_storage_no_infra_encryption PASSED")


def test_terraform_keyvault_standard_sku():
    """Test detection of Terraform Key Vault with standard SKU."""
    analyzer = FRR_UCM_02_Analyzer()
    code = """
resource "azurerm_key_vault" "example" {
  name                = "myvault"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  
  sku_name = "standard"  # Standard doesn't support HSM
}
"""
    findings = analyzer.analyze_terraform(code)
    assert len(findings) >= 1, "Should detect Standard SKU"
    assert any('standard' in f.title.lower() or 'sku' in f.title.lower() for f in findings), "Should flag Standard SKU"
    assert any(f.severity == Severity.MEDIUM for f in findings), "Should be MEDIUM severity"
    print("✓ test_terraform_keyvault_standard_sku PASSED")


def test_no_findings_for_fips_compliant_code():
    """Test that FIPS-compliant code across languages produces no findings."""
    analyzer = FRR_UCM_02_Analyzer()
    
    # Python FIPS-compliant
    python_code = """
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def secure_operations():
    hash_result = hashlib.sha256(b'data').digest()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
"""
    
    # C# FIPS-compliant
    csharp_code = """
using System.Security.Cryptography;
public class Crypto {
    public byte[] Hash(byte[] data) {
        using (var sha = SHA256.Create()) {
            return sha.ComputeHash(data);
        }
    }
}
"""
    
    # Java FIPS-compliant
    java_code = """
import javax.crypto.Cipher;
import java.security.MessageDigest;
public class Crypto {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}
"""
    
    # TypeScript FIPS-compliant
    typescript_code = """
import * as crypto from 'crypto';
export function hash(data: string): Buffer {
    return crypto.createHash('sha256').update(data).digest();
}
"""
    
    # Bicep FIPS-compliant
    bicep_code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: 'secure'
  properties: {
    encryption: {
      requireInfrastructureEncryption: true
      keySource: 'Microsoft.Keyvault'
    }
  }
}
resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: 'vault'
  properties: {
    sku: { name: 'premium' }
  }
}
"""
    
    # Terraform FIPS-compliant
    terraform_code = """
resource "azurerm_storage_account" "secure" {
  name = "secure"
  infrastructure_encryption_enabled = true
}
resource "azurerm_key_vault" "secure" {
  name = "vault"
  sku_name = "premium"
}
"""
    
    python_findings = analyzer.analyze_python(python_code)
    csharp_findings = analyzer.analyze_csharp(csharp_code)
    java_findings = analyzer.analyze_java(java_code)
    typescript_findings = analyzer.analyze_typescript(typescript_code)
    bicep_findings = analyzer.analyze_bicep(bicep_code)
    terraform_findings = analyzer.analyze_terraform(terraform_code)
    
    total_findings = len(python_findings) + len(csharp_findings) + len(java_findings) + \
                     len(typescript_findings) + len(bicep_findings) + len(terraform_findings)
    
    assert total_findings == 0, f"FIPS-compliant code should have 0 findings, got {total_findings}"
    print("✓ test_no_findings_for_fips_compliant_code PASSED")


def test_analyzer_metadata():
    """Test that analyzer has correct metadata."""
    analyzer = FRR_UCM_02_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-UCM-02", "FRR_ID should be FRR-UCM-02"
    assert analyzer.FRR_NAME == "Use of Validated Cryptographic Modules", "FRR_NAME mismatch"
    assert analyzer.FAMILY == "UCM", "FAMILY should be UCM"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "PRIMARY_KEYWORD should be MUST"
    assert analyzer.IMPACT_LOW is True, "Should apply to Low impact"
    assert analyzer.IMPACT_MODERATE is True, "Should apply to Moderate impact"
    assert analyzer.IMPACT_HIGH is True, "Should apply to High impact"
    assert analyzer.CODE_DETECTABLE is True, "Should be code-detectable"
    assert analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED", "Should be IMPLEMENTED"
    
    # Check NIST controls
    assert len(analyzer.NIST_CONTROLS) >= 2, "Should have at least 2 NIST controls"
    control_ids = [ctrl[0] for ctrl in analyzer.NIST_CONTROLS]
    assert "SC-13" in control_ids, "Should include SC-13 (Cryptographic Protection)"
    assert "SC-12" in control_ids, "Should include SC-12 (Key Management)"
    
    print("✓ test_analyzer_metadata PASSED")


def test_evidence_automation_recommendations():
    """Test that evidence automation recommendations are provided."""
    analyzer = FRR_UCM_02_Analyzer()
    recommendations = analyzer.get_evidence_automation_recommendations()
    
    assert recommendations is not None, "Should return recommendations"
    assert recommendations['frr_id'] == "FRR-UCM-02", "FRR_ID mismatch"
    assert recommendations['primary_keyword'] == "MUST", "PRIMARY_KEYWORD should be MUST"
    assert len(recommendations['impact_levels']) == 3, "Should have 3 impact levels"
    assert 'azure_services' in recommendations, "Should include Azure services"
    assert len(recommendations['azure_services']) >= 3, "Should list at least 3 Azure services"
    assert 'collection_methods' in recommendations, "Should include collection methods"
    assert len(recommendations['collection_methods']) >= 4, "Should have at least 4 collection methods"
    
    print("✓ test_evidence_automation_recommendations PASSED")


def test_evidence_collection_queries():
    """Test that evidence collection queries are provided."""
    analyzer = FRR_UCM_02_Analyzer()
    queries = analyzer.get_evidence_collection_queries()
    
    assert queries is not None, "Should return queries"
    assert len(queries) >= 3, "Should have at least 3 queries"
    
    # Check query structure
    for query in queries:
        assert 'query_type' in query, "Query should have type"
        assert 'query_name' in query, "Query should have name"
        assert 'query' in query, "Query should have query content"
        assert 'purpose' in query, "Query should have purpose"
    
    # Check for specific query types
    query_types = [q['query_type'] for q in queries]
    assert any('KQL' in qt or 'Kusto' in qt or 'Resource Graph' in qt for qt in query_types), "Should include Azure Resource Graph KQL queries"
    
    print("✓ test_evidence_collection_queries PASSED")


def test_evidence_artifacts():
    """Test that evidence artifacts are documented."""
    analyzer = FRR_UCM_02_Analyzer()
    artifacts = analyzer.get_evidence_artifacts()
    
    assert artifacts is not None, "Should return artifacts"
    assert len(artifacts) >= 4, "Should have at least 4 artifact types"
    
    # Check artifact structure
    for artifact in artifacts:
        assert 'artifact_name' in artifact, "Artifact should have name"
        assert 'artifact_type' in artifact, "Artifact should have type"
        assert 'description' in artifact, "Artifact should have description"
        assert 'collection_method' in artifact, "Artifact should have collection method"
        assert 'storage_location' in artifact, "Artifact should have storage location"
    
    # Check for required artifacts
    artifact_names = [a['artifact_name'] for a in artifacts]
    assert any('Cryptographic Module Inventory' in name for name in artifact_names), "Should include crypto module inventory"
    assert any('FIPS' in name or 'Certificate' in name for name in artifact_names), "Should include FIPS validation certificates"
    assert any('Key Vault' in name for name in artifact_names), "Should include Key Vault configuration"
    
    print("✓ test_evidence_artifacts PASSED")


def run_all_tests():
    """Run all test functions."""
    test_functions = [
        test_python_md5_detected,
        test_python_sha1_detected,
        test_python_des_cipher_detected,
        test_python_fips_compliant_passes,
        test_python_custom_crypto_detected,
        test_csharp_md5_provider_detected,
        test_csharp_des_provider_detected,
        test_csharp_fips_policy_disabled,
        test_java_md5_digest_detected,
        test_java_des_cipher_detected,
        test_typescript_md5_hash_detected,
        test_typescript_des_cipher_detected,
        test_typescript_non_fips_library,
        test_bicep_storage_no_infra_encryption,
        test_bicep_keyvault_standard_sku,
        test_terraform_storage_no_infra_encryption,
        test_terraform_keyvault_standard_sku,
        test_no_findings_for_fips_compliant_code,
        test_analyzer_metadata,
        test_evidence_automation_recommendations,
        test_evidence_collection_queries,
        test_evidence_artifacts
    ]
    
    print(f"\n{'='*70}")
    print(f"Running FRR-UCM-02 Tests ({len(test_functions)} tests)")
    print(f"{'='*70}\n")
    
    passed = 0
    failed = 0
    
    for test_func in test_functions:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_func.__name__} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__} ERROR: {e}")
            failed += 1
    
    print(f"\n{'='*70}")
    print(f"Test Results: {passed}/{len(test_functions)} passed, {failed} failed")
    print(f"{'='*70}\n")
    
    if failed == 0:
        print("ALL TESTS PASSED ✓\n")
        return 0
    else:
        print(f"SOME TESTS FAILED ✗\n")
        return 1


if __name__ == '__main__':
    exit_code = run_all_tests()
    sys.exit(exit_code)
