"""
Test KSI-AFR-11 AST-first conversion for cryptographic compliance.

Tests Python, C#, and Java AST-based detection of:
- Weak hash algorithms (MD5, SHA-1)
- Weak encryption (DES, RC4)
- Insecure TLS (TLS 1.0/1.1, SSL)
- Hardcoded cryptographic keys
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.ksi.ksi_afr_11 import KSI_AFR_11_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_weak_hash_md5():
    """Test Python AST detects MD5 (CRITICAL)."""
    code = """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    md5_findings = [f for f in findings if "MD5" in f.title]
    assert len(md5_findings) > 0, "Should detect MD5"
    assert md5_findings[0].severity == Severity.CRITICAL
    print("[PASS] Python MD5 detected (CRITICAL)")


def test_python_strong_hash_passes():
    """Test Python AST allows SHA-256 (no findings)."""
    code = """
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    hash_findings = [f for f in findings if "Hash" in f.title]
    assert len(hash_findings) == 0, "Should not flag SHA-256"
    print("[PASS] Python SHA-256 passes")


def test_python_weak_encryption_des():
    """Test Python AST detects DES (CRITICAL)."""
    code = """
from Crypto.Cipher import DES

def encrypt_data(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    des_findings = [f for f in findings if "DES" in f.title]
    assert len(des_findings) > 0, "Should detect DES"
    assert des_findings[0].severity == Severity.CRITICAL
    print("[PASS] Python DES detected (CRITICAL)")


def test_python_insecure_tls():
    """Test Python AST detects insecure TLS (HIGH)."""
    code = """
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    tls_findings = [f for f in findings if "TLS" in f.title]
    assert len(tls_findings) > 0, "Should detect TLS 1.0"
    assert tls_findings[0].severity == Severity.HIGH
    print("[PASS] Python insecure TLS detected (HIGH)")


def test_python_hardcoded_key():
    """Test Python AST detects hardcoded keys (CRITICAL)."""
    code = """
encryption_key = "MySecretKey12345"

def encrypt_data(data):
    return encrypt(encryption_key, data)
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    key_findings = [f for f in findings if "Key" in f.title]
    assert len(key_findings) > 0, "Should detect hardcoded key"
    assert key_findings[0].severity == Severity.CRITICAL
    print("[PASS] Python hardcoded key detected (CRITICAL)")


def test_python_key_from_vault_passes():
    """Test Python AST allows Azure Key Vault (no findings)."""
    code = """
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://myvault.vault.azure.net", credential=credential)
encryption_key = client.get_secret("encryption-key").value
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    key_findings = [f for f in findings if "Key" in f.title]
    assert len(key_findings) == 0, "Should not flag Key Vault"
    print("[PASS] Python Key Vault passes")


def test_csharp_weak_hash_md5():
    """Test C# AST detects MD5CryptoServiceProvider (CRITICAL)."""
    code = """
using System.Security.Cryptography;

public class Hasher {
    public byte[] HashPassword(string password) {
        using (var md5 = new MD5CryptoServiceProvider()) {
            return md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    md5_findings = [f for f in findings if "MD5" in f.title]
    assert len(md5_findings) > 0, "Should detect MD5CryptoServiceProvider"
    assert md5_findings[0].severity == Severity.CRITICAL
    print("[PASS] C# MD5CryptoServiceProvider detected (CRITICAL)")


def test_csharp_strong_hash_passes():
    """Test C# AST allows SHA256 (no findings)."""
    code = """
using System.Security.Cryptography;

public class Hasher {
    public byte[] HashPassword(string password) {
        using (var sha256 = SHA256.Create()) {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    hash_findings = [f for f in findings if "Hash" in f.title]
    assert len(hash_findings) == 0, "Should not flag SHA-256"
    print("[PASS] C# SHA256 passes")


def test_csharp_weak_encryption_des():
    """Test C# AST detects DESCryptoServiceProvider (CRITICAL)."""
    code = """
using System.Security.Cryptography;

public class Encryptor {
    public byte[] Encrypt(byte[] data, byte[] key) {
        using (var des = new DESCryptoServiceProvider()) {
            des.Key = key;
            return des.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    des_findings = [f for f in findings if "DES" in f.title]
    assert len(des_findings) > 0, "Should detect DESCryptoServiceProvider"
    assert des_findings[0].severity == Severity.CRITICAL
    print("[PASS] C# DESCryptoServiceProvider detected (CRITICAL)")


def test_csharp_insecure_tls():
    """Test C# AST detects insecure TLS (HIGH)."""
    code = """
using System.Security.Authentication;

var handler = new HttpClientHandler {
    SslProtocols = SslProtocols.Tls
};
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    tls_findings = [f for f in findings if "TLS" in f.title]
    assert len(tls_findings) > 0, "Should detect SslProtocols.Tls"
    assert tls_findings[0].severity == Severity.HIGH
    print("[PASS] C# SslProtocols.Tls detected (HIGH)")


def test_csharp_hardcoded_key():
    """Test C# AST detects hardcoded keys (CRITICAL)."""
    code = """
public class Config {
    private const string encryptionKey = "MySecretKey12345";
    
    public byte[] Encrypt(byte[] data) {
        return EncryptData(encryptionKey, data);
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    key_findings = [f for f in findings if "Key" in f.title]
    assert len(key_findings) > 0, "Should detect hardcoded key"
    assert key_findings[0].severity == Severity.CRITICAL
    print("[PASS] C# hardcoded key detected (CRITICAL)")


def test_csharp_key_from_vault_passes():
    """Test C# AST allows Azure Key Vault (no findings)."""
    code = """
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

var client = new SecretClient(
    new Uri("https://myvault.vault.azure.net"),
    new DefaultAzureCredential());

KeyVaultSecret secret = await client.GetSecretAsync("encryption-key");
string key = secret.Value;
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    key_findings = [f for f in findings if "Key" in f.title and "Vault" not in (f.code_snippet or "")]
    assert len(key_findings) == 0, "Should not flag Key Vault"
    print("[PASS] C# Key Vault passes")


def test_java_weak_hash_md5():
    """Test Java AST detects MessageDigest MD5 (CRITICAL)."""
    code = """
import java.security.MessageDigest;

public class Hasher {
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_java(code, "test.java")
    
    md5_findings = [f for f in findings if "MD5" in f.title]
    assert len(md5_findings) > 0, "Should detect MD5"
    assert md5_findings[0].severity == Severity.CRITICAL
    print("[PASS] Java MessageDigest MD5 detected (CRITICAL)")


def test_java_strong_hash_passes():
    """Test Java AST allows SHA-256 (no findings)."""
    code = """
import java.security.MessageDigest;

public class Hasher {
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(password.getBytes());
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_java(code, "test.java")
    
    hash_findings = [f for f in findings if "Hash" in f.title]
    assert len(hash_findings) == 0, "Should not flag SHA-256"
    print("[PASS] Java SHA-256 passes")


def test_java_weak_encryption_des():
    """Test Java AST detects Cipher DES (CRITICAL)."""
    code = """
import javax.crypto.Cipher;

public class Encryptor {
    public byte[] encrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_java(code, "test.java")
    
    des_findings = [f for f in findings if "DES" in f.title]
    assert len(des_findings) > 0, "Should detect DES"
    assert des_findings[0].severity == Severity.CRITICAL
    print("[PASS] Java Cipher DES detected (CRITICAL)")


def test_java_insecure_tls():
    """Test Java AST detects insecure TLS (HIGH)."""
    code = """
import javax.net.ssl.SSLContext;

public class TlsConfig {
    public SSLContext getContext() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }
}
"""
    analyzer = KSI_AFR_11_Analyzer()
    findings = analyzer.analyze_java(code, "test.java")
    
    tls_findings = [f for f in findings if "TLS" in f.title]
    assert len(tls_findings) > 0, "Should detect TLSv1"
    assert tls_findings[0].severity == Severity.HIGH
    print("[PASS] Java SSLContext TLSv1 detected (HIGH)")


if __name__ == "__main__":
    print("Testing KSI-AFR-11 AST-First Conversion (Python, C#, Java)...")
    print("=" * 70)
    
    # Python tests (6)
    test_python_weak_hash_md5()
    test_python_strong_hash_passes()
    test_python_weak_encryption_des()
    test_python_insecure_tls()
    test_python_hardcoded_key()
    test_python_key_from_vault_passes()
    
    # C# tests (6)
    test_csharp_weak_hash_md5()
    test_csharp_strong_hash_passes()
    test_csharp_weak_encryption_des()
    test_csharp_insecure_tls()
    test_csharp_hardcoded_key()
    test_csharp_key_from_vault_passes()
    
    # Java tests (4)
    test_java_weak_hash_md5()
    test_java_strong_hash_passes()
    test_java_weak_encryption_des()
    test_java_insecure_tls()
    
    print("=" * 70)
    print("ALL KSI-AFR-11 AST CONVERSION TESTS PASSED (16 tests)")
