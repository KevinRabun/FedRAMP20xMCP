#!/usr/bin/env python3
"""
Comprehensive tests for KSI-SVC-05 (Resource Integrity - File Download Validation)

Tests AST-first analysis for:
- Python: requests/urllib without hashlib validation
- C#: HttpClient without SHA256 validation
- Java: HttpClient without MessageDigest validation
- TypeScript: fetch/axios without crypto.createHash validation
- Bicep: Container Registry without Content Trust (regex-only)
- Terraform: Container Registry without trust_policy (regex-only)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_download_without_hash():
    """Test Python file download without hash verification (HIGH)"""
    code = """
import requests

def download_file(url):
    response = requests.get(url)
    with open('file.zip', 'wb') as f:
        f.write(response.content)
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'python')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "File Download Without Integrity Verification" in result.findings[0].title
    print("[PASS] Python download without hash detected (HIGH)")


def test_python_download_with_hash():
    """Test Python file download with hash verification (passes)"""
    code = """
import requests
import hashlib

def download_file(url, expected_hash):
    response = requests.get(url)
    content = response.content
    
    hash_obj = hashlib.sha256()
    hash_obj.update(content)
    calculated_hash = hash_obj.hexdigest()
    
    if calculated_hash != expected_hash:
        raise ValueError("Integrity check failed")
    
    with open('file.zip', 'wb') as f:
        f.write(content)
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'python')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Python download with hash verification passes")


def test_python_no_download():
    """Test Python code without download operations (passes)"""
    code = """
def process_data(data):
    return data.strip().upper()
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'python')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Python without download operations passes")


def test_csharp_download_without_hash():
    """Test C# file download without hash verification (HIGH)"""
    code = """
using System.Net.Http;

public class FileDownloader
{
    private readonly HttpClient _client = new HttpClient();
    
    public async Task DownloadFileAsync(string url)
    {
        var response = await _client.GetAsync(url);
        var content = await response.Content.ReadAsByteArrayAsync();
        File.WriteAllBytes("file.zip", content);
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'csharp')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "File Download Without Integrity Verification" in result.findings[0].title
    print("[PASS] C# download without hash detected (HIGH)")


def test_csharp_download_with_hash():
    """Test C# file download with hash verification (passes)"""
    code = """
using System.Net.Http;
using System.Security.Cryptography;

public class FileDownloader
{
    private readonly HttpClient _client = new HttpClient();
    
    public async Task DownloadFileAsync(string url, string expectedHash)
    {
        var response = await _client.GetAsync(url);
        var content = await response.Content.ReadAsByteArrayAsync();
        
        using (var sha256 = SHA256.Create())
        {
            var hash = sha256.ComputeHash(content);
            var calculatedHash = BitConverter.ToString(hash).Replace("-", "");
            
            if (calculatedHash != expectedHash)
                throw new InvalidOperationException("Integrity check failed");
        }
        
        File.WriteAllBytes("file.zip", content);
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'csharp')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] C# download with hash verification passes")


def test_csharp_no_download():
    """Test C# code without download operations (passes)"""
    code = """
public class DataProcessor
{
    public string ProcessData(string data)
    {
        return data.Trim().ToUpper();
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'csharp')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] C# without download operations passes")


def test_java_download_without_hash():
    """Test Java file download without hash verification (HIGH)"""
    code = """
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;

public class FileDownloader {
    private final HttpClient client = HttpClients.createDefault();
    
    public void downloadFile(String url) throws Exception {
        HttpGet request = new HttpGet(url);
        var response = client.execute(request);
        var content = response.getEntity().getContent();
        Files.copy(content, Paths.get("file.zip"));
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'java')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "File Download Without Integrity Verification" in result.findings[0].title
    print("[PASS] Java download without hash detected (HIGH)")


def test_java_download_with_hash():
    """Test Java file download with hash verification (passes)"""
    code = """
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import java.security.MessageDigest;

public class FileDownloader {
    private final HttpClient client = HttpClients.createDefault();
    
    public void downloadFile(String url, String expectedHash) throws Exception {
        HttpGet request = new HttpGet(url);
        var response = client.execute(request);
        var content = response.getEntity().getContent().readAllBytes();
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);
        String calculatedHash = bytesToHex(hash);
        
        if (!calculatedHash.equals(expectedHash)) {
            throw new SecurityException("Integrity check failed");
        }
        
        Files.write(Paths.get("file.zip"), content);
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'java')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Java download with hash verification passes")


def test_java_no_download():
    """Test Java code without download operations (passes)"""
    code = """
public class DataProcessor {
    public String processData(String data) {
        return data.trim().toUpperCase();
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'java')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Java without download operations passes")


def test_typescript_download_without_hash():
    """Test TypeScript file download without hash verification (HIGH)"""
    code = """
import * as fs from 'fs/promises';

async function downloadFile(url: string): Promise<void> {
    const response = await fetch(url);
    const buffer = await response.arrayBuffer();
    const content = Buffer.from(buffer);
    await fs.writeFile('file.zip', content);
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'typescript')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.HIGH, f"Expected HIGH, got {result.findings[0].severity}"
    assert "File Download Without Integrity Verification" in result.findings[0].title
    print("[PASS] TypeScript download without hash detected (HIGH)")


def test_typescript_download_with_hash():
    """Test TypeScript file download with hash verification (passes)"""
    code = """
import * as fs from 'fs/promises';
import * as crypto from 'crypto';

async function downloadFile(url: string, expectedHash: string): Promise<void> {
    const response = await fetch(url);
    const buffer = await response.arrayBuffer();
    const content = Buffer.from(buffer);
    
    const hash = crypto.createHash('sha256');
    hash.update(content);
    const calculatedHash = hash.digest('hex');
    
    if (calculatedHash !== expectedHash) {
        throw new Error('Integrity check failed');
    }
    
    await fs.writeFile('file.zip', content);
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'typescript')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] TypeScript download with hash verification passes")


def test_typescript_no_download():
    """Test TypeScript code without download operations (passes)"""
    code = """
function processData(data: string): string {
    return data.trim().toUpperCase();
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'typescript')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] TypeScript without download operations passes")


def test_bicep_acr_without_trust():
    """Test Bicep Container Registry without Content Trust (MEDIUM)"""
    code = """
resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: 'myacr'
  location: location
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: false
  }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'bicep')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.MEDIUM, f"Expected MEDIUM, got {result.findings[0].severity}"
    assert "Azure Container Registry Without Content Trust" in result.findings[0].title
    print("[PASS] Bicep ACR without Content Trust detected (MEDIUM)")


def test_bicep_acr_with_trust():
    """Test Bicep Container Registry with Content Trust (passes)"""
    code = """
resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: 'myacr'
  location: location
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: false
    policies: {
      trustPolicy: {
        type: 'Notary'
        status: 'enabled'
      }
    }
  }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'bicep')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Bicep ACR with Content Trust passes")


def test_terraform_acr_without_trust():
    """Test Terraform Container Registry without trust_policy (MEDIUM)"""
    code = """
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"
  admin_enabled       = false
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'terraform')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.MEDIUM, f"Expected MEDIUM, got {result.findings[0].severity}"
    assert "Azure Container Registry Without Content Trust" in result.findings[0].title
    print("[PASS] Terraform ACR without trust_policy detected (MEDIUM)")


def test_terraform_acr_with_trust():
    """Test Terraform Container Registry with trust_policy (passes)"""
    code = """
resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Premium"
  admin_enabled       = false
  
  trust_policy {
    enabled = true
  }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-05', code, 'terraform')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Terraform ACR with trust_policy passes")


if __name__ == '__main__':
    print("=" * 80)
    print("KSI-SVC-05 COMPREHENSIVE TEST SUITE")
    print("Testing: Resource Integrity (File Download Validation)")
    print("=" * 80)
    print()
    
    tests = [
        ("Python download without hash", test_python_download_without_hash),
        ("Python download with hash", test_python_download_with_hash),
        ("Python no download", test_python_no_download),
        ("C# download without hash", test_csharp_download_without_hash),
        ("C# download with hash", test_csharp_download_with_hash),
        ("C# no download", test_csharp_no_download),
        ("Java download without hash", test_java_download_without_hash),
        ("Java download with hash", test_java_download_with_hash),
        ("Java no download", test_java_no_download),
        ("TypeScript download without hash", test_typescript_download_without_hash),
        ("TypeScript download with hash", test_typescript_download_with_hash),
        ("TypeScript no download", test_typescript_no_download),
        ("Bicep ACR without trust", test_bicep_acr_without_trust),
        ("Bicep ACR with trust", test_bicep_acr_with_trust),
        ("Terraform ACR without trust", test_terraform_acr_without_trust),
        ("Terraform ACR with trust", test_terraform_acr_with_trust),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            failed += 1
    
    print()
    print("=" * 80)
    print(f"Total: {len(tests)} | Passed: {passed} | Failed: {failed}")
    if failed == 0:
        print("ALL KSI-SVC-05 TESTS PASSED [PASS]")
    else:
        print(f"TESTS FAILED: {failed}/{len(tests)} [FAIL]")
    print("=" * 80)
    
    sys.exit(0 if failed == 0 else 1)
