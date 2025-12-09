"""
Comprehensive tests for KSI-PIY-01: Automated Inventory (AST-based)

Tests application language analyzers with positive and negative cases for Azure SDK import detection.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.ksi.ksi_piy_01 import KSI_PIY_01_Analyzer


def test_python_with_resource_graph():
    """Test Python code with Azure Resource Graph SDK."""
    code = '''
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.identity import DefaultAzureCredential

def get_inventory():
    credential = DefaultAzureCredential()
    client = ResourceGraphClient(credential)
    query = "Resources | project name, type, tags"
    result = client.resources(query=query)
    return result.data
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_python(code)
    
    assert len(findings) > 0, "Should detect Resource Graph SDK usage"
    assert any("inventory query" in f.title.lower() for f in findings)
    print("[PASS] Python with Resource Graph SDK detected")


def test_python_with_resource_management():
    """Test Python code with Azure Resource Management SDK."""
    code = '''
from azure.mgmt.resource import ResourceManagementClient
from azure.identity import DefaultAzureCredential

def list_resources():
    credential = DefaultAzureCredential()
    client = ResourceManagementClient(credential, subscription_id)
    resources = list(client.resources.list())
    return resources
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_python(code)
    
    assert len(findings) > 0, "Should detect Resource Management SDK usage"
    assert any("inventory query" in f.title.lower() for f in findings)
    print("[PASS] Python with Resource Management SDK detected")


def test_python_without_azure_sdk():
    """Test Python code without Azure SDK."""
    code = '''
import os
import json

def process_data(data):
    return json.dumps(data)

def main():
    data = {"key": "value"}
    print(process_data(data))
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_python(code)
    
    assert len(findings) == 0, "Should not flag code without Azure SDK"
    print("[PASS] Python without Azure SDK passes")


def test_python_with_other_imports():
    """Test Python with non-inventory Azure imports."""
    code = '''
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient

def upload_file(data):
    client = BlobServiceClient.from_connection_string(conn_str)
    container_client = client.get_container_client("data")
    container_client.upload_blob("file.txt", data)
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_python(code)
    
    assert len(findings) == 0, "Should not flag non-inventory Azure SDK"
    print("[PASS] Python with other Azure SDK passes")


def test_csharp_with_resource_graph():
    """Test C# code with Azure Resource Graph SDK."""
    code = '''
using Azure.ResourceManager.ResourceGraph;
using Azure.Identity;

public class InventoryService
{
    public async Task<List<Resource>> GetResources()
    {
        var credential = new DefaultAzureCredential();
        var client = new ResourceGraphClient(credential);
        var query = "Resources | project name, type, tags";
        var result = await client.ResourcesAsync(query);
        return result.Value.Data;
    }
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    assert len(findings) > 0, "Should detect Resource Graph SDK usage"
    assert any("inventory query" in f.title.lower() for f in findings)
    print("[PASS] C# with Resource Graph SDK detected")


def test_csharp_with_resource_manager():
    """Test C# code with Azure Resource Manager SDK."""
    code = '''
using Azure.ResourceManager;
using Azure.Identity;

public class ResourceService
{
    public async Task<List<GenericResource>> ListAllResources()
    {
        var credential = new DefaultAzureCredential();
        var client = new ArmClient(credential);
        var subscription = await client.GetDefaultSubscriptionAsync();
        
        var resources = new List<GenericResource>();
        await foreach (var resource in subscription.GetGenericResourcesAsync())
        {
            resources.Add(resource);
        }
        return resources;
    }
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    assert len(findings) > 0, "Should detect Resource Manager SDK usage"
    assert any("inventory query" in f.title.lower() for f in findings)
    print("[PASS] C# with Resource Manager SDK detected")


def test_csharp_without_azure_sdk():
    """Test C# code without Azure SDK."""
    code = '''
using System;
using System.Collections.Generic;

public class DataProcessor
{
    public string ProcessData(string input)
    {
        return input.ToUpper();
    }
    
    public List<string> GetItems()
    {
        return new List<string> { "item1", "item2" };
    }
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    assert len(findings) == 0, "Should not flag code without Azure SDK"
    print("[PASS] C# without Azure SDK passes")


def test_csharp_with_other_azure_sdk():
    """Test C# with non-inventory Azure SDK."""
    code = '''
using Azure.Storage.Blobs;
using Azure.Security.KeyVault.Secrets;

public class StorageService
{
    public async Task UploadFile(byte[] data)
    {
        var blobClient = new BlobClient(connectionString, containerName, blobName);
        await blobClient.UploadAsync(new MemoryStream(data));
    }
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    assert len(findings) == 0, "Should not flag non-inventory Azure SDK"
    print("[PASS] C# with other Azure SDK passes")


def test_typescript_with_resource_graph():
    """Test TypeScript code with Azure Resource Graph SDK."""
    code = '''
import { ResourceGraphClient } from '@azure/arm-resourcegraph';
import { DefaultAzureCredential } from '@azure/identity';

export async function getInventory(): Promise<any[]> {
  const credential = new DefaultAzureCredential();
  const client = new ResourceGraphClient(credential);
  
  const query = `
    Resources
    | where tags has 'environment'
    | project name, type, tags
  `;
  
  const result = await client.resources({ query });
  return result.data || [];
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    assert len(findings) > 0, "Should detect Resource Graph SDK usage"
    assert any("inventory query" in f.title.lower() for f in findings)
    print("[PASS] TypeScript with Resource Graph SDK detected")


def test_typescript_with_arm_resources():
    """Test TypeScript code with ARM Resources SDK."""
    code = '''
import { ResourceManagementClient } from '@azure/arm-resources';
import { DefaultAzureCredential } from '@azure/identity';

export async function listAllResources(): Promise<Resource[]> {
  const credential = new DefaultAzureCredential();
  const client = new ResourceManagementClient(credential, subscriptionId);
  
  const resources: Resource[] = [];
  for await (const resource of client.resources.list()) {
    resources.push(resource);
  }
  return resources;
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    assert len(findings) > 0, "Should detect ARM Resources SDK usage"
    assert any("inventory query" in f.title.lower() for f in findings)
    print("[PASS] TypeScript with ARM Resources SDK detected")


def test_typescript_without_azure_sdk():
    """Test TypeScript code without Azure SDK."""
    code = '''
import express from 'express';
import { logger } from './logger';

const app = express();

app.get('/api/data', (req, res) => {
  logger.info('Request received');
  res.json({ status: 'ok' });
});

app.listen(3000);
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    assert len(findings) == 0, "Should not flag code without Azure SDK"
    print("[PASS] TypeScript without Azure SDK passes")


def test_typescript_with_other_azure_sdk():
    """Test TypeScript with non-inventory Azure SDK."""
    code = '''
import { BlobServiceClient } from '@azure/storage-blob';
import { SecretClient } from '@azure/keyvault-secrets';

export async function uploadFile(data: Buffer): Promise<void> {
  const blobClient = BlobServiceClient.fromConnectionString(connStr);
  const containerClient = blobClient.getContainerClient('data');
  const blockBlobClient = containerClient.getBlockBlobClient('file.txt');
  await blockBlobClient.upload(data, data.length);
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    assert len(findings) == 0, "Should not flag non-inventory Azure SDK"
    print("[PASS] TypeScript with other Azure SDK passes")


def test_java_no_detection():
    """Test Java analyzer (currently not detecting anything)."""
    code = '''
import com.azure.resourcemanager.ResourceManager;
import com.azure.identity.DefaultAzureCredential;

public class InventoryService {
    public void getResources() {
        DefaultAzureCredential credential = new DefaultAzureCredential();
        ResourceManager manager = ResourceManager.authenticate(credential, profile).withDefaultSubscription();
    }
}
'''
    
    analyzer = KSI_PIY_01_Analyzer()
    findings = analyzer.analyze_java(code)
    
    # Java detection not currently implemented
    assert len(findings) == 0, "Java detection not implemented yet"
    print("[PASS] Java analyzer returns empty (not implemented)")


if __name__ == "__main__":
    print("\nTesting KSI-PIY-01: Automated Inventory (AST-based)\n")
    
    # Python tests
    test_python_with_resource_graph()
    test_python_with_resource_management()
    test_python_without_azure_sdk()
    test_python_with_other_imports()
    
    # C# tests
    test_csharp_with_resource_graph()
    test_csharp_with_resource_manager()
    test_csharp_without_azure_sdk()
    test_csharp_with_other_azure_sdk()
    
    # TypeScript tests
    test_typescript_with_resource_graph()
    test_typescript_with_arm_resources()
    test_typescript_without_azure_sdk()
    test_typescript_with_other_azure_sdk()
    
    # Java test
    test_java_no_detection()
    
    print("\n" + "="*50)
    print("ALL KSI-PIY-01 TESTS PASSED [PASS]")
    print("="*50)
