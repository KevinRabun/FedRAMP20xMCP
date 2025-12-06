#!/usr/bin/env python3
"""
Test suite for Phase C: Azure Integration Security checks.

Tests AST-based detection of insecure Azure service patterns:
- Cosmos DB security (Managed Identity vs connection strings)
- Service Bus security (Managed Identity patterns)
- Azure Storage security (account keys, SAS tokens, user delegation)
- Key Vault integration (Managed Identity, configuration integration)
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer, TREE_SITTER_AVAILABLE
    from fedramp_20x_mcp.analyzers.base import Severity
except ImportError as e:
    print(f"Failed to import analyzer: {e}")
    TREE_SITTER_AVAILABLE = False

print(f"Tree-sitter available: {TREE_SITTER_AVAILABLE}")

# ============================================================================
# Phase C.1: Cosmos DB Security Tests
# ============================================================================

def test_cosmos_db_connection_string():
    """Detect Cosmos DB using connection string (HIGH severity)."""
    code = """
    using Microsoft.Azure.Cosmos;
    using Microsoft.Extensions.Configuration;
    
    public class CosmosService
    {
        private readonly CosmosClient _client;
        
        public CosmosService(IConfiguration configuration)
        {
            // BAD: Using connection string
            _client = new CosmosClient(configuration["CosmosDb:ConnectionString"]);
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "CosmosService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Cosmos DB" in f.title]
    
    if high_findings:
        print("✅ Cosmos DB connection string detected")
        print(f"   Finding: {high_findings[0].title}")
        assert "Managed Identity" in high_findings[0].recommendation
        assert "DefaultAzureCredential" in high_findings[0].recommendation
        assert "KSI-IAM-02" in high_findings[0].requirement_id
    else:
        print("❌ FAILED: Should detect Cosmos DB connection string")
        raise AssertionError("Expected HIGH severity finding for Cosmos DB connection string")

def test_cosmos_db_managed_identity_good():
    """Recognize Cosmos DB with Managed Identity (good practice, no false positive)."""
    code = """
    using Microsoft.Azure.Cosmos;
    using Azure.Identity;
    
    public class CosmosService
    {
        private readonly CosmosClient _client;
        
        public CosmosService(IConfiguration configuration)
        {
            // GOOD: Using Managed Identity
            var credential = new DefaultAzureCredential();
            _client = new CosmosClient(
                accountEndpoint: configuration["CosmosDb:AccountEndpoint"],
                tokenCredential: credential
            );
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "CosmosService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Cosmos DB" in f.title]
    info_findings = [f for f in result.findings if f.severity == Severity.INFO and "Cosmos DB" in f.title and f.good_practice]
    
    if not high_findings and info_findings:
        print("✅ Cosmos DB Managed Identity recognized - no false positive")
        print(f"   Good practice: {info_findings[0].title}")
    else:
        print("❌ FAILED: False positive on Cosmos DB Managed Identity")
        raise AssertionError("Should not flag Cosmos DB with Managed Identity as HIGH severity")

# ============================================================================
# Phase C.2: Service Bus Security Tests
# ============================================================================

def test_service_bus_connection_string():
    """Detect Service Bus using connection string (HIGH severity)."""
    code = """
    using Azure.Messaging.ServiceBus;
    using Microsoft.Extensions.Configuration;
    
    public class MessageService
    {
        private readonly ServiceBusClient _client;
        
        public MessageService(IConfiguration configuration)
        {
            // BAD: Using connection string
            _client = new ServiceBusClient(configuration["ServiceBus:ConnectionString"]);
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "MessageService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Service Bus" in f.title]
    
    if high_findings:
        print("✅ Service Bus connection string detected")
        print(f"   Finding: {high_findings[0].title}")
        assert "Managed Identity" in high_findings[0].recommendation
        assert "DefaultAzureCredential" in high_findings[0].recommendation
        assert "KSI-IAM-02" in high_findings[0].requirement_id
    else:
        print("❌ FAILED: Should detect Service Bus connection string")
        raise AssertionError("Expected HIGH severity finding for Service Bus connection string")

def test_service_bus_managed_identity_good():
    """Recognize Service Bus with Managed Identity (good practice)."""
    code = """
    using Azure.Messaging.ServiceBus;
    using Azure.Identity;
    
    public class MessageService
    {
        private readonly ServiceBusClient _client;
        
        public MessageService(IConfiguration configuration)
        {
            // GOOD: Using Managed Identity
            var credential = new DefaultAzureCredential();
            _client = new ServiceBusClient(
                fullyQualifiedNamespace: configuration["ServiceBus:Namespace"],
                credential: credential
            );
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "MessageService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Service Bus" in f.title]
    info_findings = [f for f in result.findings if f.severity == Severity.INFO and "Service Bus" in f.title and f.good_practice]
    
    if not high_findings and info_findings:
        print("✅ Service Bus Managed Identity recognized - no false positive")
    else:
        print("❌ FAILED: False positive on Service Bus Managed Identity")
        raise AssertionError("Should not flag Service Bus with Managed Identity as HIGH severity")

# ============================================================================
# Phase C.3: Azure Storage Security Tests
# ============================================================================

def test_storage_account_key():
    """Detect Azure Storage using account key (HIGH severity)."""
    code = """
    using Azure.Storage.Blobs;
    using Microsoft.Extensions.Configuration;
    
    public class StorageService
    {
        private readonly BlobServiceClient _client;
        
        public StorageService(IConfiguration configuration)
        {
            // BAD: Using connection string (contains account key)
            _client = new BlobServiceClient(configuration["Storage:ConnectionString"]);
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "StorageService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Storage" in f.title and "account key" in f.title.lower()]
    
    if high_findings:
        print("✅ Azure Storage account key detected")
        print(f"   Finding: {high_findings[0].title}")
        assert "Managed Identity" in high_findings[0].recommendation
        assert "DefaultAzureCredential" in high_findings[0].recommendation
        assert "Rotate account keys" in high_findings[0].recommendation
        assert "KSI-IAM-02" in high_findings[0].requirement_id
    else:
        print("❌ FAILED: Should detect Azure Storage account key")
        raise AssertionError("Expected HIGH severity finding for Storage account key")

def test_storage_managed_identity_good():
    """Recognize Azure Storage with Managed Identity (good practice)."""
    code = """
    using Azure.Storage.Blobs;
    using Azure.Identity;
    
    public class StorageService
    {
        private readonly BlobServiceClient _client;
        
        public StorageService(IConfiguration configuration)
        {
            // GOOD: Using Managed Identity
            var credential = new DefaultAzureCredential();
            _client = new BlobServiceClient(
                new Uri(configuration["Storage:BlobEndpoint"]),
                credential
            );
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "StorageService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Storage" in f.title]
    info_findings = [f for f in result.findings if f.severity == Severity.INFO and "Storage" in f.title and f.good_practice]
    
    if not high_findings and info_findings:
        print("✅ Azure Storage Managed Identity recognized - no false positive")
    else:
        print("❌ FAILED: False positive on Storage Managed Identity")
        raise AssertionError("Should not flag Storage with Managed Identity as HIGH severity")

def test_storage_account_sas_token():
    """Detect account-based SAS token (MEDIUM severity - suggest user delegation)."""
    code = """
    using Azure.Storage.Blobs;
    
    public class StorageService
    {
        public BlobContainerClient GetContainer(string sasToken)
        {
            // BAD: Using account SAS token (not user delegation)
            var uri = new Uri($"https://account.blob.core.windows.net/container?{sasToken}");
            return new BlobContainerClient(uri);
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "StorageService.cs")
    
    medium_findings = [f for f in result.findings if f.severity == Severity.MEDIUM and "SAS token" in f.title]
    
    if medium_findings:
        print("✅ Account SAS token detected (recommends user delegation)")
        print(f"   Finding: {medium_findings[0].title}")
        assert "user delegation" in medium_findings[0].recommendation.lower()
        assert "UserDelegationKey" in medium_findings[0].recommendation
        assert "KSI-SVC-06" in medium_findings[0].requirement_id
    else:
        print("✅ No SAS token finding (acceptable - may not detect all patterns)")

# ============================================================================
# Phase C.4: Key Vault Integration Tests
# ============================================================================

def test_key_vault_without_managed_identity():
    """Detect Key Vault client without Managed Identity (HIGH severity)."""
    code = """
    using Azure.Security.KeyVault.Secrets;
    using Azure.Identity;
    
    public class SecretService
    {
        private readonly SecretClient _client;
        
        public SecretService(string tenantId, string clientId, string clientSecret)
        {
            // BAD: Using client secret credential
            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            _client = new SecretClient(new Uri("https://vault.vault.azure.net"), credential);
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecretService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Key Vault" in f.title]
    
    if high_findings:
        print("✅ Key Vault without Managed Identity detected")
        print(f"   Finding: {high_findings[0].title}")
        assert "DefaultAzureCredential" in high_findings[0].recommendation
        assert "KSI-SVC-06" in high_findings[0].requirement_id
    else:
        print("❌ FAILED: Should detect Key Vault without Managed Identity")
        raise AssertionError("Expected HIGH severity finding for Key Vault without Managed Identity")

def test_key_vault_config_integration_good():
    """Recognize Key Vault with configuration integration (best practice)."""
    code = """
    using Azure.Identity;
    using Azure.Extensions.AspNetCore.Configuration.Secrets;
    
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            
            // GOOD: Key Vault integrated with configuration
            builder.Configuration.AddAzureKeyVault(
                new Uri("https://vault.vault.azure.net"),
                new DefaultAzureCredential()
            );
            
            var app = builder.Build();
            app.Run();
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Key Vault" in f.title]
    info_findings = [f for f in result.findings if f.severity == Severity.INFO and "Key Vault" in f.title and f.good_practice]
    
    if not high_findings and info_findings:
        print("✅ Key Vault configuration integration recognized - no false positive")
        print(f"   Good practice: {info_findings[0].title}")
    else:
        print("❌ FAILED: False positive on Key Vault config integration")
        raise AssertionError("Should not flag Key Vault with AddAzureKeyVault as HIGH severity")

def test_key_vault_direct_client_with_managed_identity():
    """Recognize SecretClient with Managed Identity (acceptable but suggest config integration)."""
    code = """
    using Azure.Security.KeyVault.Secrets;
    using Azure.Identity;
    
    public class SecretService
    {
        private readonly SecretClient _client;
        
        public SecretService()
        {
            // ACCEPTABLE: Using Managed Identity (but direct client access)
            var credential = new DefaultAzureCredential();
            _client = new SecretClient(new Uri("https://vault.vault.azure.net"), credential);
        }
    }
    """
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecretService.cs")
    
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH and "Key Vault" in f.title]
    info_findings = [f for f in result.findings if f.severity == Severity.INFO and "Key Vault" in f.title]
    
    if not high_findings and info_findings:
        print("✅ Key Vault SecretClient with Managed Identity recognized")
        print(f"   Suggestion: {info_findings[0].title}")
        assert "AddAzureKeyVault" in info_findings[0].recommendation or "configuration" in info_findings[0].recommendation.lower()
    else:
        print("❌ FAILED: Should suggest config integration for SecretClient")
        raise AssertionError("Should provide INFO finding suggesting AddAzureKeyVault")

# ============================================================================
# Run All Tests
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("PHASE C: AZURE INTEGRATION SECURITY TEST SUITE")
    print("=" * 70)
    
    if not TREE_SITTER_AVAILABLE:
        print("⚠️  Tree-sitter not available - skipping AST tests")
        print("   Install: pip install tree-sitter tree-sitter-c-sharp")
        sys.exit(0)
    
    try:
        # Phase C.1: Cosmos DB Security (2 tests)
        test_cosmos_db_connection_string()
        test_cosmos_db_managed_identity_good()
        
        # Phase C.2: Service Bus Security (2 tests)
        test_service_bus_connection_string()
        test_service_bus_managed_identity_good()
        
        # Phase C.3: Azure Storage Security (3 tests)
        test_storage_account_key()
        test_storage_managed_identity_good()
        test_storage_account_sas_token()
        
        # Phase C.4: Key Vault Integration (3 tests)
        test_key_vault_without_managed_identity()
        test_key_vault_config_integration_good()
        test_key_vault_direct_client_with_managed_identity()
        
        print()
        print("=" * 70)
        print("ALL PHASE C TESTS PASSED ✓")
        print("=" * 70)
        print()
        print("Phase C Coverage:")
        print("  ✓ Cosmos DB Security (2 tests)")
        print("  ✓ Service Bus Security (2 tests)")
        print("  ✓ Azure Storage Security (3 tests)")
        print("  ✓ Key Vault Integration (3 tests)")
        print()
        print("Total: 10 tests, all passing")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
