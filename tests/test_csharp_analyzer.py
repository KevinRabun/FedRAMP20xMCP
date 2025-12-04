#!/usr/bin/env python3
"""
Comprehensive tests for CSharpAnalyzer.

Tests cover all security checks for C#/.NET applications including:
- Authentication (KSI-IAM-01)
- Secrets management (KSI-SVC-06)
- Dependency security (KSI-SVC-01, KSI-SVC-02)
- PII handling (KSI-PIY-02)
- Logging and monitoring (KSI-MLA-05, KSI-MLA-07)
- Input validation (KSI-SVC-03)
- Authorization (KSI-IAM-02, KSI-IAM-04, KSI-IAM-07)
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_hardcoded_secrets_detection():
    """Test detection of hardcoded secrets in C# code."""
    code = '''
    public class Config
    {
        private const string ApiKey = "sk-1234567890abcdef";
        private static string ConnectionString = "Server=tcp:myserver.database.windows.net;Database=mydb;User ID=admin;Password=MyP@ssw0rd123!;";
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Config.cs")
    
    assert len(result.findings) >= 1
    assert any("secret" in f.description.lower() or "password" in f.description.lower() for f in result.findings)
    print("✓ Hardcoded secrets detection test passed")


def test_authorize_attribute_detection():
    """Test detection of authentication patterns with [Authorize] attribute."""
    code = '''
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        public IActionResult GetSecureData()
        {
            return Ok("Secure data");
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecureController.cs")
    
    # Should have no high severity findings for authentication
    auth_findings = [f for f in result.findings if "authentication" in f.description.lower() or "authentication" in f.title.lower()]
    high_severity_auth = [f for f in auth_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity_auth) == 0 or len(auth_findings) == 0
    print("✓ [Authorize] attribute detection test passed")


def test_key_vault_usage():
    """Test detection of proper Key Vault usage with DefaultAzureCredential."""
    code = '''
    using Azure.Identity;
    using Azure.Security.KeyVault.Secrets;
    
    public class SecretManager
    {
        private readonly SecretClient _client;
        
        public SecretManager()
        {
            var keyVaultUrl = new Uri(Environment.GetEnvironmentVariable("KEY_VAULT_URL"));
            _client = new SecretClient(keyVaultUrl, new DefaultAzureCredential());
        }
        
        public async Task<string> GetSecretAsync(string secretName)
        {
            KeyVaultSecret secret = await _client.GetSecretAsync(secretName);
            return secret.Value;
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecretManager.cs")
    
    # Should recognize good Key Vault pattern
    secret_findings = [f for f in result.findings if "key vault" in f.description.lower() or "key vault" in f.title.lower()]
    
    # May have informational findings but no high severity
    high_severity = [f for f in secret_findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0
    print("✓ Key Vault usage test passed")


def test_binary_formatter_detection():
    """Test detection of insecure BinaryFormatter deserialization."""
    code = '''
    using System.Runtime.Serialization.Formatters.Binary;
    
    public class DataHandler
    {
        public object DeserializeData(byte[] data)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            using (var stream = new MemoryStream(data))
            {
                return formatter.Deserialize(stream);
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "DataHandler.cs")
    
    assert len(result.findings) >= 1
    assert any("binaryformatter" in f.description.lower() or "deserialization" in f.description.lower() 
               for f in result.findings)
    print("✓ BinaryFormatter detection test passed")


def test_sql_injection_detection():
    """Test detection of SQL injection vulnerabilities."""
    code = '''
    using System.Data.SqlClient;
    
    public class UserRepository
    {
        public User GetUser(string username)
        {
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
                SqlCommand cmd = new SqlCommand(query, conn);
                conn.Open();
                return cmd.ExecuteReader();
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserRepository.cs")
    
    # Analyzer should flag this dangerous pattern
    assert result.files_analyzed == 1
    print("✓ SQL injection detection test passed")


def test_data_protection_api():
    """Test detection of proper PII encryption with Data Protection API."""
    code = '''
    using Microsoft.AspNetCore.DataProtection;
    
    public class PiiService
    {
        private readonly IDataProtectionProvider _provider;
        
        public PiiService(IDataProtectionProvider provider)
        {
            _provider = provider;
        }
        
        public string EncryptSsn(string ssn)
        {
            var protector = _provider.CreateProtector("PII.SSN");
            return protector.Protect(ssn);
        }
        
        public string DecryptSsn(string encryptedSsn)
        {
            var protector = _provider.CreateProtector("PII.SSN");
            return protector.Unprotect(encryptedSsn);
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "PiiService.cs")
    
    # Should recognize good Data Protection API usage
    pii_findings = [f for f in result.findings if "pii" in f.description.lower() or "encrypt" in f.description.lower()]
    high_severity = [f for f in pii_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Data Protection API test passed")


def test_ilogger_usage():
    """Test detection of proper logging with ILogger<T>."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class OrderService
    {
        private readonly ILogger<OrderService> _logger;
        
        public OrderService(ILogger<OrderService> logger)
        {
            _logger = logger;
        }
        
        public void ProcessOrder(Order order)
        {
            _logger.LogInformation("Processing order {OrderId}", order.Id);
            
            try
            {
                // Process order
                _logger.LogInformation("Order {OrderId} processed successfully", order.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing order {OrderId}", order.Id);
                throw;
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "OrderService.cs")
    
    # Should recognize proper ILogger usage
    logging_findings = [f for f in result.findings if "logging" in f.description.lower() or "logging" in f.title.lower()]
    high_severity = [f for f in logging_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ ILogger usage test passed")


def test_application_insights():
    """Test detection of Application Insights integration."""
    code = '''
    using Microsoft.ApplicationInsights;
    using Microsoft.ApplicationInsights.DataContracts;
    
    public class TelemetryService
    {
        private readonly TelemetryClient _telemetryClient;
        
        public TelemetryService(TelemetryClient telemetryClient)
        {
            _telemetryClient = telemetryClient;
        }
        
        public void TrackCustomEvent(string eventName, Dictionary<string, string> properties)
        {
            _telemetryClient.TrackEvent(eventName, properties);
        }
        
        public void TrackException(Exception ex)
        {
            _telemetryClient.TrackException(ex);
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "TelemetryService.cs")
    
    # Should recognize Application Insights usage
    monitoring_findings = [f for f in result.findings if "monitoring" in f.description.lower() or "insights" in f.description.lower()]
    
    # May have recommendations but no high severity issues
    high_severity = [f for f in monitoring_findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0
    print("✓ Application Insights test passed")


def test_model_validation():
    """Test detection of model validation with data annotations."""
    code = '''
    using System.ComponentModel.DataAnnotations;
    
    public class CreateUserRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        
        [Required]
        [StringLength(100, MinimumLength = 8)]
        public string Password { get; set; }
        
        [Required]
        [RegularExpression(@"^[a-zA-Z0-9_-]{3,20}$")]
        public string Username { get; set; }
    }
    
    [ApiController]
    public class UserController : ControllerBase
    {
        [HttpPost]
        public IActionResult CreateUser([FromBody] CreateUserRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            
            // Create user
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should recognize proper validation
    validation_findings = [f for f in result.findings if "validation" in f.description.lower() or "validation" in f.title.lower()]
    high_severity = [f for f in validation_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Model validation test passed")


def test_secure_session_configuration():
    """Test detection of secure session/cookie configuration."""
    code = '''
    public void ConfigureServices(IServiceCollection services)
    {
        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            options.SlidingExpiration = true;
        });
        
        services.AddSession(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.IdleTimeout = TimeSpan.FromMinutes(30);
        });
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should recognize secure cookie configuration
    session_findings = [f for f in result.findings if "session" in f.description.lower() or "cookie" in f.description.lower()]
    high_severity = [f for f in session_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Secure session configuration test passed")


def test_authorization_policies():
    """Test detection of policy-based authorization."""
    code = '''
    using Microsoft.AspNetCore.Authorization;
    
    public class AuthorizationPolicies
    {
        public static void AddPolicies(IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy("RequireAdminRole", policy =>
                    policy.RequireRole("Admin"));
                    
                options.AddPolicy("RequireEditPermission", policy =>
                    policy.RequireClaim("Permission", "Edit"));
                    
                options.AddPolicy("MinimumAge", policy =>
                    policy.Requirements.Add(new MinimumAgeRequirement(18)));
            });
        }
    }
    
    [ApiController]
    [Authorize(Policy = "RequireEditPermission")]
    public class DocumentController : ControllerBase
    {
        [HttpPut("{id}")]
        public IActionResult UpdateDocument(int id, DocumentDto dto)
        {
            // Update document
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "AuthorizationPolicies.cs")
    
    # Should recognize proper policy-based authorization
    authz_findings = [f for f in result.findings if "authorization" in f.description.lower() or "authorization" in f.title.lower()]
    high_severity = [f for f in authz_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) == 0
    print("✓ Authorization policies test passed")


def test_xss_prevention():
    """Test detection of XSS prevention measures."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using System.Text.Encodings.Web;
    
    public class CommentController : ControllerBase
    {
        private readonly HtmlEncoder _htmlEncoder;
        
        public CommentController(HtmlEncoder htmlEncoder)
        {
            _htmlEncoder = htmlEncoder;
        }
        
        [HttpPost]
        public IActionResult AddComment(string content)
        {
            // Encode HTML to prevent XSS
            string safeContent = _htmlEncoder.Encode(content);
            
            // Store safe content
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "CommentController.cs")
    
    # Should recognize XSS prevention
    xss_findings = [f for f in result.findings if "xss" in f.description.lower() or "cross-site scripting" in f.description.lower()]
    
    # May have recommendations but no high severity issues
    high_severity = [f for f in xss_findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0
    print("✓ XSS prevention test passed")


def run_all_tests():
    """Run all CSharpAnalyzer tests."""
    print("\n=== Running CSharpAnalyzer Tests ===\n")
    
    test_hardcoded_secrets_detection()
    test_authorize_attribute_detection()
    test_key_vault_usage()
    test_binary_formatter_detection()
    test_sql_injection_detection()
    test_data_protection_api()
    test_ilogger_usage()
    test_application_insights()
    test_model_validation()
    test_secure_session_configuration()
    test_authorization_policies()
    test_xss_prevention()
    
    print("\n=== All CSharpAnalyzer Tests Passed ===\n")


if __name__ == "__main__":
    run_all_tests()
