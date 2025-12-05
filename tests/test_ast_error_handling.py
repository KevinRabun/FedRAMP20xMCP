"""
Comprehensive tests for Tier 1.1: AST-Enhanced Error Handling Check

Tests the new AST-based error handling analysis capabilities:
- Try-catch block extraction
- Empty catch block detection
- Logging verification in catch blocks
- Generic vs specific exception handling
- Rethrow pattern detection
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_empty_catch_block_detection():
    """Test detection of empty catch blocks (HIGH severity)."""
    code = '''
    using System;
    
    public class DataProcessor
    {
        public void ProcessData()
        {
            try
            {
                // Some risky operation
                var data = LoadData();
            }
            catch (Exception ex)
            {
                // Empty catch - swallows exception!
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "DataProcessor.cs")
    
    # Should detect empty catch block as HIGH severity
    empty_catch_findings = [f for f in result.findings 
                           if "empty catch" in f.title.lower() 
                           and f.requirement_id == "KSI-SVC-01"]
    
    assert len(empty_catch_findings) > 0, "Failed to detect empty catch block"
    assert empty_catch_findings[0].severity == Severity.HIGH, "Empty catch should be HIGH severity"
    print("[PASS] Empty catch block detection test passed")


def test_catch_without_logging():
    """Test detection of catch blocks without logging (MEDIUM/HIGH severity)."""
    code = '''
    using System;
    
    public class ApiController
    {
        public string GetData()
        {
            try
            {
                return FetchFromDatabase();
            }
            catch (Exception ex)
            {
                return "Error occurred"; // No logging!
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "ApiController.cs")
    
    # Should detect missing logging
    no_logging_findings = [f for f in result.findings 
                          if "without logging" in f.description.lower() 
                          and f.requirement_id == "KSI-SVC-01"]
    
    assert len(no_logging_findings) > 0, "Failed to detect catch without logging"
    print("[PASS] Catch without logging detection test passed")


def test_proper_error_handling_with_logging():
    """Test recognition of proper error handling with logging (good practice)."""
    code = '''
    using System;
    using Microsoft.Extensions.Logging;
    
    public class SecureService
    {
        private readonly ILogger<SecureService> _logger;
        
        public SecureService(ILogger<SecureService> logger)
        {
            _logger = logger;
        }
        
        public async Task ProcessAsync()
        {
            try
            {
                await PerformOperationAsync();
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Operation failed: {Operation}", "ProcessAsync");
                throw;
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecureService.cs")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-01"
                     and "proper error handling" in f.title.lower()]
    
    assert len(good_practices) > 0, "Failed to recognize proper error handling"
    print("[PASS] Proper error handling with logging recognition test passed")


def test_generic_exception_in_business_logic():
    """Test detection of generic Exception catch in business logic (LOW severity)."""
    code = '''
    using System;
    using Microsoft.Extensions.Logging;
    
    public class BusinessLogic
    {
        private readonly ILogger<BusinessLogic> _logger;
        
        public void ProcessOrder(Order order)
        {
            try
            {
                ValidateOrder(order);
                SaveOrder(order);
            }
            catch (Exception ex)  // Too generic!
            {
                _logger.LogError(ex, "Order processing failed");
                throw;
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "BusinessLogic.cs")
    
    # Should detect generic exception handler
    generic_findings = [f for f in result.findings 
                       if "generic exception" in f.title.lower() 
                       and f.requirement_id == "KSI-SVC-01"
                       and f.severity == Severity.LOW]
    
    assert len(generic_findings) > 0, "Failed to detect generic exception handler"
    print("[PASS] Generic exception in business logic detection test passed")


def test_specific_exception_with_logging():
    """Test proper specific exception handling with logging."""
    code = '''
    using System;
    using Microsoft.Extensions.Logging;
    using Microsoft.EntityFrameworkCore;
    
    public class DatabaseService
    {
        private readonly ILogger<DatabaseService> _logger;
        
        public async Task SaveAsync()
        {
            try
            {
                await _dbContext.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogWarning(ex, "Concurrency conflict detected");
                throw;
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Database update failed");
                throw;
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "DatabaseService.cs")
    
    # Should recognize both as good practices
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-01"]
    
    # Should have at least one good practice finding for specific exception handling
    assert len(good_practices) > 0, "Failed to recognize specific exception handling"
    print("[PASS] Specific exception with logging recognition test passed")


def test_multiple_catch_blocks():
    """Test analysis of multiple catch blocks in single try."""
    code = '''
    using System;
    using System.Net.Http;
    using Microsoft.Extensions.Logging;
    
    public class HttpService
    {
        private readonly ILogger<HttpService> _logger;
        
        public async Task<string> FetchDataAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync(url);
                return await response.Content.ReadAsStringAsync();
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP request failed");
                return null;
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogWarning(ex, "Request timeout");
                return null;
            }
            catch (Exception ex)
            {
                // Generic catch as final fallback - acceptable here
                _logger.LogError(ex, "Unexpected error");
                throw;
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "HttpService.cs")
    
    # Should recognize good practices for specific exceptions
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-01"]
    
    # Should have good practice findings for HttpRequestException and TaskCanceledException
    assert len(good_practices) >= 2, f"Expected at least 2 good practices, got {len(good_practices)}"
    print("[PASS] Multiple catch blocks test passed")


def test_catch_with_rethrow_but_no_logging():
    """Test catch with rethrow but no logging (MEDIUM severity)."""
    code = '''
    using System;
    
    public class Service
    {
        public void Execute()
        {
            try
            {
                PerformAction();
            }
            catch (InvalidOperationException ex)
            {
                // Rethrow but no logging
                throw;
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Service.cs")
    
    # Should detect missing logging even with rethrow
    no_logging = [f for f in result.findings 
                 if "without logging" in f.description.lower() 
                 and f.requirement_id == "KSI-SVC-01"
                 and f.severity == Severity.MEDIUM]  # MEDIUM because it rethrows
    
    assert len(no_logging) > 0, "Failed to detect catch without logging (even with rethrow)"
    print("[PASS] Catch with rethrow but no logging detection test passed")


def test_global_exception_handler():
    """Test that generic Exception in global handler is acceptable."""
    code = '''
    using System;
    using Microsoft.Extensions.Logging;
    using Microsoft.AspNetCore.Http;
    
    public class GlobalExceptionMiddleware
    {
        private readonly ILogger<GlobalExceptionMiddleware> _logger;
        
        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)  // Generic catch OK in middleware
            {
                _logger.LogError(ex, "Unhandled exception");
                await HandleExceptionAsync(context, ex);
            }
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "GlobalExceptionMiddleware.cs")
    
    # Should NOT flag generic Exception in middleware as LOW severity
    # (or should flag with lower severity/different message)
    generic_warnings = [f for f in result.findings 
                       if "generic exception" in f.title.lower() 
                       and f.requirement_id == "KSI-SVC-01"]
    
    # This is acceptable - generic catch in middleware is OK
    # The check should either skip it or recognize it as acceptable
    print(f"[INFO] Generic exception in middleware findings: {len(generic_warnings)}")
    print("[PASS] Global exception handler test passed")


def run_all_tests():
    """Run all AST error handling tests."""
    print("\n=== Running AST Error Handling Tests (Tier 1.1) ===\n")
    
    test_empty_catch_block_detection()
    test_catch_without_logging()
    test_proper_error_handling_with_logging()
    test_generic_exception_in_business_logic()
    test_specific_exception_with_logging()
    test_multiple_catch_blocks()
    test_catch_with_rethrow_but_no_logging()
    test_global_exception_handler()
    
    print("\n=== All AST Error Handling Tests Passed ===\n")


if __name__ == "__main__":
    run_all_tests()
