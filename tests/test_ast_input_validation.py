"""
Comprehensive tests for Tier 1.2: AST-Enhanced Input Validation Check

Tests the new AST-based input validation analysis capabilities:
- Controller method parameter extraction
- Validation attribute detection on parameters and models
- ModelState.IsValid check verification
- Parameter binding detection (FromBody, FromQuery, etc.)
- Proper validation pattern recognition
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_unvalidated_parameters_without_modelstate():
    """Test detection of unvalidated parameters without ModelState check (HIGH severity)."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        [HttpPost]
        public IActionResult CreateUser([FromBody] CreateUserRequest request)
        {
            // No ModelState check, no validation attributes
            return Ok(request);
        }
    }
    
    public class CreateUserRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect unvalidated input as HIGH severity
    unvalidated_findings = [f for f in result.findings 
                           if "without validation" in f.title.lower() 
                           and f.requirement_id == "KSI-SVC-02"
                           and f.severity == Severity.HIGH]
    
    assert len(unvalidated_findings) > 0, "Failed to detect unvalidated parameters"
    print("[PASS] Unvalidated parameters without ModelState detection test passed")


def test_validated_model_without_modelstate_check():
    """Test detection of validated model but missing ModelState check (MEDIUM severity)."""
    code = '''
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        [HttpPost]
        public IActionResult CreateUser([FromBody] CreateUserRequest request)
        {
            // Has validation but no ModelState check!
            return Ok(request);
        }
    }
    
    public class CreateUserRequest
    {
        [Required]
        [StringLength(50)]
        public string Username { get; set; }
        
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect missing ModelState check (MEDIUM severity)
    missing_modelstate = [f for f in result.findings 
                         if "modelstate" in f.title.lower() 
                         and f.requirement_id == "KSI-SVC-02"
                         and f.severity == Severity.MEDIUM]
    
    assert len(missing_modelstate) > 0, "Failed to detect missing ModelState.IsValid check"
    print("[PASS] Validated model without ModelState check detection test passed")


def test_proper_validation_with_modelstate():
    """Test recognition of proper validation with ModelState check (good practice)."""
    code = '''
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;
        
        [HttpPost]
        public IActionResult CreateUser([FromBody] CreateUserRequest request)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Validation failed");
                return BadRequest(ModelState);
            }
            
            return Ok(request);
        }
    }
    
    public class CreateUserRequest
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3)]
        [RegularExpression(@"^[a-zA-Z0-9_]+$")]
        public string Username { get; set; }
        
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-02"
                     and "properly configured" in f.title.lower()]
    
    assert len(good_practices) > 0, "Failed to recognize proper validation"
    print("[PASS] Proper validation with ModelState recognition test passed")


def test_multiple_parameters_mixed_validation():
    """Test detection with multiple parameters, some validated and some not."""
    code = '''
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    public class DataController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetData(
            [FromQuery] string filter,  // No validation
            [FromQuery] int pageSize)    // No validation
        {
            // No ModelState check either
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "DataController.cs")
    
    # Should detect unvalidated query parameters WITHOUT ModelState check
    validation_findings = [f for f in result.findings 
                          if f.requirement_id == "KSI-SVC-02"
                          and f.severity == Severity.HIGH]
    
    # Should have HIGH severity finding about unvalidated parameters
    assert len(validation_findings) > 0, "Failed to detect mixed validation scenario"
    print("[PASS] Multiple parameters with mixed validation test passed")


def test_fromquery_parameter_validation():
    """Test validation detection for FromQuery parameters with validated model."""
    code = '''
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    public class SearchController : ControllerBase
    {
        [HttpGet]
        public IActionResult Search([FromQuery] SearchRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            
            return Ok();
        }
    }
    
    public class SearchRequest
    {
        [Required]
        [StringLength(100)]
        public string Query { get; set; }
        
        [Range(1, 100)]
        public int Limit { get; set; }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SearchController.cs")
    
    # Should recognize proper validation
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-02"]
    
    assert len(good_practices) > 0, "Failed to recognize FromQuery parameter validation"
    print("[PASS] FromQuery parameter validation test passed")


def test_fromroute_parameter_no_validation():
    """Test detection of FromRoute parameters without validation."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/users")]
    public class UserController : ControllerBase
    {
        [HttpGet("{id}")]
        public IActionResult GetUser([FromRoute] string id)
        {
            // No validation on route parameter
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect unvalidated route parameter
    unvalidated_findings = [f for f in result.findings 
                           if "without validation" in f.title.lower() 
                           and f.requirement_id == "KSI-SVC-02"]
    
    assert len(unvalidated_findings) > 0, "Failed to detect unvalidated FromRoute parameter"
    print("[PASS] FromRoute parameter without validation detection test passed")


def test_complex_model_with_nested_validation():
    """Test validation detection in complex models."""
    code = '''
    using System.ComponentModel.DataAnnotations;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    public class OrderController : ControllerBase
    {
        [HttpPost]
        public IActionResult CreateOrder([FromBody] CreateOrderRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            
            return Ok();
        }
    }
    
    public class CreateOrderRequest
    {
        [Required]
        [StringLength(100)]
        public string ProductName { get; set; }
        
        [Required]
        [Range(1, int.MaxValue)]
        public int Quantity { get; set; }
        
        [Required]
        [RegularExpression(@"^[A-Z]{2}$")]
        public string CountryCode { get; set; }
        
        [EmailAddress]
        public string ContactEmail { get; set; }
        
        [Phone]
        public string ContactPhone { get; set; }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "OrderController.cs")
    
    # Should recognize comprehensive validation
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-02"]
    
    assert len(good_practices) > 0, "Failed to recognize complex model validation"
    print("[PASS] Complex model with nested validation test passed")


def test_non_controller_class_ignored():
    """Test that non-controller classes are not analyzed for validation."""
    code = '''
    using System.ComponentModel.DataAnnotations;
    
    public class UserService
    {
        public void ProcessUser(UserData data)
        {
            // This is not a controller, should not trigger validation checks
        }
    }
    
    public class UserData
    {
        public string Name { get; set; }
        public string Email { get; set; }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserService.cs")
    
    # Should NOT have input validation findings for non-controller
    validation_findings = [f for f in result.findings 
                          if f.requirement_id == "KSI-SVC-02"]
    
    assert len(validation_findings) == 0, "Incorrectly analyzed non-controller class"
    print("[PASS] Non-controller class ignored test passed")


def run_all_tests():
    """Run all AST input validation tests."""
    print("\n=== Running AST Input Validation Tests (Tier 1.2) ===\n")
    
    test_unvalidated_parameters_without_modelstate()
    test_validated_model_without_modelstate_check()
    test_proper_validation_with_modelstate()
    test_multiple_parameters_mixed_validation()
    test_fromquery_parameter_validation()
    test_fromroute_parameter_no_validation()
    test_complex_model_with_nested_validation()
    test_non_controller_class_ignored()
    
    print("\n=== All AST Input Validation Tests Passed ===\n")


if __name__ == "__main__":
    run_all_tests()
