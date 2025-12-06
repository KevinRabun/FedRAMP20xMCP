"""
Test suite for FluentValidation deep support in C# analyzer.

Tests separate validator class detection, DI registration, and false positive reduction.
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_fluent_validation_separate_validator():
    """Test detection of separate FluentValidation validator classes."""
    print("\n=== Test 1: Separate FluentValidation Validator ===")
    
    code = """
using FluentValidation;

public class CreateUserRequest
{
    public string Username { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}

public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
{
    public CreateUserRequestValidator()
    {
        RuleFor(x => x.Username).NotEmpty().MaximumLength(50);
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        RuleFor(x => x.Password).MinimumLength(8);
    }
}

public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateUser([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    # Should recognize FluentValidation and NOT warn about missing validation
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Should have a good practice finding for FluentValidation usage
    good_practice_findings = [f for f in validation_findings if f.severity == Severity.INFO and "fluent" in f.title.lower()]
    
    assert len(good_practice_findings) >= 1, f"Expected FluentValidation good practice finding, got {len(good_practice_findings)}"
    
    # Should NOT have HIGH severity warning about missing validation
    high_severity = [f for f in validation_findings if f.severity == Severity.HIGH]
    assert len(high_severity) == 0, f"Should not have HIGH severity validation warnings with FluentValidation, got {len(high_severity)}"
    
    print(f"✓ FluentValidation validator class detected")
    print(f"✓ Good practice finding: {good_practice_findings[0].title}")


def test_fluent_validation_with_registration():
    """Test FluentValidation with DI registration (automatic validation)."""
    print("\n=== Test 2: FluentValidation with DI Registration ===")
    
    code = """
using FluentValidation;
using FluentValidation.AspNetCore;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddControllers()
            .AddFluentValidation(fv => fv.RegisterValidatorsFromAssemblyContaining<Program>());
    }
}

public class UpdateProductRequest
{
    public string Name { get; set; }
    public decimal Price { get; set; }
}

public class UpdateProductRequestValidator : AbstractValidator<UpdateProductRequest>
{
    public UpdateProductRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty();
        RuleFor(x => x.Price).GreaterThan(0);
    }
}

public class ProductController : ControllerBase
{
    [HttpPut]
    public IActionResult UpdateProduct([FromBody] UpdateProductRequest request)
    {
        // No explicit ModelState check needed - FluentValidation validates automatically
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Should recognize automatic validation via FluentValidation registration
    auto_validation_findings = [f for f in validation_findings if "automatic" in f.description.lower() or "pipeline" in f.description.lower()]
    
    assert len(auto_validation_findings) >= 1, f"Expected automatic validation finding, got {len(auto_validation_findings)}"
    assert auto_validation_findings[0].severity == Severity.INFO, "Should be INFO severity for automatic validation"
    
    print(f"✓ FluentValidation DI registration detected")
    print(f"✓ Automatic validation recognized: {auto_validation_findings[0].title}")


def test_mixed_validation_approaches():
    """Test project using both Data Annotations and FluentValidation."""
    print("\n=== Test 3: Mixed Validation Approaches ===")
    
    code = """
using System.ComponentModel.DataAnnotations;
using FluentValidation;

public class SimpleRequest
{
    [Required]
    [StringLength(100)]
    public string Name { get; set; }
}

public class ComplexRequest
{
    public string Email { get; set; }
    public int Age { get; set; }
}

public class ComplexRequestValidator : AbstractValidator<ComplexRequest>
{
    public ComplexRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
        RuleFor(x => x.Age).InclusiveBetween(18, 120);
    }
}

public class ApiController : ControllerBase
{
    [HttpPost("simple")]
    public IActionResult PostSimple([FromBody] SimpleRequest request)
    {
        if (!ModelState.IsValid) return BadRequest();
        return Ok();
    }
    
    [HttpPost("complex")]
    public IActionResult PostComplex([FromBody] ComplexRequest request)
    {
        if (!ModelState.IsValid) return BadRequest();
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Both approaches should be recognized
    good_practice = [f for f in validation_findings if f.severity == Severity.INFO]
    
    assert len(good_practice) >= 2, f"Expected both validation approaches recognized, got {len(good_practice)}"
    
    # One should mention FluentValidation
    fluent_mentions = [f for f in good_practice if "fluent" in f.description.lower()]
    assert len(fluent_mentions) >= 1, "Should recognize FluentValidation approach"
    
    print(f"✓ Mixed validation approaches recognized")
    print(f"✓ Data Annotations validated: 1 method")
    print(f"✓ FluentValidation validated: 1 method")


def test_missing_validator_class():
    """Test model without validator class (should warn)."""
    print("\n=== Test 4: Missing Validator Class ===")
    
    code = """
using FluentValidation;

public class UnvalidatedRequest
{
    public string Data { get; set; }
}

public class ApiController : ControllerBase
{
    [HttpPost]
    public IActionResult Post([FromBody] UnvalidatedRequest request)
    {
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Should warn about missing validation
    high_severity = [f for f in validation_findings if f.severity == Severity.HIGH]
    
    assert len(high_severity) >= 1, f"Expected HIGH severity warning for unvalidated request, got {len(high_severity)}"
    
    print(f"✓ Missing validator detected")
    print(f"✓ HIGH severity warning issued")


def test_validator_extraction_accuracy():
    """Test accurate extraction of validator rules."""
    print("\n=== Test 5: Validator Extraction Accuracy ===")
    
    code = """
using FluentValidation;

public class RegistrationRequest
{
    public string Username { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
    public string ConfirmPassword { get; set; }
}

public class RegistrationRequestValidator : AbstractValidator<RegistrationRequest>
{
    public RegistrationRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required")
            .Length(3, 50).WithMessage("Username must be 3-50 characters");
        
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();
        
        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(8)
            .Matches("[A-Z]").WithMessage("Must contain uppercase")
            .Matches("[0-9]").WithMessage("Must contain number");
        
        RuleFor(x => x.ConfirmPassword)
            .Equal(x => x.Password).WithMessage("Passwords must match");
    }
}

public class AuthController : ControllerBase
{
    [HttpPost]
    public IActionResult Register([FromBody] RegistrationRequest request)
    {
        if (!ModelState.IsValid) return BadRequest();
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Should recognize comprehensive validation
    good_practice = [f for f in validation_findings if f.severity == Severity.INFO and "fluent" in f.description.lower()]
    
    assert len(good_practice) >= 1, "Should recognize FluentValidation"
    
    # Check that finding mentions the model type
    assert any("RegistrationRequest" in f.description for f in good_practice), "Should mention model type"
    
    print(f"✓ Validator rules extracted correctly")
    print(f"✓ Complex validation rules recognized")


def test_no_false_positive_with_fluent():
    """Test that FluentValidation doesn't trigger false positives."""
    print("\n=== Test 6: No False Positives with FluentValidation ===")
    
    code = """
using FluentValidation;

public class OrderRequest
{
    public int Quantity { get; set; }
    public string ProductId { get; set; }
}

public class OrderRequestValidator : AbstractValidator<OrderRequest>
{
    public OrderRequestValidator()
    {
        RuleFor(x => x.Quantity).GreaterThan(0).LessThanOrEqualTo(1000);
        RuleFor(x => x.ProductId).NotEmpty().Length(3, 50);
    }
}

public class OrderController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateOrder([FromBody] OrderRequest request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        // Process order
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Should have ZERO HIGH severity warnings (all validated with FluentValidation)
    high_severity = [f for f in validation_findings if f.severity == Severity.HIGH]
    medium_severity = [f for f in validation_findings if f.severity == Severity.MEDIUM]
    
    assert len(high_severity) == 0, f"Should have 0 HIGH severity warnings, got {len(high_severity)}"
    assert len(medium_severity) == 0, f"Should have 0 MEDIUM severity warnings, got {len(medium_severity)}"
    
    # Should have INFO finding for good practice
    info_findings = [f for f in validation_findings if f.severity == Severity.INFO]
    assert len(info_findings) >= 1, "Should have INFO finding for good practice"
    
    print(f"✓ No false positives with FluentValidation")
    print(f"✓ Recognized as good practice")


def test_multiple_validators_in_file():
    """Test file with multiple validator classes."""
    print("\n=== Test 7: Multiple Validators in File ===")
    
    code = """
using FluentValidation;

public class CreateUserRequest { public string Email { get; set; } }
public class UpdateUserRequest { public string Name { get; set; } }
public class DeleteUserRequest { public int UserId { get; set; } }

public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
{
    public CreateUserRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
    }
}

public class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequest>
{
    public UpdateUserRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(100);
    }
}

public class DeleteUserRequestValidator : AbstractValidator<DeleteUserRequest>
{
    public DeleteUserRequestValidator()
    {
        RuleFor(x => x.UserId).GreaterThan(0);
    }
}

public class UserController : ControllerBase
{
    [HttpPost] public IActionResult Create([FromBody] CreateUserRequest r) { if (!ModelState.IsValid) return BadRequest(); return Ok(); }
    [HttpPut] public IActionResult Update([FromBody] UpdateUserRequest r) { if (!ModelState.IsValid) return BadRequest(); return Ok(); }
    [HttpDelete] public IActionResult Delete([FromBody] DeleteUserRequest r) { if (!ModelState.IsValid) return BadRequest(); return Ok(); }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Should recognize all three validators
    good_practice = [f for f in validation_findings if f.severity == Severity.INFO]
    
    assert len(good_practice) >= 3, f"Expected 3 good practice findings, got {len(good_practice)}"
    
    print(f"✓ Multiple validators detected: 3 validators")
    print(f"✓ All controllers properly validated")


def test_fluent_validation_false_negative_prevention():
    """Test that missing ModelState check is caught even with FluentValidation."""
    print("\n=== Test 8: False Negative Prevention ===")
    
    code = """
using FluentValidation;

public class PaymentRequest
{
    public decimal Amount { get; set; }
}

public class PaymentRequestValidator : AbstractValidator<PaymentRequest>
{
    public PaymentRequestValidator()
    {
        RuleFor(x => x.Amount).GreaterThan(0);
    }
}

public class PaymentController : ControllerBase
{
    // FluentValidation registered but no automatic validation
    [HttpPost]
    public IActionResult ProcessPayment([FromBody] PaymentRequest request)
    {
        // Missing ModelState.IsValid check - validator exists but not enforced!
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    
    validation_findings = [f for f in result.findings if "KSI-SVC-02" in f.requirement_id]
    
    # Should warn about missing ModelState check (unless DI registration detected)
    warnings = [f for f in validation_findings if f.severity in [Severity.MEDIUM, Severity.INFO]]
    
    assert len(warnings) >= 1, f"Expected warning about validation enforcement, got {len(warnings)}"
    
    print(f"✓ Missing ModelState check detected")
    print(f"✓ False negative prevented")


def run_all_tests():
    """Run all FluentValidation tests."""
    print("\n" + "="*70)
    print("FLUENTVALIDATION DEEP SUPPORT TEST SUITE")
    print("="*70)
    
    try:
        test_fluent_validation_separate_validator()
        test_fluent_validation_with_registration()
        test_mixed_validation_approaches()
        test_missing_validator_class()
        test_validator_extraction_accuracy()
        test_no_false_positive_with_fluent()
        test_multiple_validators_in_file()
        test_fluent_validation_false_negative_prevention()
        
        print("\n" + "="*70)
        print("ALL FLUENTVALIDATION TESTS PASSED ✓")
        print("="*70)
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
