"""
Test KSI-IAM-05: Least Privilege

Basic smoke test for least privilege analyzer.
"""

from fedramp_20x_mcp.analyzers.ksi.ksi_iam_05 import KSI_IAM_05_Analyzer


def test_ksi_iam_05_basic():
    """Basic smoke test for KSI-IAM-05 analyzer."""
    analyzer = KSI_IAM_05_Analyzer()
    
    # Test Python wildcard permissions
    code = """
permissions = ["*"]
scope = "*"
actions = ["*"]
"""
    result = analyzer.analyze(code, 'python', 'test.py')
    print(f"[PASS] Python analysis completed: {result.total_issues} findings")
    
    # Test C# AllowAnonymous
    csharp_code = """
[ApiController]
public class DocumentsController : ControllerBase
{
    [HttpDelete("{id}")]
    [AllowAnonymous]
    public async Task<IActionResult> DeleteDocument(int id) { return NoContent(); }
}
"""
    result = analyzer.analyze(csharp_code, 'csharp', 'DocumentsController.cs')
    print(f"[PASS] C# analysis completed: {result.total_issues} findings")
    
    # Test Terraform IAM
    terraform_code = """
resource "aws_iam_policy" "admin" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }]
  })
}
"""
    result = analyzer.analyze(terraform_code, 'terraform', 'iam.tf')
    print(f"[PASS] Terraform analysis completed: {result.total_issues} findings")
    
    print("\nKSI_IAM_05_Analyzer is functional")


if __name__ == "__main__":
    print("Testing KSI-IAM-05: Least Privilege")
    print("=" * 60)
    test_ksi_iam_05_basic()
    print("=" * 60)
    print("Basic test passed!")
