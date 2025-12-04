"""
Code analysis tools for FedRAMP 20x compliance checking.

Provides MCP tools for analyzing Infrastructure as Code, application code, and CI/CD pipelines.
"""

from typing import Optional
from ..analyzers import (
    BicepAnalyzer,
    TerraformAnalyzer,
    PythonAnalyzer,
    CSharpAnalyzer,
    JavaAnalyzer,
    TypeScriptAnalyzer,
    CICDAnalyzer
)


async def analyze_infrastructure_code_impl(
    code: str,
    file_type: str,
    file_path: Optional[str] = None,
    context: Optional[str] = None
) -> dict:
    """
    Analyze Infrastructure as Code for FedRAMP 20x compliance.
    
    Args:
        code: The IaC code content to analyze
        file_type: Type of IaC file ("bicep" or "terraform")
        file_path: Optional path to the file being analyzed (for display purposes)
        context: Optional context about the changes (e.g., PR description)
        
    Returns:
        Dictionary containing analysis results with findings and recommendations
    """
    if not file_path:
        file_path = f"file.{file_type}"
    
    # Select appropriate analyzer
    if file_type.lower() == "bicep":
        analyzer = BicepAnalyzer()
    elif file_type.lower() in ["terraform", "tf"]:
        analyzer = TerraformAnalyzer()
    else:
        return {
            "error": f"Unsupported file type: {file_type}. Supported types: bicep, terraform"
        }
    
    # Run analysis
    result = analyzer.analyze(code, file_path)
    
    # Format output
    output = result.to_dict()
    
    # Add context if provided
    if context:
        output["context"] = context
    
    # Add formatted recommendations
    if result.findings:
        output["pr_comment"] = _format_pr_comment(result, file_path)
    
    return output


async def analyze_application_code_impl(
    code: str,
    language: str,
    file_path: Optional[str] = None,
    dependencies: Optional[list[str]] = None
) -> dict:
    """
    Analyze application code for FedRAMP 20x security compliance.
    
    Args:
        code: The application code content to analyze
        language: Programming language ("python", "csharp", "java", "typescript", "javascript")
        file_path: Optional path to the file being analyzed
        dependencies: Optional list of dependencies/imports to check
        
    Returns:
        Dictionary containing analysis results with findings and recommendations
    """
    if not file_path:
        file_path = f"file.{language}"
    
    # Select appropriate analyzer based on language
    language_lower = language.lower()
    
    if language_lower in ["python", "py"]:
        analyzer = PythonAnalyzer()
    elif language_lower in ["csharp", "c#", "cs"]:
        analyzer = CSharpAnalyzer()
    elif language_lower in ["java"]:
        analyzer = JavaAnalyzer()
    elif language_lower in ["typescript", "ts", "javascript", "js"]:
        analyzer = TypeScriptAnalyzer()
    else:
        return {
            "error": f"Unsupported language: {language}. Supported languages: python, csharp, java, typescript, javascript"
        }
    
    # Run analysis
    result = analyzer.analyze(code, file_path)
    
    # Format output
    output = result.to_dict()
    
    # Add dependencies info if provided
    if dependencies:
        output["dependencies_checked"] = dependencies
    
    # Add formatted recommendations
    if result.findings:
        output["pr_comment"] = _format_pr_comment(result, file_path)
    
    return output


async def analyze_cicd_pipeline_impl(
    code: str,
    pipeline_type: str,
    file_path: Optional[str] = None
) -> dict:
    """
    Analyze CI/CD pipeline configuration for FedRAMP 20x DevSecOps compliance.
    
    Args:
        code: The pipeline configuration content (YAML/JSON)
        pipeline_type: Type of pipeline ("github-actions", "azure-pipelines", "gitlab-ci", or "generic")
        file_path: Optional path to the pipeline file
        
    Returns:
        Dictionary containing analysis results with findings and recommendations
    """
    if not file_path:
        if pipeline_type == "github-actions":
            file_path = ".github/workflows/pipeline.yml"
        elif pipeline_type == "azure-pipelines":
            file_path = "azure-pipelines.yml"
        elif pipeline_type == "gitlab-ci":
            file_path = ".gitlab-ci.yml"
        else:
            file_path = "pipeline.yml"
    
    # Use CICDAnalyzer for all pipeline types
    analyzer = CICDAnalyzer()
    
    # Run analysis
    result = analyzer.analyze(code, file_path)
    
    # Format output
    output = result.to_dict()
    output["pipeline_type"] = pipeline_type
    
    # Add formatted recommendations
    if result.findings:
        output["pr_comment"] = _format_pr_comment(result, file_path)
    
    return output


def _format_pr_comment(result, file_path: str) -> str:
    """
    Format analysis results as a PR comment.
    
    Args:
        result: AnalysisResult object
        file_path: Path to the file
        
    Returns:
        Formatted markdown comment
    """
    lines = []
    lines.append("## 🔒 FedRAMP 20x Compliance Review\n")
    lines.append(f"**File:** `{file_path}`\n")
    
    # Summary
    summary = result.to_dict()['summary']
    total_issues = summary['high_priority'] + summary['medium_priority'] + summary['low_priority']
    
    if total_issues > 0:
        lines.append(f"**{total_issues} recommendation{'s' if total_issues != 1 else ''} found:**\n")
    
    # High priority issues
    high_findings = [f for f in result.findings if f.severity.value == "high" and not f.good_practice]
    if high_findings:
        lines.append("### ⚠️ High Priority\n")
        for finding in high_findings:
            lines.append(f"**{finding.title}**")
            if finding.line_number:
                lines.append(f" (Line {finding.line_number})")
            lines.append(f"\n**Requirement:** {finding.requirement_id}")
            lines.append(f"\n**Issue:** {finding.description}\n")
            if finding.code_snippet:
                lines.append(f"**Code:**\n```\n{finding.code_snippet}\n```\n")
            lines.append(f"**Recommendation:**\n{finding.recommendation}\n")
            lines.append("---\n")
    
    # Medium priority issues
    medium_findings = [f for f in result.findings if f.severity.value == "medium" and not f.good_practice]
    if medium_findings:
        lines.append("### ⚡ Medium Priority\n")
        for finding in medium_findings:
            lines.append(f"**{finding.title}**")
            if finding.line_number:
                lines.append(f" (Line {finding.line_number})")
            lines.append(f"\n**Requirement:** {finding.requirement_id}")
            lines.append(f"\n{finding.description}\n")
            lines.append(f"**Recommendation:** {finding.recommendation}\n")
            lines.append("---\n")
    
    # Good practices
    good_practices = [f for f in result.findings if f.good_practice]
    if good_practices:
        lines.append("### ✅ Good Practices Detected\n")
        for finding in good_practices:
            lines.append(f"- **{finding.title}** ({finding.requirement_id})")
            if finding.line_number:
                lines.append(f" - Line {finding.line_number}")
            lines.append("\n")
    
    # Summary line
    if total_issues > 0:
        lines.append(f"\n**Summary:** {summary['high_priority']} high, {summary['medium_priority']} medium, {summary['low_priority']} low")
        if summary['good_practices'] > 0:
            lines.append(f", {summary['good_practices']} good practices")
        lines.append("\n")
        
        if summary['high_priority'] > 0:
            lines.append("**Action Required:** Address high-priority items before merging\n")
    elif summary['good_practices'] > 0:
        lines.append(f"\n**Summary:** All checks passed! {summary['good_practices']} good practices detected.\n")
    else:
        lines.append("\n**Summary:** No FedRAMP 20x issues detected.\n")
    
    return "".join(lines)
