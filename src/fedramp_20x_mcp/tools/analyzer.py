"""
Code analysis tools for FedRAMP 20x compliance checking.

Provides MCP tools for analyzing Infrastructure as Code, application code, and CI/CD pipelines.

Architecture:
- Hybrid analysis: Combines pattern engine (YAML-driven) with traditional analyzers
- Pattern engine provides fast, declarative detection across all requirements
- Traditional analyzers provide deep, specialized analysis for complex scenarios
- Results are merged and deduplicated for comprehensive coverage
"""

import logging
from typing import Optional
from ..analyzers.ksi.factory import get_factory as get_ksi_factory
from ..analyzers.frr.factory import get_factory as get_frr_factory
from ..analyzers import AnalysisResult, Finding, Severity
from ..analyzers.pattern_tool_adapter import analyze_with_patterns, get_pattern_coverage

logger = logging.getLogger(__name__)


def _merge_findings(pattern_findings: list[Finding], traditional_findings: list[Finding]) -> list[Finding]:
    """
    Merge and deduplicate findings from pattern engine and traditional analyzers.
    
    Deduplication strategy:
    - Same requirement_id + similar message = duplicate (keep pattern finding)
    - Same requirement_id + different message = both kept (different issues)
    - Pattern findings preferred when duplicate (faster, clearer source)
    
    Args:
        pattern_findings: Findings from pattern engine
        traditional_findings: Findings from traditional analyzers
        
    Returns:
        Merged list of unique findings
    """
    # Start with all pattern findings (pattern engine is primary)
    merged = list(pattern_findings)
    
    # Track what we've seen for deduplication
    seen_keys = set()
    for finding in pattern_findings:
        # Create deduplication key: req_id + first 50 chars of description
        desc = finding.description or ""
        key = (finding.requirement_id, desc[:50].strip().lower())
        seen_keys.add(key)
    
    # Add traditional findings that aren't duplicates
    for finding in traditional_findings:
        desc = finding.description or ""
        key = (finding.requirement_id, desc[:50].strip().lower())
        if key not in seen_keys:
            merged.append(finding)
            seen_keys.add(key)
    
    return merged


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
    
    # Validate file type
    file_type_lower = file_type.lower()
    if file_type_lower not in ["bicep", "terraform", "tf"]:
        return {
            "error": f"Unsupported file type: {file_type}. Supported types: bicep, terraform"
        }
    
    # Normalize terraform variants
    if file_type_lower == "tf":
        file_type_lower = "terraform"
    
    logger.info(f"Analyzing {file_type_lower} infrastructure code with hybrid approach")
    
    # STEP 1: Pattern-based analysis (fast, comprehensive)
    pattern_findings = []
    try:
        pattern_result = await analyze_with_patterns(
            code=code,
            language=file_type_lower,
            file_path=file_path
        )
        pattern_findings = pattern_result.findings
        logger.info(f"Pattern engine found {len(pattern_findings)} issues")
    except Exception as e:
        logger.warning(f"Pattern analysis failed, falling back to traditional analyzers only: {e}")
    
    # STEP 2: Traditional analyzer-based analysis (deep, specialized)
    ksi_factory = get_ksi_factory()
    frr_factory = get_frr_factory()
    traditional_findings = []
    
    # Run KSI analyzers
    for ksi_id in ksi_factory.list_ksis():
        result = await ksi_factory.analyze(ksi_id, code, file_type_lower, file_path)
        if result and result.findings:
            traditional_findings.extend(result.findings)
    
    # Run FRR analyzers
    for frr_id in frr_factory.list_frrs():
        result = await frr_factory.analyze(frr_id, code, file_type_lower, file_path)
        if result and result.findings:
            traditional_findings.extend(result.findings)
    
    logger.info(f"Traditional analyzers found {len(traditional_findings)} issues")
    
    # STEP 3: Merge and deduplicate findings
    all_findings = _merge_findings(pattern_findings, traditional_findings)
    logger.info(f"Total unique findings after deduplication: {len(all_findings)}")
    
    # Create aggregated result with hybrid metadata
    combined_result = AnalysisResult(
        findings=all_findings
    )
    
    # Format output with hybrid analysis metadata
    output = combined_result.to_dict()
    output["file_path"] = file_path
    output["analysis_mode"] = "hybrid"
    output["pattern_findings_count"] = len(pattern_findings)
    output["traditional_findings_count"] = len(traditional_findings)
    output["total_findings"] = len(all_findings)
    output["pattern_coverage"] = get_pattern_coverage()
    
    # Add context if provided
    if context:
        output["context"] = context
    
    # Add formatted recommendations
    if combined_result.findings:
        output["pr_comment"] = _format_pr_comment(combined_result, file_path)
    
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
    
    # Normalize language name
    language_lower = language.lower()
    language_map = {
        "py": "python",
        "c#": "csharp",
        "cs": "csharp",
        "ts": "typescript",
        "js": "typescript"  # TypeScript analyzer handles both
    }
    language_normalized = language_map.get(language_lower, language_lower)
    
    # Validate language
    if language_normalized not in ["python", "csharp", "java", "typescript"]:
        return {
            "error": f"Unsupported language: {language}. Supported languages: python, csharp, java, typescript, javascript"
        }
    
    logger.info(f"Analyzing {language_normalized} application code with hybrid approach")
    
    # STEP 1: Pattern-based analysis (fast, comprehensive)
    pattern_findings = []
    try:
        pattern_result = await analyze_with_patterns(
            code=code,
            language=language_normalized,
            file_path=file_path
        )
        pattern_findings = pattern_result.findings
        logger.info(f"Pattern engine found {len(pattern_findings)} issues")
    except Exception as e:
        logger.warning(f"Pattern analysis failed, falling back to traditional analyzers only: {e}")
    
    # STEP 2: Traditional analyzer-based analysis (deep, specialized)
    ksi_factory = get_ksi_factory()
    frr_factory = get_frr_factory()
    traditional_findings = []
    
    # Run KSI analyzers
    for ksi_id in ksi_factory.list_ksis():
        result = await ksi_factory.analyze(ksi_id, code, language_normalized, file_path)
        if result and result.findings:
            traditional_findings.extend(result.findings)
    
    # Run FRR analyzers
    for frr_id in frr_factory.list_frrs():
        result = await frr_factory.analyze(frr_id, code, language_normalized, file_path)
        if result and result.findings:
            traditional_findings.extend(result.findings)
    
    logger.info(f"Traditional analyzers found {len(traditional_findings)} issues")
    
    # STEP 3: Merge and deduplicate findings
    all_findings = _merge_findings(pattern_findings, traditional_findings)
    logger.info(f"Total unique findings after deduplication: {len(all_findings)}")
    
    # Create aggregated result with hybrid metadata
    combined_result = AnalysisResult(
        findings=all_findings
    )
    
    # Format output with hybrid analysis metadata
    output = combined_result.to_dict()
    output["file_path"] = file_path
    output["analysis_mode"] = "hybrid"
    output["pattern_findings_count"] = len(pattern_findings)
    output["traditional_findings_count"] = len(traditional_findings)
    output["total_findings"] = len(all_findings)
    output["pattern_coverage"] = get_pattern_coverage()
    
    # Add dependencies info if provided
    if dependencies:
        output["dependencies_checked"] = dependencies
    
    # Add formatted recommendations
    if combined_result.findings:
        output["pr_comment"] = _format_pr_comment(combined_result, file_path)
    
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
    
    # Normalize pipeline type name
    pipeline_map = {
        "github-actions": "github_actions",
        "azure-pipelines": "azure_pipelines",
        "gitlab-ci": "gitlab_ci"
    }
    language_normalized = pipeline_map.get(pipeline_type.lower(), pipeline_type.lower())
    
    logger.info(f"Analyzing {pipeline_type} CI/CD pipeline with hybrid approach")
    
    # STEP 1: Pattern-based analysis (fast, comprehensive)
    pattern_findings = []
    try:
        pattern_result = await analyze_with_patterns(
            code=code,
            language=language_normalized,
            file_path=file_path
        )
        pattern_findings = pattern_result.findings
        logger.info(f"Pattern engine found {len(pattern_findings)} issues")
    except Exception as e:
        logger.warning(f"Pattern analysis failed, falling back to traditional analyzers only: {e}")
    
    # STEP 2: Traditional analyzer-based analysis (deep, specialized)
    ksi_factory = get_ksi_factory()
    frr_factory = get_frr_factory()
    traditional_findings = []
    
    # Run KSI analyzers
    for ksi_id in ksi_factory.list_ksis():
        result = await ksi_factory.analyze(ksi_id, code, language_normalized, file_path)
        if result and result.findings:
            traditional_findings.extend(result.findings)
    
    # Run FRR analyzers
    for frr_id in frr_factory.list_frrs():
        result = await frr_factory.analyze(frr_id, code, language_normalized, file_path)
        if result and result.findings:
            traditional_findings.extend(result.findings)
    
    logger.info(f"Traditional analyzers found {len(traditional_findings)} issues")
    
    # STEP 3: Merge and deduplicate findings
    all_findings = _merge_findings(pattern_findings, traditional_findings)
    logger.info(f"Total unique findings after deduplication: {len(all_findings)}")
    
    # Create aggregated result with hybrid metadata
    combined_result = AnalysisResult(
        findings=all_findings
    )
    
    # Format output with hybrid analysis metadata
    output = combined_result.to_dict()
    output["file_path"] = file_path
    output["pipeline_type"] = pipeline_type
    output["analysis_mode"] = "hybrid"
    output["pattern_findings_count"] = len(pattern_findings)
    output["traditional_findings_count"] = len(traditional_findings)
    output["total_findings"] = len(all_findings)
    output["pattern_coverage"] = get_pattern_coverage()
    
    # Add formatted recommendations
    if combined_result.findings:
        output["pr_comment"] = _format_pr_comment(combined_result, file_path)
    
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
