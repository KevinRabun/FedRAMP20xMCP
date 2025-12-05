#!/usr/bin/env python3
"""
FedRAMP 20x MCP Server - Direct Analyzer Usage for CI/CD Integration

This script demonstrates how to use the FedRAMP 20x analyzers directly
in CI/CD pipelines without requiring the MCP server infrastructure.

Usage:
    python ci_cd_integration.py <file_or_directory> [--format json|markdown]

Examples:
    # Analyze a single Python file
    python ci_cd_integration.py src/app.py

    # Analyze all files in a directory
    python ci_cd_integration.py infrastructure/

    # Generate JSON output for machine processing
    python ci_cd_integration.py src/ --format json

Exit Codes:
    0 - No high-priority issues found
    1 - High-priority compliance issues detected
    2 - Analysis error occurred
"""

import sys
import json
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import asdict

# Import analyzers directly (no MCP server required)
from fedramp_20x_mcp.analyzers.python_analyzer import PythonAnalyzer
from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.java_analyzer import JavaAnalyzer
from fedramp_20x_mcp.analyzers.typescript_analyzer import TypeScriptAnalyzer
from fedramp_20x_mcp.analyzers.bicep_analyzer import BicepAnalyzer
from fedramp_20x_mcp.analyzers.terraform_analyzer import TerraformAnalyzer
from fedramp_20x_mcp.analyzers.base import AnalysisResult, Finding


def get_analyzer_for_file(file_path: Path):
    """Return the appropriate analyzer for the file extension."""
    ext = file_path.suffix.lower()
    
    analyzers = {
        '.py': PythonAnalyzer,
        '.cs': CSharpAnalyzer,
        '.java': JavaAnalyzer,
        '.ts': TypeScriptAnalyzer,
        '.tsx': TypeScriptAnalyzer,
        '.js': TypeScriptAnalyzer,
        '.jsx': TypeScriptAnalyzer,
        '.bicep': BicepAnalyzer,
        '.tf': TerraformAnalyzer,
    }
    
    analyzer_class = analyzers.get(ext)
    if analyzer_class:
        return analyzer_class()
    return None


def find_analyzable_files(path: Path) -> List[Path]:
    """Find all files that can be analyzed."""
    if path.is_file():
        return [path] if get_analyzer_for_file(path) else []
    
    # Directory - find all supported file types
    patterns = ['**/*.py', '**/*.cs', '**/*.java', '**/*.ts', '**/*.tsx', 
                '**/*.js', '**/*.jsx', '**/*.bicep', '**/*.tf']
    
    files = []
    for pattern in patterns:
        files.extend(path.rglob(pattern))
    
    # Filter out common non-source directories
    exclude_patterns = ['node_modules/', '__pycache__/', 'venv/', '.venv/', 
                       'obj/', 'bin/', 'build/', 'dist/', '.git/']
    
    return [f for f in files if not any(exclude in str(f) for exclude in exclude_patterns)]


def analyze_file(file_path: Path, analyzer) -> AnalysisResult:
    """Analyze a single file."""
    print(f"📄 Analyzing {file_path}...", file=sys.stderr)
    
    try:
        content = file_path.read_text(encoding='utf-8')
        
        # All analyzers take the same signature: (code, file_path)
        result = analyzer.analyze(content, str(file_path))
        
        return result
    
    except Exception as e:
        print(f"  ❌ Error analyzing {file_path}: {e}", file=sys.stderr)
        raise


def format_markdown_report(results: List[tuple[Path, AnalysisResult]]) -> str:
    """Generate a markdown report from analysis results."""
    report = "# FedRAMP 20x Compliance Analysis Report\n\n"
    
    # Summary statistics
    total_files = len(results)
    total_findings = sum(len(result.findings) for _, result in results)
    total_high = sum(result.high_priority_count for _, result in results)
    total_medium = sum(result.medium_priority_count for _, result in results)
    total_low = sum(result.low_priority_count for _, result in results)
    
    report += "## Summary\n\n"
    report += f"- **Files Analyzed:** {total_files}\n"
    report += f"- **Total Findings:** {total_findings}\n"
    report += f"- **High Priority:** {total_high} 🔴\n"
    report += f"- **Medium Priority:** {total_medium} 🟡\n"
    report += f"- **Low Priority:** {total_low} 🟢\n\n"
    
    if total_high > 0:
        report += "⚠️ **Action Required:** High-priority compliance issues must be addressed.\n\n"
    
    # Findings by file
    files_with_issues = [(path, result) for path, result in results if result.findings]
    
    if files_with_issues:
        report += "## Detailed Findings\n\n"
        
        for file_path, result in files_with_issues:
            report += f"### 📁 {file_path}\n\n"
            report += f"**Issues:** {len(result.findings)} "
            report += f"(High: {result.high_priority_count}, Medium: {result.medium_priority_count}, Low: {result.low_priority_count})\n\n"
            
            # Group findings by requirement ID
            by_requirement: Dict[str, List[Finding]] = {}
            for finding in result.findings:
                req_id = finding.requirement_id
                if req_id not in by_requirement:
                    by_requirement[req_id] = []
                by_requirement[req_id].append(finding)
            
            for req_id, findings in by_requirement.items():
                severity_icon = "🔴" if findings[0].severity == "high" else "🟡" if findings[0].severity == "medium" else "🟢"
                report += f"#### {severity_icon} {req_id}\n\n"
                
                for finding in findings:
                    line_info = f"Line {finding.line_number}: " if finding.line_number else ""
                    report += f"**{line_info}**{finding.description}\n\n"
                    if finding.code_snippet:
                        report += f"```\n{finding.code_snippet}\n```\n\n"
                    report += f"**Recommendation:** {finding.recommendation}\n\n"
            
            report += "---\n\n"
    else:
        report += "## ✅ No Issues Found\n\n"
        report += "All analyzed files comply with FedRAMP 20x requirements.\n\n"
    
    report += "---\n\n"
    report += "*Generated by FedRAMP 20x MCP Server*\n"
    report += "*Documentation: https://github.com/yourusername/FedRAMP20xMCP*\n"
    
    return report


def format_json_report(results: List[tuple[Path, AnalysisResult]]) -> str:
    """Generate a JSON report from analysis results."""
    report_data = {
        "summary": {
            "files_analyzed": len(results),
            "total_findings": sum(len(result.findings) for _, result in results),
            "high_priority": sum(result.high_priority_count for _, result in results),
            "medium_priority": sum(result.medium_priority_count for _, result in results),
            "low_priority": sum(result.low_priority_count for _, result in results),
        },
        "files": []
    }
    
    for file_path, result in results:
        file_data = {
            "path": str(file_path),
            "findings_count": len(result.findings),
            "summary": {
                "high": result.high_priority_count,
                "medium": result.medium_priority_count,
                "low": result.low_priority_count
            },
            "findings": []
        }
        
        for finding in result.findings:
            file_data["findings"].append({
                "requirement_id": finding.requirement_id,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                "description": finding.description,
                "line_number": finding.line_number,
                "code_snippet": finding.code_snippet,
                "recommendation": finding.recommendation,
                "file_path": finding.file_path,
            })
        
        report_data["files"].append(file_data)
    
    return json.dumps(report_data, indent=2)


def main():
    """Main entry point for the CI/CD integration script."""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    
    target_path = Path(sys.argv[1])
    output_format = 'markdown'
    
    if len(sys.argv) >= 3 and sys.argv[2] in ['--format', '-f']:
        if len(sys.argv) >= 4:
            output_format = sys.argv[3].lower()
    
    if not target_path.exists():
        print(f"❌ Error: Path not found: {target_path}", file=sys.stderr)
        sys.exit(2)
    
    # Find files to analyze
    print(f"🔍 Scanning {target_path}...", file=sys.stderr)
    files = find_analyzable_files(target_path)
    
    if not files:
        print(f"⚠️  No analyzable files found in {target_path}", file=sys.stderr)
        sys.exit(0)
    
    print(f"📋 Found {len(files)} files to analyze", file=sys.stderr)
    
    # Analyze each file
    results: List[tuple[Path, AnalysisResult]] = []
    errors = 0
    
    for file_path in files:
        analyzer = get_analyzer_for_file(file_path)
        if not analyzer:
            continue
        
        try:
            result = analyze_file(file_path, analyzer)
            results.append((file_path, result))
            
            # Log findings to stderr
            if result.findings:
                print(f"  ⚠️  Found {len(result.findings)} issues "
                      f"(High: {result.high_priority_count}, Medium: {result.medium_priority_count}, Low: {result.low_priority_count})",
                      file=sys.stderr)
            else:
                print(f"  ✅ No issues found", file=sys.stderr)
        
        except Exception as e:
            errors += 1
            print(f"  ❌ Analysis failed: {e}", file=sys.stderr)
    
    if errors > 0:
        print(f"\n⚠️  {errors} files could not be analyzed", file=sys.stderr)
    
    # Generate report
    print(f"\n📊 Generating {output_format} report...", file=sys.stderr)
    
    if output_format == 'json':
        report = format_json_report(results)
    else:
        report = format_markdown_report(results)
    
    # Output report to stdout (can be redirected to file)
    print(report)
    
    # Determine exit code
    total_high = sum(result.high_priority_count for _, result in results)
    
    if total_high > 0:
        print(f"\n❌ Analysis failed: {total_high} high-priority compliance issues found", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n✅ Analysis passed: No high-priority compliance issues", file=sys.stderr)
        sys.exit(0)


if __name__ == '__main__':
    main()
