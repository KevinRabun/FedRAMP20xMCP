"""
MCP Server Evaluator

Main evaluator class that orchestrates the evaluation process,
running test cases through appropriate judges and collecting metrics.

Includes adversarial testing capabilities to detect:
- Hallucinations
- Misinformation  
- Edge case failures
- Injection vulnerabilities
- Robustness issues
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .metrics import EvaluationMetrics, EvaluationResult, EvaluationCategory, Verdict
from .test_cases import (
    EvaluationTestCase,
    TestCaseCategory,
    ALL_TEST_CASES,
    get_test_cases_by_category,
    get_critical_test_cases,
)
from .judges import (
    BaseJudge,
    AccuracyJudge,
    CompletenessJudge,
    AnalysisQualityJudge,
    RelevanceJudge,
    ConsistencyJudge,
    get_judge,
)
from .adversarial_judges import (
    BaseAdversarialJudge,
    HallucinationJudge,
    MisinformationJudge,
    EdgeCaseJudge,
    InjectionJudge,
    RobustnessJudge,
    AdversarialCategory,
)
from .adversarial_test_cases import (
    ALL_ADVERSARIAL_TEST_CASES,
    CRITICAL_ADVERSARIAL_TEST_CASES,
    get_adversarial_test_cases_by_type,
)

logger = logging.getLogger(__name__)


class MCPServerEvaluator:
    """
    Comprehensive evaluator for the FedRAMP 20x MCP Server.
    
    Usage:
        evaluator = MCPServerEvaluator()
        results = await evaluator.run_full_evaluation()
        evaluator.generate_report(results)
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize the evaluator.
        
        Args:
            output_dir: Directory for evaluation reports (default: tests/evaluator/reports)
        """
        self.output_dir = output_dir or Path(__file__).parent / "reports"
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize judges
        self.judges: Dict[EvaluationCategory, BaseJudge] = {
            EvaluationCategory.ACCURACY: AccuracyJudge(),
            EvaluationCategory.COMPLETENESS: CompletenessJudge(),
            EvaluationCategory.ANALYSIS_QUALITY: AnalysisQualityJudge(),
            EvaluationCategory.RELEVANCE: RelevanceJudge(),
            EvaluationCategory.CONSISTENCY: ConsistencyJudge(),
        }
        
        # Initialize adversarial judges
        self.adversarial_judges: Dict[str, BaseAdversarialJudge] = {
            AdversarialCategory.HALLUCINATION: HallucinationJudge(),
            AdversarialCategory.MISINFORMATION: MisinformationJudge(),
            AdversarialCategory.EDGE_CASE: EdgeCaseJudge(),
            AdversarialCategory.INJECTION: InjectionJudge(),
            AdversarialCategory.ROBUSTNESS: RobustnessJudge(),
        }
        
        # Tool implementations will be loaded lazily
        self._tools_loaded = False
        self._data_loader = None
        self._tool_registry: Dict[str, Any] = {}
    
    async def _ensure_tools_loaded(self) -> None:
        """Lazily load tool implementations."""
        if self._tools_loaded:
            return
        
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
        
        from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
        from fedramp_20x_mcp.tools import (
            requirements, definitions, ksi, frr, documentation,
            export, enhancements, evidence, analyzer, audit,
            security, ksi_status, validation
        )
        
        # Initialize data loader
        self._data_loader = FedRAMPDataLoader()
        await self._data_loader.load_data()
        
        # Register tool implementations
        self._tool_registry = {
            # Requirements tools
            "get_control": lambda **p: requirements.get_control_impl(p["control_id"], self._data_loader),
            "list_family_controls": lambda **p: requirements.list_family_controls_impl(p["family"], self._data_loader),
            "search_requirements": lambda **p: requirements.search_requirements_impl(p["keywords"], self._data_loader),
            
            # Definition tools
            "get_definition": lambda **p: definitions.get_definition_impl(p["term"], self._data_loader),
            "list_definitions": lambda **p: definitions.list_definitions_impl(self._data_loader),
            "search_definitions": lambda **p: definitions.search_definitions_impl(p["keywords"], self._data_loader),
            
            # KSI tools
            "get_ksi": lambda **p: ksi.get_ksi_impl(p["ksi_id"], self._data_loader),
            "list_ksi": lambda **p: ksi.list_ksi_impl(self._data_loader),
            "get_ksi_implementation_summary": lambda **p: ksi.get_ksi_implementation_summary_impl(self._data_loader),
            
            # FRR tools
            "analyze_frr_code": lambda **p: frr.analyze_frr_code_impl(
                p["frr_id"], p["code"], p["language"], p.get("file_path"), self._data_loader
            ),
            
            # Analyzer tools
            "analyze_infrastructure_code": lambda **p: analyzer.analyze_infrastructure_code_impl(
                p["code"], p["file_type"], p.get("file_path"), p.get("context")
            ),
            "analyze_application_code": lambda **p: analyzer.analyze_application_code_impl(
                p["code"], p["language"], p.get("file_path"), p.get("dependencies")
            ),
        }
        
        self._tools_loaded = True
        logger.info(f"Loaded {len(self._tool_registry)} tool implementations")
    
    async def _invoke_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """
        Invoke a tool and return its result.
        
        Args:
            tool_name: Name of the tool to invoke
            params: Parameters to pass to the tool
            
        Returns:
            Tool result (string or dict)
        """
        await self._ensure_tools_loaded()
        
        if tool_name not in self._tool_registry:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool_func = self._tool_registry[tool_name]
        result = await tool_func(**params)
        return result
    
    async def evaluate_test_case(self, test_case: EvaluationTestCase) -> EvaluationResult:
        """
        Evaluate a single test case.
        
        Args:
            test_case: The test case to evaluate
            
        Returns:
            EvaluationResult with verdict and metrics
        """
        # Map TestCaseCategory to EvaluationCategory
        category_map = {
            TestCaseCategory.ACCURACY: EvaluationCategory.ACCURACY,
            TestCaseCategory.COMPLETENESS: EvaluationCategory.COMPLETENESS,
            TestCaseCategory.ANALYSIS_QUALITY: EvaluationCategory.ANALYSIS_QUALITY,
            TestCaseCategory.RELEVANCE: EvaluationCategory.RELEVANCE,
            TestCaseCategory.CONSISTENCY: EvaluationCategory.CONSISTENCY,
        }
        eval_category = category_map[test_case.category]
        
        # Invoke the tool
        start_time = time.perf_counter()
        try:
            result = await self._invoke_tool(test_case.tool_name, test_case.tool_params)
            latency_ms = (time.perf_counter() - start_time) * 1000
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Tool invocation failed for {test_case.id}: {e}")
            return EvaluationResult(
                test_case_id=test_case.id,
                category=eval_category,
                verdict=Verdict.ERROR,
                score=0.0,
                explanation=f"Tool invocation error: {str(e)}",
                latency_ms=latency_ms,
            )
        
        # Get appropriate judge and evaluate
        judge = self.judges[eval_category]
        evaluation = judge.evaluate(test_case, result, latency_ms)
        
        return evaluation
    
    async def run_test_cases(
        self,
        test_cases: List[EvaluationTestCase],
        parallel: bool = False
    ) -> EvaluationMetrics:
        """
        Run a set of test cases.
        
        Args:
            test_cases: List of test cases to run
            parallel: Whether to run tests in parallel (may affect consistency tests)
            
        Returns:
            EvaluationMetrics with all results
        """
        metrics = EvaluationMetrics()
        
        logger.info(f"Running {len(test_cases)} test cases...")
        
        if parallel:
            # Run in parallel (faster but may affect consistency tests)
            tasks = [self.evaluate_test_case(tc) for tc in test_cases]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    metrics.add_result(EvaluationResult(
                        test_case_id=test_cases[i].id,
                        category=EvaluationCategory.ACCURACY,
                        verdict=Verdict.ERROR,
                        score=0.0,
                        explanation=f"Execution error: {result}",
                    ))
                elif isinstance(result, EvaluationResult):
                    metrics.add_result(result)
        else:
            # Run sequentially (required for consistency tests)
            for tc in test_cases:
                try:
                    result = await self.evaluate_test_case(tc)
                    metrics.add_result(result)
                except Exception as e:
                    logger.error(f"Failed to evaluate {tc.id}: {e}")
                    metrics.add_result(EvaluationResult(
                        test_case_id=tc.id,
                        category=EvaluationCategory.ACCURACY,
                        verdict=Verdict.ERROR,
                        score=0.0,
                        explanation=f"Execution error: {e}",
                    ))
        
        metrics.finalize()
        return metrics
    
    async def run_full_evaluation(self) -> EvaluationMetrics:
        """
        Run the full evaluation suite.
        
        Returns:
            Complete EvaluationMetrics
        """
        logger.info("Starting full MCP Server evaluation...")
        
        # Run all test cases sequentially for consistency
        metrics = await self.run_test_cases(ALL_TEST_CASES, parallel=False)
        
        logger.info(f"Evaluation complete: {metrics.overall_score:.1%} overall score")
        return metrics
    
    async def run_critical_evaluation(self) -> EvaluationMetrics:
        """
        Run only critical test cases (faster).
        
        Returns:
            EvaluationMetrics for critical tests only
        """
        critical_tests = get_critical_test_cases()
        logger.info(f"Running {len(critical_tests)} critical test cases...")
        return await self.run_test_cases(critical_tests, parallel=True)
    
    async def run_category_evaluation(
        self,
        category: TestCaseCategory
    ) -> EvaluationMetrics:
        """
        Run test cases for a specific category.
        
        Args:
            category: The category to evaluate
            
        Returns:
            EvaluationMetrics for that category
        """
        test_cases = get_test_cases_by_category(category)
        logger.info(f"Running {len(test_cases)} {category.value} test cases...")
        return await self.run_test_cases(test_cases, parallel=category != TestCaseCategory.CONSISTENCY)
    
    async def run_consistency_check(self, iterations: int = 3) -> EvaluationMetrics:
        """
        Run consistency tests multiple times to check for variation.
        
        Args:
            iterations: Number of times to repeat each test
            
        Returns:
            EvaluationMetrics with consistency results
        """
        consistency_tests = get_test_cases_by_category(TestCaseCategory.CONSISTENCY)
        
        # Reset consistency judge
        consistency_judge = self.judges[EvaluationCategory.CONSISTENCY]
        if isinstance(consistency_judge, ConsistencyJudge):
            consistency_judge.reset()
        
        all_tests = []
        for _ in range(iterations):
            all_tests.extend(consistency_tests)
        
        logger.info(f"Running {len(all_tests)} consistency checks ({iterations} iterations)...")
        return await self.run_test_cases(all_tests, parallel=False)
    
    async def evaluate_adversarial_test_case(
        self,
        test_case: EvaluationTestCase,
        adversarial_type: str
    ) -> EvaluationResult:
        """
        Evaluate a single test case using an adversarial judge.
        
        Args:
            test_case: The test case to evaluate
            adversarial_type: Type of adversarial test (hallucination, misinformation, etc.)
            
        Returns:
            EvaluationResult with adversarial verdict
        """
        # Invoke the tool
        start_time = time.perf_counter()
        try:
            result = await self._invoke_tool(test_case.tool_name, test_case.tool_params)
            latency_ms = (time.perf_counter() - start_time) * 1000
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Tool invocation failed for adversarial test {test_case.id}: {e}")
            return EvaluationResult(
                test_case_id=test_case.id,
                category=EvaluationCategory.ACCURACY,
                verdict=Verdict.ERROR,
                score=0.0,
                explanation=f"Tool invocation error: {str(e)}",
                latency_ms=latency_ms,
                metadata={"adversarial_type": adversarial_type},
            )
        
        # Get appropriate adversarial judge
        judge = self.adversarial_judges.get(adversarial_type)
        if not judge:
            # Fall back to standard accuracy judge
            judge = self.judges[EvaluationCategory.ACCURACY]
        
        evaluation = judge.evaluate(test_case, result, latency_ms)
        return evaluation
    
    async def run_adversarial_evaluation(self, critical_only: bool = False) -> EvaluationMetrics:
        """
        Run adversarial test suite.
        
        Args:
            critical_only: If True, only run critical adversarial tests
            
        Returns:
            EvaluationMetrics with adversarial results
        """
        test_cases = CRITICAL_ADVERSARIAL_TEST_CASES if critical_only else ALL_ADVERSARIAL_TEST_CASES
        
        logger.info(f"Running {len(test_cases)} adversarial test cases...")
        metrics = EvaluationMetrics()
        
        for tc in test_cases:
            # Determine adversarial type from tags
            adversarial_type = None
            for tag in tc.tags:
                if tag in [AdversarialCategory.HALLUCINATION, AdversarialCategory.MISINFORMATION,
                          AdversarialCategory.EDGE_CASE, AdversarialCategory.INJECTION,
                          AdversarialCategory.ROBUSTNESS]:
                    adversarial_type = tag
                    break
            
            if not adversarial_type:
                # Default to hallucination check
                adversarial_type = AdversarialCategory.HALLUCINATION
            
            try:
                result = await self.evaluate_adversarial_test_case(tc, adversarial_type)
                metrics.add_result(result)
            except Exception as e:
                logger.error(f"Failed to evaluate adversarial test {tc.id}: {e}")
                metrics.add_result(EvaluationResult(
                    test_case_id=tc.id,
                    category=EvaluationCategory.ACCURACY,
                    verdict=Verdict.ERROR,
                    score=0.0,
                    explanation=f"Execution error: {e}",
                    metadata={"adversarial_type": adversarial_type},
                ))
        
        metrics.finalize()
        logger.info(f"Adversarial evaluation complete: {metrics.overall_pass_rate:.1%} pass rate")
        return metrics
    
    async def run_adversarial_by_type(self, adversarial_type: str) -> EvaluationMetrics:
        """
        Run adversarial tests of a specific type.
        
        Args:
            adversarial_type: Type from AdversarialCategory
            
        Returns:
            EvaluationMetrics for that adversarial type
        """
        test_cases = get_adversarial_test_cases_by_type(adversarial_type)
        logger.info(f"Running {len(test_cases)} {adversarial_type} adversarial tests...")
        
        metrics = EvaluationMetrics()
        for tc in test_cases:
            try:
                result = await self.evaluate_adversarial_test_case(tc, adversarial_type)
                metrics.add_result(result)
            except Exception as e:
                logger.error(f"Failed: {e}")
                metrics.add_result(EvaluationResult(
                    test_case_id=tc.id,
                    category=EvaluationCategory.ACCURACY,
                    verdict=Verdict.ERROR,
                    score=0.0,
                    explanation=f"Execution error: {e}",
                ))
        
        metrics.finalize()
        return metrics
    
    async def run_full_evaluation_with_adversarial(self) -> EvaluationMetrics:
        """
        Run full evaluation including adversarial tests.
        
        Returns:
            Combined EvaluationMetrics from standard and adversarial tests
        """
        logger.info("Starting full MCP Server evaluation with adversarial tests...")
        
        # Run standard tests
        standard_metrics = await self.run_full_evaluation()
        
        # Run adversarial tests
        adversarial_metrics = await self.run_adversarial_evaluation()
        
        # Merge metrics
        combined = EvaluationMetrics()
        for result in standard_metrics.results:
            combined.add_result(result)
        for result in adversarial_metrics.results:
            combined.add_result(result)
        combined.finalize()
        
        logger.info(f"Full evaluation complete: {combined.overall_pass_rate:.1%} combined pass rate")
        return combined
    
    def generate_report(
        self,
        metrics: EvaluationMetrics,
        format: str = "json"
    ) -> Path:
        """
        Generate an evaluation report.
        
        Args:
            metrics: The evaluation metrics
            format: Output format ("json", "markdown", or "html")
            
        Returns:
            Path to the generated report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "json":
            report_path = self.output_dir / f"evaluation_report_{timestamp}.json"
            with open(report_path, "w") as f:
                f.write(metrics.to_json())
        
        elif format == "markdown":
            report_path = self.output_dir / f"evaluation_report_{timestamp}.md"
            with open(report_path, "w") as f:
                f.write(self._generate_markdown_report(metrics))
        
        elif format == "html":
            report_path = self.output_dir / f"evaluation_report_{timestamp}.html"
            with open(report_path, "w") as f:
                f.write(self._generate_html_report(metrics))
        
        else:
            raise ValueError(f"Unknown format: {format}")
        
        logger.info(f"Report generated: {report_path}")
        return report_path
    
    def _generate_markdown_report(self, metrics: EvaluationMetrics) -> str:
        """Generate a Markdown report."""
        lines = [
            "# FedRAMP 20x MCP Server Evaluation Report",
            "",
            f"**Date:** {metrics.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {metrics.duration_seconds:.1f}s" if metrics.duration_seconds else "",
            "",
            "## Summary",
            "",
            f"- **Overall Score:** {metrics.overall_score:.1%}",
            f"- **Pass Rate:** {metrics.overall_pass_rate:.1%}",
            f"- **Total Tests:** {metrics.total_tests}",
            "",
            "## Results by Category",
            "",
        ]
        
        for category in EvaluationCategory:
            cat_metrics = metrics.get_category_metrics(category)
            if cat_metrics.total_tests > 0:
                lines.extend([
                    f"### {category.value.replace('_', ' ').title()}",
                    "",
                    f"- Pass Rate: {cat_metrics.pass_rate:.1%} ({cat_metrics.passed}/{cat_metrics.total_tests})",
                    f"- Average Score: {cat_metrics.average_score:.1%}",
                    f"- Avg Latency: {cat_metrics.average_latency_ms:.0f}ms" if cat_metrics.average_latency_ms else "",
                    "",
                ])
        
        failures = metrics.get_failures()
        if failures:
            lines.extend([
                "## Failures",
                "",
            ])
            for f in failures:
                lines.extend([
                    f"### {f.test_case_id}",
                    "",
                    f"- **Category:** {f.category.value}",
                    f"- **Explanation:** {f.explanation}",
                    "",
                ])
        
        return "\n".join(lines)
    
    def _generate_html_report(self, metrics: EvaluationMetrics) -> str:
        """Generate an HTML report."""
        # Simple HTML report
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>FedRAMP 20x MCP Server Evaluation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {'#28a745' if metrics.overall_score >= 0.8 else '#dc3545'}; }}
        .category {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007bff; }}
        .pass {{ color: #28a745; }}
        .fail {{ color: #dc3545; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
    </style>
</head>
<body>
    <h1>FedRAMP 20x MCP Server Evaluation Report</h1>
    <p>Generated: {metrics.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <div class="score">{metrics.overall_score:.0%}</div>
        <p>Overall Score ({metrics.total_tests} tests, {metrics.duration_seconds:.1f}s)</p>
    </div>
    
    <h2>Results by Category</h2>
"""
        
        for category in EvaluationCategory:
            cat_metrics = metrics.get_category_metrics(category)
            if cat_metrics.total_tests > 0:
                html += f"""
    <div class="category">
        <h3>{category.value.replace('_', ' ').title()}</h3>
        <p>Pass Rate: <strong class="{'pass' if cat_metrics.pass_rate >= 0.8 else 'fail'}">{cat_metrics.pass_rate:.0%}</strong> ({cat_metrics.passed}/{cat_metrics.total_tests})</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html


async def main():
    """Run evaluation from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate FedRAMP 20x MCP Server")
    parser.add_argument("--critical-only", action="store_true", help="Run only critical tests")
    parser.add_argument("--category", type=str, help="Run specific category")
    parser.add_argument("--format", type=str, default="json", choices=["json", "markdown", "html"])
    parser.add_argument("--output", type=str, help="Output directory")
    
    args = parser.parse_args()
    
    output_dir = Path(args.output) if args.output else None
    evaluator = MCPServerEvaluator(output_dir=output_dir)
    
    if args.critical_only:
        metrics = await evaluator.run_critical_evaluation()
    elif args.category:
        category = TestCaseCategory(args.category)
        metrics = await evaluator.run_category_evaluation(category)
    else:
        metrics = await evaluator.run_full_evaluation()
    
    # Print summary
    metrics.print_summary()
    
    # Generate report
    report_path = evaluator.generate_report(metrics, format=args.format)
    print(f"\nReport saved to: {report_path}")
    
    # Exit with appropriate code
    exit_code = 0 if metrics.overall_pass_rate >= 0.8 else 1
    return exit_code


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
