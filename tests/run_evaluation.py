#!/usr/bin/env python3
"""
Run MCP Server Evaluation

Quick script to run the evaluator from the command line.

Usage:
    python tests/run_evaluation.py                    # Full evaluation
    python tests/run_evaluation.py --critical-only   # Critical tests only
    python tests/run_evaluation.py --category accuracy  # Specific category
"""

import asyncio
import sys
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.dirname(__file__))

from evaluator import MCPServerEvaluator
from evaluator.test_cases import TestCaseCategory


async def main():
    """Run evaluation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate FedRAMP 20x MCP Server")
    parser.add_argument("--critical-only", action="store_true", help="Run only critical tests")
    parser.add_argument("--category", type=str, 
                       choices=["accuracy", "completeness", "analysis_quality", "relevance", "consistency"],
                       help="Run specific category")
    parser.add_argument("--format", type=str, default="json", 
                       choices=["json", "markdown", "html"],
                       help="Report format")
    parser.add_argument("--consistency-iterations", type=int, default=3,
                       help="Number of iterations for consistency check")
    
    args = parser.parse_args()
    
    evaluator = MCPServerEvaluator()
    
    print("=" * 60)
    print("FedRAMP 20x MCP Server Evaluator")
    print("=" * 60)
    print()
    
    if args.critical_only:
        print("Running critical tests only...")
        metrics = await evaluator.run_critical_evaluation()
    elif args.category:
        print(f"Running {args.category} tests...")
        category = TestCaseCategory(args.category)
        metrics = await evaluator.run_category_evaluation(category)
    else:
        print("Running full evaluation...")
        metrics = await evaluator.run_full_evaluation()
    
    # Print summary
    metrics.print_summary()
    
    # Generate report
    report_path = evaluator.generate_report(metrics, format=args.format)
    print(f"\nReport saved to: {report_path}")
    
    # Return exit code based on pass rate
    if metrics.overall_pass_rate >= 0.9:
        print("\n[PASS] EVALUATION PASSED")
        return 0
    elif metrics.overall_pass_rate >= 0.7:
        print("\n[WARN] EVALUATION PARTIAL PASS")
        return 0
    else:
        print("\n[FAIL] EVALUATION FAILED")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
