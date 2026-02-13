"""
Tests for ApplicationContext and context-aware analysis filtering.

Verifies that:
1. ApplicationContext profiles correctly set capabilities
2. Suppressed tags and families are computed correctly
3. Pattern filtering works based on context
4. CLI tool profile suppresses IAM, HTTP, database, PII, and network findings
5. Web app profile allows all findings through
6. from_string() correctly maps profile names
7. Integration with analyzer pipeline
"""

import asyncio
import sys
import os

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.application_context import (
    ApplicationContext,
    CAPABILITY_TAG_MAP,
    CAPABILITY_FAMILY_MAP,
)


def test_cli_tool_profile():
    """CLI tool profile should disable auth, HTTP, DB, PII, network."""
    ctx = ApplicationContext.cli_tool()
    
    assert ctx.has_authentication is False
    assert ctx.has_http_server is False
    assert ctx.has_database is False
    assert ctx.has_pii is False
    assert ctx.has_network_calls is False
    assert ctx.has_secrets is False
    assert ctx.has_containers is False
    assert ctx.has_ci_cd is False
    
    print("[OK] test_cli_tool_profile")


def test_web_app_profile():
    """Web app profile should enable auth, HTTP, DB, PII, network."""
    ctx = ApplicationContext.web_app()
    
    assert ctx.has_authentication is True
    assert ctx.has_http_server is True
    assert ctx.has_database is True
    assert ctx.has_pii is True
    assert ctx.has_network_calls is True
    assert ctx.has_secrets is True
    
    print("[OK] test_web_app_profile")


def test_full_profile_no_filtering():
    """Full profile should not suppress anything."""
    ctx = ApplicationContext.full()
    
    suppressed_tags = ctx.get_suppressed_tags()
    suppressed_families = ctx.get_suppressed_families()
    
    assert len(suppressed_tags) == 0, f"Full profile should suppress no tags, got {suppressed_tags}"
    assert len(suppressed_families) == 0, f"Full profile should suppress no families, got {suppressed_families}"
    
    print("[OK] test_full_profile_no_filtering")


def test_cli_tool_suppressed_tags():
    """CLI tool should suppress auth, HTTP, database, PII, and network tags."""
    ctx = ApplicationContext.cli_tool()
    
    suppressed = ctx.get_suppressed_tags()
    
    # Should contain auth-related tags
    assert "mfa" in suppressed
    assert "authentication" in suppressed
    assert "rbac" in suppressed
    
    # Should contain HTTP-related tags
    assert "hsts" in suppressed
    assert "tls" in suppressed
    assert "cors" in suppressed
    
    # Should contain database-related tags
    assert "database" in suppressed
    assert "data_deletion" in suppressed
    
    # Should contain PII-related tags
    assert "pii" in suppressed
    assert "personal_data" in suppressed
    
    # Should contain network-related tags
    assert "network" in suppressed
    assert "cross_border" in suppressed
    
    print("[OK] test_cli_tool_suppressed_tags")


def test_cli_tool_suppressed_families():
    """CLI tool should suppress IAM and CNA families."""
    ctx = ApplicationContext.cli_tool()
    
    suppressed = ctx.get_suppressed_families()
    
    assert "IAM" in suppressed, f"IAM should be suppressed for CLI tool, got {suppressed}"
    assert "CNA" in suppressed, f"CNA should be suppressed for CLI tool, got {suppressed}"
    
    print("[OK] test_cli_tool_suppressed_families")


def test_should_include_pattern_iam():
    """CLI tool context should exclude IAM patterns."""
    ctx = ApplicationContext.cli_tool()
    
    # IAM pattern with auth tags
    assert ctx.should_include_pattern(["mfa", "fido2", "authentication"], "IAM") is False
    
    # Generic pattern without auth tags in a non-suppressed family
    assert ctx.should_include_pattern(["logging", "monitoring"], "MLA") is True
    
    print("[OK] test_should_include_pattern_iam")


def test_should_include_pattern_http():
    """CLI tool context should exclude HSTS/TLS patterns."""
    ctx = ApplicationContext.cli_tool()
    
    assert ctx.should_include_pattern(["hsts", "security_headers"], "SVC") is False
    assert ctx.should_include_pattern(["tls", "https"], "SVC") is False
    
    print("[OK] test_should_include_pattern_http")


def test_should_include_pattern_database():
    """CLI tool context should exclude database patterns."""
    ctx = ApplicationContext.cli_tool()
    
    assert ctx.should_include_pattern(["database", "sql"], "RSC") is False
    assert ctx.should_include_pattern(["data_retention", "backup"], "RSC") is False
    
    print("[OK] test_should_include_pattern_database")


def test_should_include_pattern_pii():
    """CLI tool context should exclude PII patterns."""
    ctx = ApplicationContext.cli_tool()
    
    assert ctx.should_include_pattern(["pii", "data_protection"], "ADS") is False
    assert ctx.should_include_pattern(["gdpr", "privacy"], "ADS") is False
    
    print("[OK] test_should_include_pattern_pii")


def test_should_include_pattern_network():
    """CLI tool context should exclude network patterns."""
    ctx = ApplicationContext.cli_tool()
    
    assert ctx.should_include_pattern(["network", "firewall"], "CNA") is False
    assert ctx.should_include_pattern(["cross_border", "api_gateway"], "CNA") is False
    
    print("[OK] test_should_include_pattern_network")


def test_web_app_includes_everything():
    """Web app context should include all patterns."""
    ctx = ApplicationContext.web_app()
    
    assert ctx.should_include_pattern(["mfa", "authentication"], "IAM") is True
    assert ctx.should_include_pattern(["hsts", "tls"], "SVC") is True
    assert ctx.should_include_pattern(["database", "sql"], "RSC") is True
    assert ctx.should_include_pattern(["pii", "data_protection"], "ADS") is True
    assert ctx.should_include_pattern(["network", "firewall"], "CNA") is True
    
    print("[OK] test_web_app_includes_everything")


def test_from_string_profiles():
    """from_string should map all profile names correctly."""
    # CLI variants
    ctx = ApplicationContext.from_string("cli-tool")
    assert ctx.has_authentication is False
    
    ctx = ApplicationContext.from_string("cli")
    assert ctx.has_authentication is False
    
    # MCP server variants
    ctx = ApplicationContext.from_string("mcp-server")
    assert ctx.has_http_server is False
    
    ctx = ApplicationContext.from_string("mcp")
    assert ctx.has_http_server is False
    
    # Web app variants
    ctx = ApplicationContext.from_string("web-app")
    assert ctx.has_authentication is True
    assert ctx.has_http_server is True
    
    ctx = ApplicationContext.from_string("web")
    assert ctx.has_authentication is True
    
    # API service
    ctx = ApplicationContext.from_string("api-service")
    assert ctx.has_authentication is True
    assert ctx.has_http_server is True
    
    ctx = ApplicationContext.from_string("api")
    assert ctx.has_authentication is True
    
    # IaC only
    ctx = ApplicationContext.from_string("iac-only")
    assert ctx.has_pii is False
    
    # Library
    ctx = ApplicationContext.from_string("library")
    assert ctx.has_authentication is False
    
    # Batch job
    ctx = ApplicationContext.from_string("batch-job")
    assert ctx.has_http_server is False
    assert ctx.has_database is True
    
    # Full
    ctx = ApplicationContext.from_string("full")
    assert ctx.has_authentication is None
    
    # Unknown defaults to full
    ctx = ApplicationContext.from_string("unknown-thing")
    assert ctx.has_authentication is None
    
    print("[OK] test_from_string_profiles")


def test_from_dict_roundtrip():
    """from_dict should reconstruct context from to_dict output."""
    original = ApplicationContext.cli_tool()
    data = original.to_dict()
    restored = ApplicationContext.from_dict(data)
    
    assert restored.has_authentication == original.has_authentication
    assert restored.has_http_server == original.has_http_server
    assert restored.has_database == original.has_database
    assert restored.has_pii == original.has_pii
    assert restored.has_network_calls == original.has_network_calls
    assert restored.description == original.description
    
    print("[OK] test_from_dict_roundtrip")


def test_excluded_tags_and_families():
    """Explicit excluded_tags and excluded_families should be respected."""
    ctx = ApplicationContext(
        excluded_families={"VDR", "MLA"},
        excluded_tags={"custom_tag", "another_tag"},
    )
    
    suppressed_families = ctx.get_suppressed_families()
    assert "VDR" in suppressed_families
    assert "MLA" in suppressed_families
    
    suppressed_tags = ctx.get_suppressed_tags()
    assert "custom_tag" in suppressed_tags
    assert "another_tag" in suppressed_tags
    
    # Pattern in excluded family should be filtered
    assert ctx.should_include_pattern(["logging"], "VDR") is False
    
    # Pattern with excluded tag should be filtered
    assert ctx.should_include_pattern(["custom_tag"], "IAM") is False
    
    # Non-excluded pattern should pass
    assert ctx.should_include_pattern(["encryption"], "SVC") is True
    
    print("[OK] test_excluded_tags_and_families")


def test_none_capabilities_allow_everything():
    """None (unknown) capabilities should not suppress anything."""
    ctx = ApplicationContext()  # All None
    
    assert len(ctx.get_suppressed_tags()) == 0
    assert len(ctx.get_suppressed_families()) == 0
    assert ctx.should_include_pattern(["mfa", "authentication"], "IAM") is True
    assert ctx.should_include_pattern(["hsts", "tls"], "SVC") is True
    
    print("[OK] test_none_capabilities_allow_everything")


def test_partial_capabilities():
    """Only explicitly False capabilities should suppress findings."""
    ctx = ApplicationContext(
        has_authentication=False,
        has_http_server=True,
        has_database=None,  # Unknown — should not suppress
    )
    
    # Auth should be suppressed
    assert ctx.should_include_pattern(["mfa"], "IAM") is False
    
    # HTTP should NOT be suppressed (explicitly True)
    assert ctx.should_include_pattern(["hsts", "tls"], "SVC") is True
    
    # Database should NOT be suppressed (None = unknown)
    assert ctx.should_include_pattern(["database"], "RSC") is True
    
    print("[OK] test_partial_capabilities")


def test_mcp_server_profile():
    """MCP server profile should match CLI tool in most respects."""
    ctx = ApplicationContext.mcp_server()
    
    assert ctx.has_authentication is False
    assert ctx.has_http_server is False
    assert ctx.has_database is False
    assert ctx.has_pii is False
    assert ctx.has_network_calls is False
    
    # Should suppress IAM patterns
    assert ctx.should_include_pattern(["mfa", "authentication"], "IAM") is False
    
    # Should suppress HSTS patterns
    assert ctx.should_include_pattern(["hsts", "security_headers"], "SVC") is False
    
    print("[OK] test_mcp_server_profile")


def test_to_dict_contains_computed_fields():
    """to_dict should include suppressed_tags and suppressed_families."""
    ctx = ApplicationContext.cli_tool()
    data = ctx.to_dict()
    
    assert "suppressed_tags" in data
    assert "suppressed_families" in data
    assert "mfa" in data["suppressed_tags"]
    assert "IAM" in data["suppressed_families"]
    assert "application_context" not in data  # No nesting
    
    print("[OK] test_to_dict_contains_computed_fields")


def test_case_insensitive_tag_matching():
    """Tag matching should be case-insensitive."""
    ctx = ApplicationContext(has_authentication=False)
    
    # Tags in different cases should still be suppressed
    assert ctx.should_include_pattern(["MFA"], "SVC") is False
    assert ctx.should_include_pattern(["Authentication"], "SVC") is False
    assert ctx.should_include_pattern(["RBAC"], "SVC") is False
    
    print("[OK] test_case_insensitive_tag_matching")


# ---- Integration test with GenericPatternAnalyzer ----

def test_generic_analyzer_with_context():
    """GenericPatternAnalyzer should filter patterns when context is provided."""
    from fedramp_20x_mcp.analyzers.generic_analyzer import GenericPatternAnalyzer
    
    analyzer = GenericPatternAnalyzer()
    
    # Sample Python code with FIDO2 import (triggers IAM patterns)
    code = "import fido2\nfrom fido2 import server\n"
    
    # Without context — should find IAM-related findings
    result_no_ctx = analyzer.analyze(code, "python", "test.py")
    iam_findings_no_ctx = [f for f in result_no_ctx.findings if "IAM" in (f.requirement_id or "")]
    
    # With CLI tool context — should suppress IAM findings
    ctx = ApplicationContext.cli_tool()
    result_with_ctx = analyzer.analyze(code, "python", "test.py", application_context=ctx)
    iam_findings_with_ctx = [f for f in result_with_ctx.findings if "IAM" in (f.requirement_id or "")]
    
    # CLI tool should have fewer or no IAM findings
    assert len(iam_findings_with_ctx) <= len(iam_findings_no_ctx), \
        f"CLI context should suppress IAM findings: {len(iam_findings_with_ctx)} vs {len(iam_findings_no_ctx)}"
    
    print(f"[OK] test_generic_analyzer_with_context (no_ctx={len(iam_findings_no_ctx)}, cli={len(iam_findings_with_ctx)})")


def test_generic_analyzer_web_app_no_suppression():
    """Web app context should not suppress IAM findings."""
    from fedramp_20x_mcp.analyzers.generic_analyzer import GenericPatternAnalyzer
    
    analyzer = GenericPatternAnalyzer()
    code = "import fido2\nfrom fido2 import server\n"
    
    result_no_ctx = analyzer.analyze(code, "python", "test.py")
    
    ctx = ApplicationContext.web_app()
    result_web = analyzer.analyze(code, "python", "test.py", application_context=ctx)
    
    # Web app should keep all findings
    assert len(result_web.findings) == len(result_no_ctx.findings), \
        f"Web app context should not suppress findings: {len(result_web.findings)} vs {len(result_no_ctx.findings)}"
    
    print("[OK] test_generic_analyzer_web_app_no_suppression")


# ---- Run all tests ----

def run_all():
    """Run all application context tests."""
    tests = [
        test_cli_tool_profile,
        test_web_app_profile,
        test_full_profile_no_filtering,
        test_cli_tool_suppressed_tags,
        test_cli_tool_suppressed_families,
        test_should_include_pattern_iam,
        test_should_include_pattern_http,
        test_should_include_pattern_database,
        test_should_include_pattern_pii,
        test_should_include_pattern_network,
        test_web_app_includes_everything,
        test_from_string_profiles,
        test_from_dict_roundtrip,
        test_excluded_tags_and_families,
        test_none_capabilities_allow_everything,
        test_partial_capabilities,
        test_mcp_server_profile,
        test_to_dict_contains_computed_fields,
        test_case_insensitive_tag_matching,
        test_generic_analyzer_with_context,
        test_generic_analyzer_web_app_no_suppression,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {test_func.__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Application Context Tests: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*60}")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
