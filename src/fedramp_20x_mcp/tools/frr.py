"""
FedRAMP 20x MCP Server - FRR Tools

This module contains tool implementation functions for FedRAMP Requirements (FRR) analysis
against the FedRAMP Consolidated Rules for 2026 (CR26). Rule data (names, statements,
force, controls) comes from the data loader; code analysis and evidence guidance come
from the pattern library.
"""
import logging
from typing import Any, Dict, List, Optional

from ..analyzers.frr.factory import get_factory
from ..analyzers.frr.evidence_automation import (
    get_frr_evidence_automation,
    format_evidence_automation_markdown,
)
from ..analyzers.generic_adapter import analyze_with_generic_analyzer, get_generic_analyzer
from ._cr26 import (
    family_of,
    family_hint,
    legacy_resolution_note,
    rules_version,
    RETIRED_FAMILY_SUCCESSORS,
)
from .ksi import WORM_STORAGE_NOTE, _collect_artifacts

logger = logging.getLogger(__name__)


def _normalize_family(family: str) -> str:
    """Map a retired legacy family code to its CR26 successor (ADS -> CDS, etc.)."""
    fam = family.strip().upper()
    successor = RETIRED_FAMILY_SUCCESSORS.get(fam)
    if successor and " " not in successor:
        return successor
    return fam


async def _resolve_frr(frr_id: str, data_loader):
    """Load data and return (rule_record_or_None, legacy_note). Resolves legacy IDs."""
    if data_loader is not None:
        await data_loader.load_data()
    else:
        return None, ""
    note = legacy_resolution_note(data_loader, frr_id)
    rule = data_loader.get_control(frr_id)
    if not rule and note:
        entry = data_loader.resolve_legacy_id(frr_id) or {}
        for target in entry.get("current_ids", []):
            rule = data_loader.get_control(target)
            if rule:
                break
    return rule, note


def _frr_patterns(frr_id: str) -> List[Any]:
    """Patterns that reference the rule, falling back to patterns of its family."""
    try:
        loader = get_generic_analyzer().pattern_loader
        patterns = loader.get_all_patterns()
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"Pattern lookup failed: {e}")
        return []
    direct = [p for p in patterns if frr_id in (p.related_frrs or [])]
    if direct:
        return direct
    fam = family_of(frr_id)
    return [p for p in patterns if str(p.family or "").upper() == fam and fam]


def _family_pattern_count(family: str) -> int:
    try:
        patterns = get_generic_analyzer().pattern_loader.get_all_patterns()
    except Exception:
        return 0
    fam = family.upper()
    return sum(
        1 for p in patterns
        if str(p.family or "").upper() == fam
        or any(str(r).upper().startswith(fam + "-") for r in (p.related_frrs or []))
    )


def _default_frr_artifacts(data_loader) -> str:
    try:
        arts = data_loader.get_rules_metadata().get("default_artifacts", {}).get("FRR", [])
    except Exception:
        arts = []
    if not arts:
        return ""
    out = "## CR26 Default FRR Artifacts\n\n"
    for a in arts:
        out += f"- {a}\n"
    return out + "\n"


def _rule_header(rule: dict, note: str, title: str, data_loader) -> str:
    out = note + f"# {title}: {rule.get('id', '')} - {rule.get('name', '')}\n\n"
    out += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
    if rule.get("statement"):
        force = f" ({rule['force']})" if rule.get("force") else ""
        out += f"**Statement{force}:** {rule['statement']}\n\n"
    if rule.get("controls"):
        out += f"**NIST controls:** {', '.join(rule['controls'])}\n\n"
    return out


def _format_findings(findings, language: str, with_rule: bool) -> str:
    output = ""
    for i, finding in enumerate(findings, 1):
        output += f"### {i}. {finding.title}\n"
        if with_rule:
            output += f"- **Requirement:** {finding.requirement_id or finding.ksi_id}\n"
        output += f"- **Severity:** {finding.severity.value.upper()}\n"
        output += f"- **Line:** {finding.line_number}\n\n"
        output += f"{finding.description}\n\n"
        if finding.code_snippet:
            output += f"**Code:**\n```{language}\n{finding.code_snippet}\n```\n\n"
        if finding.recommendation:
            output += f"**Remediation:**\n{finding.recommendation}\n\n"
        output += "---\n\n"
    return output


async def analyze_frr_code_impl(
    frr_id: str,
    code: str,
    language: str,
    file_path: Optional[str] = None,
    data_loader: Any = None
) -> str:
    """
    Analyze code against a specific FedRAMP requirement.

    Args:
        frr_id: The FRR identifier (e.g., "VDR-CSO-DET", "SCG-CSO-RSC")
        code: The code to analyze
        language: Programming language or platform
        file_path: Optional file path for context
        data_loader: Data loader instance

    Returns:
        Analysis results with findings and recommendations
    """
    try:
        rule, note = await _resolve_frr(frr_id, data_loader)
        if data_loader is not None and not rule:
            return (f"FRR '{frr_id}' not found in FedRAMP Consolidated Rules for 2026 "
                    f"(version {rules_version(data_loader)}). Use list_frrs_by_family to see available rules."
                    + (f"\n\n{note}" if note else ""))
        resolved = rule.get("id", frr_id) if rule else frr_id
        family = family_of(resolved)

        result = await analyze_with_generic_analyzer(
            code=code, language=language, file_path=file_path or "",
            families=[family], ksi_ids=None,
        )
        findings = list(result.findings)
        direct = [f for f in findings if (f.requirement_id or "") == resolved
                  or resolved in (getattr(f, "related_frrs", None) or [])]
        shown = direct if direct else findings

        output = note + f"# FRR Analysis: {resolved}"
        if rule:
            output += f" - {rule.get('name', '')}"
        output += "\n\n"
        output += f"**File:** {file_path or 'N/A'}\n"
        output += f"**Language:** {language}\n"
        output += f"**Family:** {family}"
        if rule and rule.get("family_name"):
            output += f" ({rule['family_name']})"
        output += "\n"
        if rule and rule.get("force"):
            output += f"**Force:** {rule['force']}\n"
        if data_loader is not None:
            output += f"**Rules version:** {rules_version(data_loader)}\n"
        output += "\n"
        if rule and rule.get("statement"):
            output += f"**Statement:** {rule['statement']}\n\n"

        if shown:
            qualifier = "" if direct else " (family-level patterns; none reference this rule directly)"
            output += f"## Findings ({len(shown)} issues detected){qualifier}\n\n"
            output += _format_findings(shown, language, with_rule=not direct)
        else:
            output += "## ✅ No Issues Found\n\n"
            output += f"No {family} family patterns matched this code. Pattern checks are not an assessment of {resolved}.\n\n"
        return output

    except Exception as e:
        logger.error(f"Error analyzing code for {frr_id}: {e}", exc_info=True)
        return f"Error analyzing code for {frr_id}: {str(e)}"


async def analyze_all_frrs_impl(
    code: str,
    language: str,
    file_path: Optional[str] = None,
    data_loader: Any = None
) -> str:
    """
    Analyze code against all FedRAMP requirements that have patterns.

    Args:
        code: The code to analyze
        language: Programming language or platform
        file_path: Optional file path for context
        data_loader: Data loader instance

    Returns:
        Complete analysis results across all FRRs
    """
    try:
        factory = get_factory()
        results = await factory.analyze_all_frrs(code, language, file_path or "")
        findings = [f for r in results for f in r.findings]

        output = "# Comprehensive FRR Analysis\n\n"
        output += f"**File:** {file_path or 'N/A'}\n"
        output += f"**Language:** {language}\n"
        if data_loader is not None:
            await data_loader.load_data()
            output += f"**Rules version:** {rules_version(data_loader)}\n"
        output += "\n"

        family_findings: Dict[str, list] = {}
        for finding in findings:
            rid = finding.requirement_id or finding.ksi_id
            fam = family_of(rid) if rid else ""
            if fam:
                family_findings.setdefault(fam, []).append(finding)

        if findings:
            output += "## Summary\n\n"
            output += f"**Total Issues:** {len(findings)}\n\n"
            output += "**By Family:**\n"
            for fam in sorted(family_findings):
                output += f"- **{fam}:** {len(family_findings[fam])} issues\n"
            output += "\n"

            severity_counts: Dict[str, int] = {}
            for finding in findings:
                sev = finding.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            output += "**By Severity:**\n"
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in severity_counts:
                    output += f"- **{severity.upper()}:** {severity_counts[severity]}\n"
            output += "\n"

            output += "## Detailed Findings\n\n"
            for fam in sorted(family_findings):
                output += f"### {fam} ({len(family_findings[fam])} issues)\n\n"
                output += _format_findings(family_findings[fam], language, with_rule=True)
        else:
            output += "## ✅ No Issues Found\n\n"
            output += "No pattern matched this code. Pattern checks are not an assessment.\n\n"
        return output

    except Exception as e:
        logger.error(f"Error analyzing code for all FRRs: {e}", exc_info=True)
        return f"Error analyzing code: {str(e)}"


async def analyze_frr_family_impl(
    family: str,
    code: str,
    language: str,
    file_path: Optional[str] = None,
    data_loader: Any = None
) -> str:
    """
    Analyze code against all requirements in a specific FRR family.

    Args:
        family: CR26 FRR family code (e.g., VDR, SCG, CMU, SCN, CDS, CCM, MAS, IEC, AFC, IVV).
                Retired legacy codes (ADS, FSI, UCM, PVA, ICP, RSC) are mapped to their successors.
        code: The code to analyze
        language: Programming language or platform
        file_path: Optional file path for context
        data_loader: Data loader instance

    Returns:
        Analysis results for the specified family
    """
    try:
        requested = family
        family = _normalize_family(family)
        factory = get_factory()
        results = await factory.analyze_by_family(family, code, language, file_path or "")
        findings = [f for r in results for f in r.findings]

        rule_count = 0
        if data_loader is not None:
            await data_loader.load_data()
            rule_count = len(data_loader.get_family_controls(family))

        output = f"# {family} Family Analysis\n\n"
        if family != requested.strip().upper():
            output += f"> Legacy family `{requested.upper()}` is retired in CR26; analyzed successor `{family}`.\n\n"
        output += f"**File:** {file_path or 'N/A'}\n"
        output += f"**Language:** {language}\n"
        output += f"**FRRs in Family:** {rule_count}\n"
        if data_loader is not None:
            output += f"**Rules version:** {rules_version(data_loader)}\n"
        output += "\n"

        if findings:
            output += f"## Findings ({len(findings)} issues detected)\n\n"
            output += _format_findings(findings, language, with_rule=True)
        else:
            output += "## ✅ No Issues Found\n\n"
            output += f"No {family} patterns matched this code. Pattern checks are not an assessment.\n\n"
        return output

    except Exception as e:
        logger.error(f"Error analyzing code for {family} family: {e}", exc_info=True)
        return f"Error analyzing code for {family} family: {str(e)}"


async def list_frrs_by_family_impl(family: str, data_loader: Any = None) -> str:
    """
    List all FRR requirements in a specific family.

    Args:
        family: CR26 FRR family code (e.g., VDR, SCG, CMU, SCN, CDS, CCM, MAS, IEC, AFC, IVV)
        data_loader: Data loader instance

    Returns:
        List of FRRs in the specified family
    """
    try:
        requested = family
        family = _normalize_family(family)
        if data_loader is None:
            return "Data loader unavailable."
        await data_loader.load_data()
        rules = data_loader.get_family_controls(family)

        if not rules:
            return (f"No FRRs found for family '{requested}'. Available families: {family_hint(data_loader)}"
                    + (f". {requested.upper()} is retired in CR26; successor: {RETIRED_FAMILY_SUCCESSORS[requested.strip().upper()]}"
                       if requested.strip().upper() in RETIRED_FAMILY_SUCCESSORS else ""))

        pattern_count = _family_pattern_count(family)
        output = f"# {family} Family Requirements\n\n"
        output += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
        if family != requested.strip().upper():
            output += f"> Legacy family `{requested.upper()}` is retired in CR26; showing successor `{family}`.\n\n"
        output += f"**Total:** {len(rules)} requirements\n"
        output += f"**Code patterns for this family:** {pattern_count}\n\n"

        for rule in rules:
            force = f" [{rule['force']}]" if rule.get("force") else ""
            output += f"- **{rule.get('id')}**: {rule.get('name', '')}{force}\n"

        output += "\n*Pattern analysis runs per family (analyze_frr_family); most rules are process requirements.*\n"
        return output

    except Exception as e:
        logger.error(f"Error listing FRRs for family {family}: {e}", exc_info=True)
        return f"Error listing FRRs for family {family}: {str(e)}"


async def get_frr_metadata_impl(frr_id: str, data_loader: Any = None) -> str:
    """
    Get detailed metadata for a specific FRR.

    Args:
        frr_id: The FRR identifier (e.g., "VDR-CSO-DET")
        data_loader: Data loader instance

    Returns:
        FRR metadata: statement, force, controls, terms and pattern coverage
    """
    try:
        rule, note = await _resolve_frr(frr_id, data_loader)
        if not rule:
            return (f"FRR '{frr_id}' not found. Use list_frrs_by_family to see available FRRs."
                    + (f"\n\n{note}" if note else ""))

        output = _rule_header(rule, note, "FRR Metadata", data_loader)
        fam = rule.get("family", family_of(rule["id"]))
        output += f"**Family:** {fam} ({rule.get('family_name', 'N/A')})\n"
        output += f"**Scope:** {rule.get('scope', 'N/A')}\n"
        if rule.get("affects"):
            output += f"**Affects:** {', '.join(rule['affects'])}\n"
        if rule.get("terms"):
            output += f"**Terms:** {', '.join(rule['terms'])}\n"
        output += "\n"
        if rule.get("varies_by_level") or rule.get("varies_by_class"):
            import json
            varies = rule.get("varies_by_level") or rule.get("varies_by_class")
            output += f"**Varies by {'level' if rule.get('varies_by_level') else 'class'}:**\n```json\n{json.dumps(varies, indent=2)[:3000]}\n```\n\n"
        if rule.get("notes"):
            output += "**Notes:**\n" + "".join(f"- {n}\n" for n in rule["notes"]) + "\n"

        patterns = _frr_patterns(rule["id"])
        direct = [p for p in patterns if rule["id"] in (p.related_frrs or [])]
        output += f"**Code patterns:** {len(direct)} reference this rule directly; {_family_pattern_count(fam)} in the {fam} family\n"
        for p in direct[:10]:
            output += f"- `{p.pattern_id}`: {p.name}\n"
        return output

    except Exception as e:
        logger.error(f"Error getting metadata for {frr_id}: {e}", exc_info=True)
        return f"Error getting metadata for {frr_id}: {str(e)}"


async def get_frr_evidence_automation_impl(frr_id: str, data_loader: Any = None) -> str:
    """
    Get evidence automation recommendations for a specific FRR.

    Uses the family-level automation module when available, otherwise builds guidance from
    the CR26 rule record and matching patterns, with the CR26 default FRR artifacts as fallback.

    Args:
        frr_id: The FRR identifier (e.g., "VDR-CSO-DET")
        data_loader: Data loader instance

    Returns:
        Evidence automation recommendations in markdown
    """
    try:
        rule, note = await _resolve_frr(frr_id, data_loader)
        resolved = rule.get("id", frr_id) if rule else frr_id

        automation = get_frr_evidence_automation(resolved)
        if automation:
            body = format_evidence_automation_markdown(automation)
            head = ""
            if rule:
                head = _rule_header(rule, note, "Rule", data_loader)
            return head + body + "\n" + WORM_STORAGE_NOTE

        if data_loader is not None and not rule:
            return (f"FRR '{frr_id}' not found. Use list_frrs_by_family to see available FRRs."
                    + (f"\n\n{note}" if note else ""))

        output = _rule_header(rule, note, "Evidence Automation", data_loader) if rule else f"# Evidence Automation: {frr_id}\n\n"
        patterns = _frr_patterns(resolved)
        artifacts = _collect_artifacts(patterns)
        if artifacts:
            output += "## Evidence Artifacts\n\n"
            for a in artifacts:
                output += f"- **{a['name']}** ({a['artifact_type']}, {a['frequency']}, {a['format']}) from {a['source']}\n"
            output += "\n"
        else:
            output += "No pattern-defined evidence artifacts exist for this rule.\n\n"
            if data_loader is not None:
                output += _default_frr_artifacts(data_loader)
        output += WORM_STORAGE_NOTE
        return output

    except Exception as e:
        logger.error(f"Error getting evidence automation for {frr_id}: {e}", exc_info=True)
        return f"Error getting evidence automation for {frr_id}: {str(e)}"


async def get_frr_implementation_status_impl(data_loader: Any = None) -> str:
    """
    Get implementation status summary across all FRR families.

    Rule counts come from the loaded CR26 rules; pattern counts from the pattern library.

    Returns:
        Status summary by family
    """
    try:
        if data_loader is None:
            return "Data loader unavailable."
        await data_loader.load_data()
        fams = family_hint(data_loader).split(", ")

        output = "# FRR Implementation Status\n\n"
        output += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
        total_rules = sum(len(data_loader.get_family_controls(f)) for f in fams)
        covered = [f for f in fams if _family_pattern_count(f) > 0]
        output += "## Overall Statistics\n\n"
        output += f"- **FRR families:** {len(fams)}\n"
        output += f"- **FRR rules:** {total_rules}\n"
        output += f"- **Families with code patterns:** {len(covered)}\n"
        output += f"- **Families without code patterns (process based):** {len(fams) - len(covered)}\n\n"

        output += "## By Family\n\n"
        for fam in fams:
            rules = data_loader.get_family_controls(fam)
            count = _family_pattern_count(fam)
            icon = "✅" if count else "⏳"
            name = rules[0].get("family_name", fam) if rules else fam
            output += f"### {icon} {fam} - {name} ({len(rules)} requirements)\n"
            output += f"- Code patterns: {count}\n\n"
        return output

    except Exception as e:
        logger.error(f"Error getting implementation status: {e}", exc_info=True)
        return f"Error getting implementation status: {str(e)}"
