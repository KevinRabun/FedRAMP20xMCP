"""
KSI Coverage Audit Tools

Provides tools for understanding analyzer coverage and recommendation quality.

Coverage is derived at runtime from the loaded pattern set, intersected with the
KSIs in the loaded FedRAMP Consolidated Rules for 2026 (CR26). There are no
hardcoded KSI lists to go stale when the rules change.
"""

import logging
from typing import TYPE_CHECKING, Dict, Set

from ._cr26 import rules_version

if TYPE_CHECKING:
    from ..data_loader import FedRAMPDataLoader

logger = logging.getLogger(__name__)

# Pattern language keys grouped by the kind of artifact they analyze
INFRA_LANGUAGES = {"bicep", "terraform"}
APP_LANGUAGES = {"python", "csharp", "java", "typescript", "javascript"}


def get_pattern_coverage() -> Dict[str, Set[str]]:
    """
    Return KSI ids covered by loaded patterns, split into 'infra', 'app' and 'any'.

    Ids are read from each pattern's related_ksis (and ksi_id when present).
    Callers should intersect with the CR26 KSI ids to drop stale ids.
    """
    coverage: Dict[str, Set[str]] = {"infra": set(), "app": set(), "any": set()}
    try:
        from ..analyzers.ksi.factory import get_factory
        factory = get_factory()
        factory._ensure_analyzer()
        patterns = factory._generic_analyzer.pattern_loader._patterns.values()
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"Pattern coverage unavailable: {e}")
        return coverage

    for pattern in patterns:
        ids = set()
        pid = getattr(pattern, "ksi_id", None)
        if isinstance(pid, str) and pid.startswith("KSI-"):
            ids.add(pid)
        for rid in getattr(pattern, "related_ksis", None) or []:
            if isinstance(rid, str) and rid.startswith("KSI-"):
                ids.add(rid)
        if not ids:
            continue
        langs = {str(k).lower() for k in (getattr(pattern, "languages", None) or {}).keys()}
        coverage["any"] |= ids
        if langs & INFRA_LANGUAGES:
            coverage["infra"] |= ids
        if langs & APP_LANGUAGES:
            coverage["app"] |= ids
    return coverage


def _cr26_coverage(ksi_ids: Set[str]) -> Dict[str, Set[str]]:
    raw = get_pattern_coverage()
    return {k: v & ksi_ids for k, v in raw.items()}


def _pct(part: int, whole: int) -> float:
    return (part / whole * 100) if whole else 0.0


async def get_ksi_coverage_summary_impl(data_loader: "FedRAMPDataLoader") -> str:
    """Get a summary of KSI analyzer coverage and recommendation quality."""
    data = await data_loader.load_data()
    ksi_data = data.get('ksi', {})
    ksi_ids = set(ksi_data.keys())
    total_ksis = len(ksi_ids)

    cov = _cr26_coverage(ksi_ids)
    infra, app, covered = cov["infra"], cov["app"], cov["any"]
    uncovered = ksi_ids - covered

    result = "# FedRAMP 20x KSI Coverage Summary\n\n"
    result += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
    result += "## Quick Stats\n\n"
    result += f"- **Total KSIs:** {total_ksis}\n"
    result += f"- **Infrastructure Coverage (Bicep/Terraform patterns):** {len(infra)} KSIs ({_pct(len(infra), total_ksis):.1f}%)\n"
    result += f"- **Application Coverage (Python/C#/Java/TypeScript patterns):** {len(app)} KSIs ({_pct(len(app), total_ksis):.1f}%)\n"
    result += f"- **Unique KSIs With Any Code Pattern:** {len(covered)} KSIs ({_pct(len(covered), total_ksis):.1f}%)\n"
    result += f"- **KSIs Without Code Patterns (process or evidence based):** {len(uncovered)} KSIs\n\n"

    result += "## What We CAN Attest To ✅\n\n"
    result += "- Recommendations follow Azure Well-Architected Framework principles\n"
    result += "- Code patterns detect common security misconfigurations\n"
    result += "- Infrastructure templates use Azure best practices\n"
    result += "- Recommendations cite specific Azure services and documentation\n\n"

    result += "## What We CANNOT Attest To ❌\n\n"
    result += "- Recommendations have NOT been validated by FedRAMP assessors\n"
    result += "- Code has NOT been tested against real certification packages\n"
    result += "- No production validation in FedRAMP-certified environments\n"
    result += "- No external security expert review\n"
    result += "- Framework-specific edge cases may not be covered\n"
    result += f"- Only {_pct(len(infra), total_ksis):.0f}% of KSIs have infrastructure pattern coverage\n"
    result += f"- Only {_pct(len(app), total_ksis):.0f}% of KSIs have application code pattern coverage\n\n"

    result += "## ⚠️ IMPORTANT DISCLAIMER\n\n"
    result += "**This MCP server should be treated as:**\n\n"
    result += "- ✅ A helpful development-time guardrail\n"
    result += "- ✅ A starting point for FedRAMP compliance\n"
    result += "- ✅ An educational tool for understanding KSI requirements\n\n"
    result += "**This MCP server is NOT:**\n\n"
    result += "- ❌ A substitute for independent assessment\n"
    result += "- ❌ A guarantee of FedRAMP certification\n"
    result += "- ❌ A replacement for security expert review\n\n"

    result += f"## KSIs Without Code Patterns ({len(uncovered)})\n\n"
    if uncovered:
        for ksi_id in sorted(uncovered):
            ksi_info = ksi_data.get(ksi_id, {})
            title = ksi_info.get('title', ksi_info.get('name', 'No title'))
            result += f"- **{ksi_id}**: {title}\n"

    result += "\n---\n"
    result += "*Coverage is computed from the loaded pattern files and the loaded CR26 KSI list.*\n"

    return result


async def get_ksi_coverage_status_impl(ksi_id: str, data_loader: "FedRAMPDataLoader") -> str:
    """Check if a specific KSI has analyzer coverage and what the limitations are."""
    data = await data_loader.load_data()
    ksi_data = data.get('ksi', {})

    requested = ksi_id
    ksi = data_loader.get_ksi(ksi_id)
    if ksi:
        ksi_id = ksi.get('id', ksi_id)
    if ksi_id not in ksi_data:
        return (f"❌ Error: KSI '{requested}' not found in the FedRAMP Consolidated Rules for 2026 "
                f"(version {rules_version(data_loader)})")

    ksi_info = ksi_data[ksi_id]
    title = ksi_info.get('title', ksi_info.get('name', 'No title'))

    cov = _cr26_coverage(set(ksi_data.keys()))
    in_infra = ksi_id in cov["infra"]
    in_app = ksi_id in cov["app"]
    has_any = ksi_id in cov["any"]

    result = f"# Coverage Status: {ksi_id}\n\n"
    if requested.upper() != ksi_id.upper():
        result += f"> Requested `{requested}` resolved to `{ksi_id}`.\n\n"
    result += f"**Title:** {title}\n\n"
    result += f"*Rules version: {rules_version(data_loader)}*\n\n"

    result += "## Analyzer Coverage\n\n"
    result += f"- **Infrastructure as Code (Bicep/Terraform):** {'✅ Covered' if in_infra else '❌ Not covered'}\n"
    result += f"- **Application code (Python/C#/Java/TypeScript):** {'✅ Covered' if in_app else '❌ Not covered'}\n\n"

    if in_infra and in_app:
        result += "## Status: ✅ Full Coverage\n\n"
        result += "This KSI has both infrastructure and application code pattern coverage.\n\n"
    elif in_infra:
        result += "## Status: 🟡 Partial Coverage (IaC Only)\n\n"
        result += "This KSI has infrastructure pattern coverage but lacks application code checks.\n"
        result += "Application-level implementations of this KSI will not be validated.\n\n"
    elif in_app:
        result += "## Status: 🟡 Partial Coverage (Application Only)\n\n"
        result += "This KSI has application code pattern coverage but lacks infrastructure checks.\n"
        result += "Infrastructure-level implementations of this KSI will not be validated.\n\n"
    elif has_any:
        result += "## Status: 🟡 Partial Coverage (Other Artifact Types)\n\n"
        result += "This KSI has patterns for other artifact types (for example CI/CD pipelines) only.\n\n"
    else:
        result += "## Status: ⚪ No Code Pattern Coverage\n\n"
        result += "No code patterns exist for this KSI. It is process or evidence based and needs\n"
        result += "documented procedures or collected evidence rather than code scanning.\n\n"

    result += "## ⚠️ Important Limitations\n\n"
    result += "Even with analyzer coverage, please note:\n\n"
    result += "1. **Not Assessor Validated**: Analyzer rules have not been reviewed by FedRAMP assessors\n"
    result += "2. **Best Effort**: Recommendations are based on Azure best practices, not certification packages\n"
    result += "3. **May Miss Edge Cases**: Framework-specific or complex scenarios may not be detected\n"
    result += "4. **No Guarantee**: Passing analyzer checks does NOT guarantee FedRAMP compliance\n\n"

    result += "**Always consult an independent assessor for authoritative guidance.**\n"

    return result


def get_coverage_disclaimer() -> str:
    """Get a standard disclaimer about analyzer coverage limitations."""
    return (
        "\n\n---\n\n"
        "⚠️ **Analyzer Coverage Disclaimer**: This recommendation is based on Azure best practices "
        "and has NOT been validated by FedRAMP assessors. Analyzer coverage varies by KSI "
        "(use `get_ksi_coverage_summary` for current percentages). Always consult an independent "
        "assessor for authoritative guidance. "
        "Use `get_ksi_coverage_status` to check coverage for specific KSIs."
    )
