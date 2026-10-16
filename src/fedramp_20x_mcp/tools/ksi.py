"""
FedRAMP 20x MCP Server - Ksi Tools

This module contains tool implementation functions for ksi.
"""
import json
import logging
from typing import Any
from ..analyzers.ksi.factory import get_factory
from ._cr26 import legacy_resolution_note, rules_version
from .ksi_status import build_ksi_rows

logger = logging.getLogger(__name__)

async def get_ksi_impl(ksi_id: str, data_loader) -> str:
    """
    Get detailed information about a specific Key Security Indicator.

    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-APM")

    Returns:
        Detailed KSI information
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Explain legacy IDs (crosswalk basis and confidence)
        note = legacy_resolution_note(data_loader, ksi_id)

        # Get the KSI
        ksi = data_loader.get_ksi(ksi_id)

        if not ksi and note:
            entry = data_loader.resolve_legacy_id(ksi_id) or {}
            for target in entry.get("current_ids", []):
                ksi = data_loader.get_ksi(target)
                if ksi:
                    break

        if not ksi:
            return (f"Key Security Indicator {ksi_id} not found in FedRAMP Consolidated Rules for 2026 "
                    f"(version {rules_version(data_loader)}). Use list_ksi() to see all available indicators."
                    + (f"\n\n{note}" if note else ""))

        resolved = ksi.get("id", ksi_id)
        if not note and resolved.upper() != ksi_id.upper():
            note = f"> Requested `{ksi_id}` resolved to `{resolved}` (formerly-known-as match).\n\n"

        # Format the KSI information
        result = note
        result += f"# Key Security Indicator: {ksi.get('id', ksi_id)}\n\n"
        
        # Add all KSI fields
        for key, value in ksi.items():
            if key not in ["id", "document", "document_name", "section"]:
                result += f"**{key.replace('_', ' ').title()}:**\n"
                if isinstance(value, (dict, list)):
                    result += f"```json\n{json.dumps(value, indent=2)}\n```\n\n"
                else:
                    result += f"{value}\n\n"
        
        # Add context
        result += f"**Document:** {ksi.get('document_name') or ksi.get('document', 'Unknown')}\n"
        result += f"\n*Rules version: {rules_version(data_loader)}*\n"

        return result

    except Exception as e:
        logger.error(f"Error fetching KSI {ksi_id}: {e}")
        return f"Error retrieving KSI {ksi_id}: {str(e)}"



async def list_ksi_impl(data_loader) -> str:
    """
    List all Key Security Indicators with their implementation status.

    Returns:
        Complete list of all Key Security Indicators with status
    """
    try:
        # Get all KSI rows (CR26 rules data plus pattern coverage)
        await data_loader.load_data()
        ksis = await build_ksi_rows(data_loader)

        if not ksis:
            return "No Key Security Indicators found."

        # Group by family
        families = {}
        for ksi in ksis:
            family = ksi.get('family', 'UNKNOWN')
            if family not in families:
                families[family] = []
            families[family].append(ksi)

        # Format the results
        result = f"# Key Security Indicators\n\n"
        result += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
        result += f"**Total:** {len(ksis)} KSIs in {len(families)} families\n\n"

        # Count by status
        implemented = sum(1 for k in ksis if k.get('implementation_status') == 'IMPLEMENTED')
        not_implemented = sum(1 for k in ksis if k.get('implementation_status') == 'NOT_IMPLEMENTED')
        retired = sum(1 for k in ksis if k.get('retired', False))
        code_detectable = sum(1 for k in ksis if k.get('code_detectable', False) and not k.get('retired', False))
        active = len(ksis) - retired
        
        result += f"**Status Summary:**\n"
        result += f"- ✅ Implemented: {implemented}\n"
        result += f"- ⏳ Not Implemented: {not_implemented}\n"
        result += f"- 🔄 Retired: {retired}\n"
        result += f"- 💻 Code-Detectable: {code_detectable}\n"
        result += f"- 📄 Process-Based: {active - code_detectable}\n\n"
        
        # List by family
        for family in sorted(families.keys()):
            family_ksis = families[family]
            family_name = family_ksis[0].get('family_name', family)
            result += f"## {family} - {family_name} ({len(family_ksis)} KSIs)\n\n"
            
            for ksi in family_ksis:
                ksi_id = ksi.get('id')
                ksi_name = ksi.get('name', ksi_id)
                status = ksi.get('implementation_status', 'NOT_IMPLEMENTED')
                is_retired = ksi.get('retired', False)
                is_code_detectable = ksi.get('code_detectable', False)
                
                status_icon = "✅" if status == "IMPLEMENTED" else "⏳"
                if is_retired:
                    status_icon = "🔄"
                
                code_icon = "💻" if is_code_detectable else "📄"
                
                result += f"- {status_icon} {code_icon} **{ksi_id}**: {ksi_name}"
                
                if is_retired:
                    result += " (RETIRED)"
                elif not is_code_detectable:
                    result += " (Process/Documentation)"
                    
                result += "\n"
            
            result += "\n"
        
        result += "\n*Legend:*\n"
        result += "- ✅ = Implemented\n"
        result += "- ⏳ = Not Implemented\n"
        result += "- 🔄 = Retired\n"
        result += "- 💻 = Code-Detectable\n"
        result += "- 📄 = Process-Based\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing KSI: {e}")
        return f"Error listing KSIs: {str(e)}"


async def get_ksi_implementation_summary_impl(data_loader) -> str:
    """
    Get a summary of KSI implementation status across all families.

    Returns:
        Summary statistics and breakdown by family
    """
    try:
        # Get all KSI rows (CR26 rules data plus pattern coverage)
        await data_loader.load_data()
        ksis = await build_ksi_rows(data_loader)

        if not ksis:
            return "No Key Security Indicators found."

        # Calculate statistics
        total_ksis = len(ksis)
        active_ksis = sum(1 for k in ksis if not k.get('retired', False))
        implemented = sum(1 for k in ksis if k.get('implementation_status') == 'IMPLEMENTED' and not k.get('retired', False))
        code_detectable = sum(1 for k in ksis if k.get('code_detectable', False) and not k.get('retired', False))
        process_based = active_ksis - code_detectable
        retired = total_ksis - active_ksis
        
        # Calculate coverage
        if code_detectable > 0:
            coverage_pct = (implemented / code_detectable) * 100
        else:
            coverage_pct = 0
        
        # Group by family
        families = {}
        for ksi in ksis:
            ksi_id = ksi.get('id')
            family = ksi.get('family', 'UNKNOWN')
            if family not in families:
                families[family] = {
                    "name": ksi.get('family_name', family),
                    "total": 0,
                    "implemented": 0,
                    "code_detectable": 0,
                    "retired": 0
                }
            
            families[family]["total"] += 1
            if ksi.get('implementation_status') == "IMPLEMENTED" and not ksi.get('retired', False):
                families[family]["implemented"] += 1
            if ksi.get('code_detectable', False) and not ksi.get('retired', False):
                families[family]["code_detectable"] += 1
            if ksi.get('retired', False):
                families[family]["retired"] += 1
        
        # Format the results
        result = "# KSI Implementation Summary\n\n"
        result += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
        result += f"## Overall Status\n\n"
        result += f"- **Total KSIs:** {total_ksis}\n"
        result += f"- **Active KSIs:** {active_ksis} ({retired} retired)\n"
        result += f"- **Implemented:** {implemented}/{code_detectable} code-detectable KSIs ({coverage_pct:.1f}%)\n"
        result += f"- **Code-Detectable:** {code_detectable} KSIs\n"
        result += f"- **Process-Based:** {process_based} KSIs\n\n"
        
        result += f"## By Family\n\n"
        
        for family in sorted(families.keys()):
            stats = families[family]
            family_active = stats["total"] - stats["retired"]
            
            if stats["code_detectable"] > 0:
                family_pct = (stats["implemented"] / stats["code_detectable"]) * 100
            else:
                family_pct = 0
            
            status_icon = "✅" if stats["implemented"] == stats["code_detectable"] and stats["code_detectable"] > 0 else "⏳"
            
            result += f"### {status_icon} {family} - {stats['name']}\n"
            result += f"- Total: {stats['total']} KSIs"
            if stats["retired"] > 0:
                result += f" ({stats['retired']} retired)"
            result += "\n"
            result += f"- Implemented: {stats['implemented']}/{stats['code_detectable']} code-detectable"
            if stats["code_detectable"] > 0:
                result += f" ({family_pct:.0f}%)"
            result += "\n"
            result += f"- Process-based: {family_active - stats['code_detectable']} KSIs\n\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting implementation summary: {e}")
        return f"Error getting implementation summary: {str(e)}"


WORM_STORAGE_NOTE = (
    "## Evidence Storage (WORM conventions)\n\n"
    "- Authenticate with Microsoft Entra ID only (disable shared key and SAS access).\n"
    "- Use container-level time-based immutability (WORM); never overwrite or delete evidence.\n"
    "- Layout: `<container>/<report>/<yyyy-MM-dd>/<runId>/` containing the evidence files plus "
    "`run.json` and `sha256-manifest.txt`.\n"
    "- CR26 defines no numeric evidence retention period; set immutability duration per your policy "
    "and agency agreements.\n\n"
)


def _patterns_for_ksi(ksi_id: str) -> list:
    """Return the loaded pattern objects whose related_ksis include ksi_id."""
    try:
        from ..analyzers.generic_adapter import get_generic_analyzer
        loader = get_generic_analyzer().pattern_loader
        return [p for p in loader.get_all_patterns() if ksi_id in (p.related_ksis or [])]
    except Exception as e:  # pragma: no cover - defensive
        logger.warning(f"Pattern lookup failed for {ksi_id}: {e}")
        return []


async def _resolve_ksi(ksi_id: str, data_loader):
    """Load data, resolve legacy IDs, and return (ksi_record_or_None, note)."""
    await data_loader.load_data()
    note = legacy_resolution_note(data_loader, ksi_id)
    ksi = data_loader.get_ksi(ksi_id)
    if not ksi and note:
        entry = data_loader.resolve_legacy_id(ksi_id) or {}
        for target in entry.get("current_ids", []):
            ksi = data_loader.get_ksi(target)
            if ksi:
                break
    return ksi, note


def _ksi_header(ksi: dict, note: str, title: str, data_loader) -> str:
    out = note + f"# {title}: {ksi['id']} - {ksi.get('name', '')}\n\n"
    out += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
    if ksi.get("statement"):
        out += f"**KSI statement:** {ksi['statement']}\n\n"
    if ksi.get("controls"):
        out += f"**NIST controls:** {', '.join(ksi['controls'])}\n\n"
    return out


def _default_artifacts_section(data_loader) -> str:
    try:
        arts = data_loader.get_rules_metadata().get("default_artifacts", {}).get("KSI", [])
    except Exception:
        arts = []
    if not arts:
        return ""
    out = "## CR26 Default KSI Artifacts\n\n"
    for a in arts:
        out += f"- {a}\n"
    return out + "\n"


def _not_found(ksi_id: str, data_loader, note: str) -> str:
    return (f"KSI '{ksi_id}' not found in FedRAMP Consolidated Rules for 2026 "
            f"(version {rules_version(data_loader)}). Use list_ksi to see all available KSIs."
            + (f"\n\n{note}" if note else ""))


async def get_ksi_evidence_automation_impl(ksi_id: str, data_loader) -> str:
    """
    Get evidence automation recommendations for a specific KSI.

    Built from the CR26 KSI record plus the pattern library entries that
    reference the KSI (recommended services, automation, evidence artifacts).

    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-APM")

    Returns:
        Evidence automation recommendations in markdown
    """
    try:
        ksi, note = await _resolve_ksi(ksi_id, data_loader)
        if not ksi:
            return _not_found(ksi_id, data_loader, note)

        result = _ksi_header(ksi, note, "Evidence Automation", data_loader)
        patterns = _patterns_for_ksi(ksi["id"])

        if not patterns:
            result += "No code patterns reference this KSI, so there is no pattern-derived automation guidance. "
            result += "Evidence for this KSI is process or evidence based; collect it per the CR26 default artifacts below.\n\n"
            result += _default_artifacts_section(data_loader)
            result += WORM_STORAGE_NOTE
            return result

        result += f"**Patterns referencing this KSI:** {len(patterns)}\n\n"

        # Recommended Azure services (merged across patterns)
        services = {}
        for p in patterns:
            guide = p.azure_guidance or {}
            for svc in guide.get("recommended_services", []) or []:
                name = svc.get("service")
                if name and name not in services:
                    services[name] = svc
        if services:
            result += "## Azure Services\n\n"
            result += ("*Note: Microsoft Defender for Cloud is recommended (not mandatory) for streamlining compliance. "
                       "Alternative tools can be used.*\n\n")
            for name, svc in sorted(services.items()):
                result += f"- **{name}**"
                if svc.get("purpose"):
                    result += f": {svc['purpose']}"
                result += "\n"
            result += "\n"

        # Collection methods (automation blocks)
        methods = []
        for p in patterns:
            for key, auto in sorted((p.automation or {}).items()):
                if isinstance(auto, dict) and auto.get("description"):
                    methods.append((p.pattern_id, auto["description"]))
        if methods:
            result += "## Automation Methods\n\n"
            seen = set()
            for pid, desc in methods:
                if desc in seen:
                    continue
                seen.add(desc)
                result += f"- {desc} (pattern `{pid}`)\n"
            result += "\n"

        # Evidence artifacts
        artifacts = _collect_artifacts(patterns)
        if artifacts:
            result += "## Evidence Artifacts\n\n"
            for a in artifacts:
                result += f"- **{a['name']}** ({a['artifact_type']}, {a['frequency']}, {a['format']}) from {a['source']}\n"
            result += "\n*Use `get_ksi_evidence_artifacts` for details and `get_ksi_evidence_queries` for queries.*\n\n"

        result += WORM_STORAGE_NOTE
        result += "---\n*Generated by FedRAMP 20x MCP Server - Evidence Automation Tool*\n"
        return result

    except Exception as e:
        logger.error(f"Error getting evidence automation for {ksi_id}: {e}")
        return f"Error retrieving evidence automation recommendations: {str(e)}"


def _collect_artifacts(patterns: list) -> list:
    """Unique evidence artifacts across patterns, keyed by name and source."""
    out, seen = [], set()
    for p in patterns:
        for a in p.evidence_artifacts or []:
            if not isinstance(a, dict):
                continue
            name = a.get("name") or a.get("artifact_name") or "Artifact"
            source = a.get("source", "N/A")
            key = (name, source)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "name": name,
                "artifact_type": a.get("artifact_type", "other"),
                "source": source,
                "frequency": a.get("frequency", "N/A"),
                "format": a.get("format", "N/A"),
                "description": a.get("description", ""),
                "pattern_id": p.pattern_id,
            })
    return out


async def get_ksi_evidence_queries_impl(ksi_id: str, data_loader) -> str:
    """
    Get evidence collection queries for a specific KSI.

    Returns KQL, Azure CLI and PowerShell queries from the pattern library
    entries that reference the KSI.

    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-APM")

    Returns:
        Collection queries in markdown
    """
    try:
        ksi, note = await _resolve_ksi(ksi_id, data_loader)
        if not ksi:
            return _not_found(ksi_id, data_loader, note)

        result = _ksi_header(ksi, note, "Evidence Collection Queries", data_loader)
        patterns = _patterns_for_ksi(ksi["id"])

        queries = []  # (kind, description, text, pattern_id)
        seen = set()
        for p in patterns:
            ec = p.evidence_collection or {}
            for q in ec.get("azure_monitor_kql", []) or []:
                text = q.get("query", "")
                if text and text not in seen:
                    seen.add(text)
                    queries.append(("KQL (Log Analytics)", q.get("description", ""), text, p.pattern_id))
            for q in ec.get("azure_cli", []) or []:
                text = q.get("command", "")
                if text and text not in seen:
                    seen.add(text)
                    queries.append(("Azure CLI", q.get("description", ""), text, p.pattern_id))
            for q in ec.get("powershell", []) or []:
                text = q.get("script", "")
                if text and text not in seen:
                    seen.add(text)
                    queries.append(("PowerShell", q.get("description", ""), text, p.pattern_id))
            for q in ec.get("validation_queries", []) or []:
                text = q.get("query", "") if isinstance(q, dict) else str(q)
                if text and text not in seen:
                    seen.add(text)
                    desc = q.get("description", "") if isinstance(q, dict) else ""
                    queries.append(("Validation query", desc, text, p.pattern_id))

        if not queries:
            result += (f"No evidence collection queries are defined for {ksi['id']} "
                       f"({len(patterns)} pattern(s) reference it). This KSI may require manual evidence collection.\n\n")
            result += _default_artifacts_section(data_loader)
            result += WORM_STORAGE_NOTE
            return result

        result += f"**Total Queries:** {len(queries)}\n\n"
        for i, (kind, desc, text, pid) in enumerate(queries, 1):
            result += f"## Query {i}: {kind}\n\n"
            result += f"**Source pattern:** `{pid}`\n\n"
            if desc:
                result += f"**Description:** {desc}\n\n"
            result += f"```\n{text}\n```\n\n"

        result += WORM_STORAGE_NOTE
        result += "---\n*Run these with Azure CLI, PowerShell, or Azure SDKs and write results to the WORM layout above.*\n"
        return result

    except Exception as e:
        logger.error(f"Error getting evidence queries for {ksi_id}: {e}")
        return f"Error retrieving evidence queries: {str(e)}"


async def get_ksi_evidence_artifacts_impl(ksi_id: str, data_loader) -> str:
    """
    Get list of evidence artifacts that should be collected for a specific KSI.

    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-APM")

    Returns:
        Evidence artifacts list with collection details
    """
    try:
        ksi, note = await _resolve_ksi(ksi_id, data_loader)
        if not ksi:
            return _not_found(ksi_id, data_loader, note)

        result = _ksi_header(ksi, note, "Evidence Artifacts", data_loader)
        artifacts = _collect_artifacts(_patterns_for_ksi(ksi["id"]))

        if not artifacts:
            result += (f"No pattern-defined evidence artifacts exist for {ksi['id']}. "
                       "Use the CR26 default KSI artifacts below.\n\n")
            result += _default_artifacts_section(data_loader)
            result += WORM_STORAGE_NOTE
            return result

        result += f"**Total Artifacts:** {len(artifacts)}\n\n"
        by_type = {}
        for a in artifacts:
            by_type.setdefault(a["artifact_type"], []).append(a)

        for atype in sorted(by_type):
            result += f"## {atype.upper()} Artifacts\n\n"
            for a in by_type[atype]:
                result += f"### {a['name']}\n\n"
                if a["description"]:
                    result += f"**Description:** {a['description']}\n\n"
                result += f"**Collection source:** {a['source']}\n\n"
                result += f"- Format: {a['format']}\n"
                result += f"- Frequency: {a['frequency']}\n"
                result += f"- Pattern: `{a['pattern_id']}`\n\n"

        result += _default_artifacts_section(data_loader)
        result += WORM_STORAGE_NOTE
        return result

    except Exception as e:
        logger.error(f"Error getting evidence artifacts for {ksi_id}: {e}")
        return f"Error retrieving evidence artifacts: {str(e)}"
