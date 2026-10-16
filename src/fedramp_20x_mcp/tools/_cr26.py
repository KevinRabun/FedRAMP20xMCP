"""
Shared CR26 helpers for the tool layer.

Everything here is derived from the data loader at runtime so the tools never
hardcode rule counts, family lists or the rules version.
"""
from typing import Any, Dict, List, Optional

# Families retired between the legacy 20x documents and CR26, with their CR26 successor.
# Kept only so a user who types a legacy family code gets a pointer, not a dead end.
RETIRED_FAMILY_SUCCESSORS: Dict[str, str] = {
    "ADS": "CDS",
    "FSI": "AFC",
    "UCM": "CMU",
    "PVA": "IVV",
    "ICP": "IEC",
    "RSC": "SCG",
    "TPR": "SCR (KSI-TPR became KSI-SCR)",
}


def rules_version(data_loader: Any) -> str:
    """Return the loaded CR26 rules version string (e.g. '2026.10.13.01') or 'unknown'."""
    try:
        return str(data_loader.get_rules_metadata().get("version") or "unknown")
    except Exception:
        return "unknown"


def version_line(data_loader: Any) -> str:
    """One-line markdown header fragment naming the rules version."""
    return f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"


def frr_family_codes(data_loader: Any) -> List[str]:
    """FRR family codes present in the loaded rules (KSI and FRD excluded), sorted."""
    reqs = getattr(data_loader, "_data_cache", None) or {}
    fams = set()
    for r in (reqs.get("requirements") or {}).values():
        doc = r.get("document", "")
        if doc.startswith("FRR-") and r.get("family"):
            fams.add(r["family"])
    return sorted(fams)


def family_hint(data_loader: Any) -> str:
    """Short 'Available families: ...' sentence derived from the loader."""
    fams = frr_family_codes(data_loader)
    return ", ".join(fams) if fams else "VDR, SCN, CCM, MAS"


def family_of(rule_id: str) -> str:
    """Family code for a CR26 rule id: 'VDR-CSO-DET' -> 'VDR', 'KSI-IAM-APM' -> 'IAM'."""
    parts = (rule_id or "").split("-")
    if not parts or not parts[0]:
        return ""
    if parts[0] in ("KSI", "FRR") and len(parts) > 1:
        return parts[1]
    return parts[0]


def legacy_resolution_note(data_loader: Any, requested_id: str, resolved_id: Optional[str] = None) -> str:
    """
    Markdown note explaining how a legacy ID the user typed maps to CR26.

    Returns '' when the requested ID is current/unknown to the crosswalk.
    """
    try:
        entry = data_loader.resolve_legacy_id(requested_id)
    except Exception:
        entry = None
    if not entry:
        return ""
    targets = entry.get("current_ids") or []
    basis = entry.get("basis", "unknown")
    confidence = entry.get("confidence", "unknown")
    legacy_name = entry.get("legacy_name") or ""
    names = entry.get("current_names") or []
    lines = [f"> **Legacy ID:** `{entry.get('legacy_id', requested_id)}`"
             + (f" ({legacy_name})" if legacy_name else "")
             + " is not a CR26 ID."]
    if targets:
        shown = ", ".join(
            f"`{t}`" + (f" ({names[i]})" if i < len(names) else "") for i, t in enumerate(targets)
        )
        lines.append(f"> Crosswalk target: {shown}. Basis: **{basis}**, confidence: **{confidence}**.")
    else:
        lines.append(f"> No CR26 successor. Basis: **{basis}**, confidence: **{confidence}**.")
    if basis == "related":
        lines.append("> CR26 has no single successor for this ID. The target is the nearest related rule, not a rename; review it before relying on it.")
    if resolved_id and resolved_id not in targets:
        lines.append(f"> Showing `{resolved_id}`.")
    return "\n".join(lines) + "\n\n"
