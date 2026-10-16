"""
FedRAMP 20x MCP Server - Requirements Tools

This module contains tool implementation functions for requirements
(FedRAMP Consolidated Rules for 2026, CR26).
"""
import json
import logging
from typing import Any

from ._cr26 import (
    family_hint,
    legacy_resolution_note,
    rules_version,
    RETIRED_FAMILY_SUCCESSORS,
)

logger = logging.getLogger(__name__)


def _format_varies_by_class(varies: dict) -> str:
    """
    Render a CR26 rule whose text differs by Certification Class (A-D).

    These rules (e.g. VDR-TFR-PVR, CCM-QTR-MTG, IEC-CSO-IIR) have no top-level
    statement; each class carries its own statement, force, optional
    timeframe, artifacts and, for VDR-TFR-PVR, a pain_timeframes table keyed
    by Potential Agency Impact N-rating and reachability/exploitability.
    """
    out = "**Varies by Certification Class:**\n\n"
    for cls, body in varies.items():
        if not isinstance(body, dict):
            continue
        force = f" ({body['force']})" if body.get("force") else ""
        out += f"### Class {cls.upper()}{force}\n\n"
        if body.get("statement"):
            out += f"{body['statement']}\n\n"
        if body.get("timeframe_num") is not None:
            out += f"- **Timeframe:** {body['timeframe_num']} {body.get('timeframe_type', '')}\n"
        for item in body.get("following_information", []) or []:
            out += f"- {item}\n"
        if body.get("note"):
            out += f"- **Note:** {body['note']}\n"
        if body.get("rev5_controls_list"):
            out += f"- **Rev5 controls:** {', '.join(map(str, body['rev5_controls_list']))}\n"
        pain = body.get("pain_timeframes")
        if isinstance(pain, dict) and pain:
            cols: list = []
            for row in pain.values():
                for key in (row or {}):
                    if key not in cols:
                        cols.append(key)
            if cols:
                desc = {k: next((r[k].get("description", k) for r in pain.values() if r and k in r), k) for k in cols}
                out += "\n| N-rating | " + " | ".join(desc[c] for c in cols) + " |\n"
                out += "|---|" + "---|" * len(cols) + "\n"
                for n, row in pain.items():
                    cells = []
                    for c in cols:
                        tf = (row or {}).get(c)
                        cells.append(f"{tf['timeframe_num']} {tf['timeframe_type']}" if tf else "no timeframe")
                    out += f"| N{n} | " + " | ".join(cells) + " |\n"
        if body.get("artifacts"):
            out += "\n**Artifacts:**\n" + "".join(f"- {a}\n" for a in body["artifacts"])
        out += "\n"
    return out


def _format_requirement(req: dict, fallback_id: str) -> str:
    """Render a CR26 rule (or an FRD definition) as markdown."""
    result = f"# Requirement: {req.get('id', fallback_id)}\n\n"

    if req.get("name"):
        result += f"## {req['name']}\n\n"
    if "term" in req:
        result += f"## Term: {req['term']}\n\n"

    if req.get("statement"):
        force = f" ({req['force']})" if req.get("force") else ""
        result += f"**Statement{force}:**\n{req['statement']}\n\n"
    if "definition" in req:
        result += f"**Definition:**\n{req['definition']}\n\n"
    if req.get("danger"):
        result += f"**Danger:** {req['danger']}\n\n"

    if "alts" in req and req["alts"]:
        result += f"**Also known as:** {', '.join(req['alts'])}\n\n"

    meta = []
    if req.get("force"):
        meta.append(f"**Force:** {req['force']}")
    if req.get("affects"):
        meta.append(f"**Affects:** {', '.join(req['affects'])}")
    if req.get("scope"):
        meta.append(f"**Scope:** {req['scope']}")
    if req.get("family"):
        fam = req["family"]
        if req.get("family_name"):
            fam += f" ({req['family_name']})"
        meta.append(f"**Family:** {fam}")
    if meta:
        result += "\n".join(meta) + "\n\n"

    if req.get("varies_by_level"):
        result += f"**Varies by level:**\n```json\n{json.dumps(req['varies_by_level'], indent=2)}\n```\n\n"
    if req.get("varies_by_class"):
        result += _format_varies_by_class(req["varies_by_class"])
    if req.get("controls"):
        result += f"**NIST controls:** {', '.join(req['controls'])}\n\n"
    if req.get("terms"):
        result += f"**Terms:** {', '.join(req['terms'])}\n\n"

    if "note" in req:
        result += f"**Note:**\n{req['note']}\n\n"
    elif "notes" in req and isinstance(req["notes"], list):
        result += "**Notes:**\n"
        for note in req["notes"]:
            result += f"- {note}\n"
        result += "\n"

    if "reference" in req:
        ref_url = req.get("reference_url", "")
        if ref_url:
            result += f"**Reference:** [{req['reference']}]({ref_url})\n\n"
        else:
            result += f"**Reference:** {req['reference']}\n\n"

    if req.get("updated"):
        last = req["updated"][0]
        result += f"**Last updated:** {last.get('date', '?')} - {last.get('comment', '')}\n\n"

    if req.get("document") or req.get("document_name"):
        result += f"**Document:** {req.get('document_name') or req.get('document')}\n"
    if req.get("section"):
        result += f"**Section:** {req['section']}\n"
    return result


async def get_control_impl(control_id: str, data_loader) -> str:
    """
    Get detailed information about a specific FedRAMP 20x requirement.

    Args:
        control_id: The requirement identifier (e.g., "VDR-CSO-DET", "KSI-IAM-APM").
            Legacy IDs are resolved through the CR26 crosswalk.

    Returns:
        Detailed information about the requirement including statement, force,
        controls, notes and, for legacy IDs, how the ID resolved to CR26.
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()

        note = legacy_resolution_note(data_loader, control_id)

        # Get the requirement
        req = data_loader.get_control(control_id)

        if not req and note:
            # Crosswalk knows the legacy ID; try its targets directly.
            entry = data_loader.resolve_legacy_id(control_id) or {}
            for target in entry.get("current_ids", []):
                req = data_loader.get_control(target)
                if req:
                    break

        if not req:
            hint = f" {note}" if note else ""
            return (f"Requirement {control_id} not found in FedRAMP Consolidated Rules for 2026 "
                    f"(version {rules_version(data_loader)}).{hint}")

        resolved_id = req.get("id")
        if resolved_id and resolved_id.upper() != control_id.upper() and not note:
            note = (f"> Requested `{control_id}` resolved to `{resolved_id}` "
                    f"(formerly-known-as match).\n\n")

        result = note + _format_requirement(req, control_id)
        result += f"\n*Rules version: {rules_version(data_loader)}*\n"
        return result

    except Exception as e:
        logger.error(f"Error fetching requirement {control_id}: {e}")
        return f"Error retrieving requirement {control_id}: {str(e)}"


async def list_family_controls_impl(family: str, data_loader) -> str:
    """
    List all requirements within a specific document family.

    Args:
        family: The document family identifier (e.g., "FRD", "VDR", "SCN", "VER")

    Returns:
        List of all requirements in the specified family with brief descriptions
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()

        # Get family requirements
        reqs = data_loader.get_family_controls(family)

        if not reqs:
            msg = f"No requirements found for family {family}. Available families: FRD, {family_hint(data_loader)}."
            successor = RETIRED_FAMILY_SUCCESSORS.get(family.upper())
            if successor:
                msg += f" Family {family.upper()} is retired in CR26; its successor is {successor}."
            return msg

        # Format the results
        result = f"# Requirements in Family: {family.upper()}\n\n"
        result += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
        result += f"Found {len(reqs)} requirements:\n\n"

        for req in reqs:
            req_id = req.get("id", "Unknown")
            term = req.get("name", req.get("term", req.get("title", "No term")))
            force = f" [{req['force']}]" if req.get("force") else ""
            result += f"- **{req_id}**: {term}{force}\n"

        return result

    except Exception as e:
        logger.error(f"Error listing family {family}: {e}")
        return f"Error retrieving family {family}: {str(e)}"


async def search_requirements_impl(keywords: str, data_loader) -> str:
    """
    Search for FedRAMP 20x requirements containing specific keywords.

    Args:
        keywords: Keywords to search for in requirement text (space-separated)

    Returns:
        Matching requirements with IDs and relevant excerpts
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()

        # Search for requirements
        reqs = data_loader.search_controls(keywords)

        if not reqs:
            return f"No requirements found matching keywords: '{keywords}'"

        # Format the results
        result = f"# Search Results for: '{keywords}'\n\n"
        result += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
        result += f"Found {len(reqs)} matching requirements:\n\n"

        # Limit to first 20 results to avoid overwhelming output
        for req in reqs[:20]:
            req_id = req.get("id", "Unknown")
            term = req.get("name", req.get("term", ""))
            text = req.get("statement", req.get("definition", ""))

            result += f"## {req_id}"
            if term:
                result += f": {term}"
            result += "\n"

            # Show a snippet of the statement/definition
            if text:
                snippet = text[:200] + "..." if len(text) > 200 else text
                result += f"{snippet}\n\n"
            else:
                result += "Match found in requirement data.\n\n"

        if len(reqs) > 20:
            result += f"\n*Showing first 20 of {len(reqs)} results. Refine your search for more specific results.*\n"

        return result

    except Exception as e:
        logger.error(f"Error searching for '{keywords}': {e}")
        return f"Error searching for '{keywords}': {str(e)}"


async def get_control_parameters_impl(control_id: str, data_loader) -> str:
    """
    Get the FedRAMP parameter values and guidance for a NIST SP 800-53 control.

    Args:
        control_id: NIST control id such as "AC-6(1)", "ac-6.1" or "AC-06-01"

    Returns:
        FedRAMP-defined parameter values (CTL section of the consolidated rules)
    """
    try:
        await data_loader.load_data()

        entry = data_loader.get_control_parameters(control_id)
        if not entry:
            return (f"No FedRAMP parameter data found for control '{control_id}' in the "
                    f"FedRAMP Consolidated Rules for 2026 (version {rules_version(data_loader)}). "
                    f"Use NIST identifiers such as 'AC-6(1)' or 'SC-28'.")

        result = f"# FedRAMP Control Parameters: {entry.get('id', control_id)}\n\n"
        result += f"*FedRAMP Consolidated Rules for 2026, version {rules_version(data_loader)}*\n\n"
        if entry.get("family"):
            result += f"**Control family:** {entry['family']}\n\n"

        params = entry.get("parameters") or []
        if params:
            result += f"## Parameters ({len(params)})\n\n"
            for p in params:
                pid = p.get("parameterId", "?")
                value = p.get("value")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value)
                result += f"- `{pid}`: {value}\n"
            result += "\n"

        # Surface any other guidance fields the data carries
        extras = {k: v for k, v in entry.items() if k not in ("id", "family", "parameters")}
        for key, value in extras.items():
            result += f"**{key.replace('_', ' ').title()}:**\n"
            if isinstance(value, (dict, list)):
                result += f"```json\n{json.dumps(value, indent=2)}\n```\n\n"
            else:
                result += f"{value}\n\n"

        return result

    except Exception as e:
        logger.error(f"Error fetching control parameters for {control_id}: {e}")
        return f"Error retrieving control parameters for {control_id}: {str(e)}"
