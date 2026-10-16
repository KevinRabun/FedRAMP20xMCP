"""
Build the legacy-ID crosswalk for the FedRAMP Consolidated Rules for 2026 (CR26).

FedRAMP retired the pre-2026 machine-readable file (FRMR.documentation.json in
FedRAMP/docs) when it published CR26 in FedRAMP/rules, and CR26 carries no
"fka" (formerly known as) fields. Older material, including this server's own
pattern library and prompts, still cites the legacy IDs. This script chains:

  1. legacy numbered ID  -> 2025 named ID   (authoritative: FRMR "fka" fields)
  2. 2025 named ID       -> CR26 ID          (derived: identical ID, reviewed
                                              override, family rename with the
                                              same code, or text similarity)

and writes src/fedramp_20x_mcp/rules_data/legacy-crosswalk.json. Every entry
records its basis and confidence so a derived mapping is never presented as an
official FedRAMP crosswalk.

Usage:
    python scripts/build_rules_crosswalk.py [--legacy PATH] [--current PATH]

--legacy defaults to downloading FRMR.documentation.json at the pinned commit
below (the last FedRAMP/docs commit before the file was removed).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "src" / "fedramp_20x_mcp" / "rules_data"
CURRENT_DEFAULT = RULES_DIR / "fedramp-consolidated-rules.json"
OUTPUT = RULES_DIR / "legacy-crosswalk.json"

LEGACY_COMMIT = "a06fa8f9b1"  # FedRAMP/docs, 2026-04-08, FRMR v0.9.43-beta
LEGACY_URL = (
    f"https://raw.githubusercontent.com/FedRAMP/docs/{LEGACY_COMMIT}/FRMR.documentation.json"
)

# Pre-CR26 FRR family -> CR26 family candidates, tried in order with the same
# subgroup/code. Reviewed against the CR26 family purposes.
FAMILY_RENAMES = {
    "ADS": ["CDS"],          # Authorization Data Sharing -> Certification Data Sharing
    "FSI": ["AFC"],          # FedRAMP Security Inbox -> Addressing FedRAMP Communication
    "UCM": ["CMU"],          # Using Cryptographic Modules -> Cryptographic Module Use
    "PVA": ["IVV", "VDR"],   # Persistent Validation and Assessment -> IVV / VDR
    "ICP": ["IEC", "VER"],   # Incident Communications Procedures -> IEC
    "VDR": ["VDR", "VER"],   # VDR split into VDR (detect/respond) and VER (evaluate/report)
    "CCM": ["CCM", "AGU"],   # agency-side CCM rules moved to AGU
    "KSI": ["FRC", "SDR"],   # KSI-CSX-* process rules moved to FRC / SDR
}

# Reviewed 2025 -> CR26 mappings that the mechanical passes get wrong or can't
# reach. "related" means no single successor: the target is the closest CR26
# rule or family, and callers must not treat it as a rename.
OVERRIDES: dict[str, dict] = {
    # The 2025 KSI-AFR-* indicators were "follow the <FRR family> process". CR26
    # dropped the AFR KSI family; the processes are FRR families of their own.
    "KSI-AFR-ADS": {"ids": ["CDS-CSO-PUB"], "family": "CDS", "basis": "family-successor"},
    "KSI-AFR-CCM": {"ids": ["CCM-OCR-AVL"], "family": "CCM", "basis": "family-successor"},
    "KSI-AFR-FSI": {"ids": ["AFC-CSO-INB"], "family": "AFC", "basis": "family-successor"},
    "KSI-AFR-ICP": {"ids": ["IEC-CSO-IIR"], "family": "IEC", "basis": "family-successor"},
    "KSI-AFR-MAS": {"ids": ["MAS-CSO-IIR"], "family": "MAS", "basis": "family-successor"},
    "KSI-AFR-PVA": {"ids": ["VDR-TFR-MVX", "IVV-CSO-SEE"], "family": "IVV", "basis": "family-successor"},
    "KSI-AFR-SCG": {"ids": ["SCG-CSO-RSC"], "family": "SCG", "basis": "family-successor"},
    "KSI-AFR-SCN": {"ids": ["SCN-CSO-EVA"], "family": "SCN", "basis": "family-successor"},
    "KSI-AFR-UCM": {"ids": ["CMU-CSO-UVM"], "family": "CMU", "basis": "family-successor"},
    "KSI-AFR-VDR": {"ids": ["VDR-CSO-DET", "VER-EVA-EFA"], "family": "VDR", "basis": "family-successor"},
    # CR26 merged the four training KSIs into one.
    "KSI-CED-DET": {"ids": ["KSI-CED-RAT"], "basis": "merged"},
    "KSI-CED-RGT": {"ids": ["KSI-CED-RAT"], "basis": "merged"},
    "KSI-CED-RRT": {"ids": ["KSI-CED-RAT"], "basis": "merged"},
    "KSI-CED-RST": {"ids": ["KSI-CED-RAT"], "basis": "merged"},
    # Phishing-resistant MFA is now the fallback clause of the passwordless KSI.
    "KSI-IAM-MFA": {"ids": ["KSI-IAM-APM"], "basis": "merged"},
    # Network-traffic security folded into "information is encrypted or secured".
    "KSI-SVC-SNT": {"ids": ["KSI-SVC-SIN"], "basis": "merged"},
    "KSI-CSX-ORD": {"ids": ["SDR-CSX-KSI"], "basis": "related"},
    "KSI-CSX-SUM": {"ids": ["SDR-CSX-KSI"], "basis": "renamed"},
    "CCM-AGM-SSR": {"ids": ["AGU-USE-DSO"], "basis": "renamed"},
    "CCM-AGM-NFR": {"ids": ["AGU-USE-NFC"], "basis": "renamed"},
    "CCM-AGM-NFA": {"ids": ["AGU-AGC-NAI"], "basis": "renamed"},
    "CCM-OAR-RPS": {"ids": ["CCM-OCR-RPS"], "basis": "renamed"},
    "ADS-CSO-HAD": {"ids": ["CDS-CSO-HAD"], "basis": "renamed"},
    "ADS-CSL-UCP": {"ids": ["CDS-CSO-UTC"], "basis": "related"},
    "ADS-CSL-LRE": {"ids": ["CDS-CSF-TCM"], "basis": "related"},
    "ADS-TRC-RSP": {"ids": ["CDS-TRC-USH"], "basis": "related"},
    "ADS-UTC-PGD": {"ids": ["CDS-CSO-UTC"], "basis": "related"},
    "UCM-CSX-UVM": {"ids": ["CMU-CSO-UVM"], "basis": "renamed"},
    "PVA-CSX-FAV": {"ids": ["VDR-CSO-FAV"], "basis": "renamed"},
    "PVA-CSX-VAL": {"ids": ["VDR-TFR-MVX"], "basis": "related"},
    "PVA-CSX-PMV": {"ids": ["VDR-TFR-MVX"], "basis": "renamed"},
    "PVA-CSX-NMV": {"ids": ["VDR-TFR-NMV"], "basis": "renamed"},
    "PVA-CSX-RPV": {"ids": ["VER-RPT-PER"], "basis": "related"},
    "PVA-CSX-IVV": {"ids": ["IVV-CSO-FIA"], "basis": "related"},
    "PVA-CSX-PTE": {"ids": ["IVV-CSO-STE"], "basis": "renamed"},
    "PVA-CSX-RAD": {"ids": ["IVV-CSO-RAA"], "basis": "renamed"},
    "PVA-TPX-MME": {"ids": ["IVV-IAS-VEF"], "basis": "related"},
    "PVA-TPX-NOR": {"ids": ["IVV-IAS-SUM"], "basis": "related"},
    "PVA-TPX-OUC": {"ids": ["IVV-IAS-VEF"], "basis": "related"},
    "PVA-TPX-PAD": {"ids": ["IVV-IAS-VIM"], "basis": "related"},
    "PVA-TPX-PDK": {"ids": ["IVV-IAS-VIM"], "basis": "related"},
    "PVA-TPX-STE": {"ids": ["IVV-CSO-SEI"], "basis": "related"},
    "PVA-TPX-UNP": {"ids": ["IVV-IAS-VIM"], "basis": "related"},
    "ICP-CSX-AUR": {"ids": ["IEC-CSO-AIR"], "basis": "renamed"},
    "ICP-CSX-FIR": {"ids": ["IEC-CSO-FIR"], "basis": "renamed"},
    "ICP-CSX-HRM": {"ids": ["IEC-CSO-AIR"], "basis": "related"},
    "ICP-CSX-ICU": {"ids": ["IEC-CSO-OIR"], "basis": "renamed"},
    "ICP-CSX-IRA": {"ids": ["IEC-CSO-IIR"], "basis": "related"},
    "ICP-CSX-IRC": {"ids": ["IEC-CSO-IIR"], "basis": "related"},
    "ICP-CSX-IRF": {"ids": ["IEC-CSO-IIR"], "basis": "related"},
    "ICP-CSX-RPT": {"ids": ["IEC-CSO-FIR"], "basis": "related"},
    "ICP-CSX-RSD": {"ids": ["VER-RPT-NID"], "basis": "related"},
    "VDR-AGM-DRE": {"ids": ["AGU-AGC-NAR"], "basis": "related"},
    "VDR-AGM-NFR": {"ids": ["AGU-AGC-NAI"], "basis": "related"},
    "VDR-CSO-DOC": {"ids": ["VER-RPT-HLO"], "basis": "related"},
    "VDR-TFR-EVU": {"ids": ["VER-TFR-EVU"], "basis": "renamed"},
    "VDR-TFR-IRI": {"ids": ["VER-TFR-IRI"], "basis": "renamed"},
    "VDR-TFR-NRI": {"ids": ["VER-TFR-NRI"], "basis": "renamed"},
    "VDR-TFR-MRH": {"ids": ["VER-TFR-MRH"], "basis": "renamed"},
}

CONFIDENCE = {
    "unchanged": "high",
    "fka": "high",
    "renamed": "high",
    "merged": "high",
    "family-successor": "medium",
    "renamed-by-text": "medium",
    "related": "low",
}


def _load_json(path_or_url: str) -> tuple[dict, str]:
    if re.match(r"^https?://", path_or_url):
        with urllib.request.urlopen(path_or_url, timeout=60) as resp:  # noqa: S310 (pinned https URL)
            raw = resp.read()
    else:
        raw = Path(path_or_url).read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def _frr(doc: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for family in doc.get("FRR", {}).values():
        for scope in family.get("data", {}).values():
            for group in scope.values():
                if isinstance(group, dict):
                    out.update({k: v for k, v in group.items() if isinstance(v, dict)})
    return out


def _ksi(doc: dict) -> dict[str, dict]:
    return {
        k: v
        for cat in doc.get("KSI", {}).values()
        for k, v in cat.get("indicators", {}).items()
        if isinstance(v, dict)
    }


def _text(rule: dict) -> str:
    stmt = rule.get("statement") or ""
    if not stmt and isinstance(rule.get("varies_by_level"), dict):
        stmt = " ".join(str(v.get("statement", "")) for v in rule["varies_by_level"].values())
    return f"{rule.get('name', '')} {stmt}".lower()


def _tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-z]{4,}", s))


def _jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def build(legacy_doc: dict, current_doc: dict) -> dict[str, dict]:
    cur = {**_frr(current_doc), **_ksi(current_doc)}
    cur_tokens = {k: _tokens(_text(v)) for k, v in cur.items()}
    old = {**_frr(legacy_doc), **_ksi(legacy_doc)}

    def map_named(old_id: str) -> dict:
        if old_id in cur:
            return {"ids": [old_id], "basis": "unchanged"}
        if old_id in OVERRIDES:
            o = dict(OVERRIDES[old_id])
            missing = [i for i in o["ids"] if i not in cur]
            if missing:
                raise SystemExit(f"override for {old_id} names unknown CR26 ids: {missing}")
            return o
        fam, *rest = old_id.split("-")
        code = rest[-1] if rest else ""
        old_tok = _tokens(_text(old.get(old_id, {})))
        for target_fam in FAMILY_RENAMES.get(fam, []):
            same_code = [k for k in cur if k.startswith(f"{target_fam}-") and k.endswith(f"-{code}")]
            if len(same_code) == 1:
                return {"ids": same_code, "basis": "renamed"}
        scored = sorted(((_jaccard(old_tok, t), k) for k, t in cur_tokens.items()), reverse=True)
        if scored and scored[0][0] >= 0.6:
            return {"ids": [scored[0][1]], "basis": "renamed-by-text"}
        raise SystemExit(
            f"no reviewed mapping for {old_id} (best text match {scored[0] if scored else None}); "
            "add it to OVERRIDES"
        )

    crosswalk: dict[str, dict] = {}

    def add(legacy_id: str, via: str | None, target: dict, old_rule: dict) -> None:
        # A legacy ID whose 2025 successor survived unchanged is an
        # authoritative FedRAMP rename (fka), not a derived one.
        basis = "fka" if via and target["basis"] == "unchanged" else target["basis"]
        entry = {
            "current_ids": target["ids"],
            "basis": basis,
            "confidence": CONFIDENCE[basis],
            "legacy_name": old_rule.get("name", ""),
            "current_names": [cur[i].get("name", "") for i in target["ids"]],
        }
        if target.get("family"):
            entry["current_family"] = target["family"]
        if via:
            entry["via"] = via
        crosswalk[legacy_id] = entry

    for named_id, rule in sorted(old.items()):
        target = map_named(named_id)
        if target["basis"] != "unchanged":
            add(named_id, None, target, rule)
        for key in ("fka", "fkas"):
            vals = rule.get(key)
            for fka in [vals] if isinstance(vals, str) else (vals or []):
                if fka and fka.upper() not in cur:
                    add(fka.upper(), named_id, target, rule)
    return crosswalk


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--legacy", default=LEGACY_URL, help="pre-CR26 FRMR.documentation.json (path or URL)")
    ap.add_argument("--current", default=str(CURRENT_DEFAULT), help="CR26 consolidated rules JSON")
    args = ap.parse_args()

    legacy_doc, legacy_sha = _load_json(args.legacy)
    current_doc, current_sha = _load_json(args.current)
    entries = build(legacy_doc, current_doc)

    out = {
        "info": {
            "description": (
                "Legacy FedRAMP 20x rule and KSI IDs mapped to the FedRAMP Consolidated Rules "
                "for 2026. Legacy-to-2025 links come from FRMR 'fka' fields (authoritative); "
                "2025-to-2026 links are derived and reviewed, not published by FedRAMP. "
                "basis=related means no single successor exists."
            ),
            "generated_by": "scripts/build_rules_crosswalk.py",
            "legacy_source": {
                "url": LEGACY_URL,
                "version": legacy_doc.get("info", {}).get("version", ""),
                "sha256": legacy_sha,
            },
            "current_source": {
                "version": current_doc.get("info", {}).get("version", ""),
                "last_updated": current_doc.get("info", {}).get("last_updated", ""),
                "sha256": current_sha,
            },
            "entry_count": len(entries),
        },
        "crosswalk": dict(sorted(entries.items())),
    }
    OUTPUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(entries)} entries to {OUTPUT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
