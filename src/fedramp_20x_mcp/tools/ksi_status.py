"""
KSI implementation status tools.

Dynamically queries KSI analyzers to report on implementation status
and code detectability without maintaining separate tracking lists.
Syncs with authoritative FedRAMP data to ensure accuracy.
"""

from typing import Dict, Any, List
from ..analyzers.ksi.factory import get_factory


async def build_ksi_rows(data_loader=None) -> List[Dict[str, Any]]:
    """
    Build one status row per CR26 KSI.

    The KSI list, names and families come from the loaded CR26 rules. Pattern
    coverage (code detectability and implementation status) comes from the
    pattern-based analyzer factory, intersected with the CR26 KSI ids so stale
    pattern ids never inflate the numbers.
    """
    covered = set()
    try:
        covered = set(get_factory().list_ksis())
    except Exception:
        covered = set()

    rows: List[Dict[str, Any]] = []
    ksis = data_loader.list_all_ksi() if data_loader else []
    for ksi in sorted(ksis, key=lambda k: k.get("id", "")):
        ksi_id = ksi.get("id", "")
        has_patterns = ksi_id in covered
        parts = ksi_id.split("-")
        family = ksi.get("category_id") or (parts[1] if len(parts) > 1 else "UNKNOWN")
        rows.append({
            "id": ksi_id,
            "name": ksi.get("name", ksi_id),
            "family": family,
            "family_name": ksi.get("category", family),
            "retired": str(ksi.get("status", "")).lower() in ("retired", "removed"),
            "code_detectable": has_patterns,
            "implementation_status": "IMPLEMENTED" if has_patterns else "NOT_IMPLEMENTED",
            "controls": ksi.get("controls", []),
        })
    return rows


async def get_ksi_implementation_status_impl(data_loader=None) -> Dict[str, Any]:
    """
    Get comprehensive status of all KSI implementations.
    
    Queries each KSI analyzer for:
    - CODE_DETECTABLE: Whether the KSI can be detected in code
    - IMPLEMENTATION_STATUS: Current implementation state
    - Retirement status (synced from authoritative source)
    - Impact levels
    - NIST control mappings
    
    Args:
        data_loader: Optional DataLoader for syncing with authoritative data
    
    Returns:
        Dictionary with complete KSI status information organized by family
    """
    if data_loader:
        await data_loader.load_data()
    rows = await build_ksi_rows(data_loader)
    ksi_ids = [r["id"] for r in rows]
    row_by_id = {r["id"]: r for r in rows}

    status = {
        "rules_version": data_loader.get_rules_metadata().get("version") if data_loader else None,
        "total_ksis": len(ksi_ids),
        "active_ksis": 0,
        "retired_ksis": 0,
        "implemented_ksis": 0,
        "code_detectable_ksis": 0,
        "process_based_ksis": 0,
        "families": {},
        "ksi_details": []
    }
    
    for ksi_id in ksi_ids:
        row = row_by_id[ksi_id]

        # Get KSI properties (CR26 rules data plus pattern coverage)
        is_retired = row["retired"]
        code_detectable = row["code_detectable"]
        impl_status = row["implementation_status"]
        family = row["family"]
        family_name = row["family_name"]
        ksi_name = row["name"]
        # CR26 no longer defines per-KSI impact levels
        impact_low = False
        impact_moderate = False
        nist_controls = row["controls"]
        
        # Update counters
        if is_retired:
            status["retired_ksis"] += 1
        else:
            status["active_ksis"] += 1
            if code_detectable:
                status["code_detectable_ksis"] += 1
            else:
                status["process_based_ksis"] += 1
            
            if impl_status == 'IMPLEMENTED':
                status["implemented_ksis"] += 1
        
        # Organize by family
        if family not in status["families"]:
            status["families"][family] = {
                "name": family_name,
                "total": 0,
                "active": 0,
                "retired": 0,
                "implemented": 0,
                "code_detectable": 0,
                "process_based": 0,
                "ksis": []
            }
        
        family_data = status["families"][family]
        family_data["total"] += 1
        
        if is_retired:
            family_data["retired"] += 1
        else:
            family_data["active"] += 1
            if code_detectable:
                family_data["code_detectable"] += 1
            else:
                family_data["process_based"] += 1
            if impl_status == 'IMPLEMENTED':
                family_data["implemented"] += 1
        
        # Add KSI details
        ksi_detail = {
            "ksi_id": ksi_id,
            "name": ksi_name,
            "family": family,
            "family_name": family_name,
            "retired": is_retired,
            "code_detectable": code_detectable,
            "implementation_status": impl_status,
            "impact_low": impact_low,
            "impact_moderate": impact_moderate,
            "nist_controls_count": len(nist_controls)
        }
        
        family_data["ksis"].append(ksi_detail)
        status["ksi_details"].append(ksi_detail)
    
    # Calculate percentages
    if status["active_ksis"] > 0:
        status["implementation_percentage"] = round(
            (status["implemented_ksis"] / status["active_ksis"]) * 100, 1
        )
        status["code_detectable_percentage"] = round(
            (status["code_detectable_ksis"] / status["active_ksis"]) * 100, 1
        )
    else:
        status["implementation_percentage"] = 0.0
        status["code_detectable_percentage"] = 0.0
    
    return status


async def get_ksi_family_status_impl(family: str, data_loader=None) -> Dict[str, Any]:
    """
    Get implementation status for a specific KSI family.
    
    Args:
        family: Family code (e.g., "IAM", "SVC", "CNA")
        data_loader: Optional DataLoader for syncing with authoritative data
    
    Returns:
        Dictionary with family-specific status information
    """
    if data_loader:
        await data_loader.load_data()
    rows = await build_ksi_rows(data_loader)
    row_by_id = {r["id"]: r for r in rows}
    ksi_ids = list(row_by_id.keys())

    family_status = {
        "family": family.upper(),
        "rules_version": data_loader.get_rules_metadata().get("version") if data_loader else None,
        "total_ksis": 0,
        "active_ksis": 0,
        "retired_ksis": 0,
        "implemented_ksis": 0,
        "code_detectable_ksis": 0,
        "process_based_ksis": 0,
        "ksis": []
    }
    
    for ksi_id in ksi_ids:
        row = row_by_id[ksi_id]
        if row["family"].upper() != family.upper():
            continue

        # Get KSI properties
        is_retired = row["retired"]
        code_detectable = row["code_detectable"]
        impl_status = row["implementation_status"]
        ksi_name = row["name"]
        
        family_status["total_ksis"] += 1
        
        if is_retired:
            family_status["retired_ksis"] += 1
        else:
            family_status["active_ksis"] += 1
            if code_detectable:
                family_status["code_detectable_ksis"] += 1
            else:
                family_status["process_based_ksis"] += 1
            
            if impl_status == 'IMPLEMENTED':
                family_status["implemented_ksis"] += 1
        
        family_status["ksis"].append({
            "ksi_id": ksi_id,
            "name": ksi_name,
            "retired": is_retired,
            "code_detectable": code_detectable,
            "implementation_status": impl_status
        })
    
    # Calculate percentage
    if family_status["active_ksis"] > 0:
        family_status["implementation_percentage"] = round(
            (family_status["implemented_ksis"] / family_status["active_ksis"]) * 100, 1
        )
    else:
        family_status["implementation_percentage"] = 0.0
    
    return family_status
