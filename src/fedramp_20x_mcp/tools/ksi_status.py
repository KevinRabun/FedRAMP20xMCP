"""
KSI implementation status tools.

Dynamically queries KSI analyzers to report on implementation status
and code detectability without maintaining separate tracking lists.
Syncs with authoritative FedRAMP data to ensure accuracy.
"""

from typing import Dict, Any, List
from ..analyzers.ksi.factory import get_factory


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
    factory = get_factory()
    
    # Sync with authoritative data if data_loader provided
    if data_loader:
        await factory.sync_with_authoritative_data(data_loader)
    
    ksi_ids = factory.list_ksis()
    
    status = {
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
        analyzer = factory.get_analyzer(ksi_id)
        if not analyzer:
            continue
        
        # Get KSI properties
        is_retired = getattr(analyzer, 'RETIRED', False)
        code_detectable = getattr(analyzer, 'CODE_DETECTABLE', True)
        impl_status = getattr(analyzer, 'IMPLEMENTATION_STATUS', 'NOT_IMPLEMENTED')
        family = getattr(analyzer, 'FAMILY', 'UNKNOWN')
        family_name = getattr(analyzer, 'FAMILY_NAME', 'Unknown')
        ksi_name = getattr(analyzer, 'KSI_NAME', 'Unknown')
        impact_low = getattr(analyzer, 'IMPACT_LOW', False)
        impact_moderate = getattr(analyzer, 'IMPACT_MODERATE', False)
        nist_controls = getattr(analyzer, 'NIST_CONTROLS', [])
        
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
    factory = get_factory()
    
    # Sync with authoritative data if data_loader provided
    if data_loader:
        await factory.sync_with_authoritative_data(data_loader)
    
    ksi_ids = factory.list_ksis()
    
    family_status = {
        "family": family.upper(),
        "total_ksis": 0,
        "active_ksis": 0,
        "retired_ksis": 0,
        "implemented_ksis": 0,
        "code_detectable_ksis": 0,
        "process_based_ksis": 0,
        "ksis": []
    }
    
    for ksi_id in ksi_ids:
        analyzer = factory.get_analyzer(ksi_id)
        if not analyzer:
            continue
        
        ksi_family = getattr(analyzer, 'FAMILY', '')
        if ksi_family.upper() != family.upper():
            continue
        
        # Get KSI properties
        is_retired = getattr(analyzer, 'RETIRED', False)
        code_detectable = getattr(analyzer, 'CODE_DETECTABLE', True)
        impl_status = getattr(analyzer, 'IMPLEMENTATION_STATUS', 'NOT_IMPLEMENTED')
        ksi_name = getattr(analyzer, 'KSI_NAME', 'Unknown')
        
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
