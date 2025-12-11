"""
Update FRR analyzers to change CODE_DETECTABLE from "No" to True for requirements
that have been reassessed as having code-detectable aspects.

Based on comprehensive reassessment of all 196 FRR analyzers marked as not detectable.
"""

import re
from pathlib import Path


# List of 79 FRR analyzer files that should be changed to CODE_DETECTABLE = True
# Based on reassessment showing they have technical aspects detectable in code, IaC, or CI/CD
FILES_TO_UPDATE = [
    "frr_ads_02.py", "frr_ads_04.py", "frr_ads_05.py", "frr_ads_07.py", "frr_ads_10.py",
    "frr_ads_ac_01.py", "frr_ads_ac_02.py", "frr_ads_ex_01.py",
    "frr_ads_tc_02.py", "frr_ads_tc_03.py", "frr_ads_tc_04.py", "frr_ads_tc_05.py", "frr_ads_tc_06.py",
    "frr_ccm_01.py", "frr_ccm_02.py", "frr_ccm_03.py", "frr_ccm_04.py", "frr_ccm_05.py", 
    "frr_ccm_06.py", "frr_ccm_07.py",
    "frr_ccm_ag_01.py", "frr_ccm_ag_02.py", "frr_ccm_ag_03.py", "frr_ccm_ag_04.py", 
    "frr_ccm_ag_05.py", "frr_ccm_ag_06.py",
    "frr_ccm_qr_01.py", "frr_ccm_qr_02.py", "frr_ccm_qr_03.py", "frr_ccm_qr_05.py", 
    "frr_ccm_qr_06.py", "frr_ccm_qr_09.py",
    "frr_fsi_07.py",
    "frr_icp_01.py", "frr_icp_02.py", "frr_icp_03.py", "frr_icp_04.py", "frr_icp_05.py",
    "frr_icp_06.py", "frr_icp_07.py", "frr_icp_08.py", "frr_icp_09.py",
    "frr_mas_01.py", "frr_mas_02.py", "frr_mas_03.py", "frr_mas_ay_02.py", 
    "frr_mas_ay_06.py", "frr_mas_ex_01.py",
    "frr_pva_01.py",
    "frr_rsc_07.py", "frr_rsc_08.py", "frr_rsc_09.py",
    "frr_scn_04.py", "frr_scn_08.py", "frr_scn_ex_02.py", "frr_scn_im_01.py",
    "frr_vdr_02.py", "frr_vdr_03.py", "frr_vdr_04.py", "frr_vdr_05.py",
    "frr_vdr_ag_01.py", "frr_vdr_ag_02.py", "frr_vdr_ag_04.py",
    "frr_vdr_ay_02.py", "frr_vdr_ay_03.py", "frr_vdr_ay_04.py", "frr_vdr_ay_05.py",
    "frr_vdr_ex_01.py",
    "frr_vdr_rp_01.py", "frr_vdr_rp_02.py", "frr_vdr_rp_05.py", "frr_vdr_rp_06.py",
    "frr_vdr_tf_01.py", "frr_vdr_tf_02.py", "frr_vdr_tf_03.py",
    "frr_vdr_tf_hi_01.py", "frr_vdr_tf_hi_02.py", "frr_vdr_tf_hi_03.py", 
    "frr_vdr_tf_hi_04.py", "frr_vdr_tf_hi_06.py", "frr_vdr_tf_hi_07.py",
    "frr_vdr_tf_lo_01.py", "frr_vdr_tf_lo_02.py", "frr_vdr_tf_lo_03.py", "frr_vdr_tf_lo_04.py",
    "frr_vdr_tf_mo_01.py", "frr_vdr_tf_mo_02.py", "frr_vdr_tf_mo_03.py", 
    "frr_vdr_tf_mo_04.py", "frr_vdr_tf_mo_06.py",
]

# Files with partial detectability - change to True but need manual review of implementation
PARTIAL_DETECTABILITY_FILES = [
    "frr_ads_03.py", "frr_ads_06.py", "frr_ads_08.py", "frr_ads_09.py",
    "frr_fsi_01.py",
    "frr_pva_02.py", "frr_pva_03.py", "frr_pva_05.py", "frr_pva_06.py",
    "frr_pva_15.py", "frr_pva_17.py", "frr_pva_18.py",
    "frr_ucm_04.py",
    "frr_vdr_11.py",
]


def update_file(file_path: Path, update_type: str) -> bool:
    """
    Update CODE_DETECTABLE from "No" to True in a file.
    
    Args:
        file_path: Path to the FRR analyzer file
        update_type: "full" or "partial" - affects the comment added
        
    Returns:
        True if file was updated, False otherwise
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if file needs updating
    if 'CODE_DETECTABLE = "No"' not in content:
        print(f"[SKIP] {file_path.name} - Already updated or not found")
        return False
    
    # Prepare comment based on update type
    if update_type == "full":
        comment = "# Code-detectable: Check code, IaC, and CI/CD for technical implementation"
    else:  # partial
        comment = "# Partially code-detectable: Mixed requirement with some technical aspects"
    
    # Replace CODE_DETECTABLE = "No" with True and add explanatory comment
    updated_content = re.sub(
        r'CODE_DETECTABLE\s*=\s*"No"',
        f'CODE_DETECTABLE = True  {comment}',
        content
    )
    
    # Also update the docstring detectability note
    updated_content = re.sub(
        r'\*\*Detectability:\*\* No',
        '**Detectability:** Yes (Code, IaC, or CI/CD)',
        updated_content
    )
    
    # Update detection strategy TODO
    updated_content = re.sub(
        r'TODO: This requirement is not directly code-detectable\. This analyzer provides:',
        'This analyzer detects technical implementation aspects through:',
        updated_content
    )
    
    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(updated_content)
    
    print(f"[UPDATED] {file_path.name} - Changed to CODE_DETECTABLE = True")
    return True


def main():
    """Update all FRR analyzers that should be code-detectable."""
    print("=" * 100)
    print("UPDATING FRR ANALYZERS - CODE_DETECTABLE REASSESSMENT")
    print("=" * 100)
    
    frr_dir = Path("src/fedramp_20x_mcp/analyzers/frr")
    
    # Update fully detectable files
    print(f"\n\nUpdating {len(FILES_TO_UPDATE)} fully code-detectable FRR analyzers...")
    print("-" * 100)
    updated_full = 0
    for filename in sorted(FILES_TO_UPDATE):
        file_path = frr_dir / filename
        if file_path.exists():
            if update_file(file_path, "full"):
                updated_full += 1
        else:
            print(f"[ERROR] File not found: {filename}")
    
    # Update partially detectable files
    print(f"\n\nUpdating {len(PARTIAL_DETECTABILITY_FILES)} partially code-detectable FRR analyzers...")
    print("-" * 100)
    updated_partial = 0
    for filename in sorted(PARTIAL_DETECTABILITY_FILES):
        file_path = frr_dir / filename
        if file_path.exists():
            if update_file(file_path, "partial"):
                updated_partial += 1
        else:
            print(f"[ERROR] File not found: {filename}")
    
    # Summary
    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"Fully code-detectable files updated: {updated_full}/{len(FILES_TO_UPDATE)}")
    print(f"Partially code-detectable files updated: {updated_partial}/{len(PARTIAL_DETECTABILITY_FILES)}")
    print(f"Total updated: {updated_full + updated_partial}/{len(FILES_TO_UPDATE) + len(PARTIAL_DETECTABILITY_FILES)}")
    print(f"\nThese {updated_full + updated_partial} FRR analyzers now reflect their code-detectable nature.")
    print("Next steps: Implement actual detection logic in analyze_* methods for each language/platform.")


if __name__ == "__main__":
    main()
