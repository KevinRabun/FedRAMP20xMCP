#!/usr/bin/env python3
"""
Metadata Extraction Script for Data-Driven Refactoring

This script extracts metadata from all KSI and FRR analyzer classes and generates
JSON files for the data-driven architecture.

Phase 1 of the refactoring plan: Extract metadata to create single source of truth.
"""

import ast
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def extract_class_attributes(node: ast.ClassDef) -> Dict[str, Any]:
    """Extract class-level attributes from an analyzer class."""
    attributes = {}
    
    for item in node.body:
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    attr_name = target.id
                    try:
                        # Try to evaluate the value
                        value = ast.literal_eval(item.value)
                        attributes[attr_name] = value
                    except (ValueError, TypeError):
                        # For complex expressions, store as string
                        attributes[attr_name] = ast.unparse(item.value)
    
    return attributes


def extract_docstring(node: ast.ClassDef) -> Optional[str]:
    """Extract docstring from class."""
    if (node.body and 
        isinstance(node.body[0], ast.Expr) and 
        isinstance(node.body[0].value, ast.Constant)):
        return node.body[0].value.value
    return None


def parse_analyzer_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Parse a single analyzer file and extract metadata."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content)
        
        # Find the analyzer class (should be the main class in the file)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Look for classes ending with 'Analyzer'
                if node.name.endswith('Analyzer'):
                    attributes = extract_class_attributes(node)
                    docstring = extract_docstring(node)
                    
                    # Extract module docstring
                    module_docstring = None
                    if (tree.body and 
                        isinstance(tree.body[0], ast.Expr) and 
                        isinstance(tree.body[0].value, ast.Constant)):
                        module_docstring = tree.body[0].value.value
                    
                    return {
                        'class_name': node.name,
                        'file_path': str(file_path),
                        'attributes': attributes,
                        'docstring': docstring,
                        'module_docstring': module_docstring
                    }
        
        return None
    
    except Exception as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)
        return None


def normalize_ksi_metadata(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize extracted KSI metadata to standard schema."""
    attrs = raw_data['attributes']
    
    # Extract NIST controls
    nist_controls = []
    if 'NIST_CONTROLS' in attrs:
        controls_raw = attrs['NIST_CONTROLS']
        if isinstance(controls_raw, list):
            for item in controls_raw:
                if isinstance(item, tuple) and len(item) >= 2:
                    nist_controls.append({
                        'id': item[0],
                        'name': item[1]
                    })
                elif isinstance(item, str):
                    nist_controls.append({'id': item, 'name': ''})
    
    # Extract impact levels
    impact_levels = []
    if attrs.get('IMPACT_LOW'):
        impact_levels.append('Low')
    if attrs.get('IMPACT_MODERATE'):
        impact_levels.append('Moderate')
    if attrs.get('IMPACT_HIGH'):
        impact_levels.append('High')
    
    # Extract related requirements
    related_ksis = attrs.get('RELATED_KSIS', [])
    if isinstance(related_ksis, str):
        related_ksis = [related_ksis]
    
    related_frrs = attrs.get('RELATED_FRRS', [])
    if isinstance(related_frrs, str):
        related_frrs = [related_frrs]
    
    metadata = {
        'id': attrs.get('KSI_ID', ''),
        'name': attrs.get('KSI_NAME', ''),
        'statement': attrs.get('KSI_STATEMENT', ''),
        'family': attrs.get('FAMILY', ''),
        'family_name': attrs.get('FAMILY_NAME', ''),
        'impact_levels': impact_levels,
        'nist_controls': nist_controls,
        'code_detectable': attrs.get('CODE_DETECTABLE', False),
        'implementation_status': attrs.get('IMPLEMENTATION_STATUS', 'NOT_IMPLEMENTED'),
        'retired': attrs.get('RETIRED', False),
        'related_ksis': related_ksis,
        'related_frrs': related_frrs,
        'source_file': raw_data['file_path'],
        'class_name': raw_data['class_name']
    }
    
    return metadata


def normalize_frr_metadata(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize extracted FRR metadata to standard schema."""
    attrs = raw_data['attributes']
    
    # Extract NIST controls
    nist_controls = []
    if 'NIST_CONTROLS' in attrs:
        controls_raw = attrs['NIST_CONTROLS']
        if isinstance(controls_raw, list):
            for item in controls_raw:
                if isinstance(item, tuple) and len(item) >= 2:
                    nist_controls.append({
                        'id': item[0],
                        'name': item[1]
                    })
                elif isinstance(item, str):
                    nist_controls.append({'id': item, 'name': ''})
    
    # Extract impact levels
    impact_levels = []
    if attrs.get('IMPACT_LOW'):
        impact_levels.append('Low')
    if attrs.get('IMPACT_MODERATE'):
        impact_levels.append('Moderate')
    if attrs.get('IMPACT_HIGH'):
        impact_levels.append('High')
    
    # Extract related requirements
    related_ksis = attrs.get('RELATED_KSIS', [])
    if isinstance(related_ksis, str):
        related_ksis = [related_ksis]
    
    related_frrs = attrs.get('RELATED_FRRS', [])
    if isinstance(related_frrs, str):
        related_frrs = [related_frrs]
    
    metadata = {
        'id': attrs.get('FRR_ID', ''),
        'name': attrs.get('FRR_NAME', ''),
        'statement': attrs.get('FRR_STATEMENT', ''),
        'family': attrs.get('FAMILY', ''),
        'family_name': attrs.get('FAMILY_NAME', ''),
        'primary_keyword': attrs.get('PRIMARY_KEYWORD', ''),
        'impact_levels': impact_levels,
        'nist_controls': nist_controls,
        'code_detectable': attrs.get('CODE_DETECTABLE', False),
        'implementation_status': attrs.get('IMPLEMENTATION_STATUS', 'NOT_IMPLEMENTED'),
        'related_ksis': related_ksis,
        'related_frrs': related_frrs,
        'source_file': raw_data['file_path'],
        'class_name': raw_data['class_name']
    }
    
    return metadata


def extract_ksi_metadata(ksi_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Extract metadata from all KSI analyzer files."""
    ksi_metadata = {}
    
    ksi_files = sorted(ksi_dir.glob('ksi_*.py'))
    print(f"Found {len(ksi_files)} KSI analyzer files")
    
    for file_path in ksi_files:
        if file_path.name == '__init__.py':
            continue
        
        print(f"Processing {file_path.name}...", end=' ')
        raw_data = parse_analyzer_file(file_path)
        
        if raw_data and 'KSI_ID' in raw_data['attributes']:
            metadata = normalize_ksi_metadata(raw_data)
            ksi_id = metadata['id']
            ksi_metadata[ksi_id] = metadata
            print(f"✓ {ksi_id}")
        else:
            print("✗ (no metadata found)")
    
    return ksi_metadata


def extract_frr_metadata(frr_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Extract metadata from all FRR analyzer files."""
    frr_metadata = {}
    
    frr_files = sorted(frr_dir.glob('frr_*.py'))
    print(f"Found {len(frr_files)} FRR analyzer files")
    
    for file_path in frr_files:
        if file_path.name == '__init__.py':
            continue
        
        print(f"Processing {file_path.name}...", end=' ')
        raw_data = parse_analyzer_file(file_path)
        
        if raw_data and 'FRR_ID' in raw_data['attributes']:
            metadata = normalize_frr_metadata(raw_data)
            frr_id = metadata['id']
            frr_metadata[frr_id] = metadata
            print(f"✓ {frr_id}")
        else:
            print("✗ (no metadata found)")
    
    return frr_metadata


def generate_summary(ksi_metadata: Dict, frr_metadata: Dict) -> Dict[str, Any]:
    """Generate summary statistics."""
    ksi_families = {}
    frr_families = {}
    
    for ksi_id, data in ksi_metadata.items():
        family = data['family']
        ksi_families[family] = ksi_families.get(family, 0) + 1
    
    for frr_id, data in frr_metadata.items():
        family = data['family']
        frr_families[family] = frr_families.get(family, 0) + 1
    
    return {
        'extraction_date': '2024-12-12',
        'total_ksis': len(ksi_metadata),
        'total_frrs': len(frr_metadata),
        'ksi_families': ksi_families,
        'frr_families': frr_families,
        'ksi_implemented': sum(1 for d in ksi_metadata.values() if d['implementation_status'] == 'IMPLEMENTED'),
        'frr_implemented': sum(1 for d in frr_metadata.values() if d['implementation_status'] == 'IMPLEMENTED'),
        'ksi_retired': sum(1 for d in ksi_metadata.values() if d['retired']),
    }


def main():
    """Main extraction process."""
    # Setup paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    ksi_dir = project_root / "src" / "fedramp_20x_mcp" / "analyzers" / "ksi"
    frr_dir = project_root / "src" / "fedramp_20x_mcp" / "analyzers" / "frr"
    output_dir = project_root / "data" / "requirements"
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 80)
    print("FedRAMP 20x Metadata Extraction")
    print("=" * 80)
    print()
    
    # Extract KSI metadata
    print("Extracting KSI metadata...")
    print("-" * 80)
    ksi_metadata = extract_ksi_metadata(ksi_dir)
    print(f"\n✓ Extracted {len(ksi_metadata)} KSI requirements\n")
    
    # Extract FRR metadata
    print("Extracting FRR metadata...")
    print("-" * 80)
    frr_metadata = extract_frr_metadata(frr_dir)
    print(f"\n✓ Extracted {len(frr_metadata)} FRR requirements\n")
    
    # Generate summary
    summary = generate_summary(ksi_metadata, frr_metadata)
    
    # Write output files
    print("Writing output files...")
    print("-" * 80)
    
    ksi_output = output_dir / "ksi_metadata.json"
    with open(ksi_output, 'w', encoding='utf-8') as f:
        json.dump(ksi_metadata, f, indent=2, ensure_ascii=False)
    print(f"✓ {ksi_output}")
    
    frr_output = output_dir / "frr_metadata.json"
    with open(frr_output, 'w', encoding='utf-8') as f:
        json.dump(frr_metadata, f, indent=2, ensure_ascii=False)
    print(f"✓ {frr_output}")
    
    summary_output = output_dir / "extraction_summary.json"
    with open(summary_output, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"✓ {summary_output}")
    
    # Print summary
    print()
    print("=" * 80)
    print("Extraction Summary")
    print("=" * 80)
    print(f"Total KSI requirements: {summary['total_ksis']}")
    print(f"  - Implemented: {summary['ksi_implemented']}")
    print(f"  - Retired: {summary['ksi_retired']}")
    print(f"\nKSI Families:")
    for family, count in sorted(summary['ksi_families'].items()):
        print(f"  - {family}: {count}")
    
    print(f"\nTotal FRR requirements: {summary['total_frrs']}")
    print(f"  - Implemented: {summary['frr_implemented']}")
    print(f"\nFRR Families:")
    for family, count in sorted(summary['frr_families'].items()):
        print(f"  - {family}: {count}")
    
    print("\n✓ Metadata extraction complete!")
    print(f"Output directory: {output_dir}")


if __name__ == '__main__':
    main()
