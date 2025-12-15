"""
Fix hardcoded absolute paths in metadata JSON files.

Converts absolute Windows paths like:
    "C:\\Source\\FedRAMP20xMCP\\src\\fedramp_20x_mcp\\analyzers\\ksi\\ksi_afr_01.py"
To relative paths like:
    "src/fedramp_20x_mcp/analyzers/ksi/ksi_afr_01.py"
"""
import json
import re
from pathlib import Path


def fix_metadata_paths(file_path: Path) -> None:
    """Fix hardcoded paths in a metadata JSON file."""
    print(f"\nProcessing {file_path.name}...")
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Count occurrences before
    matches_before = len(re.findall(r'C:\\\\Source\\\\FedRAMP20xMCP\\\\', content))
    print(f"  Found {matches_before} hardcoded paths")
    
    # Replace absolute paths with relative paths
    # Pattern: "C:\\Source\\FedRAMP20xMCP\\src\\..." -> "src/..."
    # Use forward slashes for cross-platform compatibility
    content = re.sub(
        r'"C:\\\\Source\\\\FedRAMP20xMCP\\\\([^"]+)"',
        lambda m: '"' + m.group(1).replace('\\\\', '/') + '"',
        content
    )
    
    # Verify replacement
    matches_after = len(re.findall(r'C:\\\\Source\\\\FedRAMP20xMCP\\\\', content))
    if matches_after > 0:
        print(f"  WARNING: {matches_after} hardcoded paths remain!")
        return
    
    # Write back to file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"  ✓ Fixed {matches_before} paths → relative paths with forward slashes")
    
    # Validate JSON structure
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            json.load(f)
        print(f"  ✓ JSON structure validated")
    except json.JSONDecodeError as e:
        print(f"  ✗ JSON validation failed: {e}")
        raise


def main():
    """Fix hardcoded paths in all metadata files."""
    repo_root = Path(__file__).parent.parent
    data_dir = repo_root / "data" / "requirements"
    
    metadata_files = [
        data_dir / "ksi_metadata.json",
        data_dir / "frr_metadata.json",
    ]
    
    print("=" * 60)
    print("Fixing hardcoded paths in metadata files")
    print("=" * 60)
    
    for file_path in metadata_files:
        if not file_path.exists():
            print(f"\nSkipping {file_path.name} (not found)")
            continue
        
        fix_metadata_paths(file_path)
    
    print("\n" + "=" * 60)
    print("✓ All metadata files processed successfully")
    print("=" * 60)


if __name__ == "__main__":
    main()
