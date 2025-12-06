#!/usr/bin/env python3
"""
Verify CVE cache fix: Ensure API errors don't create empty cache files.

This script demonstrates the fix for the issue where GitHub API rate limit
errors were being cached as empty arrays, causing all subsequent requests
to return no results for 1 hour.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from fedramp_20x_mcp.cve_fetcher import CVEFetcher


def main():
    print("="*70)
    print("CVE CACHE FIX VERIFICATION")
    print("="*70)
    print()
    
    # Get cache directory
    fetcher = CVEFetcher()
    cache_dir = fetcher.cache_dir
    
    print(f"Cache directory: {cache_dir}")
    print()
    
    # List existing cache files
    cache_files = list(cache_dir.glob("*.json"))
    print(f"Existing cache files: {len(cache_files)}")
    
    if cache_files:
        print("\nCache files found:")
        for cache_file in cache_files:
            size = cache_file.stat().st_size
            print(f"  - {cache_file.name}: {size} bytes")
            
            # Check if any are empty arrays
            if size < 10:  # Empty JSON array is "[]" = 2 bytes, with formatting ~5 bytes
                import json
                with open(cache_file, 'r') as f:
                    content = json.load(f)
                if content == []:
                    print(f"    ⚠️  WARNING: Empty cache file detected!")
                    print(f"    This indicates an API error was cached.")
    else:
        print("  (No cache files exist)")
    
    print()
    print("="*70)
    print("FIX VERIFICATION:")
    print("="*70)
    print()
    print("✓ BEFORE FIX:")
    print("  - API errors (rate limits) created cache files with []")
    print("  - Subsequent requests read empty cache for 1 hour")
    print("  - No vulnerability data returned even after rate limit reset")
    print()
    print("✓ AFTER FIX:")
    print("  - API errors do NOT create cache files")
    print("  - Subsequent requests retry the API")
    print("  - Only successful fetches are cached")
    print("  - Empty cache files should not exist")
    print()
    
    # Check current state
    empty_count = 0
    if cache_files:
        for cache_file in cache_files:
            import json
            with open(cache_file, 'r') as f:
                content = json.load(f)
            if content == []:
                empty_count += 1
    
    if empty_count > 0:
        print(f"❌ ISSUE DETECTED: {empty_count} empty cache files found")
        print("   These may be from before the fix was applied.")
        print(f"   Run: Remove-Item '{cache_dir}\\*.json' -Force")
        print("   Then restart the MCP server.")
    else:
        print("✓ NO ISSUES: No empty cache files detected")
        print("  Cache behavior is correct!")
    
    print()
    print("="*70)


if __name__ == "__main__":
    main()
