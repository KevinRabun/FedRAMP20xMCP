"""Fix Unicode characters in all test files for Windows compatibility."""

import os
import re
from pathlib import Path

# Unicode to ASCII mappings
REPLACEMENTS = {
    '\u2713': '[PASS]',  # ✓
    '\u2705': '[OK]',    # ✅
    '\u274c': '[FAIL]',  # ❌
    '\u2717': '[FAIL]',  # ✗
    '\u2718': '[FAIL]',  # ✘
    '\u2192': '->',      # →
    '\u2190': '<-',      # ←
    '\u2191': '^',       # ↑
    '\u2193': 'v',       # ↓
    '\U0001f4ca': '[DATA]',  # 📊
    '\U0001f4dd': '[NOTE]',  # 📝
    '\U0001f4cb': '[LIST]',  # 📋
    '\U0001f4c4': '[FILE]',  # 📄
    '\U0001f4c5': '[DATE]',  # 📅
    '\U0001f4c6': '[CAL]',   # 📆
    '\u26a0\ufe0f': '[WARN]',  # ⚠️
    '\u26a0': '[WARN]',  # ⚠
}

def fix_file(filepath):
    """Fix Unicode characters in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Replace known Unicode characters
        for unicode_char, ascii_replacement in REPLACEMENTS.items():
            content = content.replace(unicode_char, ascii_replacement)
        
        # Remove any remaining emojis (chars > U+1F000)
        content = re.sub(r'[\U0001F000-\U0001F9FF]', '[EMOJI]', content)
        
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    tests_dir = Path(__file__).parent
    python_files = list(tests_dir.glob('test_*.py'))
    
    fixed_count = 0
    for filepath in python_files:
        if fix_file(filepath):
            print(f"Fixed: {filepath.name}")
            fixed_count += 1
        else:
            print(f"No changes: {filepath.name}")
    
    print(f"\n Total: {fixed_count}/{len(python_files)} files fixed")

if __name__ == "__main__":
    main()
