#!/usr/bin/env python3
"""
Fix test files by removing sys.path manipulation that breaks pytest.

The package is installed with `pip install -e ".[dev]"` in GitHub Actions,
so sys.path.insert is unnecessary and breaks pytest's capture mechanism.
"""

import re
from pathlib import Path

def fix_file(filepath: Path):
    """Remove sys.path manipulation from a test file."""
    content = filepath.read_text(encoding='utf-8')
    original = content
    
    # Remove sys import if it's only used for sys.path
    # Pattern 1: Remove sys.path.insert lines
    content = re.sub(r'\nsys\.path\.insert\(.*?\)\n', '\n', content)
    
    # Pattern 2: Remove sys import if no longer needed
    lines = content.split('\n')
    filtered = []
    for i, line in enumerate(lines):
        # Skip sys import if sys is not used elsewhere in the file
        if line.strip().startswith('import sys'):
            # Check if sys is used elsewhere
            rest_of_file = '\n'.join(lines[i+1:])
            if 'sys.' not in rest_of_file or only_stdout_wrapper(rest_of_file):
                continue  # Skip this line
        # Skip UTF-8 wrapper lines
        if 'sys.stdout = io.TextIOWrapper' in line:
            continue
        filtered.append(line)
    
    content = '\n'.join(filtered)
    
    # Remove pathlib import if not needed
    if 'from pathlib import Path' in content:
        # Check if Path is used elsewhere
        temp = content.replace('from pathlib import Path', '')
        if 'Path(' not in temp:
            content = content.replace('from pathlib import Path\n', '')
    
    # Clean up multiple blank lines
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    if content != original:
        filepath.write_text(content, encoding='utf-8')
        print(f"Fixed: {filepath.name}")
        return True
    return False

def only_stdout_wrapper(text: str) -> bool:
    """Check if sys is only used for stdout wrapper."""
    sys_uses = [m.group() for m in re.finditer(r'sys\.\w+', text)]
    return all('sys.stdout' in use for use in sys_uses)

# Fix all test files with sys.path manipulation
test_files = [
    "test_audit_tools.py",
    "test_code_analyzer.py",
    "test_cve_fetcher.py",
    "test_docs_integration.py",
    "test_implementation_mapping_tools.py",
    "test_implementation_questions.py",
    "test_ksi_architecture.py",
    "test_new_language_support.py",
    "test_prompts.py",
    "test_security_tools.py",
    "test_templates.py",
]

tests_dir = Path(__file__).parent / "tests"
fixed_count = 0

for filename in test_files:
    filepath = tests_dir / filename
    if filepath.exists():
        if fix_file(filepath):
            fixed_count += 1

print(f"\nFixed {fixed_count} test files")
