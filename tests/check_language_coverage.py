#!/usr/bin/env python3
"""
Check language coverage consistency across all pattern files.
Application patterns should have: Python, C#, Java, TypeScript/JavaScript
"""

import yaml
from pathlib import Path
from collections import defaultdict

def check_pattern_file(file_path):
    """Check a single pattern file for language coverage issues."""
    issues = []
    pattern_count = 0
    
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            # Load all YAML documents
            docs = list(yaml.safe_load_all(f))
            
            for doc in docs:
                if not doc or 'pattern_id' not in doc:
                    continue
                    
                pattern_count += 1
                pattern_id = doc['pattern_id']
                pattern_type = doc.get('pattern_type', 'unknown')
                
                # Skip non-application patterns
                if pattern_type in ['resource', 'pipeline', 'configuration']:
                    # Check if it's really an application pattern
                    languages = doc.get('languages', [])
                    
                    # Convert dict to list of keys if needed
                    if isinstance(languages, dict):
                        languages = list(languages.keys())
                    
                    # Normalize language names
                    languages = [lang.lower().replace('typescript', 'typescript')
                                for lang in languages]
                    
                    # Only check if it has application languages
                    app_languages = {'python', 'csharp', 'java', 'typescript'}
                    has_app_lang = any(lang in app_languages for lang in languages)
                    
                    if not has_app_lang:
                        continue  # It's IaC/CI/CD only
                
                # Get languages for this pattern
                languages = doc.get('languages', [])
                
                if not languages:
                    continue  # No languages defined
                
                # Convert dict to list of keys if needed (Phase 1 format)
                if isinstance(languages, dict):
                    languages = list(languages.keys())
                
                # Normalize language names
                normalized = set()
                for lang in languages:
                    lang_lower = lang.lower()
                    if lang_lower in ['python', 'py']:
                        normalized.add('python')
                    elif lang_lower in ['csharp', 'c#', 'cs']:
                        normalized.add('csharp')
                    elif lang_lower in ['java']:
                        normalized.add('java')
                    elif lang_lower in ['typescript', 'javascript', 'ts', 'js']:
                        normalized.add('typescript')
                    elif lang_lower in ['bicep']:
                        normalized.add('bicep')
                    elif lang_lower in ['terraform', 'tf']:
                        normalized.add('terraform')
                    elif lang_lower in ['yaml', 'yml']:
                        normalized.add('yaml')
                    elif lang_lower in ['github_actions', 'github-actions']:
                        normalized.add('github_actions')
                    elif lang_lower in ['azure_pipelines', 'azure-pipelines']:
                        normalized.add('azure_pipelines')
                    elif lang_lower in ['gitlab_ci', 'gitlab-ci']:
                        normalized.add('gitlab_ci')
                    elif lang_lower in ['dockerfile', 'docker']:
                        normalized.add('dockerfile')
                    elif lang_lower in ['json']:
                        normalized.add('json')
                
                # Determine if this is an application pattern
                app_languages = {'python', 'csharp', 'java', 'typescript'}
                iac_languages = {'bicep', 'terraform'}
                cicd_languages = {'github_actions', 'azure_pipelines', 'gitlab_ci'}
                
                has_app = bool(normalized & app_languages)
                has_iac = bool(normalized & iac_languages)
                has_cicd = bool(normalized & cicd_languages)
                
                # Check for missing application languages
                if has_app and not has_iac and not has_cicd:
                    # This is an application pattern
                    missing = app_languages - normalized
                    if missing:
                        issues.append({
                            'pattern_id': pattern_id,
                            'pattern_type': pattern_type,
                            'has_languages': sorted(normalized & app_languages),
                            'missing_languages': sorted(missing),
                            'severity': 'WARNING'
                        })
                
        except yaml.YAMLError as e:
            print(f"ERROR parsing {file_path.name}: {e}")
    
    return issues, pattern_count

def main():
    """Check all pattern files."""
    pattern_dir = Path(__file__).parent.parent / 'data' / 'patterns'
    
    all_issues = []
    total_patterns = 0
    
    # Check all pattern files
    for pattern_file in sorted(pattern_dir.glob('*_patterns.yaml')):
        issues, count = check_pattern_file(pattern_file)
        total_patterns += count
        
        if issues:
            print(f"\n{'='*70}")
            print(f"File: {pattern_file.name}")
            print(f"{'='*70}")
            for issue in issues:
                print(f"\nPattern: {issue['pattern_id']}")
                print(f"  Type: {issue['pattern_type']}")
                print(f"  Has: {', '.join(issue['has_languages'])}")
                print(f"  Missing: {', '.join(issue['missing_languages'])}")
            all_issues.extend(issues)
    
    # Summary
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total patterns checked: {total_patterns}")
    print(f"Patterns with missing languages: {len(all_issues)}")
    
    if all_issues:
        print(f"\nRECOMMENDATION:")
        print(f"Add missing languages to ensure consistency across application patterns.")
        print(f"Application patterns should include: Python, C#, Java, TypeScript/JavaScript")
        return 1
    else:
        print(f"\nAll application patterns have complete language coverage!")
        return 0

if __name__ == '__main__':
    exit(main())
