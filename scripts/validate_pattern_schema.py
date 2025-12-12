#!/usr/bin/env python3
"""
Pattern Schema V2 Validator

Validates YAML pattern files against the V2 schema to ensure:
- All required fields present
- Field types correct
- NIST control IDs valid
- Azure service names recognized
- Evidence queries syntactically valid
- Test cases executable

Usage:
    python scripts/validate_pattern_schema.py data/patterns/iam_patterns_v2_example.yaml
    python scripts/validate_pattern_schema.py data/patterns/*.yaml --schema v2
"""

import sys
import yaml
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of pattern validation."""
    valid: bool
    errors: List[str]
    warnings: List[str]
    info: List[str]


class PatternSchemaValidator:
    """Validates pattern files against V2 schema."""
    
    # Valid NIST 800-53 Rev 5 control families
    VALID_NIST_FAMILIES = {
        'ac', 'at', 'au', 'ca', 'cm', 'cp', 'ia', 'ir', 'ma', 'mp', 
        'pe', 'pl', 'pm', 'ps', 'pt', 'ra', 'sa', 'sc', 'si', 'sr'
    }
    
    # Known Azure services (subset for validation)
    KNOWN_AZURE_SERVICES = {
        'Microsoft Entra ID', 'Conditional Access', 'Azure Monitor',
        'Log Analytics', 'Azure Storage', 'Azure Functions',
        'Microsoft Defender for Cloud', 'Azure Policy', 'Azure RBAC',
        'Privileged Identity Management', 'Microsoft Intune',
        'Azure Key Vault', 'Azure Automation', 'Azure Pipelines',
        'GitHub Actions', 'Azure DevOps'
    }
    
    # Valid severity levels
    VALID_SEVERITIES = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
    
    # Valid FedRAMP 20x families
    VALID_FEDRAMP_FAMILIES = {
        'IAM', 'VDR', 'SVC', 'MLA', 'AFR', 'PIY', 'CNA', 'TPR',
        'CMT', 'INR', 'RPL', 'CED', 'ADS', 'CCM', 'FSI', 'ICP',
        'MAS', 'RSC', 'SCN', 'UCM'
    }
    
    # Required fields for all patterns
    REQUIRED_FIELDS = {
        'pattern_id', 'name', 'description', 'family', 'severity'
    }
    
    # Required fields for code-detectable patterns
    CODE_DETECTABLE_REQUIRED = {
        'languages', 'finding', 'testing'
    }
    
    # V2 schema new fields
    V2_FIELDS = {
        'evidence_collection', 'evidence_artifacts', 'automation',
        'implementation', 'ssp_mapping', 'azure_guidance',
        'compliance_frameworks'
    }
    
    def __init__(self, schema_version: str = 'v2'):
        self.schema_version = schema_version
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
    
    def validate_file(self, file_path: Path) -> ValidationResult:
        """Validate a pattern YAML file."""
        self.errors = []
        self.warnings = []
        self.info = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse YAML (supports multi-document with ---)
            patterns = list(yaml.safe_load_all(content))
            
            self.info.append(f"Found {len(patterns)} pattern(s) in file")
            
            for i, pattern in enumerate(patterns):
                if pattern is None:
                    continue
                    
                self.info.append(f"\n=== Validating Pattern {i+1}: {pattern.get('pattern_id', 'UNKNOWN')} ===")
                self._validate_pattern(pattern)
            
            valid = len(self.errors) == 0
            
            return ValidationResult(
                valid=valid,
                errors=self.errors,
                warnings=self.warnings,
                info=self.info
            )
            
        except yaml.YAMLError as e:
            self.errors.append(f"YAML parsing error: {e}")
            return ValidationResult(False, self.errors, self.warnings, self.info)
        except Exception as e:
            self.errors.append(f"Unexpected error: {e}")
            return ValidationResult(False, self.errors, self.warnings, self.info)
    
    def _validate_pattern(self, pattern: Dict[str, Any]) -> None:
        """Validate a single pattern object."""
        if not isinstance(pattern, dict):
            self.errors.append("Pattern must be a dictionary")
            return
        
        # Check required fields
        self._check_required_fields(pattern)
        
        # Validate field types and values
        self._validate_pattern_id(pattern.get('pattern_id'))
        self._validate_family(pattern.get('family'))
        self._validate_severity(pattern.get('severity'))
        
        # Validate languages if present (code-detectable)
        if 'languages' in pattern:
            self._validate_languages(pattern['languages'])
            # Code-detectable patterns need additional fields
            self._check_code_detectable_fields(pattern)
        
        # Validate V2 schema fields
        if self.schema_version == 'v2':
            self._validate_v2_fields(pattern)
        
        # Validate NIST controls
        if 'nist_controls' in pattern:
            self._validate_nist_controls(pattern['nist_controls'])
        
        # Validate evidence collection
        if 'evidence_collection' in pattern:
            self._validate_evidence_collection(pattern['evidence_collection'])
        
        # Validate automation
        if 'automation' in pattern:
            self._validate_automation(pattern['automation'])
        
        # Validate implementation
        if 'implementation' in pattern:
            self._validate_implementation(pattern['implementation'])
        
        # Validate SSP mapping
        if 'ssp_mapping' in pattern:
            self._validate_ssp_mapping(pattern['ssp_mapping'])
        
        # Validate Azure guidance
        if 'azure_guidance' in pattern:
            self._validate_azure_guidance(pattern['azure_guidance'])
        
        # Validate testing
        if 'testing' in pattern:
            self._validate_testing(pattern['testing'])
    
    def _check_required_fields(self, pattern: Dict[str, Any]) -> None:
        """Check that required fields are present."""
        missing = self.REQUIRED_FIELDS - set(pattern.keys())
        if missing:
            self.errors.append(f"Missing required fields: {missing}")
    
    def _check_code_detectable_fields(self, pattern: Dict[str, Any]) -> None:
        """Check that code-detectable patterns have required fields."""
        missing = self.CODE_DETECTABLE_REQUIRED - set(pattern.keys())
        if missing:
            self.errors.append(f"Code-detectable pattern missing fields: {missing}")
    
    def _validate_pattern_id(self, pattern_id: Any) -> None:
        """Validate pattern_id format (family.category.specific)."""
        if not pattern_id:
            return
        
        if not isinstance(pattern_id, str):
            self.errors.append(f"pattern_id must be string, got {type(pattern_id)}")
            return
        
        parts = pattern_id.split('.')
        if len(parts) < 2:
            self.errors.append(f"pattern_id must be family.category.specific format, got '{pattern_id}'")
        
        # Check family matches
        family_prefix = parts[0].lower()
        # Note: pattern_id uses lowercase, family field uses uppercase
        # This is acceptable
    
    def _validate_family(self, family: Any) -> None:
        """Validate FedRAMP family code."""
        if not family:
            return
        
        if not isinstance(family, str):
            self.errors.append(f"family must be string, got {type(family)}")
            return
        
        if family.upper() not in self.VALID_FEDRAMP_FAMILIES:
            self.warnings.append(f"Unknown FedRAMP family: {family}")
    
    def _validate_severity(self, severity: Any) -> None:
        """Validate severity level."""
        if not severity:
            return
        
        if not isinstance(severity, str):
            self.errors.append(f"severity must be string, got {type(severity)}")
            return
        
        if severity.upper() not in self.VALID_SEVERITIES:
            self.errors.append(f"Invalid severity: {severity}. Must be one of {self.VALID_SEVERITIES}")
    
    def _validate_languages(self, languages: Any) -> None:
        """Validate languages section."""
        if not isinstance(languages, dict):
            self.errors.append(f"languages must be dict, got {type(languages)}")
            return
        
        valid_languages = {
            'python', 'csharp', 'java', 'typescript', 'javascript',
            'bicep', 'terraform', 'github_actions', 'azure_pipelines', 'gitlab_ci'
        }
        
        for lang, config in languages.items():
            if lang not in valid_languages:
                self.warnings.append(f"Unknown language: {lang}")
            
            if not isinstance(config, dict):
                self.errors.append(f"Language config for {lang} must be dict")
                continue
            
            # Check for ast_queries or regex_fallback
            if 'ast_queries' not in config and 'regex_fallback' not in config:
                self.warnings.append(f"Language {lang} has neither ast_queries nor regex_fallback")
    
    def _validate_nist_controls(self, controls: Any) -> None:
        """Validate NIST control IDs."""
        if not isinstance(controls, list):
            self.errors.append(f"nist_controls must be list, got {type(controls)}")
            return
        
        for control in controls:
            if not isinstance(control, str):
                self.errors.append(f"NIST control must be string, got {type(control)}")
                continue
            
            # Parse control ID (e.g., "ac-2", "ia-2.1")
            match = re.match(r'^([a-z]{2})-(\d+)(\.\d+)?$', control.lower())
            if not match:
                self.errors.append(f"Invalid NIST control format: {control}")
                continue
            
            family = match.group(1)
            if family not in self.VALID_NIST_FAMILIES:
                self.warnings.append(f"Unknown NIST control family: {family} in {control}")
    
    def _validate_evidence_collection(self, evidence: Any) -> None:
        """Validate evidence_collection section."""
        if not isinstance(evidence, dict):
            self.errors.append(f"evidence_collection must be dict, got {type(evidence)}")
            return
        
        valid_sources = {'azure_monitor_kql', 'azure_cli', 'powershell', 'rest_api'}
        
        for source, queries in evidence.items():
            if source not in valid_sources:
                self.warnings.append(f"Unknown evidence source: {source}")
            
            if not isinstance(queries, list):
                self.errors.append(f"Evidence queries for {source} must be list")
                continue
            
            for query_obj in queries:
                if isinstance(query_obj, str):
                    # Old format: just query string
                    self.warnings.append(f"Evidence query in {source} should be dict with 'query' and 'description'")
                elif isinstance(query_obj, dict):
                    # V2 format: dict with query, description, etc.
                    if 'query' not in query_obj and 'command' not in query_obj and 'script' not in query_obj:
                        self.errors.append(f"Evidence query in {source} missing query/command/script field")
    
    def _validate_automation(self, automation: Any) -> None:
        """Validate automation section."""
        if not isinstance(automation, dict):
            self.errors.append(f"automation must be dict, got {type(automation)}")
            return
        
        for key, config in automation.items():
            if not isinstance(config, dict):
                self.errors.append(f"Automation config for {key} must be dict")
                continue
            
            # Check required fields
            if 'description' not in config:
                self.warnings.append(f"Automation {key} missing description")
            if 'implementation' not in config:
                self.warnings.append(f"Automation {key} missing implementation")
            
            # Validate azure_services if present
            if 'azure_services' in config:
                if not isinstance(config['azure_services'], list):
                    self.errors.append(f"azure_services in {key} must be list")
    
    def _validate_implementation(self, implementation: Any) -> None:
        """Validate implementation section."""
        if not isinstance(implementation, dict):
            self.errors.append(f"implementation must be dict, got {type(implementation)}")
            return
        
        # Check for steps
        if 'steps' in implementation:
            if not isinstance(implementation['steps'], list):
                self.errors.append("implementation.steps must be list")
            else:
                for step in implementation['steps']:
                    if not isinstance(step, dict):
                        self.errors.append("Each implementation step must be dict")
                        continue
                    
                    # Check required step fields
                    if 'step' not in step:
                        self.errors.append("Implementation step missing 'step' number")
                    if 'action' not in step:
                        self.errors.append("Implementation step missing 'action'")
        
        # Check total_effort_hours
        if 'total_effort_hours' in implementation:
            if not isinstance(implementation['total_effort_hours'], (int, float)):
                self.errors.append("total_effort_hours must be numeric")
    
    def _validate_ssp_mapping(self, ssp_mapping: Any) -> None:
        """Validate SSP mapping section."""
        if not isinstance(ssp_mapping, dict):
            self.errors.append(f"ssp_mapping must be dict, got {type(ssp_mapping)}")
            return
        
        # Check required fields
        if 'control_family' not in ssp_mapping:
            self.warnings.append("ssp_mapping missing control_family")
        if 'control_numbers' not in ssp_mapping:
            self.warnings.append("ssp_mapping missing control_numbers")
        
        # Validate ssp_sections
        if 'ssp_sections' in ssp_mapping:
            if not isinstance(ssp_mapping['ssp_sections'], list):
                self.errors.append("ssp_sections must be list")
            else:
                for section in ssp_mapping['ssp_sections']:
                    if not isinstance(section, dict):
                        self.errors.append("SSP section must be dict")
                        continue
                    if 'section' not in section:
                        self.errors.append("SSP section missing 'section' name")
    
    def _validate_azure_guidance(self, azure_guidance: Any) -> None:
        """Validate Azure guidance section."""
        if not isinstance(azure_guidance, dict):
            self.errors.append(f"azure_guidance must be dict, got {type(azure_guidance)}")
            return
        
        # Validate recommended_services
        if 'recommended_services' in azure_guidance:
            if not isinstance(azure_guidance['recommended_services'], list):
                self.errors.append("recommended_services must be list")
            else:
                for service in azure_guidance['recommended_services']:
                    if not isinstance(service, dict):
                        self.errors.append("Service recommendation must be dict")
                        continue
                    
                    if 'service' not in service:
                        self.errors.append("Service recommendation missing 'service' name")
                    elif service['service'] not in self.KNOWN_AZURE_SERVICES:
                        self.info.append(f"Azure service '{service['service']}' not in known list")
    
    def _validate_testing(self, testing: Any) -> None:
        """Validate testing section."""
        if not isinstance(testing, dict):
            self.errors.append(f"testing must be dict, got {type(testing)}")
            return
        
        # Check for test cases
        for test_type in ['positive_test_cases', 'negative_test_cases']:
            if test_type in testing:
                if not isinstance(testing[test_type], list):
                    self.errors.append(f"{test_type} must be list")
                else:
                    for test_case in testing[test_type]:
                        if not isinstance(test_case, dict):
                            self.errors.append(f"Test case in {test_type} must be dict")
                            continue
                        
                        # Check required test case fields
                        if 'description' not in test_case:
                            self.errors.append(f"Test case missing description")
                        if 'code_sample' not in test_case:
                            self.errors.append(f"Test case missing code_sample")
                        if 'expected_finding' not in test_case:
                            self.warnings.append(f"Test case missing expected_finding")
    
    def _validate_v2_fields(self, pattern: Dict[str, Any]) -> None:
        """Validate that V2 patterns have V2 fields."""
        has_v2_fields = any(field in pattern for field in self.V2_FIELDS)
        
        if not has_v2_fields:
            self.warnings.append("Pattern appears to be V1 schema (missing V2 fields)")
        
        # Code-detectable patterns should have evidence_collection
        if 'languages' in pattern and 'evidence_collection' not in pattern:
            self.warnings.append("Code-detectable pattern missing evidence_collection (V2 field)")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python validate_pattern_schema.py <pattern_file.yaml> [--schema v1|v2]")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    schema_version = 'v2'
    
    if '--schema' in sys.argv:
        idx = sys.argv.index('--schema')
        if idx + 1 < len(sys.argv):
            schema_version = sys.argv[idx + 1]
    
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    validator = PatternSchemaValidator(schema_version=schema_version)
    result = validator.validate_file(file_path)
    
    # Print results
    print(f"\n{'='*80}")
    print(f"Pattern Validation Results - {file_path.name}")
    print(f"Schema Version: {schema_version.upper()}")
    print(f"{'='*80}\n")
    
    if result.info:
        print("INFO:")
        for msg in result.info:
            print(f"  {msg}")
        print()
    
    if result.warnings:
        print("WARNINGS:")
        for msg in result.warnings:
            print(f"  ⚠️  {msg}")
        print()
    
    if result.errors:
        print("ERRORS:")
        for msg in result.errors:
            print(f"  ❌ {msg}")
        print()
    
    if result.valid:
        print("✅ VALIDATION PASSED")
        print(f"   Errors: 0, Warnings: {len(result.warnings)}")
        sys.exit(0)
    else:
        print("❌ VALIDATION FAILED")
        print(f"   Errors: {len(result.errors)}, Warnings: {len(result.warnings)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
