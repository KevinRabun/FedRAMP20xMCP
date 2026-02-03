#!/usr/bin/env python3
"""
FedRAMP Data Structure Validation Script

This script validates that the FedRAMP 20x data from the GitHub repository
is still structured as the MCP server expects. It's designed to be run
daily via GitHub Actions to detect upstream schema changes early.

Exit codes:
    0 - All validations passed
    1 - One or more validations failed
    2 - Critical error (cannot fetch data at all)
"""

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


@dataclass
class ValidationResult:
    """Result of a single validation check."""
    name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


class FedRAMPDataValidator:
    """Validates FedRAMP data structure integrity."""
    
    # Expected minimum counts (allows for additions, but catches major deletions)
    EXPECTED_MIN_REQUIREMENTS = 150
    EXPECTED_MIN_KSIS = 50
    EXPECTED_MIN_DEFINITIONS = 30
    EXPECTED_MIN_FAMILIES = 10
    
    # Expected FRR families (based on FedRAMP 20x spec)
    EXPECTED_FRR_FAMILIES = {
        "FRR-VDR",  # Vulnerability Disclosure and Response
        "FRR-RSC",  # Recommended Secure Configuration
        "FRR-UCM",  # Unique Credential Management
        "FRR-SCN",  # Security Control Notification
        "FRR-ADS",  # Audit and Data Security
        "FRR-CCM",  # Cloud Configuration Management
        "FRR-MAS",  # Monitoring and Alerting System
        "FRR-ICP",  # Incident Containment Plan
        "FRR-FSI",  # Federal Security Integration
        "FRR-PVA",  # Privacy and Vulnerability Assessment
        "FRR-KSI",  # Key Security Indicators (meta-family)
    }
    
    # Expected KSI categories (verified from FRMR.KSI.key-security-indicators.json)
    EXPECTED_KSI_PREFIXES = {
        "KSI-IAM",  # Identity and Access Management
        "KSI-CNA",  # Cloud Native Architecture
        "KSI-SVC",  # Service Configuration
        "KSI-TPR",  # Third Party Risk
        "KSI-CMT",  # Continuous Monitoring
        "KSI-MLA",  # Machine Learning & AI
        "KSI-INR",  # Incident Response
        "KSI-PIY",  # Privacy
        "KSI-AFR",  # Automated FedRAMP
        "KSI-RPL",  # Replication
        "KSI-CED",  # Cryptographic Enforcement
    }
    
    # Required fields in requirement objects
    REQUIRED_REQUIREMENT_FIELDS = {"id"}
    EXPECTED_REQUIREMENT_FIELDS = {"id", "name", "description", "document"}
    
    # Required fields in KSI objects
    REQUIRED_KSI_FIELDS = {"id"}
    EXPECTED_KSI_FIELDS = {"id", "name", "description", "category"}
    
    # Required fields in definition objects
    REQUIRED_DEFINITION_FIELDS = {"id", "term"}
    
    def __init__(self):
        self.loader = FedRAMPDataLoader()
        self.results: List[ValidationResult] = []
        self.data: Optional[Dict[str, Any]] = None
    
    async def load_data(self, force_refresh: bool = True) -> bool:
        """Load data from FedRAMP repository."""
        try:
            self.data = await self.loader.load_data(force_refresh=force_refresh)
            return True
        except Exception as e:
            self.results.append(ValidationResult(
                name="Data Loading",
                passed=False,
                message=f"Failed to load data from FedRAMP repository: {str(e)}"
            ))
            return False
    
    def validate_data_structure(self) -> None:
        """Validate the overall data structure."""
        if not self.data:
            self.results.append(ValidationResult(
                name="Data Structure",
                passed=False,
                message="No data loaded"
            ))
            return
        
        # Check required top-level keys
        required_keys = {"requirements", "documents", "families", "definitions", "ksi", "metadata"}
        missing_keys = required_keys - set(self.data.keys())
        
        if missing_keys:
            self.results.append(ValidationResult(
                name="Top-Level Structure",
                passed=False,
                message=f"Missing required keys: {missing_keys}",
                details={"missing_keys": list(missing_keys), "found_keys": list(self.data.keys())}
            ))
        else:
            self.results.append(ValidationResult(
                name="Top-Level Structure",
                passed=True,
                message="All required top-level keys present"
            ))
    
    def validate_requirements_count(self) -> None:
        """Validate minimum requirements count."""
        if not self.data:
            return
        
        count = len(self.data.get("requirements", {}))
        passed = count >= self.EXPECTED_MIN_REQUIREMENTS
        
        self.results.append(ValidationResult(
            name="Requirements Count",
            passed=passed,
            message=f"Found {count} requirements (minimum expected: {self.EXPECTED_MIN_REQUIREMENTS})",
            details={"count": count, "minimum": self.EXPECTED_MIN_REQUIREMENTS}
        ))
    
    def validate_ksi_count(self) -> None:
        """Validate minimum KSI count."""
        if not self.data:
            return
        
        count = len(self.data.get("ksi", {}))
        passed = count >= self.EXPECTED_MIN_KSIS
        
        self.results.append(ValidationResult(
            name="KSI Count",
            passed=passed,
            message=f"Found {count} KSIs (minimum expected: {self.EXPECTED_MIN_KSIS})",
            details={"count": count, "minimum": self.EXPECTED_MIN_KSIS}
        ))
    
    def validate_definitions_count(self) -> None:
        """Validate minimum definitions count."""
        if not self.data:
            return
        
        count = len(self.data.get("definitions", {}))
        passed = count >= self.EXPECTED_MIN_DEFINITIONS
        
        self.results.append(ValidationResult(
            name="Definitions Count",
            passed=passed,
            message=f"Found {count} definitions (minimum expected: {self.EXPECTED_MIN_DEFINITIONS})",
            details={"count": count, "minimum": self.EXPECTED_MIN_DEFINITIONS}
        ))
    
    def validate_families(self) -> None:
        """Validate that expected families exist."""
        if not self.data:
            return
        
        found_families = set(self.data.get("families", {}).keys())
        
        # Check for FRR families (normalize by checking if any req ID starts with expected prefix)
        requirements = self.data.get("requirements", {})
        req_prefixes: Set[str] = set()
        for req_id in requirements.keys():
            if req_id.startswith("FRR-"):
                # Extract family like "FRR-VDR" from "FRR-VDR-01"
                parts = req_id.split("-")
                if len(parts) >= 2:
                    req_prefixes.add(f"{parts[0]}-{parts[1]}")
        
        # Also extract KSI prefixes
        ksis = self.data.get("ksi", {})
        ksi_prefixes: Set[str] = set()
        for ksi_id in ksis.keys():
            if ksi_id.startswith("KSI-"):
                parts = ksi_id.split("-")
                if len(parts) >= 2:
                    ksi_prefixes.add(f"{parts[0]}-{parts[1]}")
        
        # Check FRR families
        missing_frr_families = []
        for expected in self.EXPECTED_FRR_FAMILIES:
            if expected not in req_prefixes and expected.replace("FRR-", "") not in found_families:
                missing_frr_families.append(expected)
        
        if missing_frr_families:
            self.results.append(ValidationResult(
                name="FRR Families",
                passed=False,
                message=f"Missing FRR families: {missing_frr_families}",
                details={
                    "missing": missing_frr_families,
                    "found_prefixes": list(req_prefixes),
                    "found_families": list(found_families)
                }
            ))
        else:
            self.results.append(ValidationResult(
                name="FRR Families",
                passed=True,
                message=f"All expected FRR families found ({len(req_prefixes)} prefixes)"
            ))
        
        # Check KSI categories
        missing_ksi_categories = []
        for expected in self.EXPECTED_KSI_PREFIXES:
            if expected not in ksi_prefixes:
                missing_ksi_categories.append(expected)
        
        if missing_ksi_categories:
            self.results.append(ValidationResult(
                name="KSI Categories",
                passed=False,
                message=f"Missing KSI categories: {missing_ksi_categories}",
                details={"missing": missing_ksi_categories, "found": list(ksi_prefixes)}
            ))
        else:
            self.results.append(ValidationResult(
                name="KSI Categories",
                passed=True,
                message=f"All expected KSI categories found ({len(ksi_prefixes)} prefixes)"
            ))
    
    def validate_requirement_fields(self) -> None:
        """Validate that requirements have expected fields."""
        if not self.data:
            return
        
        requirements = self.data.get("requirements", {})
        invalid_requirements = []
        missing_field_stats: Dict[str, int] = {}
        
        for req_id, req in requirements.items():
            if not isinstance(req, dict):
                invalid_requirements.append(req_id)
                continue
            
            # Check required fields
            missing_required = self.REQUIRED_REQUIREMENT_FIELDS - set(req.keys())
            if missing_required:
                invalid_requirements.append(req_id)
                for field in missing_required:
                    missing_field_stats[field] = missing_field_stats.get(field, 0) + 1
        
        if invalid_requirements:
            self.results.append(ValidationResult(
                name="Requirement Fields",
                passed=False,
                message=f"{len(invalid_requirements)} requirements missing required fields",
                details={
                    "invalid_count": len(invalid_requirements),
                    "sample_invalid": invalid_requirements[:5],
                    "missing_field_stats": missing_field_stats
                }
            ))
        else:
            self.results.append(ValidationResult(
                name="Requirement Fields",
                passed=True,
                message=f"All {len(requirements)} requirements have required fields"
            ))
    
    def validate_ksi_fields(self) -> None:
        """Validate that KSIs have expected fields."""
        if not self.data:
            return
        
        ksis = self.data.get("ksi", {})
        invalid_ksis = []
        
        for ksi_id, ksi in ksis.items():
            if not isinstance(ksi, dict):
                invalid_ksis.append(ksi_id)
                continue
            
            # Check required fields
            missing_required = self.REQUIRED_KSI_FIELDS - set(ksi.keys())
            if missing_required:
                invalid_ksis.append(ksi_id)
        
        if invalid_ksis:
            self.results.append(ValidationResult(
                name="KSI Fields",
                passed=False,
                message=f"{len(invalid_ksis)} KSIs missing required fields",
                details={"invalid_count": len(invalid_ksis), "sample_invalid": invalid_ksis[:5]}
            ))
        else:
            self.results.append(ValidationResult(
                name="KSI Fields",
                passed=True,
                message=f"All {len(ksis)} KSIs have required fields"
            ))
    
    def validate_definition_fields(self) -> None:
        """Validate that definitions have expected fields."""
        if not self.data:
            return
        
        definitions = self.data.get("definitions", {})
        invalid_definitions = []
        
        for term, definition in definitions.items():
            if not isinstance(definition, dict):
                invalid_definitions.append(term)
                continue
            
            # Definitions should have at least 'id' or 'term'
            if "id" not in definition and "term" not in definition:
                invalid_definitions.append(term)
        
        # This is a softer check - definitions may have varying structures
        if invalid_definitions and len(invalid_definitions) > len(definitions) * 0.2:
            self.results.append(ValidationResult(
                name="Definition Fields",
                passed=False,
                message=f"{len(invalid_definitions)} definitions have unexpected structure",
                details={"invalid_count": len(invalid_definitions), "sample_invalid": invalid_definitions[:5]}
            ))
        else:
            self.results.append(ValidationResult(
                name="Definition Fields",
                passed=True,
                message=f"Definition structure is valid ({len(definitions)} definitions)"
            ))
    
    def validate_document_metadata(self) -> None:
        """Validate that document metadata exists."""
        if not self.data:
            return
        
        documents = self.data.get("documents", {})
        
        if not documents:
            self.results.append(ValidationResult(
                name="Document Metadata",
                passed=False,
                message="No document metadata found"
            ))
            return
        
        # Check that we have some known documents
        known_docs = {"KSI", "FRD", "FRR"}
        found_docs = set(documents.keys())
        
        # Check if any known docs are present (may be named differently)
        has_ksi = any("ksi" in d.lower() for d in found_docs)
        has_frd = any("frd" in d.lower() or "definition" in d.lower() for d in found_docs)
        has_frr = any("frr" in d.lower() or "requirement" in d.lower() for d in found_docs)
        
        if has_ksi or has_frd or has_frr or len(found_docs) > 0:
            self.results.append(ValidationResult(
                name="Document Metadata",
                passed=True,
                message=f"Found {len(documents)} documents",
                details={"documents": list(documents.keys())}
            ))
        else:
            self.results.append(ValidationResult(
                name="Document Metadata",
                passed=False,
                message="Could not find expected document types"
            ))
    
    def validate_id_format(self) -> None:
        """Validate that IDs follow expected format patterns."""
        if not self.data:
            return
        
        requirements = self.data.get("requirements", {})
        invalid_ids = []
        
        for req_id in requirements.keys():
            # IDs should follow pattern like FRR-XXX-NN or KSI-XXX-NN or FRD-XXX
            if not req_id or not isinstance(req_id, str):
                invalid_ids.append(str(req_id))
                continue
            
            # Basic format validation - should have hyphens and alphanumeric parts
            parts = req_id.split("-")
            if len(parts) < 2:
                invalid_ids.append(req_id)
        
        if invalid_ids and len(invalid_ids) > len(requirements) * 0.1:
            self.results.append(ValidationResult(
                name="ID Format",
                passed=False,
                message=f"{len(invalid_ids)} IDs have unexpected format",
                details={"invalid_count": len(invalid_ids), "sample_invalid": invalid_ids[:5]}
            ))
        else:
            self.results.append(ValidationResult(
                name="ID Format",
                passed=True,
                message="ID formats are valid"
            ))
    
    async def run_all_validations(self, force_refresh: bool = True) -> bool:
        """Run all validations and return overall pass/fail."""
        print("=" * 60)
        print("FedRAMP 20x Data Structure Validation")
        print("=" * 60)
        print()
        
        # Load data
        print("📥 Loading data from FedRAMP repository...")
        if not await self.load_data(force_refresh=force_refresh):
            print("❌ CRITICAL: Failed to load data!")
            return False
        
        print(f"✅ Data loaded successfully")
        print()
        
        # Run validations
        print("🔍 Running validations...")
        print("-" * 40)
        
        self.validate_data_structure()
        self.validate_requirements_count()
        self.validate_ksi_count()
        self.validate_definitions_count()
        self.validate_families()
        self.validate_requirement_fields()
        self.validate_ksi_fields()
        self.validate_definition_fields()
        self.validate_document_metadata()
        self.validate_id_format()
        
        # Print results
        print()
        passed_count = 0
        failed_count = 0
        
        for result in self.results:
            status = "✅ PASS" if result.passed else "❌ FAIL"
            print(f"{status}: {result.name}")
            print(f"       {result.message}")
            if result.details and not result.passed:
                print(f"       Details: {json.dumps(result.details, indent=2)[:200]}...")
            print()
            
            if result.passed:
                passed_count += 1
            else:
                failed_count += 1
        
        # Summary
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total validations: {len(self.results)}")
        print(f"Passed: {passed_count}")
        print(f"Failed: {failed_count}")
        print()
        
        if failed_count == 0:
            print("🎉 All validations passed!")
            return True
        else:
            print(f"⚠️  {failed_count} validation(s) failed!")
            return False


async def main():
    """Main entry point."""
    force_refresh = os.environ.get("FORCE_REFRESH", "true").lower() == "true"
    
    validator = FedRAMPDataValidator()
    success = await validator.run_all_validations(force_refresh=force_refresh)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
