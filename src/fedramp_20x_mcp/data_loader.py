"""
FedRAMP Data Loader

This module handles fetching and caching FedRAMP 20x requirements data
from the official GitHub repository.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import httpx

logger = logging.getLogger(__name__)

# GitHub API configuration
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"
FEDRAMP_REPO = "FedRAMP/docs"
FEDRAMP_BRANCH = "main"
DATA_PATH = "data"

# Cache configuration
CACHE_DIR = Path(__file__).parent / "__fedramp_cache__"
CACHE_DURATION = timedelta(hours=1)


class FedRAMPDataLoader:
    """Loads and caches FedRAMP 20x requirements data."""

    def __init__(self):
        """Initialize the data loader."""
        self.cache_dir = CACHE_DIR
        self.cache_dir.mkdir(exist_ok=True)
        self._data_cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[datetime] = None

    def _get_cache_file(self) -> Path:
        """Get the cache file path."""
        return self.cache_dir / "fedramp_controls.json"

    def _is_cache_valid(self) -> bool:
        """Check if the cache is still valid."""
        if not self._cache_timestamp:
            return False
        return datetime.now() - self._cache_timestamp < CACHE_DURATION

    def _load_from_cache(self) -> Optional[Dict[str, Any]]:
        """Load data from local cache if available and valid."""
        cache_file = self._get_cache_file()
        
        if not cache_file.exists():
            logger.info("No cache file found")
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.info("Loaded data from cache")
                return data
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return None

    def _save_to_cache(self, data: Dict[str, Any]) -> None:
        """Save data to local cache."""
        cache_file = self._get_cache_file()
        
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                logger.info("Saved data to cache")
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    async def _fetch_file_list(self) -> List[Dict[str, Any]]:
        """Fetch the list of JSON files from the GitHub repository."""
        url = f"{GITHUB_API_BASE}/repos/{FEDRAMP_REPO}/contents/{DATA_PATH}"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                files = response.json()
                
                # Filter for JSON files
                json_files = [
                    f for f in files 
                    if isinstance(f, dict) and f.get("name", "").endswith(".json")
                ]
                
                logger.info(f"Found {len(json_files)} JSON files in repository")
                return json_files
            except Exception as e:
                logger.error(f"Failed to fetch file list: {e}")
                return []

    async def _fetch_json_file(self, filename: str) -> Optional[Dict[str, Any]]:
        """Fetch a single JSON file from the repository."""
        url = f"{GITHUB_RAW_BASE}/{FEDRAMP_REPO}/{FEDRAMP_BRANCH}/{DATA_PATH}/{filename}"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                logger.info(f"Fetched {filename}")
                return data
            except Exception as e:
                logger.error(f"Failed to fetch {filename}: {e}")
                return None

    async def load_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Load FedRAMP requirements data.

        Args:
            force_refresh: Force refresh from remote source

        Returns:
            Dictionary containing all FedRAMP 20x requirement data
        """
        # Check memory cache first
        if not force_refresh and self._data_cache and self._is_cache_valid():
            logger.info("Using in-memory cache")
            return self._data_cache

        # Try to load from disk cache
        if not force_refresh:
            cached_data = self._load_from_cache()
            if cached_data:
                self._data_cache = cached_data
                self._cache_timestamp = datetime.now()
                return cached_data

        # Fetch from remote
        logger.info("Fetching data from GitHub repository")
        
        files = await self._fetch_file_list()
        if not files:
            # If fetch fails and we have cache, use it even if old
            cached_data = self._load_from_cache()
            if cached_data:
                logger.warning("Using stale cache due to fetch failure")
                return cached_data
            raise Exception("Failed to fetch data and no cache available")

        # Fetch all JSON files
        all_data: Dict[str, Any] = {
            "requirements": {},  # All requirements by ID
            "documents": {},     # Documents by short_name
            "families": {},      # Requirements grouped by family
            "definitions": {},   # FedRAMP definitions (FRD)
            "ksi": {},          # Key Security Indicators (KSI)
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "source": f"{FEDRAMP_REPO}/{DATA_PATH}",
            }
        }

        for file_info in files:
            filename = file_info.get("name", "")
            data = await self._fetch_json_file(filename)
            
            if not data:
                continue
                
            # Extract document info
            info = data.get("info", {})
            short_name = info.get("short_name", filename.replace(".json", ""))
            
            # Store the document
            all_data["documents"][short_name] = {
                "name": info.get("name", ""),
                "short_name": short_name,
                "effective": info.get("effective", {}),
                "releases": info.get("releases", []),
                "filename": filename,
            }
            
            # Extract requirements from all sections
            for section_key, section_data in data.items():
                if section_key in ["$schema", "$id", "info"]:
                    continue
                    
                # Each section can have subsections with requirements
                if isinstance(section_data, dict):
                    for subsection_key, subsection_data in section_data.items():
                        # Handle KSI special structure: categories with 'indicators' lists
                        if short_name == "KSI" and isinstance(subsection_data, dict) and "indicators" in subsection_data:
                            indicator_list = subsection_data.get("indicators", [])
                            category_name = subsection_data.get("name", subsection_key)
                            
                            for indicator in indicator_list:
                                if isinstance(indicator, dict) and "id" in indicator:
                                    ksi_id = indicator["id"]
                                    
                                    # Add document and category context
                                    indicator["document"] = short_name
                                    indicator["document_name"] = info.get("name", "")
                                    indicator["section"] = f"{section_key}-{subsection_key}"
                                    indicator["category"] = category_name
                                    indicator["category_id"] = subsection_key
                                    
                                    # Store in requirements and KSI
                                    all_data["requirements"][ksi_id] = indicator
                                    all_data["ksi"][ksi_id] = indicator
                                    
                                    # Extract family from ID
                                    family = ksi_id.split("-")[0] if "-" in ksi_id else "OTHER"
                                    if family not in all_data["families"]:
                                        all_data["families"][family] = []
                                    all_data["families"][family].append(ksi_id)
                        
                        # Handle nested dict structure: check if it contains sub-dicts with 'requirements' key
                        # This handles structures like FRR -> MAS -> base/application/exceptions -> requirements[]
                        elif isinstance(subsection_data, dict) and not "requirements" in subsection_data:
                            # Check if any nested values have 'requirements' key
                            has_nested_requirements = any(
                                isinstance(v, dict) and "requirements" in v 
                                for v in subsection_data.values()
                            )
                            
                            if has_nested_requirements:
                                # Iterate over nested sections (base, application, exceptions, etc.)
                                for nested_key, nested_data in subsection_data.items():
                                    if isinstance(nested_data, dict) and "requirements" in nested_data:
                                        req_list = nested_data.get("requirements", [])
                                        nested_name = nested_data.get("name", nested_key)
                                        nested_id = nested_data.get("id", f"{section_key}-{subsection_key}-{nested_key}")
                                        
                                        for req in req_list:
                                            if isinstance(req, dict) and "id" in req:
                                                req_id = req["id"]
                                                
                                                # Add document context
                                                req["document"] = short_name
                                                req["document_name"] = info.get("name", "")
                                                req["section"] = f"{section_key}-{subsection_key}-{nested_key}"
                                                req["subsection_name"] = nested_name
                                                req["subsection_id"] = nested_id
                                                req["category"] = subsection_key
                                                
                                                # Store by ID
                                                all_data["requirements"][req_id] = req
                                                
                                                # Extract family from ID
                                                family = req_id.split("-")[0] if "-" in req_id else "OTHER"
                                                if family not in all_data["families"]:
                                                    all_data["families"][family] = []
                                                all_data["families"][family].append(req_id)
                        
                        # Handle direct dict structure with 'requirements' key
                        elif isinstance(subsection_data, dict) and "requirements" in subsection_data:
                            req_list = subsection_data.get("requirements", [])
                            subsection_name = subsection_data.get("name", subsection_key)
                            subsection_id = subsection_data.get("id", f"{section_key}-{subsection_key}")
                            
                            for req in req_list:
                                if isinstance(req, dict) and "id" in req:
                                    req_id = req["id"]
                                    
                                    # Add document context
                                    req["document"] = short_name
                                    req["document_name"] = info.get("name", "")
                                    req["section"] = f"{section_key}-{subsection_key}"
                                    req["subsection_name"] = subsection_name
                                    req["subsection_id"] = subsection_id
                                    
                                    # Store by ID
                                    all_data["requirements"][req_id] = req
                                    
                                    # Extract family from ID
                                    family = req_id.split("-")[0] if "-" in req_id else "OTHER"
                                    if family not in all_data["families"]:
                                        all_data["families"][family] = []
                                    all_data["families"][family].append(req_id)
                                    
                                    # Track definitions (FRD) separately
                                    if short_name == "FRD" and "term" in req:
                                        all_data["definitions"][req.get("term", req_id)] = req
                        
                        # Handle regular list-based requirements
                        elif isinstance(subsection_data, list):
                            for req in subsection_data:
                                if isinstance(req, dict) and "id" in req:
                                    req_id = req["id"]
                                    
                                    # Add document context
                                    req["document"] = short_name
                                    req["document_name"] = info.get("name", "")
                                    req["section"] = f"{section_key}-{subsection_key}"
                                    
                                    # Store by ID
                                    all_data["requirements"][req_id] = req
                                    
                                    # Extract family from ID (e.g., "AC" from "AC-1")
                                    family = req_id.split("-")[0] if "-" in req_id else "OTHER"
                                    if family not in all_data["families"]:
                                        all_data["families"][family] = []
                                    all_data["families"][family].append(req_id)
                                    
                                    # Track definitions (FRD) separately
                                    if short_name == "FRD" and "term" in req:
                                        all_data["definitions"][req.get("term", req_id)] = req

        # Save to cache
        self._save_to_cache(all_data)
        self._data_cache = all_data
        self._cache_timestamp = datetime.now()

        logger.info(f"Loaded {len(all_data['requirements'])} requirements from {len(all_data['documents'])} documents")
        return all_data

    def get_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific requirement by ID.

        Args:
            control_id: The requirement identifier

        Returns:
            Requirement data or None if not found
        """
        if not self._data_cache:
            return None
        
        return self._data_cache["requirements"].get(control_id.upper())

    def get_family_controls(self, family: str) -> List[Dict[str, Any]]:
        """
        Get all requirements in a specific family.

        Args:
            family: The family identifier

        Returns:
            List of requirements in the family
        """
        if not self._data_cache:
            return []

        family_upper = family.upper()
        req_ids = self._data_cache["families"].get(family_upper, [])
        
        return [
            self._data_cache["requirements"][req_id]
            for req_id in req_ids
            if req_id in self._data_cache["requirements"]
        ]

    def search_controls(self, keywords: str) -> List[Dict[str, Any]]:
        """
        Search requirements by keywords.

        Args:
            keywords: Keywords to search for

        Returns:
            List of matching requirements
        """
        if not self._data_cache:
            return []

        keywords_lower = keywords.lower()
        results = []

        for req_id, req in self._data_cache["requirements"].items():
            # Search in requirement text fields
            searchable_text = json.dumps(req).lower()
            if keywords_lower in searchable_text:
                results.append(req)

        return results
    
    def get_definition(self, term: str) -> Optional[Dict[str, Any]]:
        """
        Get a FedRAMP definition by term.

        Args:
            term: The term to look up (case-insensitive)

        Returns:
            Definition data or None if not found
        """
        if not self._data_cache:
            return None
        
        # Try exact match first
        for key, definition in self._data_cache["definitions"].items():
            if key.lower() == term.lower():
                return definition
            # Check alternatives
            if "alts" in definition:
                for alt in definition["alts"]:
                    if alt.lower() == term.lower():
                        return definition
        
        return None
    
    def list_all_definitions(self) -> List[Dict[str, Any]]:
        """
        List all FedRAMP definitions.

        Returns:
            List of all definition entries
        """
        if not self._data_cache:
            return []
        
        return list(self._data_cache["definitions"].values())
    
    def get_ksi(self, ksi_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a Key Security Indicator by ID.

        Args:
            ksi_id: The KSI identifier

        Returns:
            KSI data or None if not found
        """
        if not self._data_cache:
            return None
        
        return self._data_cache["ksi"].get(ksi_id.upper())
    
    def list_all_ksi(self) -> List[Dict[str, Any]]:
        """
        List all Key Security Indicators.

        Returns:
            List of all KSI entries
        """
        if not self._data_cache:
            return []
        
        return list(self._data_cache["ksi"].values())
    
    def search_definitions(self, keywords: str) -> List[Dict[str, Any]]:
        """
        Search FedRAMP definitions by keywords.

        Args:
            keywords: Keywords to search for

        Returns:
            List of matching definitions
        """
        if not self._data_cache:
            return []

        keywords_lower = keywords.lower()
        results = []

        for term, definition in self._data_cache["definitions"].items():
            # Search in definition text
            searchable_text = json.dumps(definition).lower()
            if keywords_lower in searchable_text:
                results.append(definition)

        return results


# Global data loader instance
_data_loader: Optional[FedRAMPDataLoader] = None


def get_data_loader() -> FedRAMPDataLoader:
    """Get or create the global data loader instance."""
    global _data_loader
    if _data_loader is None:
        _data_loader = FedRAMPDataLoader()
    return _data_loader
