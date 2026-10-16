"""
FedRAMP Data Loader

Loads the FedRAMP Consolidated Rules for 2026 (CR26) and the FedRAMP
documentation that explains them.

Rules source of truth: the single machine-readable file published in the
FedRAMP/rules repository (fedramp-consolidated-rules.json). The legacy
FedRAMP/docs repository (now FedRAMP/docs-legacy) no longer carries it.

Resolution order for rules data:
  1. In-memory cache (CACHE_DURATION)
  2. On-disk cache, if it was written by this loader format (CACHE_FORMAT)
  3. Remote fetch of FEDRAMP_RULES_URL, or the local FEDRAMP_RULES_FILE
  4. Stale on-disk cache
  5. The pinned snapshot bundled in rules_data/ (always available offline)

Set FEDRAMP_RULES_OFFLINE=1 to skip the network and use the bundled snapshot
(or FEDRAMP_RULES_FILE). Every load records the rules version and sha256 in
metadata so a finding can be traced to the exact rules release it used.
"""

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

import httpx

logger = logging.getLogger(__name__)

# GitHub configuration
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

# Rules: FedRAMP/rules publishes one consolidated JSON at the repo root.
FEDRAMP_REPO = "FedRAMP/rules"
FEDRAMP_BRANCH = "main"
DATA_PATH = ""  # Consolidated rules file lives in the repo root
RULES_FILENAME = "fedramp-consolidated-rules.json"
DEFAULT_RULES_URL = f"{GITHUB_RAW_BASE}/{FEDRAMP_REPO}/{FEDRAMP_BRANCH}/{RULES_FILENAME}"

# Documentation: the CR26 site content lives in FedRAMP/2026 under content/.
DOCS_REPO = "FedRAMP/2026"
DOCS_BRANCH = "main"
DOCS_PATH = "content"

# Bundled, pinned data shipped inside the package.
RULES_DATA_DIR = Path(__file__).parent / "rules_data"
BUNDLED_RULES_FILE = RULES_DATA_DIR / RULES_FILENAME
CROSSWALK_FILE = RULES_DATA_DIR / "legacy-crosswalk.json"

# Cache configuration
CACHE_DIR = Path(__file__).parent / "__fedramp_cache__"
CACHE_DURATION = timedelta(hours=1)
# Bump when the cached structure changes so older caches are ignored.
CACHE_FORMAT = 2
HTTP_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _github_headers() -> Dict[str, str]:
    """Use GITHUB_TOKEN when present to avoid API rate limits."""
    token = os.environ.get("GITHUB_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


class FedRAMPDataLoader:
    """Loads and caches FedRAMP Consolidated Rules data."""

    def __init__(self):
        """Initialize the data loader."""
        self.cache_dir = CACHE_DIR
        self.cache_dir.mkdir(exist_ok=True)
        self._data_cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._docs_cache: Optional[Dict[str, str]] = None
        self._docs_cache_timestamp: Optional[datetime] = None
        self._fka_map: Dict[str, str] = {}  # Maps legacy IDs to current IDs
        self._crosswalk: Dict[str, Dict[str, Any]] = self._load_crosswalk()

    @staticmethod
    def _load_crosswalk() -> Dict[str, Dict[str, Any]]:
        """Load the bundled legacy-ID crosswalk (legacy ID -> CR26 IDs)."""
        try:
            with open(CROSSWALK_FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("crosswalk", {})
        except Exception as e:
            logger.warning(f"Legacy crosswalk unavailable: {e}")
            return {}

    def _get_cache_file(self) -> Path:
        """Get the cache file path."""
        return self.cache_dir / "fedramp_controls.json"

    def _get_docs_cache_file(self) -> Path:
        """Get the documentation cache file path."""
        return self.cache_dir / "fedramp_docs.json"

    def _is_cache_valid(self) -> bool:
        """Check if the cache is still valid."""
        if not self._cache_timestamp:
            return False
        return datetime.now() - self._cache_timestamp < CACHE_DURATION

    def _load_from_cache(self) -> Optional[Dict[str, Any]]:
        """Load data from local cache if it exists and matches CACHE_FORMAT."""
        cache_file = self._get_cache_file()

        if not cache_file.exists():
            logger.info("No cache file found")
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("metadata", {}).get("cache_format") != CACHE_FORMAT:
                logger.info("Ignoring cache written by an older loader format")
                return None
            logger.info("Loaded data from cache")
            return data
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return None

    def _save_to_cache(self, data: Dict[str, Any]) -> None:
        """
        Save data to local cache with restricted permissions.

        Security: Creates file with owner-only permissions (0600) using thread-safe approach.
        """
        cache_file = self._get_cache_file()

        try:
            # Create or truncate cache file with explicit owner-only permissions (0600)
            # This is thread-safe unlike os.umask()
            fd = os.open(cache_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                    logger.info("Saved data to cache")
            except Exception:
                # Close fd if fdopen failed or json.dump failed
                try:
                    os.close(fd)
                except OSError:
                    pass  # fd may already be closed by fdopen
                raise
        except Exception as e:
            # Broad exception catch is intentional - cache failures should never crash the app
            logger.error(f"Failed to save cache: {e}")

    async def _fetch_rules_bytes(self) -> Optional[tuple]:
        """
        Fetch the consolidated rules file.

        Returns (raw_bytes, source_description) or None. Honors
        FEDRAMP_RULES_FILE (local path) and FEDRAMP_RULES_URL (override URL).
        """
        local = os.environ.get("FEDRAMP_RULES_FILE")
        if local:
            try:
                return Path(local).read_bytes(), f"file:{local}"
            except Exception as e:
                logger.error(f"Failed to read FEDRAMP_RULES_FILE {local}: {e}")
                return None

        if _truthy(os.environ.get("FEDRAMP_RULES_OFFLINE")):
            return None

        url = os.environ.get("FEDRAMP_RULES_URL", DEFAULT_RULES_URL)
        async with httpx.AsyncClient(follow_redirects=True, timeout=HTTP_TIMEOUT) as client:
            try:
                response = await client.get(url, headers=_github_headers())
                response.raise_for_status()
                logger.info(f"Fetched rules from {url}")
                return response.content, url
            except Exception as e:
                logger.error(f"Failed to fetch rules from {url}: {e}")
                return None

    def _load_bundled(self) -> Optional[tuple]:
        """Read the pinned rules snapshot shipped with the package."""
        try:
            return BUNDLED_RULES_FILE.read_bytes(), f"bundled:{BUNDLED_RULES_FILE.name}"
        except Exception as e:
            logger.error(f"Bundled rules snapshot unreadable: {e}")
            return None

    def _build_dataset(self, raw: bytes, source: str) -> Dict[str, Any]:
        """Parse a rules file into the loader's indexed structure."""
        data = json.loads(raw.decode("utf-8"))
        info = data.get("info", {})

        all_data: Dict[str, Any] = {
            "requirements": {},  # All requirements by ID
            "documents": {},     # Documents by short_name
            "families": {},      # Requirements grouped by family
            "definitions": {},   # FedRAMP definitions (FRD)
            "ksi": {},           # Key Security Indicators (KSI)
            "control_parameters": {},  # FedRAMP NIST control parameters/guidance (CTL)
            "metadata": {
                "cache_format": CACHE_FORMAT,
                "loaded_at": datetime.now().isoformat(),
                "source": source,
                "title": info.get("title", ""),
                "version": info.get("version", ""),
                "last_updated": info.get("last_updated", ""),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "default_artifacts": info.get("default_artifacts", {}),
            },
        }

        short_name = info.get("short_name", "FRMR")
        all_data["documents"][short_name] = {
            "name": info.get("title", info.get("name", "")),
            "short_name": short_name,
            "version": info.get("version", ""),
            "last_updated": info.get("last_updated", ""),
            "filename": RULES_FILENAME,
        }

        if "FRD" in data and "FRR" in data and "KSI" in data:
            self._process_consolidated_format(data, all_data)
        else:
            self._process_legacy_format(data, info, short_name, all_data)
        return all_data

    async def load_data(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Load FedRAMP requirements data.

        Args:
            force_refresh: Force refresh from remote source

        Returns:
            Dictionary containing all FedRAMP requirement data
        """
        # Check memory cache first
        if not force_refresh and self._data_cache and self._is_cache_valid():
            logger.info("Using in-memory cache")
            return self._data_cache

        # Try to load from disk cache
        if not force_refresh:
            cached_data = self._load_from_cache()
            if cached_data:
                self._set_data(cached_data)
                return cached_data

        logger.info("Fetching FedRAMP Consolidated Rules")
        fetched = await self._fetch_rules_bytes()
        all_data: Optional[Dict[str, Any]] = None
        if fetched:
            try:
                all_data = self._build_dataset(*fetched)
            except Exception as e:
                logger.error(f"Fetched rules could not be parsed: {e}")

        if all_data is None:
            stale = self._load_from_cache()
            if stale:
                logger.warning("Using stale cache because the rules fetch failed")
                self._set_data(stale)
                return stale
            bundled = self._load_bundled()
            if not bundled:
                raise Exception("Failed to fetch rules and no cache or bundled snapshot available")
            logger.warning("Using bundled rules snapshot")
            all_data = self._build_dataset(*bundled)
        else:
            self._save_to_cache(all_data)

        self._set_data(all_data)
        meta = all_data["metadata"]
        logger.info(
            f"Loaded {len(all_data['requirements'])} requirements, {len(all_data['ksi'])} KSIs "
            f"from {meta['source']} (version {meta['version']})"
        )
        return all_data

    def _set_data(self, data: Dict[str, Any]) -> None:
        self._data_cache = data
        self._cache_timestamp = datetime.now()
        self._build_fka_map()

    def get_rules_metadata(self) -> Dict[str, Any]:
        """Return source, version and checksum of the loaded rules."""
        if not self._data_cache:
            return {}
        return dict(self._data_cache.get("metadata", {}))

    def _process_consolidated_format(self, data: Dict[str, Any], all_data: Dict[str, Any]) -> None:
        """
        Process the new consolidated FRMR.documentation.json format.
        
        Structure:
        - FRD: definitions at FRD.data.both.<def_id>
        - FRR: requirements at FRR.<family>.data.<scope>.<group>.<req_id>
        - KSI: indicators at KSI.<category>.indicators.<ksi_id>
        """
        # Process FRD (FedRAMP Definitions)
        frd_section = data.get("FRD", {})
        frd_info = frd_section.get("info", {})
        frd_data = frd_section.get("data", {})
        
        # Store FRD document info
        all_data["documents"]["FRD"] = {
            "name": frd_info.get("name", "FedRAMP Definitions"),
            "short_name": frd_info.get("short_name", "FRD"),
            "web_name": frd_info.get("web_name", ""),
        }
        
        # Process definitions from all scopes (both, 20x, rev5)
        for scope, scope_data in frd_data.items():
            if isinstance(scope_data, dict):
                for def_id, definition in scope_data.items():
                    if isinstance(definition, dict):
                        # Enrich definition with metadata
                        definition["id"] = def_id
                        definition["document"] = "FRD"
                        definition["scope"] = scope
                        
                        # Store by ID and by term
                        all_data["definitions"][def_id] = definition
                        if "term" in definition:
                            all_data["definitions"][definition["term"]] = definition
                        
                        # Also store in requirements for unified search
                        all_data["requirements"][def_id] = definition
                        
                        # Track in families
                        if "FRD" not in all_data["families"]:
                            all_data["families"]["FRD"] = []
                        all_data["families"]["FRD"].append(def_id)
        
        # Process FRR (FedRAMP Requirements)
        frr_section = data.get("FRR", {})
        
        for family_key, family_data in frr_section.items():
            if not isinstance(family_data, dict):
                continue
                
            family_info = family_data.get("info", {})
            family_name = family_info.get("name", family_key)
            
            # Store family document info
            all_data["documents"][f"FRR-{family_key}"] = {
                "name": family_name,
                "short_name": family_key,
                "web_name": family_info.get("web_name", ""),
            }
            
            # Process requirements from all scopes
            req_data = family_data.get("data", {})
            for scope, scope_data in req_data.items():
                if not isinstance(scope_data, dict):
                    continue
                    
                # scope_data contains groups (like CSX, AGM, etc.)
                for group_key, group_data in scope_data.items():
                    if not isinstance(group_data, dict):
                        continue
                        
                    # group_data contains individual requirements
                    for req_id, requirement in group_data.items():
                        if not isinstance(requirement, dict):
                            continue
                            
                        # Enrich requirement with metadata
                        requirement["id"] = req_id
                        requirement["document"] = f"FRR-{family_key}"
                        requirement["family"] = family_key
                        requirement["family_name"] = family_name
                        requirement["group"] = group_key
                        requirement["scope"] = scope
                        
                        # Store in requirements
                        all_data["requirements"][req_id] = requirement
                        
                        # Track in families by first part of ID
                        family_prefix = req_id.split("-")[0] if "-" in req_id else family_key
                        if family_prefix not in all_data["families"]:
                            all_data["families"][family_prefix] = []
                        all_data["families"][family_prefix].append(req_id)
        
        # Process KSI (Key Security Indicators)
        ksi_section = data.get("KSI", {})
        
        for category_key, category_data in ksi_section.items():
            if not isinstance(category_data, dict):
                continue
                
            category_id = category_data.get("id", f"KSI-{category_key}")
            category_name = category_data.get("name", category_key)
            category_theme = category_data.get("theme", "")
            
            # Store category document info
            all_data["documents"][f"KSI-{category_key}"] = {
                "name": category_name,
                "short_name": category_key,
                "web_name": category_data.get("web_name", ""),
                "theme": category_theme,
            }
            
            # Process indicators
            indicators = category_data.get("indicators", {})
            for ksi_id, indicator in indicators.items():
                if not isinstance(indicator, dict):
                    continue
                    
                # Enrich indicator with metadata
                indicator["id"] = ksi_id
                indicator["document"] = f"KSI-{category_key}"
                indicator["category"] = category_name
                indicator["category_id"] = category_key
                indicator["theme"] = category_theme
                indicator.setdefault("status", category_data.get("status", ""))

                # Store in both ksi and requirements
                all_data["ksi"][ksi_id] = indicator
                all_data["requirements"][ksi_id] = indicator

                # Track in families
                if "KSI" not in all_data["families"]:
                    all_data["families"]["KSI"] = []
                all_data["families"]["KSI"].append(ksi_id)

        # Process CTL (FedRAMP-specific NIST SP 800-53 parameter values and
        # guidance for Rev5 controls), keyed like "AC-06-01".
        for control_family, controls in data.get("CTL", {}).items():
            if not isinstance(controls, dict):
                continue
            for control_id, control in controls.items():
                if isinstance(control, dict):
                    all_data["control_parameters"][control_id.upper()] = {
                        "id": control_id.upper(),
                        "family": control_family,
                        **control,
                    }

    def _process_legacy_format(self, data: Dict[str, Any], info: Dict[str, Any], 
                               short_name: str, all_data: Dict[str, Any]) -> None:
        """
        Process legacy individual JSON file format for backwards compatibility.
        This handles the old multi-file structure where each family had its own JSON file.
        """
        # Extract requirements from all sections (legacy format)
        for section_key, section_data in data.items():
            if section_key in ["$schema", "$id", "info"]:
                continue
                
            if not isinstance(section_data, dict):
                continue
                
            for subsection_key, subsection_data in section_data.items():
                # Handle KSI special structure
                if short_name == "KSI" and isinstance(subsection_data, dict) and "indicators" in subsection_data:
                    indicator_list = subsection_data.get("indicators", [])
                    category_name = subsection_data.get("name", subsection_key)
                    
                    for indicator in indicator_list:
                        if isinstance(indicator, dict) and "id" in indicator:
                            ksi_id = indicator["id"]
                            indicator["document"] = short_name
                            indicator["category"] = category_name
                            all_data["requirements"][ksi_id] = indicator
                            all_data["ksi"][ksi_id] = indicator
                            
                            family = ksi_id.split("-")[0] if "-" in ksi_id else "OTHER"
                            if family not in all_data["families"]:
                                all_data["families"][family] = []
                            all_data["families"][family].append(ksi_id)
                
                # Handle requirements lists
                elif isinstance(subsection_data, dict) and "requirements" in subsection_data:
                    req_list = subsection_data.get("requirements", [])
                    for req in req_list:
                        if isinstance(req, dict) and "id" in req:
                            req_id = req["id"]
                            req["document"] = short_name
                            all_data["requirements"][req_id] = req
                            
                            family = req_id.split("-")[0] if "-" in req_id else "OTHER"
                            if family not in all_data["families"]:
                                all_data["families"][family] = []
                            all_data["families"][family].append(req_id)
                            
                            if short_name == "FRD" and "term" in req:
                                all_data["definitions"][req.get("term", req_id)] = req

    def _build_fka_map(self) -> None:
        """
        Build a reverse lookup map from legacy IDs to current IDs.

        CR26 carries no fka (formerly known as) fields, so the map is seeded
        from the bundled crosswalk (rules_data/legacy-crosswalk.json): legacy
        IDs like 'VDR-CSO-DET' or 'KSI-IAM-APM' resolve to their CR26 successor
        ('VDR-CSO-DET', 'KSI-IAM-APM'). Any fka fields present in the loaded
        data (older rule files) still take precedence.
        """
        self._fka_map.clear()

        if not self._data_cache:
            return

        requirements = self._data_cache.get("requirements", {})
        for legacy_id, entry in self._crosswalk.items():
            targets = [t for t in entry.get("current_ids", []) if t in requirements]
            if targets:
                self._fka_map[legacy_id.upper()] = targets[0]

        # Scan all requirements and KSIs for fka fields
        for req_id, req in self._data_cache.get("requirements", {}).items():
            if isinstance(req, dict) and "fka" in req:
                fka = req["fka"]
                if fka:
                    self._fka_map[fka.upper()] = req_id
        
        # Also scan KSIs separately (they may have different fka structure)
        for ksi_id, ksi in self._data_cache.get("ksi", {}).items():
            if isinstance(ksi, dict) and "fka" in ksi:
                fka = ksi["fka"]
                if fka:
                    self._fka_map[fka.upper()] = ksi_id
        
        logger.debug(f"Built fka map with {len(self._fka_map)} entries")

    def resolve_legacy_id(self, legacy_id: str) -> Optional[Dict[str, Any]]:
        """
        Explain how a legacy rule/KSI ID maps to CR26.

        Returns the crosswalk entry (current_ids, basis, confidence, names) or
        None when the ID is current or unknown. basis "related" means CR26 has
        no single successor; treat the target as the nearest rule, not a rename.
        """
        entry = self._crosswalk.get(legacy_id.upper())
        if entry is None:
            return None
        return {"legacy_id": legacy_id.upper(), **entry}

    def get_control_parameters(self, control_id: str) -> Optional[Dict[str, Any]]:
        """
        Get FedRAMP parameter values/guidance for a NIST control (CTL section).

        Accepts "AC-6(1)", "ac-6.1" or "AC-06-01".
        """
        if not self._data_cache:
            return None
        import re
        m = re.match(r"^\s*([A-Za-z]{2})-?0*(\d+)(?:[.(\-]0*(\d+)\)?)?\s*$", control_id)
        if not m:
            return None
        fam, base, enh = m.group(1).upper(), int(m.group(2)), m.group(3)
        key = f"{fam}-{base:02d}" + (f"-{int(enh):02d}" if enh else "")
        return self._data_cache.get("control_parameters", {}).get(key)

    def get_control(self, control_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific requirement by ID.
        
        Supports both CR26 IDs (e.g., 'VER-EVA-EFA', 'KSI-IAM-APM') and legacy IDs
        (e.g., 'VDR-CSO-DET', 'KSI-IAM-APM') via the legacy crosswalk.

        Args:
            control_id: The requirement identifier (new or legacy format)

        Returns:
            Requirement data or None if not found
        """
        if not self._data_cache:
            return None
        
        normalized_id = control_id.upper()
        
        # Try direct lookup first
        result = self._data_cache["requirements"].get(normalized_id)
        if result:
            return result
        
        # Fall back to fka (formerly known as) lookup for backward compatibility
        if normalized_id in self._fka_map:
            new_id = self._fka_map[normalized_id]
            return self._data_cache["requirements"].get(new_id)

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
        
        Supports both CR26 IDs (e.g., 'KSI-IAM-APM') and legacy IDs
        (e.g., 'KSI-IAM-APM') via the legacy crosswalk.

        Args:
            ksi_id: The KSI identifier (new or legacy format)

        Returns:
            KSI data or None if not found
        """
        if not self._data_cache:
            return None
        
        normalized_id = ksi_id.upper()
        
        # Try direct lookup first
        result = self._data_cache["ksi"].get(normalized_id)
        if result:
            return result
        
        # Fall back to fka (formerly known as) lookup for backward compatibility
        if normalized_id in self._fka_map:
            new_id = self._fka_map[normalized_id]
            return self._data_cache["ksi"].get(new_id)
    
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


    async def _fetch_docs_file_list(self) -> List[Dict[str, Any]]:
        """
        List markdown files under DOCS_PATH in DOCS_REPO (recursive).

        Uses one git trees call instead of walking directories. Each entry has
        "name" (path relative to DOCS_PATH, e.g. "providers/20x/index.md") and
        "path" (repo path).
        """
        url = f"{GITHUB_API_BASE}/repos/{DOCS_REPO}/git/trees/{DOCS_BRANCH}?recursive=1"
        prefix = f"{DOCS_PATH}/"

        async with httpx.AsyncClient(follow_redirects=True, timeout=HTTP_TIMEOUT) as client:
            try:
                response = await client.get(url, headers=_github_headers())
                response.raise_for_status()
                tree = response.json().get("tree", [])
                markdown_files = [
                    {"name": item["path"][len(prefix):], "path": item["path"]}
                    for item in tree
                    if item.get("type") == "blob"
                    and item.get("path", "").startswith(prefix)
                    and item["path"].endswith(".md")
                ]
                logger.info(f"Found {len(markdown_files)} markdown files in {DOCS_REPO}/{DOCS_PATH}")
                return markdown_files
            except Exception as e:
                logger.error(f"Failed to fetch docs file list: {e}")
                return []

    async def _fetch_markdown_file(self, filename: str, client: Optional[httpx.AsyncClient] = None) -> Optional[str]:
        """Fetch one markdown file; filename is relative to DOCS_PATH."""
        url = f"{GITHUB_RAW_BASE}/{DOCS_REPO}/{DOCS_BRANCH}/{DOCS_PATH}/{filename}"

        async def _get(c: httpx.AsyncClient) -> Optional[str]:
            try:
                response = await c.get(url)
                response.raise_for_status()
                return response.text
            except Exception as e:
                logger.error(f"Failed to fetch {filename}: {e}")
                return None

        if client is not None:
            return await _get(client)
        async with httpx.AsyncClient(follow_redirects=True, timeout=HTTP_TIMEOUT) as c:
            return await _get(c)

    def _read_docs_cache(self) -> Optional[Dict[str, str]]:
        cache_file = self._get_docs_cache_file()
        if not cache_file.exists():
            return None
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cached = json.load(f)
            meta = cached.get("__meta__", {}) if isinstance(cached, dict) else {}
            if meta.get("repo") != DOCS_REPO or meta.get("cache_format") != CACHE_FORMAT:
                logger.info("Ignoring documentation cache from an older source")
                return None
            return {k: v for k, v in cached.items() if k != "__meta__"}
        except Exception as e:
            logger.error(f"Failed to load docs cache: {e}")
            return None

    async def load_documentation(self, force_refresh: bool = False) -> Dict[str, str]:
        """
        Load FedRAMP documentation markdown files.

        Args:
            force_refresh: Force refresh from remote source

        Returns:
            Dictionary mapping file paths (relative to the docs root) to markdown
        """
        # Check memory cache first
        if not force_refresh and self._docs_cache and self._docs_cache_timestamp:
            if datetime.now() - self._docs_cache_timestamp < CACHE_DURATION:
                logger.info("Using in-memory docs cache")
                return self._docs_cache

        # Try to load from disk cache
        if not force_refresh:
            cached_data = self._read_docs_cache()
            if cached_data:
                logger.info("Loaded documentation from cache")
                self._docs_cache = cached_data
                self._docs_cache_timestamp = datetime.now()
                return cached_data

        logger.info(f"Fetching documentation from {DOCS_REPO}")
        files = [] if _truthy(os.environ.get("FEDRAMP_RULES_OFFLINE")) else await self._fetch_docs_file_list()
        if not files:
            stale = self._read_docs_cache()
            if stale:
                logger.warning("Using stale docs cache due to fetch failure")
                self._docs_cache = stale
                self._docs_cache_timestamp = datetime.now()
                return stale
            raise Exception("Failed to fetch documentation and no cache available")

        docs_data: Dict[str, str] = {}
        async with httpx.AsyncClient(follow_redirects=True, timeout=HTTP_TIMEOUT) as client:
            semaphore = asyncio.Semaphore(8)

            async def fetch(name: str) -> None:
                async with semaphore:
                    content = await self._fetch_markdown_file(name, client)
                if content:
                    docs_data[name] = content

            await asyncio.gather(*(fetch(f["name"]) for f in files))
        docs_data = dict(sorted(docs_data.items()))

        cache_file = self._get_docs_cache_file()
        try:
            payload = {"__meta__": {"repo": DOCS_REPO, "cache_format": CACHE_FORMAT,
                                    "fetched_at": datetime.now().isoformat()}, **docs_data}
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                logger.info("Saved documentation to cache")
        except Exception as e:
            logger.error(f"Failed to save docs cache: {e}")

        self._docs_cache = docs_data
        self._docs_cache_timestamp = datetime.now()

        logger.info(f"Loaded {len(docs_data)} documentation files")
        return docs_data

    def search_documentation(self, keywords: str) -> List[Dict[str, Any]]:
        """
        Search FedRAMP documentation by keywords.

        Args:
            keywords: Keywords to search for

        Returns:
            List of matching documentation sections with context
        """
        if not self._docs_cache:
            return []

        keywords_lower = keywords.lower()
        results = []

        for filename, content in self._docs_cache.items():
            content_lower = content.lower()
            
            # Check if keywords appear in the document
            if keywords_lower in content_lower:
                # Find all occurrences with context
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if keywords_lower in line.lower():
                        # Get context (3 lines before and after)
                        start = max(0, i - 3)
                        end = min(len(lines), i + 4)
                        context_lines = lines[start:end]
                        
                        results.append({
                            "filename": filename,
                            "line_number": i + 1,
                            "match": line.strip(),
                            "context": '\n'.join(context_lines)
                        })

        return results

    def get_documentation_file(self, filename: str) -> Optional[str]:
        """
        Get the full content of a specific documentation file.

        Args:
            filename: Path relative to the docs root (e.g., "providers/20x/index.md").
                A bare name or a path suffix also works when it matches one file.

        Returns:
            Full markdown content or None if not found
        """
        if not self._docs_cache:
            return None

        key = filename.strip().lstrip("/")
        if key.startswith(f"{DOCS_PATH}/"):
            key = key[len(DOCS_PATH) + 1:]
        if key in self._docs_cache:
            return self._docs_cache[key]
        matches = [k for k in self._docs_cache if k == key or k.endswith(f"/{key}")]
        return self._docs_cache[matches[0]] if len(matches) == 1 else None

    def list_documentation_files(self) -> List[str]:
        """
        List all available documentation files.

        Returns:
            List of documentation filenames
        """
        if not self._docs_cache:
            return []
        
        return list(self._docs_cache.keys())


# Global data loader instance
_data_loader: Optional[FedRAMPDataLoader] = None


def get_data_loader() -> FedRAMPDataLoader:
    """Get or create the global data loader instance."""
    global _data_loader
    if _data_loader is None:
        _data_loader = FedRAMPDataLoader()
    return _data_loader
