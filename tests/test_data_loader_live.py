"""
Tests for FedRAMP Data Loader - Live GitHub Sources (CR26)

These tests exercise the real remote sources used by the data loader:

1. FedRAMP/rules: the single consolidated rules file (raw.githubusercontent.com)
2. FedRAMP/2026: documentation file tree (GitHub git trees API)

They validate the fetched dataset shape: 17 FRR families, 10 KSI families,
FRD definitions, NIST control mappings, and the cache behavior.

NOTE: These tests require network access to github.com. They are skipped
cleanly when FEDRAMP_RULES_OFFLINE=1 is set or when the network or GitHub API
is unavailable (rate limit, auth).
"""

import os

import pytest

from fedramp_20x_mcp import data_loader as dl
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader

OFFLINE = os.environ.get("FEDRAMP_RULES_OFFLINE", "").strip().lower() in ("1", "true", "yes", "on")

pytestmark = pytest.mark.skipif(OFFLINE, reason="FEDRAMP_RULES_OFFLINE is set; live tests need network")

CR26_FRR_FAMILIES = {
    "AFC", "AGU", "CCM", "CDS", "CMU", "CPO", "FRC", "IEC", "IVV",
    "MAS", "MKT", "REC", "SCG", "SCN", "SDR", "VDR", "VER",
}
CR26_KSI_FAMILIES = {"CED", "CMT", "CNA", "IAM", "INR", "MLA", "PIY", "RPL", "SCR", "SVC"}


@pytest.fixture
def fresh_loader(tmp_path, monkeypatch):
    """Loader with an isolated cache dir so the package dir is never written."""
    monkeypatch.setattr(dl, "CACHE_DIR", tmp_path)
    monkeypatch.delenv("FEDRAMP_RULES_FILE", raising=False)
    return FedRAMPDataLoader()


@pytest.fixture
async def live_loader(fresh_loader):
    """Loader populated from the live rules file (skips if the fetch fails)."""
    fetched = await fresh_loader._fetch_rules_bytes()
    if not fetched:
        pytest.skip("FedRAMP/rules unreachable (network, auth or rate limit)")
    raw, source = fetched
    fresh_loader._set_data(fresh_loader._build_dataset(raw, source))
    return fresh_loader


class TestDataLoaderLive:
    """Test data loader against the live FedRAMP GitHub repositories."""

    @pytest.mark.asyncio
    async def test_fetch_rules_bytes_from_github(self, fresh_loader):
        """The consolidated rules file can be fetched and parsed as JSON."""
        import json

        fetched = await fresh_loader._fetch_rules_bytes()
        if not fetched:
            pytest.skip("FedRAMP/rules unreachable (network, auth or rate limit)")

        raw, source = fetched
        assert not source.startswith("bundled:")
        data = json.loads(raw.decode("utf-8"))
        assert {"info", "FRD", "FRR", "KSI"} <= set(data.keys())

    @pytest.mark.asyncio
    async def test_build_dataset_structure(self, live_loader):
        """Dataset built from the live rules has the expected sections."""
        data = live_loader._data_cache

        assert data is not None
        for section in ("requirements", "ksi", "definitions", "families", "metadata"):
            assert section in data, f"Should have {section} section"
        assert data["metadata"]["cache_format"] == dl.CACHE_FORMAT
        assert data["metadata"]["sha256"]

    @pytest.mark.asyncio
    async def test_rules_metadata(self, live_loader):
        """get_rules_metadata reports source, version and checksum."""
        meta = live_loader.get_rules_metadata()
        assert meta.get("version")
        assert meta.get("source")
        assert len(meta.get("sha256", "")) == 64

    @pytest.mark.asyncio
    async def test_ksi_families_and_controls(self, live_loader):
        """KSIs parse across the CR26 families and carry NIST control mappings."""
        ksis = live_loader.list_all_ksi()

        assert len(ksis) >= 40, f"Expected the CR26 KSI set, found {len(ksis)}"
        families = {k["id"].split("-")[1] for k in ksis}
        assert families == CR26_KSI_FAMILIES, f"Unexpected KSI families: {sorted(families)}"
        assert not any(k["id"].startswith(("KSI-AFR", "KSI-TPR", "KSI-VDR")) for k in ksis)

        with_controls = [k for k in ksis if k.get("controls")]
        assert with_controls, "Should have KSIs with NIST control mappings"
        assert all(isinstance(c, str) for c in with_controls[0]["controls"])

    @pytest.mark.asyncio
    async def test_frr_families(self, live_loader):
        """FRRs are grouped under the 17 CR26 families."""
        families = live_loader._data_cache["families"]
        found = CR26_FRR_FAMILIES & set(families.keys())
        assert found == CR26_FRR_FAMILIES, f"Missing FRR families: {sorted(CR26_FRR_FAMILIES - found)}"

        frr_count = sum(len(families[f]) for f in CR26_FRR_FAMILIES)
        assert frr_count >= 200, f"Expected the CR26 rule set, found {frr_count}"

        requirements = live_loader._data_cache["requirements"]
        sample = requirements[families["VDR"][0]]
        assert "id" in sample and "document" in sample

    @pytest.mark.asyncio
    async def test_definition_parsing(self, live_loader):
        """FRD definitions parse with term and definition."""
        definitions = live_loader.list_all_definitions()

        assert len(definitions) >= 40, f"Should have many definitions, found {len(definitions)}"
        assert "term" in definitions[0]
        assert "definition" in definitions[0]

    @pytest.mark.asyncio
    async def test_get_specific_rules_and_legacy_ids(self, live_loader):
        """Current IDs resolve; retired IDs resolve through the crosswalk."""
        assert live_loader.get_control("VDR-CSO-DET")["id"] == "VDR-CSO-DET"
        assert live_loader.get_ksi("KSI-IAM-APM")["id"] == "KSI-IAM-APM"
        assert live_loader.get_ksi("KSI-IAM-MFA") is not None, "legacy KSI should resolve via crosswalk"

    @pytest.mark.asyncio
    async def test_cache_written_after_remote_fetch(self, fresh_loader):
        """A successful remote fetch writes the cache; a new loader reads it."""
        data = await fresh_loader.load_data(force_refresh=True)
        if data["metadata"]["source"].startswith("bundled:"):
            pytest.skip("Remote fetch failed; loader fell back to bundled snapshot")

        assert fresh_loader._get_cache_file().exists()

        loader2 = FedRAMPDataLoader()
        cached = loader2._load_from_cache()
        assert cached is not None
        assert len(cached["requirements"]) == len(data["requirements"])

    @pytest.mark.asyncio
    async def test_fetch_docs_file_list_from_github(self, fresh_loader):
        """FedRAMP/2026 docs tree lists markdown files keyed by relative path."""
        files = await fresh_loader._fetch_docs_file_list()
        if not files:
            pytest.skip("GitHub trees API unavailable - likely auth/rate limit issue")

        assert all(f["name"].endswith(".md") for f in files)
        assert all(f["path"].startswith(f"{dl.DOCS_PATH}/") for f in files)
        assert all(f["path"] == f"{dl.DOCS_PATH}/{f['name']}" for f in files)


def test_loader_can_import():
    """Basic import test."""
    loader = FedRAMPDataLoader()
    assert loader is not None
