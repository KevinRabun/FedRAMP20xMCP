"""
Alignment with the FedRAMP Consolidated Rules for 2026 (CR26).

Guards against the drift this server suffered before: rule/KSI IDs that no
longer (or never) existed in the published rules, a dead upstream data source,
and evidence pipeline templates that could overwrite or key-authenticate.

All tests run offline against the bundled snapshot.
"""

import asyncio
import json
import os
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
RULES_DIR = REPO / "src" / "fedramp_20x_mcp" / "rules_data"

os.environ["FEDRAMP_RULES_OFFLINE"] = "1"

ID_RE = re.compile(r"\b(?:KSI|FRR|[A-Z]{3})-[A-Z0-9]{2,3}(?:-[A-Z0-9]{2,3}){0,3}\b")
# Placeholders used in docs/templates/tests, never real IDs.
PLACEHOLDER_RE = re.compile(r"^(KSI|FRR)-(XXX|XYZ|YYY|FAM|ID)\b|^KSI-0\d$|^(KSI|FRR)-[A-Z]{3}$")


def _rules() -> dict:
    return json.loads((RULES_DIR / "fedramp-consolidated-rules.json").read_text(encoding="utf-8"))


def _current_ids() -> set:
    d = _rules()
    ids = set(d["FRD"]["data"]["all"])
    for fam in d["FRR"].values():
        for scope in fam["data"].values():
            for group in scope.values():
                ids |= set(group)
    for cat in d["KSI"].values():
        ids |= set(cat["indicators"])
    return ids


def _crosswalk() -> dict:
    return json.loads((RULES_DIR / "legacy-crosswalk.json").read_text(encoding="utf-8"))["crosswalk"]


def _rule_like_tokens(text: str) -> set:
    """Tokens that look like FedRAMP rule/KSI IDs (KSI-*, FRR-*, or a CR26/legacy family prefix)."""
    families = {"AFC", "AGU", "CCM", "CDS", "CMU", "CPO", "FRC", "IEC", "IVV", "MAS", "MKT", "REC",
                "SCG", "SCN", "SDR", "VDR", "VER", "ADS", "PVA", "FSI", "RSC", "UCM", "ICP", "FRD"}
    out = set()
    for tok in ID_RE.findall(text):
        head = tok.split("-")[0]
        if (head in ("KSI", "FRR") or head in families) and tok.count("-") >= 2 and not PLACEHOLDER_RE.match(tok):
            out.add(tok)
    return out


class TestBundledRules:
    def test_snapshot_shape(self):
        d = _rules()
        assert d["info"]["version"].startswith("2026.")
        assert len(d["FRR"]) == 17
        assert sum(len(c["indicators"]) for c in d["KSI"].values()) == 46

    def test_loader_uses_bundled_offline(self, tmp_path, monkeypatch):
        from fedramp_20x_mcp import data_loader as dl
        monkeypatch.setattr(dl, "CACHE_DIR", tmp_path)
        loader = dl.FedRAMPDataLoader()
        data = asyncio.run(loader.load_data())
        meta = loader.get_rules_metadata()
        assert meta["source"].startswith("bundled:")
        assert meta["version"] == _rules()["info"]["version"]
        assert len(meta["sha256"]) == 64
        assert len(data["ksi"]) == 46
        assert data["control_parameters"], "CTL section should be parsed"

    def test_loader_points_at_fedramp_rules(self):
        from fedramp_20x_mcp import data_loader as dl
        assert dl.DEFAULT_RULES_URL.endswith("FedRAMP/rules/main/fedramp-consolidated-rules.json")
        assert dl.DOCS_REPO == "FedRAMP/2026"


class TestCrosswalk:
    def test_targets_exist(self):
        current = _current_ids()
        bad = {k: v["current_ids"] for k, v in _crosswalk().items() if not set(v["current_ids"]) <= current}
        assert not bad

    def test_keys_are_not_current_ids(self):
        assert not set(_crosswalk()) & _current_ids()

    def test_every_entry_has_basis_and_confidence(self):
        for k, v in _crosswalk().items():
            assert v["basis"] in {"fka", "renamed", "merged", "family-successor", "renamed-by-text", "related"}, k
            assert v["confidence"] in {"high", "medium", "low"}, k

    @pytest.mark.parametrize("legacy,current", [
        ("KSI-IAM-01", "KSI-IAM-APM"),
        ("KSI-IAM-MFA", "KSI-IAM-APM"),
        ("FRR-VDR-01", "VDR-CSO-DET"),
        ("FRR-ADS-01", "CDS-CSO-PUB"),
        ("VDR-EVA-EFA", "VER-EVA-EFA"),
        ("FSI-CSO-INB", "AFC-CSO-INB"),
    ])
    def test_legacy_ids_resolve(self, legacy, current, tmp_path, monkeypatch):
        from fedramp_20x_mcp import data_loader as dl
        monkeypatch.setattr(dl, "CACHE_DIR", tmp_path)
        loader = dl.FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        assert loader.get_control(legacy)["id"] == current
        assert loader.resolve_legacy_id(legacy)["current_ids"][0] == current


# Files that must cite only current CR26 IDs. Tests, the crosswalk tooling and
# loader/tool docstrings that explain legacy resolution are excluded.
SCANNED = [
    "data/patterns",
    "src/fedramp_20x_mcp/prompts",
    "src/fedramp_20x_mcp/templates",
    "examples",
    ".azuredevops",
]


def _scanned_files():
    for rel in SCANNED:
        base = REPO / rel
        for f in sorted(base.rglob("*")):
            if f.is_file() and f.suffix in {".yaml", ".yml", ".txt", ".py", ".md"} and "__pycache__" not in f.parts:
                yield f


@pytest.mark.parametrize("path", list(_scanned_files()), ids=lambda p: str(p.relative_to(REPO)))
def test_only_current_rule_ids(path):
    current = _current_ids()
    stale = sorted(t for t in _rule_like_tokens(path.read_text(encoding="utf-8")) if t not in current)
    assert not stale, f"{path.relative_to(REPO)} cites IDs not in CR26: {stale}"


class TestEvidenceTemplates:
    def _load(self, rel):
        text = (REPO / rel).read_text(encoding="utf-8")
        return text, yaml.safe_load(text)

    def test_upload_template_is_worm_safe(self):
        text, doc = self._load(".azuredevops/templates/evidence-upload-steps.yml")
        params = {p["name"]: p for p in doc["parameters"]}
        assert params["storageAccount"]["default"] == "intellievidence"
        assert params["container"]["default"] == "vdr-reports"
        assert params["serviceConnection"]["default"] == "evidence-writer"
        assert params["blocking"]["default"] is True
        assert "--auth-mode login" in text
        code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
        assert "--overwrite" not in code
        assert "account-key" not in code and "sas-token" not in code and "connection-string" not in code
        assert "sha256-manifest.txt" in text and "run.json" in text

    @pytest.mark.parametrize("rel", [
        ".azuredevops/fedramp-compliance-pipeline.yml",
        ".azuredevops/templates/fedramp-scan-steps.yml",
        "examples/azure-devops/scan-and-store-evidence.yml",
        "examples/azure-devops/ksi-evidence-collection.yml",
        ".github/workflows/fedramp-compliance-check.yml",
    ])
    def test_pipelines_parse_and_use_real_entrypoint(self, rel):
        text, doc = self._load(rel)
        assert doc
        assert "bicep_analyzer" not in text and "python_analyzer" not in text
        if "scan" in rel or "compliance" in rel:
            assert "fedramp-20x-scan" in text or "fedramp-scan-steps.yml" in text

    def test_evidence_stage_skips_pull_requests(self):
        text, _ = self._load(".azuredevops/fedramp-compliance-pipeline.yml")
        assert "ne(variables['Build.Reason'], 'PullRequest')" in text


class TestScanner:
    def test_scan_writes_provenance(self, tmp_path):
        from fedramp_20x_mcp.ci import main

        src = tmp_path / "src"
        src.mkdir()
        (src / "main.tf").write_text(
            'resource "azurerm_storage_account" "x" {\n'
            '  name = "x"\n  min_tls_version = "TLS1_0"\n'
            '  allow_nested_items_to_be_public = true\n}\n', encoding="utf-8")
        (src / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
        out = tmp_path / "out"

        rc = main([str(src), "--output-dir", str(out), "--fail-on", "none"])
        assert rc == 0
        run = json.loads((out / "run.json").read_text(encoding="utf-8"))
        findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        assert run["rules"]["version"] == _rules()["info"]["version"]
        assert len(run["rules"]["sha256"]) == 64
        assert set(run["outputs"]) == {"findings.json", "report.md"}
        assert findings["summary"]["files_analyzed"] == 2
        assert findings["summary"]["invalid_requirement_ids"] == []
        assert (out / "report.md").read_text(encoding="utf-8").startswith("# FedRAMP 20x Pattern Scan")

    def test_gate_exit_code(self, tmp_path):
        from fedramp_20x_mcp.ci import main

        (tmp_path / "app.py").write_text("password = 'hunter2'\nimport hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
        rc_none = main([str(tmp_path), "--output-dir", str(tmp_path / "o1"), "--fail-on", "none"])
        rc_low = main([str(tmp_path), "--output-dir", str(tmp_path / "o2"), "--fail-on", "low"])
        issues = json.loads((tmp_path / "o2" / "findings.json").read_text(encoding="utf-8"))["summary"]["issues"]
        assert rc_none == 0
        assert rc_low == (1 if issues else 0)
