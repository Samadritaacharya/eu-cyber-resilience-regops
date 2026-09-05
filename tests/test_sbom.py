import json
from pathlib import Path
import pytest
from src.regops.sbom import summarize_cyclonedx

def test_demo_sbom():
    doc=json.loads(Path('data/demo-bom.cdx.json').read_text())
    r=summarize_cyclonedx(doc)
    assert r.components==6
    assert r.vulnerabilities==3
    assert r.high_or_critical==2
    assert 'CVE-DEMO-2026-0001' in r.vulnerability_ids

def test_rejects_non_cyclonedx():
    with pytest.raises(ValueError): summarize_cyclonedx({'bomFormat':'SPDX'})
