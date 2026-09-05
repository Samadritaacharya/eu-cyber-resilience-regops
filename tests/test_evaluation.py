import json
from pathlib import Path
from src.regops.models import IncidentInput
from src.regops.policy import screen

def test_all_labeled_cases():
    cases=json.loads(Path('data/evaluation_cases.json').read_text())
    assert len(cases)==30
    for c in cases:
        r=screen(IncidentInput(**c['input']))
        assert r.cra_status==c['expected']['cra_status'], c['id']
        assert r.nis2_status==c['expected']['nis2_status'], c['id']
        assert r.decision==c['expected']['decision'], c['id']
