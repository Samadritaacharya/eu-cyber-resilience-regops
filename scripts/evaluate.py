import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.regops.models import IncidentInput
from src.regops.policy import screen

cases=json.loads((ROOT/'data/evaluation_cases.json').read_text())
ok=0
for c in cases:
    r=screen(IncidentInput(**c['input']))
    good=(r.cra_status==c['expected']['cra_status'] and r.nis2_status==c['expected']['nis2_status'] and r.decision==c['expected']['decision'])
    ok+=int(good)
print(json.dumps({'cases':len(cases),'passed':ok,'accuracy':ok/len(cases)},indent=2))
raise SystemExit(0 if ok==len(cases) else 1)
