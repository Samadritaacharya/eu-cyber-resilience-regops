from fastapi.testclient import TestClient
from api import app
client=TestClient(app)

def payload(**kw):
    x={'product_name':'Gateway','purpose':'Synthetic portfolio incident with enough descriptive context.'}
    x.update(kw); return {'incident':x}

def test_health():
    r=client.get('/health'); assert r.status_code==200 and r.json()['paid_api_required'] is False

def test_analyze():
    r=client.post('/v1/analyze',json=payload(actively_exploited_vulnerability=True))
    assert r.status_code==200
    assert r.json()['screening']['decision']=='HUMAN_REVIEW_REQUIRED'
    assert r.json()['report_draft']['status']=='DRAFT_REQUIRES_HUMAN_APPROVAL'

def test_validation_rejects_unknown_fields():
    x=payload(); x['incident']['admin_override']=True
    assert client.post('/v1/analyze',json=x).status_code==422

def test_invalid_sbom():
    x=payload(); x['sbom']={'bomFormat':'SPDX'}
    assert client.post('/v1/analyze',json=x).status_code==422
