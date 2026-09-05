from datetime import datetime, timezone
from src.regops.models import IncidentInput
from src.regops.policy import screen

def base(**kw):
    x=dict(product_name='Gateway',purpose='Synthetic gateway incident used for deterministic portfolio testing.',owner_assigned=True,incident_timeline_available=True,mitigation_documented=True)
    x.update(kw); return IncidentInput(**x)

def test_active_exploit_routes_to_human_review():
    r=screen(base(actively_exploited_vulnerability=True))
    assert r.cra_status=='reporting-candidate'
    assert r.decision=='HUMAN_REVIEW_REQUIRED'
    assert 'CRA Compliance' in r.approval_route

def test_severe_incident_routes_to_human_review():
    assert screen(base(severe_security_incident=True)).cra_status=='reporting-candidate'

def test_nis2_candidate():
    r=screen(base(cra_scope_candidate=False,nis2_entity_candidate=True,significant_nis2_incident=True))
    assert r.nis2_status=='reporting-candidate'
    assert 'CISO / NIS2 Owner' in r.approval_route

def test_deadlines_are_24_72():
    t=datetime(2026,9,5,12,tzinfo=timezone.utc)
    r=screen(base(actively_exploited_vulnerability=True,awareness_at=t))
    due={d.label:d.due_at for d in r.deadlines}
    assert (due['CRA early warning']-t).total_seconds()==24*3600
    assert (due['CRA notification']-t).total_seconds()==72*3600

def test_no_trigger_but_missing_evidence_is_control_review():
    r=screen(base(owner_assigned=False))
    assert r.decision=='CONTROL_REVIEW'

def test_high_cvss_alone_does_not_create_reporting_claim():
    r=screen(base(cvss_score=10))
    assert r.cra_status=='no-trigger-detected'
