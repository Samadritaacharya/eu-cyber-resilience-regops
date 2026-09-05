from __future__ import annotations
from datetime import timedelta
from .models import IncidentInput, ScreeningResult, Deadline

EVIDENCE = {
    'sbom_available': 'SBOM / affected component inventory',
    'affected_versions_known': 'Affected product versions',
    'exploit_evidence_available': 'Exploit / incident evidence',
    'incident_timeline_available': 'Incident timeline',
    'mitigation_documented': 'Mitigation / corrective action',
    'owner_assigned': 'Named accountable owner',
    'csirt_contact_ready': 'Regulatory / CSIRT contact path',
    'legal_review_complete': 'Qualified legal/compliance review',
}

def _deadlines(x: IncidentInput, cra: str, nis2: str) -> list[Deadline]:
    if not x.awareness_at:
        return []
    out: list[Deadline] = []
    if cra == 'reporting-candidate':
        out += [
            Deadline(label='CRA early warning', due_at=x.awareness_at + timedelta(hours=24), hours_from_awareness=24, legal_basis='CRA Article 14 reporting workflow'),
            Deadline(label='CRA notification', due_at=x.awareness_at + timedelta(hours=72), hours_from_awareness=72, legal_basis='CRA Article 14 reporting workflow'),
        ]
        if x.actively_exploited_vulnerability and x.corrective_measure_available_at:
            out.append(Deadline(label='CRA final vulnerability report', due_at=x.corrective_measure_available_at + timedelta(days=14), legal_basis='CRA final-report workflow'))
        elif x.severe_security_incident:
            out.append(Deadline(label='CRA final incident report', due_at=x.awareness_at + timedelta(hours=72, days=30), legal_basis='CRA final-report workflow'))
    if nis2 == 'reporting-candidate':
        out += [
            Deadline(label='NIS2 Germany early warning', due_at=x.awareness_at + timedelta(hours=24), hours_from_awareness=24, legal_basis='BSIG §32(1) no. 1'),
            Deadline(label='NIS2 Germany incident notification', due_at=x.awareness_at + timedelta(hours=72), hours_from_awareness=72, legal_basis='BSIG §32(1) no. 2'),
            Deadline(label='NIS2 Germany final report', due_at=x.awareness_at + timedelta(hours=72, days=30), legal_basis='BSIG §32(1) no. 4'),
        ]
    return out

def screen(x: IncidentInput) -> ScreeningResult:
    reasons: list[str] = []
    if not x.cra_scope_candidate:
        cra = 'scope-review'
        reasons.append('Product is not pre-classified as a CRA scope candidate; scope review is required before reporting logic is relied upon.')
    elif x.actively_exploited_vulnerability:
        cra = 'reporting-candidate'
        reasons.append('Actively exploited vulnerability indicator detected for a CRA scope candidate.')
    elif x.severe_security_incident:
        cra = 'reporting-candidate'
        reasons.append('Severe security-incident indicator detected for a CRA scope candidate.')
    else:
        cra = 'no-trigger-detected'
        reasons.append('No CRA reporting trigger is detected by the checked-in screening policy.')

    if x.nis2_entity_candidate and x.significant_nis2_incident:
        nis2 = 'reporting-candidate'
        reasons.append('NIS2 entity + significant-incident indicators require human reporting review under the German BSIG workflow.')
    elif x.nis2_entity_candidate:
        nis2 = 'no-trigger-detected'
        reasons.append('NIS2 entity candidate is present, but the significant-incident indicator is not set.')
    else:
        nis2 = 'not-assessed'

    required = ['Named accountable owner', 'Incident timeline', 'Mitigation / corrective action']
    if cra == 'reporting-candidate':
        required += ['SBOM / affected component inventory','Affected product versions','Exploit / incident evidence','Regulatory / CSIRT contact path','Qualified legal/compliance review']
    if nis2 == 'reporting-candidate':
        required += ['Exploit / incident evidence','Regulatory / CSIRT contact path','Qualified legal/compliance review']
    required = list(dict.fromkeys(required))
    present = {label: bool(getattr(x, key)) for key, label in EVIDENCE.items()}
    missing = [label for label in required if not present.get(label, False)]

    score = 15
    score += int(x.cvss_score * 5)
    score += 20 if x.actively_exploited_vulnerability else 0
    score += 20 if x.severe_security_incident else 0
    score += 15 if x.customer_impact in {'high','critical'} else 5 if x.customer_impact == 'medium' else 0
    score += 10 if x.critical_service_dependency else 0
    score += 8 if x.supply_chain_exposure else 0
    score += 5 if x.internet_exposed else 0
    score = min(100, score)

    if cra == 'reporting-candidate' or nis2 == 'reporting-candidate':
        decision = 'HUMAN_REVIEW_REQUIRED'
    elif cra == 'scope-review' or missing:
        decision = 'CONTROL_REVIEW'
    else:
        decision = 'STANDARD_MONITORING'

    route = ['Security / PSIRT']
    if cra == 'reporting-candidate': route += ['Product Owner','CRA Compliance','Legal / Regulatory','Release Authority']
    if nis2 == 'reporting-candidate': route += ['CISO / NIS2 Owner','Legal / Regulatory','Executive Duty Manager']
    route = list(dict.fromkeys(route))

    sections = ['executive_summary','product_and_versions','incident_timeline','technical_impact','mitigation','evidence_inventory']
    if cra == 'reporting-candidate': sections += ['cra_trigger_analysis','cra_notification_draft']
    if nis2 == 'reporting-candidate': sections += ['nis2_significance_analysis','nis2_notification_draft']

    return ScreeningResult(
        cra_status=cra, nis2_status=nis2, decision=decision, risk_score=score,
        reasons=reasons, required_evidence=required, missing_evidence=missing,
        approval_route=route, deadlines=_deadlines(x,cra,nis2), report_sections=sections,
    )
