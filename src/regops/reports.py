from __future__ import annotations
from .models import IncidentInput, ScreeningResult

def draft_report(x: IncidentInput, r: ScreeningResult) -> dict:
    return {
        'title': f'RegOps EU evidence pack — {x.product_name}',
        'status': 'DRAFT_REQUIRES_HUMAN_APPROVAL',
        'legal_notice': r.legal_notice,
        'summary': f'{x.product_name} screened as CRA={r.cra_status}, NIS2={r.nis2_status}, decision={r.decision}.',
        'sections': r.report_sections,
        'reasons': r.reasons,
        'missing_evidence': r.missing_evidence,
        'approval_route': r.approval_route,
        'deadlines': [d.model_dump(mode='json') for d in r.deadlines],
    }
