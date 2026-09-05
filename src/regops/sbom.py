from __future__ import annotations
from .models import SBOMSummary

def summarize_cyclonedx(doc: dict) -> SBOMSummary:
    if not isinstance(doc, dict) or doc.get('bomFormat') != 'CycloneDX':
        raise ValueError('CycloneDX JSON object required')
    comps = doc.get('components') or []
    vulns = doc.get('vulnerabilities') or []
    if not isinstance(comps, list) or not isinstance(vulns, list):
        raise ValueError('components and vulnerabilities must be arrays')
    names = [str(c.get('name','unknown')) for c in comps[:50] if isinstance(c,dict)]
    ids, high = [], 0
    for v in vulns[:100]:
        if not isinstance(v,dict): continue
        ids.append(str(v.get('id','unknown')))
        ratings = v.get('ratings') or []
        severities = {str(r.get('severity','')).lower() for r in ratings if isinstance(r,dict)}
        scores = [float(r.get('score',0) or 0) for r in ratings if isinstance(r,dict) and isinstance(r.get('score',0),(int,float))]
        if {'high','critical'} & severities or any(s >= 7 for s in scores): high += 1
    return SBOMSummary(format='CycloneDX', spec_version=str(doc.get('specVersion') or ''), components=len(comps), vulnerabilities=len(vulns), high_or_critical=high, component_names=names, vulnerability_ids=ids)
