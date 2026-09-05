from __future__ import annotations
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from src.regops.models import IncidentInput
from src.regops.policy import screen
from src.regops.reports import draft_report
from src.regops.sbom import summarize_cyclonedx
from src.regops.registry import Registry

app=FastAPI(title='RegOps EU API',version='1.0.0')
registry=Registry()

class AnalyzeRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    incident: IncidentInput
    sbom: dict|None=None

@app.get('/health')
def health(): return {'ok':True,'paid_api_required':False,'policy_version':'2026.09'}

@app.post('/v1/analyze')
def analyze(req:AnalyzeRequest):
    result=screen(req.incident)
    sbom=None
    if req.sbom is not None:
        try: sbom=summarize_cyclonedx(req.sbom).model_dump()
        except ValueError as e: raise HTTPException(status_code=422,detail=str(e))
    report=draft_report(req.incident,result)
    return {'screening':result.model_dump(mode='json'),'sbom':sbom,'report_draft':report}

@app.post('/v1/registry')
def save(req:AnalyzeRequest):
    result=screen(req.incident)
    cid=registry.save(req.incident.model_dump(mode='json'),result.model_dump(mode='json'))
    return {'id':cid}

@app.get('/v1/registry/{case_id}')
def get(case_id:str):
    item=registry.get(case_id)
    if not item: raise HTTPException(status_code=404,detail='not found')
    return item
