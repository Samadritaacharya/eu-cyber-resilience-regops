from __future__ import annotations
import json, os, urllib.request

def advisory_summary(payload: dict, deterministic_result: dict) -> str:
    """Optional advisory summarisation. Never changes policy outputs."""
    base=os.getenv('REGOPS_LLM_BASE_URL','').strip(); model=os.getenv('REGOPS_LLM_MODEL','').strip()
    fallback=(f"RegOps EU screened {payload.get('product_name','the product')} as "
              f"CRA={deterministic_result.get('cra_status')} and NIS2={deterministic_result.get('nis2_status')}. "
              f"Human decision={deterministic_result.get('decision')}. "
              f"Missing evidence: {', '.join(deterministic_result.get('missing_evidence',[])[:5]) or 'none detected'}.")
    if not base or not model: return fallback
    try:
        body=json.dumps({"model":model,"messages":[
            {"role":"system","content":"Summarise the supplied deterministic cyber-resilience screening. Do not make legal determinations, invent facts, alter deadlines, or change the decision."},
            {"role":"user","content":json.dumps({"input":payload,"screening":deterministic_result},default=str)}
        ],"temperature":0}).encode()
        req=urllib.request.Request(base.rstrip('/')+'/chat/completions',data=body,headers={'content-type':'application/json'})
        with urllib.request.urlopen(req,timeout=8) as resp:
            data=json.loads(resp.read().decode())
        return str(data['choices'][0]['message']['content'])[:3000]
    except Exception:
        return fallback
