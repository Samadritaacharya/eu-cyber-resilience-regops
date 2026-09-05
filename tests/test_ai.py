from src.regops.ai import advisory_summary

def test_zero_key_fallback_is_advisory(monkeypatch):
    monkeypatch.delenv('REGOPS_LLM_BASE_URL',raising=False)
    monkeypatch.delenv('REGOPS_LLM_MODEL',raising=False)
    text=advisory_summary({'product_name':'Gateway'},{'cra_status':'reporting-candidate','nis2_status':'not-assessed','decision':'HUMAN_REVIEW_REQUIRED','missing_evidence':['Legal review']})
    assert 'HUMAN_REVIEW_REQUIRED' in text and 'Legal review' in text
