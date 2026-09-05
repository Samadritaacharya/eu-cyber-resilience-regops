from src.regops.registry import Registry

def test_registry_round_trip(tmp_path):
    r=Registry(str(tmp_path/'db.sqlite3'))
    cid=r.save({'x':1},{'decision':'CONTROL_REVIEW'})
    r.audit(cid,'HUMAN_APPROVED')
    item=r.get(cid)
    assert item['payload']['x']==1
    assert [e['event'] for e in item['audit']]==['SCREENED','HUMAN_APPROVED']
