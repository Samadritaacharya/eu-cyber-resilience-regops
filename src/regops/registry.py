from __future__ import annotations
import json, sqlite3, uuid
from datetime import datetime, timezone

class Registry:
    def __init__(self, path: str='regops.sqlite3'):
        self.path=path; self._init()
    def _db(self): return sqlite3.connect(self.path)
    def _init(self):
        with self._db() as db:
            db.execute('create table if not exists cases(id text primary key, created_at text not null, payload text not null, result text not null)')
            db.execute('create table if not exists audit(id integer primary key autoincrement, case_id text not null, created_at text not null, event text not null)')
    def save(self,payload:dict,result:dict)->str:
        cid=str(uuid.uuid4()); now=datetime.now(timezone.utc).isoformat()
        with self._db() as db:
            db.execute('insert into cases values(?,?,?,?)',(cid,now,json.dumps(payload,default=str),json.dumps(result,default=str)))
            db.execute('insert into audit(case_id,created_at,event) values(?,?,?)',(cid,now,'SCREENED'))
        return cid
    def audit(self,cid:str,event:str):
        with self._db() as db: db.execute('insert into audit(case_id,created_at,event) values(?,?,?)',(cid,datetime.now(timezone.utc).isoformat(),event))
    def get(self,cid:str):
        with self._db() as db:
            row=db.execute('select id,created_at,payload,result from cases where id=?',(cid,)).fetchone()
            if not row:return None
            events=db.execute('select created_at,event from audit where case_id=? order by id',(cid,)).fetchall()
        return {'id':row[0],'created_at':row[1],'payload':json.loads(row[2]),'result':json.loads(row[3]),'audit':[{'created_at':a,'event':e} for a,e in events]}
