'use client';
import dynamic from 'next/dynamic';
import {AnimatePresence,motion,useReducedMotion} from 'motion/react';
import {useEffect,useMemo,useState} from 'react';
import type {IncidentInput,ScreeningResult} from '../lib/engine';
import {ExperienceChrome,Reveal} from './experience-chrome';

const ResilienceScene=dynamic(()=>import('./resilience-scene').then(m=>m.ResilienceScene),{ssr:false});

type SBOMSummary={components:number;vulnerabilities:number;high:number;names:string[];ids:string[]};
const nowMinus=(hours:number)=>new Date(Date.now()-hours*3600000).toISOString();
const presets:Record<string,IncidentInput>={
 'Exploited gateway':{product_name:'SmartFleet API Gateway',manufacturer:'Europa Mobility Systems',product_type:'commercial software',purpose:'API gateway distributed to enterprise fleet customers across the European market.',cra_scope_candidate:true,actively_exploited_vulnerability:true,severe_security_incident:false,nis2_entity_candidate:false,internet_exposed:true,customer_impact:'high',critical_service_dependency:false,supply_chain_exposure:true,cvss_score:9.8,sbom_available:true,affected_versions_known:true,exploit_evidence_available:true,incident_timeline_available:true,mitigation_documented:true,owner_assigned:true,csirt_contact_ready:false,legal_review_complete:false,awareness_at:nowMinus(5)},
 'Severe incident':{product_name:'Connected Device Cloud',manufacturer:'Nordlicht Devices GmbH',product_type:'IoT cloud software',purpose:'Cloud management software supporting commercially distributed connected devices in the EU.',cra_scope_candidate:true,severe_security_incident:true,nis2_entity_candidate:true,significant_nis2_incident:true,internet_exposed:true,customer_impact:'critical',critical_service_dependency:true,supply_chain_exposure:false,cvss_score:8.7,sbom_available:true,affected_versions_known:true,exploit_evidence_available:true,incident_timeline_available:true,mitigation_documented:false,owner_assigned:true,csirt_contact_ready:true,legal_review_complete:false,awareness_at:nowMinus(12)},
 'NIS2 service outage':{product_name:'Managed Infrastructure Service',manufacturer:'Rhein Digital Services',product_type:'managed ICT service',purpose:'Managed infrastructure and platform service used by important European enterprise customers.',cra_scope_candidate:false,nis2_entity_candidate:true,significant_nis2_incident:true,internet_exposed:true,customer_impact:'high',critical_service_dependency:true,supply_chain_exposure:true,cvss_score:7.9,exploit_evidence_available:true,incident_timeline_available:true,mitigation_documented:true,owner_assigned:true,csirt_contact_ready:true,legal_review_complete:false,awareness_at:nowMinus(7)},
 'Routine advisory':{product_name:'Desktop Analytics Client',manufacturer:'Demo Software GmbH',product_type:'desktop software',purpose:'Commercial desktop analytics product with a routine dependency advisory and no known exploitation.',cra_scope_candidate:true,actively_exploited_vulnerability:false,severe_security_incident:false,nis2_entity_candidate:false,internet_exposed:false,customer_impact:'low',cvss_score:5.2,sbom_available:true,affected_versions_known:true,exploit_evidence_available:false,incident_timeline_available:true,mitigation_documented:true,owner_assigned:true,csirt_contact_ready:false,legal_review_complete:false}
};
const checks:[keyof IncidentInput,string][]=[
 ['cra_scope_candidate','CRA scope candidate'],['actively_exploited_vulnerability','Actively exploited'],['severe_security_incident','Severe security incident'],
 ['nis2_entity_candidate','NIS2 entity candidate'],['significant_nis2_incident','Significant NIS2 incident'],['internet_exposed','Internet exposed'],
 ['critical_service_dependency','Critical service dependency'],['supply_chain_exposure','Supply-chain exposure'],
 ['sbom_available','SBOM available'],['affected_versions_known','Affected versions known'],['exploit_evidence_available','Exploit evidence'],
 ['incident_timeline_available','Incident timeline'],['mitigation_documented','Mitigation documented'],['owner_assigned','Owner assigned'],
 ['csirt_contact_ready','CSIRT contact ready'],['legal_review_complete','Legal review complete']
];
function pct(result:ScreeningResult|null){if(!result)return 0;return Math.round((result.required_evidence.length-result.missing_evidence.length)/Math.max(1,result.required_evidence.length)*100)}
function hoursLeft(iso:string){return Math.round((new Date(iso).getTime()-Date.now())/3600000*10)/10}
function parseSbom(doc:any):SBOMSummary{
 if(!doc||doc.bomFormat!=='CycloneDX')throw new Error('Upload CycloneDX JSON');
 const comps=Array.isArray(doc.components)?doc.components:[];const vulns=Array.isArray(doc.vulnerabilities)?doc.vulnerabilities:[];
 let high=0;for(const v of vulns){for(const r of (v.ratings||[])){if(['high','critical'].includes(String(r.severity||'').toLowerCase())||Number(r.score||0)>=7){high++;break}}}
 return {components:comps.length,vulnerabilities:vulns.length,high,names:comps.slice(0,6).map((x:any)=>x.name||'unknown'),ids:vulns.slice(0,6).map((x:any)=>x.id||'unknown')};
}
export function CommandCenter(){
 const reduced=useReducedMotion();const [active,setActive]=useState('Exploited gateway');const [form,setForm]=useState<IncidentInput>(presets[active]);const [result,setResult]=useState<ScreeningResult|null>(null);
 const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [sbom,setSbom]=useState<SBOMSummary|null>(null);const [history,setHistory]=useState<{name:string;decision:string;risk:number}[]>([]);
 const [evaluation,setEvaluation]=useState<{cases:number;passed:number;accuracy:number}|null>(null);
 useEffect(()=>{fetch('/api/evaluation').then(r=>r.json()).then(setEvaluation).catch(()=>{});try{setHistory(JSON.parse(localStorage.getItem('regops-history')||'[]'))}catch{}},[]);
 useEffect(()=>{setForm(presets[active]);setResult(null);setError('');setSbom(null)},[active]);
 const set=<K extends keyof IncidentInput>(k:K,v:IncidentInput[K])=>{setForm(f=>({...f,[k]:v}));setResult(null)};
 async function run(){
  setBusy(true);setError('');
  try{const r=await fetch('/api/analyze',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(form)});const d=await r.json();if(!r.ok)throw new Error(d.error||'Analysis failed');setResult(d.screening);
   const next=[{name:form.product_name,decision:d.screening.decision,risk:d.screening.risk_score},...history].slice(0,5);setHistory(next);localStorage.setItem('regops-history',JSON.stringify(next));
  }catch(e){setError(e instanceof Error?e.message:'Analysis failed')}finally{setBusy(false)}
 }
 async function upload(file:File){try{const doc=JSON.parse(await file.text());const sum=parseSbom(doc);setSbom(sum);set('sbom_available',true)}catch(e){setError(e instanceof Error?e.message:'SBOM parse failed')}}
 function exportPack(){if(!result)return;const blob=new Blob([JSON.stringify({generated_at:new Date().toISOString(),incident:form,sbom_summary:sbom,screening:result,status:'DRAFT_REQUIRES_HUMAN_APPROVAL'},null,2)],{type:'application/json'});const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download='regops-evidence-pack.json';a.click();URL.revokeObjectURL(u)}
 const coverage=pct(result);const color=result?.decision==='HUMAN_REVIEW_REQUIRED'?'danger':result?.decision==='CONTROL_REVIEW'?'warn':'safe';
 return <main className="experience">
  <ExperienceChrome/>
  <nav className="nav glass"><a className="brand" href="#top"><span>R</span>REGOPS <b>EU</b></a><div><a href="#triage">Triage</a><a href="#evidence">Evidence</a><a href="#deadlines">Deadlines</a><a href="#method">Method</a></div><em>zero-key public mode</em></nav>
  <section id="top" className="hero section">
   <motion.div className="hero-copy" initial={reduced?false:{opacity:0,y:30}} animate={{opacity:1,y:0}} transition={{duration:.8}}>
    <p className="eyebrow"><span/> CRA · NIS2 · SBOM · cyber resilience operations</p>
    <h1>From vulnerability<br/><i>to regulatory evidence.</i></h1>
    <p className="lede">A rules-first command center for cyber-resilience triage, reporting deadlines, evidence readiness and human approval — designed for European product and security teams.</p>
    <div className="hero-actions"><a className="primary" href="#triage">Run incident triage ↗</a><a className="secondary" href="#method">Inspect the control model</a></div>
    <div className="proof"><span>no paid API</span><span>CycloneDX-ready</span><span>human approval</span><span>synthetic demo data</span></div>
   </motion.div>
   <motion.div className="hero-scene" initial={reduced?false:{opacity:0,scale:.96}} animate={{opacity:1,scale:1}} transition={{duration:1,delay:.1}}><ResilienceScene risk={result?.risk_score||72}/></motion.div>
  </section>
  <section className="ticker"><div>CRA 24H EARLY WARNING · CRA 72H NOTIFICATION · NIS2 GERMANY 24H / 72H · SBOM EVIDENCE · HUMAN APPROVAL · AUDIT TRAIL · </div></section>

  <section id="triage" className="section">
   <Reveal><div className="section-head"><div><p className="eyebrow">01 / triage</p><h2>Turn an incident into an accountable workflow.</h2></div><p>Change any signal and rerun. The policy engine is deterministic; model output cannot create, waive or submit a regulatory obligation.</p></div></Reveal>
   <div className="scenario-row">{Object.keys(presets).map(x=><button key={x} className={active===x?'scenario active':'scenario'} onClick={()=>setActive(x)}>{x}</button>)}</div>
   <div className="grid two">
    <Reveal className="panel glass controls">
     <div className="panel-title"><span>Incident context</span><small>editable</small></div>
     <label>Product<input value={form.product_name} onChange={e=>set('product_name',e.target.value)}/></label>
     <label>Manufacturer<input value={form.manufacturer||''} onChange={e=>set('manufacturer',e.target.value)}/></label>
     <label>Purpose<textarea value={form.purpose} onChange={e=>set('purpose',e.target.value)}/></label>
     <div className="slider-row"><label>CVSS / technical severity <b>{form.cvss_score}</b><input type="range" min="0" max="10" step=".1" value={form.cvss_score??7.5} onChange={e=>set('cvss_score',Number(e.target.value))}/></label></div>
     <label>Customer impact<select value={form.customer_impact||'medium'} onChange={e=>set('customer_impact',e.target.value as any)}><option>none</option><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
     <div className="toggle-grid">{checks.map(([k,l])=><label className="toggle" key={String(k)}><input type="checkbox" checked={Boolean(form[k])} onChange={e=>set(k,e.target.checked as never)}/><span>{l}</span></label>)}</div>
     <div className="upload"><strong>CycloneDX SBOM</strong><input type="file" accept=".json,application/json" onChange={e=>e.target.files?.[0]&&upload(e.target.files[0])}/><small>{sbom?`${sbom.components} components · ${sbom.vulnerabilities} vulnerabilities · ${sbom.high} high/critical`:'Upload a .cdx.json or CycloneDX JSON file'}</small></div>
     <button className="primary full" onClick={run} disabled={busy}>{busy?'Analyzing evidence…':'Run RegOps analysis →'}</button>{error&&<p className="error">{error}</p>}
    </Reveal>
    <Reveal className={`panel glass outcome ${color}`}>
     <div className="panel-title"><span>Control decision</span><small>{result?'policy 2026.09':'awaiting run'}</small></div>
     <AnimatePresence mode="wait">{result?<motion.div key={result.decision} initial={{opacity:0,y:12}} animate={{opacity:1,y:0}} exit={{opacity:0}}>
       <p className="decision">{result.decision.replaceAll('_',' ')}</p><div className="risk-orb"><b>{result.risk_score}</b><span>risk index</span></div>
       <div className="status-grid"><div><small>CRA</small><strong>{result.cra_status}</strong></div><div><small>NIS2 DE</small><strong>{result.nis2_status}</strong></div><div><small>Evidence</small><strong>{coverage}%</strong></div></div>
       <div className="reasons">{result.reasons.map(x=><p key={x}>↳ {x}</p>)}</div>
       <div className="notice">{result.legal_notice}</div>
      </motion.div>:<div className="empty"><span>R</span><h3>Policy engine ready</h3><p>Select a scenario or edit the incident context, then run the analysis.</p>{evaluation&&<small>{evaluation.passed}/{evaluation.cases} synthetic regression cases passing</small>}</div>}</AnimatePresence>
    </Reveal>
   </div>
  </section>

  <section id="evidence" className="section">
   <Reveal><div className="section-head"><div><p className="eyebrow">02 / evidence</p><h2>Make proof visible before the clock wins.</h2></div><p>RegOps separates technical evidence from approval authority so teams can see exactly what is missing.</p></div></Reveal>
   <div className="grid three">
    <Reveal className="panel glass metric"><small>Evidence coverage</small><strong>{result?coverage:'—'}{result&&'%'}</strong><div className="bar"><i style={{width:`${coverage}%`}}/></div></Reveal>
    <Reveal className="panel glass metric"><small>Missing controls</small><strong>{result?result.missing_evidence.length:'—'}</strong><p>{result?.missing_evidence.slice(0,3).join(' · ')||'Run analysis to inspect gaps'}</p></Reveal>
    <Reveal className="panel glass metric"><small>SBOM intelligence</small><strong>{sbom?sbom.components:'—'}</strong><p>{sbom?`${sbom.vulnerabilities} vulnerabilities · ${sbom.ids.join(', ')}`:'CycloneDX upload ready'}</p></Reveal>
   </div>
   {result&&<Reveal className="panel glass matrix"><div className="panel-title"><span>Required evidence matrix</span><small>{result.required_evidence.length} controls</small></div>{result.required_evidence.map(x=><div className="evidence-row" key={x}><span className={result.missing_evidence.includes(x)?'dot missing':'dot ok'}/><b>{x}</b><em>{result.missing_evidence.includes(x)?'missing':'ready'}</em></div>)}</Reveal>}
  </section>

  <section id="deadlines" className="section">
   <Reveal><div className="section-head"><div><p className="eyebrow">03 / deadlines</p><h2>Operationalise the 24h / 72h reporting clock.</h2></div><p>Deadlines are generated from awareness time only when the deterministic screening identifies a reporting candidate.</p></div></Reveal>
   <div className="deadline-grid">{result?.deadlines.length?result.deadlines.map((d,i)=><motion.div className="deadline glass" key={d.label} initial={{opacity:0,y:20}} whileInView={{opacity:1,y:0}} transition={{delay:i*.08}}><small>{d.legal_basis}</small><h3>{d.label}</h3><strong>{hoursLeft(d.due_at)}h</strong><p>remaining · {new Date(d.due_at).toLocaleString()}</p></motion.div>):<div className="panel glass empty-wide">No reporting clock is active yet. Run a reporting-candidate scenario.</div>}</div>
   {result&&<Reveal className="panel glass route"><div className="panel-title"><span>Human approval route</span><small>submission never automatic</small></div><div className="route-line">{result.approval_route.map((x,i)=><div key={x}><span>{String(i+1).padStart(2,'0')}</span><b>{x}</b></div>)}</div><button className="secondary" onClick={exportPack}>Export evidence pack JSON ↓</button></Reveal>}
  </section>

  <section id="method" className="section method">
   <Reveal><div className="section-head"><div><p className="eyebrow">04 / control model</p><h2>AI assists. Policy decides. Humans approve.</h2></div></div></Reveal>
   <div className="grid three">
    <Reveal className="principle"><span>01</span><h3>Rules own obligation routing</h3><p>CRA/NIS2 candidate logic and reporting clocks stay deterministic, testable and versioned.</p></Reveal>
    <Reveal className="principle"><span>02</span><h3>AI is advisory only</h3><p>A future local model may organise evidence or draft narrative, but cannot change the policy result.</p></Reveal>
    <Reveal className="principle"><span>03</span><h3>Human release authority</h3><p>Every external notification remains a draft until a qualified reviewer explicitly approves it.</p></Reveal>
   </div>
   <div className="architecture glass"><code>SBOM / CVE / incident → deterministic risk + scope screen → CRA / NIS2 candidate → deadline engine → evidence gaps → human approval → report draft → audit</code></div>
   {history.length>0&&<div className="history"><small>recent local runs</small>{history.map((h,i)=><span key={i}>{h.name} · {h.decision} · {h.risk}</span>)}</div>}
  </section>
  <footer><b>RegOps EU</b><span>Cyber Resilience Operations Platform · synthetic portfolio demo · not legal advice</span></footer>
 </main>
}
