export type CRAStatus='scope-review'|'no-trigger-detected'|'reporting-candidate';
export type NIS2Status='not-assessed'|'no-trigger-detected'|'reporting-candidate';
export type Decision='STANDARD_MONITORING'|'CONTROL_REVIEW'|'HUMAN_REVIEW_REQUIRED';

export type IncidentInput={
  product_name:string; manufacturer?:string; product_type?:string; purpose:string;
  cra_scope_candidate?:boolean; actively_exploited_vulnerability?:boolean; severe_security_incident?:boolean;
  nis2_entity_candidate?:boolean; significant_nis2_incident?:boolean; internet_exposed?:boolean;
  customer_impact?:'none'|'low'|'medium'|'high'|'critical'; critical_service_dependency?:boolean;
  supply_chain_exposure?:boolean; cvss_score?:number; affected_versions_known?:boolean; sbom_available?:boolean;
  exploit_evidence_available?:boolean; incident_timeline_available?:boolean; mitigation_documented?:boolean;
  owner_assigned?:boolean; csirt_contact_ready?:boolean; legal_review_complete?:boolean;
  awareness_at?:string; corrective_measure_available_at?:string; cra_notification_submitted_at?:string; nis2_notification_submitted_at?:string;
};

export type Deadline={label:string;due_at:string;hours_from_awareness?:number|null;legal_basis:string};
export type ScreeningResult={
  cra_status:CRAStatus; nis2_status:NIS2Status; decision:Decision; risk_score:number; reasons:string[];
  required_evidence:string[]; missing_evidence:string[]; approval_route:string[]; deadlines:Deadline[];
  report_sections:string[]; policy_version:string; legal_notice:string;
};
const b=(x:IncidentInput,k:keyof IncidentInput,d=false)=>typeof x[k]==='boolean'?Boolean(x[k]):d;
const n=(x:IncidentInput,k:keyof IncidentInput,d:number)=>typeof x[k]==='number'?Number(x[k]):d;
const s=(x:IncidentInput,k:keyof IncidentInput,d:string)=>typeof x[k]==='string'?String(x[k]):d;

const evidence:Record<string,keyof IncidentInput>={
 'SBOM / affected component inventory':'sbom_available','Affected product versions':'affected_versions_known',
 'Exploit / incident evidence':'exploit_evidence_available','Incident timeline':'incident_timeline_available',
 'Mitigation / corrective action':'mitigation_documented','Named accountable owner':'owner_assigned',
 'Regulatory / CSIRT contact path':'csirt_contact_ready','Qualified legal/compliance review':'legal_review_complete'
};
const iso=(date:Date)=>date.toISOString();
const addHours=(v:string,h:number)=>{const d=new Date(v);d.setTime(d.getTime()+h*3600000);return iso(d)};
const addDays=(v:string,d:number)=>addHours(v,d*24);
const addCalendarMonth=(v:string)=>{
  const d=new Date(v),month=d.getUTCMonth()+1,year=d.getUTCFullYear()+Math.floor(month/12),targetMonth=month%12;
  const lastDay=new Date(Date.UTC(year,targetMonth+1,0)).getUTCDate();
  d.setUTCFullYear(year,targetMonth,Math.min(d.getUTCDate(),lastDay));
  return iso(d);
};

export function screen(x:IncidentInput):ScreeningResult{
  let cra:CRAStatus,reasons:string[]=[];
  if(!b(x,'cra_scope_candidate',true)){cra='scope-review';reasons.push('Product is not pre-classified as a CRA scope candidate; scope review is required before reporting logic is relied upon.')}
  else if(b(x,'actively_exploited_vulnerability')){cra='reporting-candidate';reasons.push('Actively exploited vulnerability indicator detected for a CRA scope candidate.')}
  else if(b(x,'severe_security_incident')){cra='reporting-candidate';reasons.push('Severe security-incident indicator detected for a CRA scope candidate.')}
  else {cra='no-trigger-detected';reasons.push('No CRA reporting trigger is detected by the checked-in screening policy.')}

  let nis2:NIS2Status='not-assessed';
  if(b(x,'nis2_entity_candidate')&&b(x,'significant_nis2_incident')){nis2='reporting-candidate';reasons.push('NIS2 entity + significant-incident indicators require human reporting review under the German BSIG workflow.')}
  else if(b(x,'nis2_entity_candidate')){nis2='no-trigger-detected';reasons.push('NIS2 entity candidate is present, but the significant-incident indicator is not set.')}

  let required=['Named accountable owner','Incident timeline','Mitigation / corrective action'];
  if(cra==='reporting-candidate')required.push('SBOM / affected component inventory','Affected product versions','Exploit / incident evidence','Regulatory / CSIRT contact path','Qualified legal/compliance review');
  if(nis2==='reporting-candidate')required.push('Exploit / incident evidence','Regulatory / CSIRT contact path','Qualified legal/compliance review');
  required=[...new Set(required)];
  const missing=required.filter(label=>!b(x,evidence[label],false));

  let risk=15+Math.trunc(n(x,'cvss_score',7.5)*5);
  if(b(x,'actively_exploited_vulnerability'))risk+=20;
  if(b(x,'severe_security_incident'))risk+=20;
  const impact=s(x,'customer_impact','medium'); if(['high','critical'].includes(impact))risk+=15;else if(impact==='medium')risk+=5;
  if(b(x,'critical_service_dependency'))risk+=10;if(b(x,'supply_chain_exposure'))risk+=8;if(b(x,'internet_exposed',true))risk+=5;
  risk=Math.min(100,risk);

  let decision:Decision='STANDARD_MONITORING';
  if(cra==='reporting-candidate'||nis2==='reporting-candidate')decision='HUMAN_REVIEW_REQUIRED';
  else if(cra==='scope-review'||missing.length)decision='CONTROL_REVIEW';

  let route=['Security / PSIRT'];
  if(cra==='reporting-candidate')route.push('Product Owner','CRA Compliance','Legal / Regulatory','Release Authority');
  if(nis2==='reporting-candidate')route.push('CISO / NIS2 Owner','Legal / Regulatory','Executive Duty Manager');
  route=[...new Set(route)];

  const awareness=x.awareness_at; const deadlines:Deadline[]=[];
  if(cra==='reporting-candidate'){
    if(awareness){
      deadlines.push({label:'CRA early warning',due_at:addHours(awareness,24),hours_from_awareness:24,legal_basis:'CRA Article 14 reporting workflow'});
      deadlines.push({label:'CRA notification',due_at:addHours(awareness,72),hours_from_awareness:72,legal_basis:'CRA Article 14 reporting workflow'});
    }
    if(b(x,'actively_exploited_vulnerability')&&x.corrective_measure_available_at)deadlines.push({label:'CRA final vulnerability report',due_at:addDays(x.corrective_measure_available_at,14),legal_basis:'CRA final-report workflow after corrective/mitigating measure availability'});
    else if(b(x,'severe_security_incident')&&x.cra_notification_submitted_at)deadlines.push({label:'CRA final incident report',due_at:addCalendarMonth(x.cra_notification_submitted_at),legal_basis:'CRA final-report workflow after submitted 72h notification'});
  }
  if(nis2==='reporting-candidate'){
    if(awareness){
      deadlines.push({label:'NIS2 Germany early warning',due_at:addHours(awareness,24),hours_from_awareness:24,legal_basis:'BSIG §32(1) no. 1'});
      deadlines.push({label:'NIS2 Germany incident notification',due_at:addHours(awareness,72),hours_from_awareness:72,legal_basis:'BSIG §32(1) no. 2'});
    }
    if(x.nis2_notification_submitted_at)deadlines.push({label:'NIS2 Germany final report',due_at:addCalendarMonth(x.nis2_notification_submitted_at),legal_basis:'BSIG §32(1) no. 4 after submitted incident notification'});
  }
  const sections=['executive_summary','product_and_versions','incident_timeline','technical_impact','mitigation','evidence_inventory'];
  if(cra==='reporting-candidate')sections.push('cra_trigger_analysis','cra_notification_draft');
  if(nis2==='reporting-candidate')sections.push('nis2_significance_analysis','nis2_notification_draft');
  return {cra_status:cra,nis2_status:nis2,decision,risk_score:risk,reasons,required_evidence:required,missing_evidence:missing,approval_route:route,deadlines,report_sections:sections,policy_version:'2026.09',legal_notice:'Decision-support screening only; not a legal determination or regulatory submission.'};
}
